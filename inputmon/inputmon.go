// Package inputmon is the input-source attribution logger for LinAudit.
//
// It reads every key-capable /dev/input/event* device and logs each key event
// tagged with its SOURCE device name plus the kernel timestamp. A periodic
// rescan (every RESCAN) detects new or virtual (uinput) input devices -- the
// signature of a software keystroke injector.
//
// This is a pure-Go port of inputmon/inputmon.py. evdev access is implemented
// directly via raw ioctls (EVIOCGNAME / EVIOCGPHYS / EVIOCGBIT(EV_KEY)) and a
// hand-rolled 24-byte input_event decode -- no external dependencies.
//
// Log: /var/log/linaudit/input/keys.log  (root only, 0600)
// Format (tab separated, %.6f timestamps, single-quoted names):
//
//	<ts>  KEY            <devpath>  '<name>'  <KEYNAME>  <0=up|1=down|2=repeat>
//	<ts>  DEVICE_ADDED   <devpath>  '<name>'  phys='<phys>'  key-capable|non-key
//	<ts>  DEVICE_REMOVED <devpath>  '<name>'
//	<ts>  AUDIT_START    pid=<pid>  devices=<N>
package inputmon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	// logDir holds the keystroke log; created 0700, root only.
	logDir = "/var/log/linaudit/input"
	// logFile is the append-only keystroke log; created 0600.
	logFile = logDir + "/keys.log"
	// rescan is the interval between device rescans.
	rescan = 3 * time.Second
	// readEvents is the number of input_event records read per syscall.
	readEvents = 64
)

// device is a tracked /dev/input/event* node.
type device struct {
	path    string
	name    string
	keyCap  bool
	fd      int
	devFile *os.File
}

// monitor owns the shared state: the open log file, the set of known devices,
// and the synchronization that protects each.
type monitor struct {
	logMu sync.Mutex
	logf  *os.File

	mu    sync.Mutex
	known map[string]*device
}

// Run is the package entry point. It opens the log, performs the initial device
// enumeration, emits AUDIT_START, then loops rescanning forever. It returns a
// non-nil error only on a fatal setup failure (log directory/file unopenable).
// Transient per-device errors never crash the process.
func Run() error {
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}
	// Best-effort tighten on the directory (mirrors the Python chmod).
	_ = os.Chmod(logDir, 0700)

	logf, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_ = os.Chmod(logFile, 0600)

	m := &monitor{
		logf:  logf,
		known: make(map[string]*device),
	}
	defer logf.Close()

	// Initial enumeration, then AUDIT_START with the device count.
	m.scan()
	m.logFields(now(), "AUDIT_START", "pid="+strconv.Itoa(os.Getpid()),
		"devices="+strconv.Itoa(m.deviceCount()))

	// Rescan loop. The reader goroutines run independently; this loop only
	// discovers newly-appeared devices.
	ticker := time.NewTicker(rescan)
	defer ticker.Stop()
	for range ticker.C {
		m.scan()
	}
	return nil
}

// deviceCount returns the number of currently-known devices.
func (m *monitor) deviceCount() int {
	m.mu.Lock()
	n := len(m.known)
	m.mu.Unlock()
	return n
}

// scan enumerates /dev/input/event* and opens any path not already known. For
// every NEW device it logs DEVICE_ADDED (key-capable or not); for key-capable
// devices it spawns a dedicated reader goroutine.
func (m *monitor) scan() {
	defer func() { _ = recover() }()

	paths, err := filepath.Glob("/dev/input/event*")
	if err != nil {
		return
	}
	sort.Strings(paths)

	for _, path := range paths {
		m.mu.Lock()
		_, seen := m.known[path]
		m.mu.Unlock()
		if seen {
			continue
		}
		m.openDevice(path)
	}
}

// openDevice opens a single new device path, queries its metadata, registers it
// in the known-set, logs DEVICE_ADDED, and starts a reader for key-capable
// devices. Failures to open are silently skipped (matching the Python try/except).
func (m *monitor) openDevice(path string) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return
	}
	fd := int(f.Fd())

	name := deviceName(fd)
	phys := devicePhys(fd)
	keyCap := keyCapable(fd)

	dev := &device{
		path:    path,
		name:    name,
		keyCap:  keyCap,
		fd:      fd,
		devFile: f,
	}

	// Register before logging/reading so a concurrent rescan won't double-open.
	m.mu.Lock()
	if _, exists := m.known[path]; exists {
		m.mu.Unlock()
		f.Close()
		return
	}
	m.known[path] = dev
	m.mu.Unlock()

	capStr := "non-key"
	if keyCap {
		capStr = "key-capable"
	}
	m.logFields(now(), "DEVICE_ADDED", path, reprSingle(name),
		"phys="+reprSingle(phys), capStr)

	if keyCap {
		go m.reader(dev)
	}
}

// reader is the per-device read loop. It blocks on Read in its own goroutine
// (so blocking is fine), decodes each 24-byte input_event, and logs a KEY line
// for every EV_KEY event. On any read error (device removed / ENODEV) it logs
// DEVICE_REMOVED, closes the fd, drops the device from the known-set, and exits.
func (m *monitor) reader(dev *device) {
	defer func() { _ = recover() }()

	buf := make([]byte, eventSize*readEvents)
	for {
		n, err := dev.devFile.Read(buf)
		if err != nil {
			m.removeDevice(dev)
			return
		}
		// Process only whole events; a partial tail (should not happen on
		// evdev) is ignored until the next read.
		for off := 0; off+eventSize <= n; off += eventSize {
			ev, ok := decodeEvent(buf[off : off+eventSize])
			if !ok {
				continue
			}
			if ev.Type != evKey {
				continue
			}
			m.logFields(
				fmtTime(eventTimestamp(ev)),
				"KEY",
				dev.path,
				reprSingle(dev.name),
				keyname(ev.Code),
				strconv.Itoa(int(ev.Value)),
			)
		}
		// A zero-length read with no error indicates EOF; treat as removal.
		if n == 0 {
			m.removeDevice(dev)
			return
		}
	}
}

// removeDevice logs DEVICE_REMOVED, closes the device, and drops it from the
// known-set. It is idempotent: a device already removed is a no-op.
func (m *monitor) removeDevice(dev *device) {
	m.mu.Lock()
	cur, ok := m.known[dev.path]
	if !ok || cur != dev {
		m.mu.Unlock()
		// Still ensure our fd is closed.
		dev.devFile.Close()
		return
	}
	delete(m.known, dev.path)
	m.mu.Unlock()

	m.logFields(now(), "DEVICE_REMOVED", dev.path, reprSingle(dev.name))
	dev.devFile.Close()
}

// logFields writes one tab-separated record terminated by '\n'. Writes are
// serialized by logMu; write errors are tolerated and dropped (matching the
// line-buffered, best-effort Python logger).
func (m *monitor) logFields(fields ...string) {
	line := strings.Join(fields, "\t") + "\n"
	m.logMu.Lock()
	_, _ = m.logf.WriteString(line)
	// Append mode on a regular file is already flushed by the write syscall;
	// Sync would be far too costly per keystroke. We deliberately do not Sync.
	m.logMu.Unlock()
}

// now formats the current wall-clock time as %.6f epoch seconds, used for all
// records except KEY (which uses the kernel event timestamp).
func now() string {
	return fmtTime(float64(time.Now().UnixNano()) / 1e9)
}

// fmtTime formats an epoch-seconds value as %.6f, matching Python's
// "%.6f" % t. strconv.FormatFloat with prec 6 in 'f' mode is byte-identical
// (round-half-to-even, fixed 6 fractional digits).
func fmtTime(t float64) string {
	return strconv.FormatFloat(t, 'f', 6, 64)
}

// reprSingle renders s the way Python's repr() renders a str: wrapped in single
// quotes (switching to double quotes only when s contains a single quote but no
// double quote), with backslash, the active quote, and every non-printable rune
// escaped (\t \n \r, then \xNN / \uNNNN / \UNNNNNNNN). This guarantees a raw TAB
// or newline embedded in a device name or phys string can never break the
// tab-separated, one-record-per-line keys.log contract that the report/logview
// parsers depend on. Plain ASCII names (the overwhelmingly common case) are
// emitted unchanged as 'name'.
//
//	abc        -> 'abc'
//	it's       -> "it's"
//	back\slash -> 'back\\slash'
//	a<TAB>b    -> 'a\tb'
func reprSingle(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xff:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}
