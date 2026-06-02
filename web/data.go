package web

// Data helpers backing the dashboard JSON endpoints: layer status, log
// metadata, log tailing, the journal view, the cross-plane correlation report,
// and the layer toggle. These mirror server.py's helpers and JSON contracts
// exactly.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// nowSeconds returns the current time as float seconds (matching Python time.time()).
func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// ----------------------------- status payload ------------------------------

// layersJSON is the layers block of /api/status.
type layersJSON struct {
	Zsh   bool `json:"zsh"`
	Input bool `json:"input"`
	Audit bool `json:"audit"`
}

// logMetaJSON is a per-file metadata block: byte size, newline count, float mtime.
type logMetaJSON struct {
	Bytes int64   `json:"bytes"`
	Lines int     `json:"lines"`
	Mtime float64 `json:"mtime"`
}

// logsJSON groups the three monitored log files.
type logsJSON struct {
	Buffer   logMetaJSON `json:"buffer"`
	Commands logMetaJSON `json:"commands"`
	Keys     logMetaJSON `json:"keys"`
}

// statusJSON is the full /api/status document.
type statusJSON struct {
	Layers    layersJSON `json:"layers"`
	Logs      logsJSON   `json:"logs"`
	Encrypted bool       `json:"encrypted"`
	Time      float64    `json:"time"`
}

// svcActive reports whether a systemd unit is active (`systemctl is-active
// --quiet name` exits 0).
func svcActive(name string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", name)
	return cmd.Run() == nil
}

// logmeta stats path and counts its newline-terminated lines. On any error all
// fields are zero, matching Python's OSError fallback.
func logmeta(path string) logMetaJSON {
	fi, err := os.Stat(path)
	if err != nil {
		return logMetaJSON{}
	}
	lines, err := countLines(path)
	if err != nil {
		return logMetaJSON{}
	}
	return logMetaJSON{
		Bytes: fi.Size(),
		Lines: lines,
		Mtime: float64(fi.ModTime().UnixNano()) / 1e9,
	}
}

// countLines counts '\n' bytes in path. Python counts file iterator lines, which
// equals the number of newline characters for newline-terminated logs.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	count := 0
	for {
		n, err := f.Read(buf)
		for _, b := range buf[:n] {
			if b == '\n' {
				count++
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return count, nil
			}
			// Any non-EOF read error after a successful stat is treated like
			// Python's broad OSError -> caller reports zero metadata.
			return 0, err
		}
		if n == 0 {
			return count, nil
		}
	}
}

// zshOn reports whether the zsh layer is wired and not disabled: ~/.zshrc must
// reference the linaudit hook AND the disable flag must be absent.
func zshOn() bool {
	wired := false
	if data, err := os.ReadFile(homeDir + "/.zshrc"); err == nil {
		wired = strings.Contains(string(data), "config/zsh/linaudit.zsh")
	}
	if !wired {
		return false
	}
	if _, err := os.Stat(disFlag); err == nil {
		return false
	}
	return true
}

// status assembles the /api/status payload.
func status() statusJSON {
	return statusJSON{
		Layers: layersJSON{
			Zsh:   zshOn(),
			Input: svcActive(inputService),
			Audit: svcActive(auditService),
		},
		Logs: logsJSON{
			Buffer:   logmeta(bufLog),
			Commands: logmeta(cmdLog),
			Keys:     logmeta(keyLog),
		},
		Encrypted: isMountpoint(mnt),
		Time:      nowSeconds(),
	}
}

// isMountpoint reports whether path is a mount point by comparing its device id
// with that of its parent directory (st_dev differs across a mount boundary).
func isMountpoint(path string) bool {
	var st, parent syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false
	}
	if err := syscall.Stat(path+"/..", &parent); err != nil {
		return false
	}
	return st.Dev != parent.Dev
}

// ------------------------------ log tailing --------------------------------

// tail returns the last n lines of path, reading at most the trailing 512 KiB
// and replacing invalid UTF-8. On error it returns a single diagnostic line.
func tail(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("(unavailable: %v)", err)}
	}
	defer f.Close()

	size, err := f.Seek(0, 2)
	if err != nil {
		return []string{fmt.Sprintf("(unavailable: %v)", err)}
	}
	blk := int64(512 * 1024)
	if size < blk {
		blk = size
	}
	if _, err := f.Seek(size-blk, 0); err != nil {
		return []string{fmt.Sprintf("(unavailable: %v)", err)}
	}
	data := make([]byte, blk)
	got, err := readFull(f, data)
	if err != nil {
		return []string{fmt.Sprintf("(unavailable: %v)", err)}
	}
	data = data[:got]

	lines := splitLines(strings.ToValidUTF8(string(data), "�"))
	if n >= 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// readFull fills buf from f, tolerating short reads. A short read terminated by
// EOF is not an error (the trailing 512 KiB window may shrink between seek and
// read on an actively-written log).
func readFull(f *os.File, buf []byte) (int, error) {
	n, err := io.ReadFull(f, buf)
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return n, nil
	}
	return n, err
}

// splitLines mirrors Python str.splitlines() for our log content: split on '\n'
// and drop a single trailing empty element produced by a terminating newline.
func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// journal returns the last n linaudit-usb / linaudit-input journal lines, or a
// diagnostic line on empty output / error.
func journal(n int) []string {
	cmd := exec.Command("journalctl", "-t", "linaudit-usb", "-t", "linaudit-input",
		"-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso")
	out, err := cmd.Output()
	if err != nil {
		return []string{fmt.Sprintf("(journal error: %v)", err)}
	}
	text := string(out)
	if text == "" {
		text = "(no usb/input journal entries)"
	}
	return splitLines(text)
}

// logview returns the requested log slice. which selects the source; n caps the
// number of lines.
func logview(which string, n int) []string {
	switch which {
	case "buffer":
		return tail(bufLog, n)
	case "exec", "commands":
		return tail(cmdLog, n)
	case "keys":
		return tail(keyLog, n)
	case "devices":
		marks := []string{"\tDEVICE_ADDED\t", "\tDEVICE_REMOVED\t", "\tAUDIT_START\t"}
		var kept []string
		for _, l := range tail(keyLog, 8000) {
			for _, m := range marks {
				if strings.Contains(l, m) {
					kept = append(kept, l)
					break
				}
			}
		}
		if n >= 0 && len(kept) > n {
			kept = kept[len(kept)-n:]
		}
		if kept == nil {
			kept = []string{}
		}
		return kept
	case "usb":
		return journal(n)
	default:
		return []string{"(unknown log)"}
	}
}

// ------------------------------- report ------------------------------------

// reportItem is one correlated event for /api/report. Kind carries the input
// bus for KEY events (wired|wireless|virtual|other) and is empty for other
// planes; the dashboard uses it to optionally hide wired-keyboard noise.
type reportItem struct {
	Ts     float64 `json:"ts"`
	Tag    string  `json:"tag"`
	Detail string  `json:"detail"`
	Kind   string  `json:"kind,omitempty"`
}

// reportRow is the intermediate (ts, tag, detail, kind) tuple used while
// merging. kind is set only for KEY rows.
type reportRow struct {
	ts     float64
	tag    string
	detail string
	kind   string
}

// report correlates the last n prompt buffer entries with exec and keystroke
// events, mirroring server.py report() exactly.
func report(n int) []reportItem {
	var bufs []reportRow
	for _, line := range tail(bufLog, 6000) {
		p := strings.Split(line, "\t")
		if len(p) >= 6 && p[4] == "BUFFER" {
			if ts, err := strconv.ParseFloat(p[1], 64); err == nil {
				bufs = append(bufs, reportRow{ts: ts, tag: "BUF", detail: p[5]})
			}
		}
	}
	if n >= 0 && len(bufs) > n {
		bufs = bufs[len(bufs)-n:]
	}
	if len(bufs) == 0 {
		return []reportItem{}
	}
	t0 := bufs[0].ts

	merged := make([]reportRow, len(bufs))
	copy(merged, bufs)

	for _, line := range tail(cmdLog, 6000) {
		p := strings.Split(line, "\t")
		if len(p) >= 6 && p[4] == "EXEC" {
			ts, err := strconv.ParseFloat(p[1], 64)
			if err != nil {
				continue
			}
			if ts >= t0 {
				merged = append(merged, reportRow{ts: ts, tag: "EXEC", detail: p[5]})
			}
		}
	}

	for _, line := range tail(keyLog, 12000) {
		p := strings.Split(line, "\t")
		if len(p) < 2 {
			continue
		}
		ts, err := strconv.ParseFloat(p[0], 64)
		if err != nil {
			continue
		}
		if ts < t0 {
			continue
		}
		if p[1] == "KEY" && len(p) >= 6 {
			kind := ""
			if len(p) >= 7 {
				kind = p[6]
			}
			merged = append(merged, reportRow{ts: ts, tag: "KEY",
				detail: fmt.Sprintf("%s %s val=%s", p[3], p[4], p[5]), kind: kind})
		} else if p[1] == "DEVICE_ADDED" || p[1] == "DEVICE_REMOVED" {
			extra := ""
			if len(p) >= 4 {
				extra = p[3]
			}
			merged = append(merged, reportRow{ts: ts, tag: "DEV",
				detail: fmt.Sprintf("%s %s", p[1], extra)})
		}
	}

	sort.SliceStable(merged, func(i, j int) bool { return merged[i].ts < merged[j].ts })

	items := make([]reportItem, 0, len(merged))
	for _, m := range merged {
		items = append(items, reportItem{Ts: m.ts, Tag: m.tag, Detail: m.detail, Kind: m.kind})
	}
	return items
}

// ------------------------------- toggle ------------------------------------

// toggle applies an enable/disable action to a layer and returns the new status.
func toggle(layer, action string) statusJSON {
	switch layer {
	case "zsh":
		if action == "disable" {
			if f, err := os.OpenFile(disFlag, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644); err == nil {
				f.Close()
				chownToUser(disFlag)
			}
		} else if _, err := os.Stat(disFlag); err == nil {
			os.Remove(disFlag)
		}
	default:
		svc := auditService
		if layer == "input" {
			svc = inputService
		}
		if action == "enable" {
			exec.Command("systemctl", "enable", "--now", svc).Run()
			if layer == "audit" {
				exec.Command("auditctl", "-e", "1").Run()
			}
		} else {
			exec.Command("systemctl", "disable", "--now", svc).Run()
		}
	}
	return status()
}

// chownToUser best-effort chowns path to the configured USER's uid/gid.
func chownToUser(path string) {
	u, err := user.Lookup(linauditUser)
	if err != nil {
		return
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return
	}
	os.Chown(path, uid, gid)
}
