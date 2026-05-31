// Package procmon is the LinAudit process resource monitor.
//
// Per-process CPU% (delta of /proc/pid/stat utime+stime), RSS memory, thread
// count, and owning user; per-process VRAM + GPU summary via nvidia-smi; plus a
// system CPU/RAM summary. A background sampler updates a snapshot under a mutex;
// it is fully local (no network). Mirrors web/procmon.py: Start() + SnapshotJSON().
package procmon

import (
	"encoding/binary"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	sampleInterval = 2 * time.Second
	// maxRows caps the returned process rows. When exceeded we keep the union
	// of the top rows by EACH sortable metric so client-side sorting by any
	// column still reveals the true leaders (not just the CPU top-N).
	maxRows = 300
)

// clkTck is jiffies per second (typically 100). PAGE is bytes per page. ncpu is
// the logical CPU count. All resolved once at init.
var (
	clkTck = readClkTck()
	page   = uint64(os.Getpagesize())
	ncpu   = max1(runtime.NumCPU())
)

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// readClkTck reads AT_CLKTCK (type 17) from /proc/self/auxv, a sequence of
// little-endian uint64 (type, value) pairs terminated by a (0, 0) pair. Falls
// back to 100 if unavailable or zero (matching os.sysconf("SC_CLK_TCK")).
func readClkTck() uint64 {
	const fallback = 100
	const atClkTck = 17
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return fallback
	}
	for off := 0; off+16 <= len(data); off += 16 {
		typ := binary.LittleEndian.Uint64(data[off : off+8])
		val := binary.LittleEndian.Uint64(data[off+8 : off+16])
		if typ == 0 && val == 0 {
			break
		}
		if typ == atClkTck {
			if val == 0 {
				return fallback
			}
			return val
		}
	}
	return fallback
}

// ----------------------------- JSON contract -------------------------------

// Proc is one process row. Field names/types match the /api/proc contract.
type Proc struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	RSS     int64   `json:"rss"`
	VRAM    int64   `json:"vram"`
	Threads int     `json:"threads"`
}

// GPU is the aggregate GPU summary (nil -> JSON null when no GPU/data).
type GPU struct {
	Name     string `json:"name"`
	MemUsed  int64  `json:"mem_used"`
	MemTotal int64  `json:"mem_total"`
	Util     int    `json:"util"`
	MemUtil  int    `json:"mem_util"`
}

// System is the system-wide summary block.
type System struct {
	CPU      float64 `json:"cpu"`
	NCPU     int     `json:"ncpu"`
	MemUsed  int64   `json:"mem_used"`
	MemTotal int64   `json:"mem_total"`
	GPUOk    bool    `json:"gpu_ok"`
	GPU      *GPU    `json:"gpu"`
}

// Snapshot is the full /api/proc payload.
type Snapshot struct {
	Processes []Proc  `json:"processes"`
	Count     int     `json:"count"`
	System    System  `json:"system"`
	Time      float64 `json:"time"`
}

// ----------------------------- shared state --------------------------------

var (
	mu    sync.RWMutex
	state = Snapshot{
		Processes: []Proc{},
		Count:     0,
		System: System{
			NCPU:  ncpu,
			GPUOk: hasNV(),
			GPU:   nil,
		},
		Time: 0,
	}
)

// ----------------------------- /proc parsing -------------------------------

var (
	uidCacheMu sync.Mutex
	uidCache   = map[uint32]string{}
)

// pids returns the numeric pid directory names under /proc.
func pids() []int {
	f, err := os.Open("/proc")
	if err != nil {
		return nil
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil
	}
	out := make([]int, 0, len(names))
	for _, n := range names {
		if pid, err := strconv.Atoi(n); err == nil && pid > 0 {
			out = append(out, pid)
		}
	}
	return out
}

// readStat parses /proc/<pid>/stat. comm is the parenthesized field (may contain
// spaces/parens), parsed between the FIRST '(' and the LAST ')'. The remaining
// fields are split on spaces; on rest (0-based, field 3 = rest[0]):
// utime=rest[11], stime=rest[12], num_threads=rest[17], rss_pages=rest[21].
// ticks = utime + stime. ok is false on any read/parse failure.
func readStat(pid int) (comm string, ticks uint64, threads int, rssPages uint64, ok bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", 0, 0, 0, false
	}
	return splitStat(string(raw))
}

// splitStat is the pure parser behind readStat (separated for testability). comm
// is parsed between the FIRST '(' and the LAST ')'; the remaining fields are
// split on spaces; on rest (0-based): utime=rest[11], stime=rest[12],
// num_threads=rest[17], rss_pages=rest[21]; ticks = utime + stime.
func splitStat(data string) (comm string, ticks uint64, threads int, rssPages uint64, ok bool) {
	rp := strings.LastIndexByte(data, ')')
	lp := strings.IndexByte(data, '(')
	if rp < 0 || lp < 0 || rp < lp {
		return "", 0, 0, 0, false
	}
	comm = data[lp+1 : rp]
	// rest starts 2 chars after the last ')': ") " then the state field.
	if rp+2 > len(data) {
		return "", 0, 0, 0, false
	}
	rest := strings.Fields(data[rp+2:])
	if len(rest) < 22 {
		return "", 0, 0, 0, false
	}
	utime, err1 := strconv.ParseUint(rest[11], 10, 64)
	stime, err2 := strconv.ParseUint(rest[12], 10, 64)
	thr, err3 := strconv.Atoi(rest[17])
	rss, err4 := strconv.ParseUint(rest[21], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return "", 0, 0, 0, false
	}
	return comm, utime + stime, thr, rss, true
}

// userName resolves the owning username of /proc/<pid> via its st_uid, cached.
// Falls back to the decimal uid, or "?" if the directory cannot be stat'd.
func userName(pid int) string {
	fi, err := os.Stat("/proc/" + strconv.Itoa(pid))
	if err != nil {
		return "?"
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return "?"
	}
	uid := st.Uid
	uidCacheMu.Lock()
	defer uidCacheMu.Unlock()
	if u, ok := uidCache[uid]; ok {
		return u
	}
	u := strconv.FormatUint(uint64(uid), 10)
	if usr, err := user.LookupId(u); err == nil {
		u = usr.Username
	}
	if len(uidCache) > 4096 {
		uidCache = map[uint32]string{}
	}
	uidCache[uid] = u
	return u
}

// meminfo parses /proc/meminfo MemTotal and MemAvailable, returned in bytes.
func meminfo() (total, avail int64) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = kbField(line) * 1024
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = kbField(line) * 1024
			return total, avail
		}
	}
	return total, avail
}

// kbField extracts the numeric kB value from a /proc/meminfo line ("Key: N kB").
func kbField(line string) int64 {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	v, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// cpuTotal returns (busy, total) jiffies from the aggregate /proc/stat line.
// busy = sum(all fields) - (idle + iowait); total = sum(all fields).
func cpuTotal() (busy, total uint64) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := string(raw)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, 0
	}
	vals := make([]uint64, 0, len(parts)-1)
	for _, p := range parts[1:] {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			break
		}
		vals = append(vals, v)
	}
	var sum uint64
	for _, v := range vals {
		sum += v
	}
	var idle uint64
	if len(vals) > 3 {
		idle = vals[3]
	}
	if len(vals) > 4 {
		idle += vals[4]
	}
	return sum - idle, sum
}

// ----------------------------- sampler -------------------------------------

// build computes a fresh Snapshot (minus Time) plus the per-pid tick map for the
// next delta. prev maps pid->ticks from the previous cycle; dt is the elapsed
// seconds; vram maps pid->VRAM bytes; gsum is the GPU summary; cpuBusyD/cpuTotD
// are the busy/total jiffy deltas for the system CPU figure.
func build(prev map[int]uint64, dt float64, vram map[int]int64, gsum *GPU, cpuBusyD, cpuTotD uint64) (Snapshot, map[int]uint64) {
	cur := make(map[int]uint64)
	rows := []Proc{}
	for _, pid := range pids() {
		comm, ticks, threads, rssPages, ok := readStat(pid)
		if !ok {
			continue
		}
		cur[pid] = ticks
		var cpu float64
		if p0, had := prev[pid]; had && dt > 0 {
			d := int64(ticks) - int64(p0)
			if d < 0 {
				d = 0
			}
			cpu = float64(d) / (float64(clkTck) * dt) * 100.0
		}
		rss := int64(rssPages * page)
		v := vram[pid]
		if rss <= 0 && v <= 0 && cpu <= 0.0 {
			// skip idle kernel threads / gone procs
			continue
		}
		rows = append(rows, Proc{
			PID:     pid,
			Name:    comm,
			User:    userName(pid),
			CPU:     round1(cpu),
			RSS:     rss,
			VRAM:    v,
			Threads: threads,
		})
	}
	total := len(rows)
	if total > maxRows {
		rows = capUnion(rows)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CPU > rows[j].CPU })

	mt, ma := meminfo()
	var sysCPU float64
	if cpuTotD > 0 {
		sysCPU = round1(float64(cpuBusyD) / float64(cpuTotD) * 100.0)
	}
	snap := Snapshot{
		Processes: rows,
		Count:     total,
		System: System{
			CPU:      sysCPU,
			NCPU:     ncpu,
			MemUsed:  mt - ma,
			MemTotal: mt,
			GPUOk:    hasNV(),
			GPU:      gsum,
		},
	}
	return snap, cur
}

// capUnion keeps the union of the top maxRows rows by each of cpu, rss, vram and
// threads, then returns the deduped set (final sort applied by the caller).
func capUnion(rows []Proc) []Proc {
	keep := map[int]Proc{}
	metrics := []func(p Proc) float64{
		func(p Proc) float64 { return p.CPU },
		func(p Proc) float64 { return float64(p.RSS) },
		func(p Proc) float64 { return float64(p.VRAM) },
		func(p Proc) float64 { return float64(p.Threads) },
	}
	for _, metric := range metrics {
		sorted := make([]Proc, len(rows))
		copy(sorted, rows)
		m := metric
		sort.SliceStable(sorted, func(i, j int) bool { return m(sorted[i]) > m(sorted[j]) })
		limit := maxRows
		if limit > len(sorted) {
			limit = len(sorted)
		}
		for _, r := range sorted[:limit] {
			keep[r.PID] = r
		}
	}
	// Emit in the deterministic order of the source slice (directory order), not
	// Go's randomized map-iteration order; the caller's stable cpu-desc sort then
	// gives a stable tie order across snapshots.
	out := make([]Proc, 0, len(keep))
	for _, r := range rows {
		if k, ok := keep[r.PID]; ok {
			out = append(out, k)
			delete(keep, r.PID)
		}
	}
	return out
}

// round1 rounds to one decimal place using round-half-to-even, matching Python's
// round(x, 1). strconv.FormatFloat with 'f',1 implements banker's rounding, so
// half cases (e.g. 6.25 -> 6.2, 12.35 -> 12.3) agree with the Python original.
func round1(x float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', 1, 64), 64)
	return v
}

// sampler is the background loop. It seeds prev ticks, then every interval
// computes deltas, refreshes the GPU on the first cycle and every 3rd cycle, and
// stores the snapshot under the lock. It never crashes on a transient error.
func sampler() {
	prev := map[int]uint64{}
	for _, pid := range pids() {
		if _, ticks, _, _, ok := readStat(pid); ok {
			prev[pid] = ticks
		}
	}
	tprev := time.Now()
	cb0, ct0 := cpuTotal()
	var gsum *GPU
	vram := map[int]int64{}
	i := 0
	hasGPU := hasNV()
	for {
		time.Sleep(sampleInterval)
		i++
		// Run one cycle under a recover so a transient panic backs off one
		// interval and continues (mirroring procmon.py's per-iteration
		// try/except) without crashing the process or losing the baseline.
		func() {
			defer func() { _ = recover() }()
			tcur := time.Now()
			dt := tcur.Sub(tprev).Seconds()
			cb1, ct1 := cpuTotal()
			if hasGPU && (gsum == nil || i%3 == 0) {
				gsum, vram = gpu()
			}
			var busyD, totD uint64
			if cb1 >= cb0 {
				busyD = cb1 - cb0
			}
			if ct1 >= ct0 {
				totD = ct1 - ct0
			}
			snap, cur := build(prev, dt, vram, gsum, busyD, totD)
			snap.Time = nowSeconds()
			mu.Lock()
			state = snap
			mu.Unlock()
			prev, tprev, cb0, ct0 = cur, tcur, cb1, ct1
		}()
	}
}

// nowSeconds returns the current time as float seconds (matching time.time()).
func nowSeconds() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// SnapshotJSON returns the most recent snapshot, suitable for json.Marshal.
func SnapshotJSON() any {
	mu.RLock()
	defer mu.RUnlock()
	s := state
	// Defensive copy of the slice so callers cannot observe a future mutation.
	procs := make([]Proc, len(s.Processes))
	copy(procs, s.Processes)
	s.Processes = procs
	return s
}

// Start launches the background sampler goroutine.
func Start() {
	go sampler()
}
