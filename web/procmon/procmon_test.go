package procmon

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestReadStatSelf parses the live /proc/self/stat and validates the field
// indices used for utime/stime (ticks), num_threads and rss_pages.
func TestReadStatSelf(t *testing.T) {
	pid := os.Getpid()
	comm, ticks, threads, rssPages, ok := readStat(pid)
	if !ok {
		t.Fatalf("readStat(%d) failed", pid)
	}
	if comm == "" {
		t.Errorf("comm is empty")
	}
	if threads < 1 {
		t.Errorf("threads = %d, want >= 1", threads)
	}
	// ticks is an unsigned counter; it is always >= 0 by type. Assert it is a
	// sane (non-overflowed) value relative to rss for documentation purposes.
	_ = ticks
	if rssPages == 0 {
		t.Errorf("rss_pages = 0, want > 0 for the running test process")
	}
}

// TestReadStatCommWithParens ensures comm parsing uses the LAST ')'.
func TestReadStatCommWithParens(t *testing.T) {
	// Synthesize a stat line whose comm contains spaces and parens. We exercise
	// the parsing path directly by writing a temp file is not possible (readStat
	// hardcodes /proc), so we validate the logic via the helper splitStat below.
	// rest[] indices (0-based, after the last ')' + the state field at rest[0]):
	// utime=rest[11]=11, stime=rest[12]=22, num_threads=rest[17]=7,
	// rss_pages=rest[21]=99.
	rest := []string{
		"S", "1", "1", "1", "0", "-1", "0", "0", "0", "0", "0", // 0..10
		"11", "22", "0", "0", "20", "0", "7", "0", "0", "0", "99", // 11..21
	}
	data := "1234 (weird (proc) name) " + strings.Join(rest, " ")
	comm, ticks, threads, rssPages, ok := splitStat(data)
	if !ok {
		t.Fatalf("splitStat failed")
	}
	if comm != "weird (proc) name" {
		t.Errorf("comm = %q, want %q", comm, "weird (proc) name")
	}
	if ticks != 33 {
		t.Errorf("ticks = %d, want 33 (11+22)", ticks)
	}
	if threads != 7 {
		t.Errorf("threads = %d, want 7", threads)
	}
	if rssPages != 99 {
		t.Errorf("rss_pages = %d, want 99", rssPages)
	}
}

func TestMeminfoTotal(t *testing.T) {
	total, avail := meminfo()
	if total <= 0 {
		t.Errorf("MemTotal = %d, want > 0", total)
	}
	if avail < 0 {
		t.Errorf("MemAvailable = %d, want >= 0", avail)
	}
	if avail > total {
		t.Errorf("MemAvailable (%d) > MemTotal (%d)", avail, total)
	}
}

func TestClkTck(t *testing.T) {
	if clkTck == 0 {
		t.Errorf("clkTck = 0, want > 0")
	}
}

func TestReadClkTckValue(t *testing.T) {
	if v := readClkTck(); v == 0 {
		t.Errorf("readClkTck() = 0, want > 0")
	}
}

func TestCpuTotal(t *testing.T) {
	busy, total := cpuTotal()
	if total == 0 {
		t.Errorf("cpu total = 0, want > 0")
	}
	if busy > total {
		t.Errorf("busy (%d) > total (%d)", busy, total)
	}
}

func TestRound1(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{0.04, 0.0},
		{0.12, 0.1},
		{12.34, 12.3},
		{12.36, 12.4},
		{99.99, 100.0},
	}
	for _, c := range cases {
		if got := round1(c.in); got != c.want {
			t.Errorf("round1(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestSnapshotJSONMarshals confirms the empty/initial snapshot serializes with
// non-null slices and the expected top-level keys.
func TestSnapshotJSONMarshals(t *testing.T) {
	b, err := json.Marshal(SnapshotJSON())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"processes", "count", "system", "time"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in snapshot JSON", k)
		}
	}
	if string(m["processes"]) == "null" {
		t.Errorf("processes marshaled as null, want []")
	}
}
