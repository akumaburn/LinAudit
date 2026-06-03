package netmon

// asn.go adds an offline IP -> ASN/organization lookup, parallel to the GeoIP
// country DB in geoip.go. It powers the "known network owner" classification
// (corp / cloud / cdn / gov / telecom) shown per connection in the dashboard.
//
// Data source: sapics/ip-location-db, family "asn" (asn-ipv4.csv / asn-ipv6.csv),
// rows of [start, end, asn, as_name]; CC BY 4.0 (RouteViews / DB-IP / NRO).
//
// The range-lookup logic intentionally parallels countryDB rather than sharing a
// generic index with it: geoip.go is a frozen, parity-tested path (it mirrors
// netmon.py bit-for-bit), and keeping the two independent avoids disturbing that
// contract. Unlike countryDB's [][]byte layout, asnDB packs the start/end/maxend
// keys into flat width-strided byte slices, which roughly halves resident memory
// for the larger ASN table (~400k IPv4 rows) on this long-lived root service.

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// asnDB is a sorted, overlap-safe set of [start,end] IP ranges, each carrying an
// ASN number and organization name. Keys are fixed-width big-endian (4 or 16
// bytes) packed contiguously: row i's start key is starts[i*width:(i+1)*width].
// maxend[i] is the running max of ends[0..i], enabling the same nested-range
// walk-back countryDB uses.
type asnDB struct {
	width  int
	n      int
	starts []byte
	ends   []byte
	maxend []byte
	nums   []uint32
	names  []string
}

func (d *asnDB) startAt(i int) []byte  { return d.starts[i*d.width : (i+1)*d.width] }
func (d *asnDB) endAt(i int) []byte    { return d.ends[i*d.width : (i+1)*d.width] }
func (d *asnDB) maxendAt(i int) []byte { return d.maxend[i*d.width : (i+1)*d.width] }

// asnRow is an intermediate parsed row used only for sorting before the flat
// columnar arrays are built.
type asnRow struct {
	start []byte
	end   []byte
	num   uint32
	name  string
}

// newASNDB parses a CSV file of [startIP, endIP, asn, as_name] rows for the
// given address width. Rows that fail to parse, do not match the width, or have
// fewer than 4 columns are skipped. Returns an error if no usable rows remain.
func newASNDB(path string, width int) (*asnDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate variable column counts
	r.ReuseRecord = true

	rows := make([]asnRow, 0, 1024)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed lines rather than aborting the whole DB.
			continue
		}
		if len(rec) < 4 {
			continue
		}
		si := net.ParseIP(rec[0])
		ei := net.ParseIP(rec[1])
		if si == nil || ei == nil {
			continue
		}
		sb := toFixed(si, width)
		eb := toFixed(ei, width)
		if sb == nil || eb == nil {
			continue
		}
		num, _ := strconv.ParseUint(strings.TrimSpace(rec[2]), 10, 32)
		rows = append(rows, asnRow{start: sb, end: eb, num: uint32(num), name: strings.TrimSpace(rec[3])})
	}

	if len(rows) == 0 {
		return nil, errors.New("empty or corrupt asn csv: " + path)
	}

	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].start, rows[j].start) < 0
	})

	n := len(rows)
	db := &asnDB{
		width:  width,
		n:      n,
		starts: make([]byte, n*width),
		ends:   make([]byte, n*width),
		maxend: make([]byte, n*width),
		nums:   make([]uint32, n),
		names:  make([]string, n),
	}
	var mx []byte
	for i, row := range rows {
		copy(db.starts[i*width:], row.start)
		copy(db.ends[i*width:], row.end)
		if mx == nil || bytes.Compare(row.end, mx) > 0 {
			mx = row.end
		}
		copy(db.maxend[i*width:], mx)
		db.nums[i] = row.num
		db.names[i] = row.name
	}
	return db, nil
}

// find returns the index of the most-specific range containing x (a width-byte
// big-endian key), or -1. Mirrors countryDB.lookup's bisect_right-1 + overlap
// walk-back exactly.
func (d *asnDB) find(x []byte) int {
	if d == nil || d.n == 0 || len(x) != d.width {
		return -1
	}
	idx := sort.Search(d.n, func(k int) bool {
		return bytes.Compare(d.startAt(k), x) > 0
	})
	i := idx - 1
	if i < 0 {
		return -1
	}
	if bytes.Compare(x, d.endAt(i)) <= 0 { // disjoint fast path
		return i
	}
	for j := i - 1; j >= 0 && bytes.Compare(d.maxendAt(j), x) >= 0; j-- {
		if bytes.Compare(d.startAt(j), x) <= 0 && bytes.Compare(x, d.endAt(j)) <= 0 {
			return j
		}
	}
	return -1
}

// asnState holds both loaded databases plus the ready flag. Guarded by mu.
type asnState struct {
	mu    sync.RWMutex
	v4    *asnDB
	v6    *asnDB
	ready bool
}

var asnst asnState

// loadASN parses asn-ipv4.csv and asn-ipv6.csv from geodir. It publishes both
// databases and sets ready=true only if BOTH parse successfully. Intended to run
// in a goroutine started by Start().
func loadASN(geodir string) {
	v4, err4 := newASNDB(filepath.Join(geodir, "asn-ipv4.csv"), 4)
	v6, err6 := newASNDB(filepath.Join(geodir, "asn-ipv6.csv"), 16)
	asnst.mu.Lock()
	defer asnst.mu.Unlock()
	if err4 != nil || err6 != nil {
		asnst.ready = false
		return
	}
	asnst.v4 = v4
	asnst.v6 = v6
	asnst.ready = true
}

// ASNReady reports whether both ASN databases have parsed successfully.
func ASNReady() bool {
	asnst.mu.RLock()
	defer asnst.mu.RUnlock()
	return asnst.ready
}

// asnLookup returns the ASN number and organization name for ip, or (0, "") if
// the DB is not ready or no range matches. IPv4-mapped IPv6 addresses are
// unwrapped to v4 first, mirroring country().
func asnLookup(ip string) (uint32, string) {
	asnst.mu.RLock()
	ready := asnst.ready
	v4 := asnst.v4
	v6 := asnst.v6
	asnst.mu.RUnlock()
	if !ready {
		return 0, ""
	}
	a := net.ParseIP(ip)
	if a == nil {
		return 0, ""
	}
	if b4 := a.To4(); b4 != nil {
		key := make([]byte, 4)
		copy(key, b4)
		if i := v4.find(key); i >= 0 {
			return v4.nums[i], v4.names[i]
		}
		return 0, ""
	}
	b16 := a.To16()
	if b16 == nil {
		return 0, ""
	}
	key := make([]byte, 16)
	copy(key, b16)
	if i := v6.find(key); i >= 0 {
		return v6.nums[i], v6.names[i]
	}
	return 0, ""
}
