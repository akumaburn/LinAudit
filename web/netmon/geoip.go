package netmon

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// countryDB holds GeoIP ranges sorted by start IP with an overlap-safe lookup.
// Rows are sorted by start, but a small fraction nest a more-specific range
// inside a broader one; the maxend running-max-of-end prefix lets us walk back
// to a covering range. IPs are fixed-width big-endian byte slices (4 bytes for
// v4, 16 for v6) compared via bytes.Compare.
type countryDB struct {
	starts [][]byte
	ends   [][]byte
	ccs    []string
	maxend [][]byte // running max of ends[0..i]
	width  int      // 4 or 16
}

// dbRow is an intermediate parsed row used only for sorting before the
// columnar arrays are built.
type dbRow struct {
	start []byte
	end   []byte
	cc    string
}

// toFixed normalizes a net.IP into a width-byte big-endian slice, or returns
// nil if it does not match the requested width family.
func toFixed(ip net.IP, width int) []byte {
	if ip == nil {
		return nil
	}
	if width == 4 {
		v4 := ip.To4()
		if v4 == nil {
			return nil
		}
		b := make([]byte, 4)
		copy(b, v4)
		return b
	}
	// width == 16: reject genuine IPv4 (To4 != nil) so v4 rows never leak into
	// the v6 DB; v4-mapped handling happens before lookup in country().
	if ip.To4() != nil {
		return nil
	}
	v16 := ip.To16()
	if v16 == nil {
		return nil
	}
	b := make([]byte, 16)
	copy(b, v16)
	return b
}

// newCountryDB parses a CSV file of [startIP, endIP, cc] rows for the given
// address width. Rows that fail net.ParseIP, do not match the width, or have
// fewer than 3 columns are skipped. Returns an error if no usable rows remain.
func newCountryDB(path string, width int) (*countryDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // tolerate variable column counts
	r.ReuseRecord = true

	rows := make([]dbRow, 0, 1024)
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed lines rather than aborting the whole DB.
			if errors.Is(err, csv.ErrFieldCount) {
				continue
			}
			continue
		}
		if len(rec) < 3 {
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
		rows = append(rows, dbRow{start: sb, end: eb, cc: rec[2]})
	}

	if len(rows) == 0 {
		return nil, errors.New("empty or corrupt geoip csv: " + path)
	}

	sort.Slice(rows, func(i, j int) bool {
		return bytes.Compare(rows[i].start, rows[j].start) < 0
	})

	db := &countryDB{
		starts: make([][]byte, len(rows)),
		ends:   make([][]byte, len(rows)),
		ccs:    make([]string, len(rows)),
		maxend: make([][]byte, len(rows)),
		width:  width,
	}
	var mx []byte
	for i, row := range rows {
		db.starts[i] = row.start
		db.ends[i] = row.end
		db.ccs[i] = row.cc
		if mx == nil || bytes.Compare(row.end, mx) > 0 {
			mx = row.end
		}
		db.maxend[i] = mx
	}
	return db, nil
}

// lookup returns the country code for x (a width-byte big-endian key) or ""
// if not found. Mirrors the Python bisect_right - 1 + overlap walk-back.
func (d *countryDB) lookup(x []byte) string {
	if len(x) != d.width {
		return ""
	}
	// i = largest index with starts[i] <= x. sort.Search finds the first index
	// with starts[idx] > x; back up by one.
	n := len(d.starts)
	idx := sort.Search(n, func(k int) bool {
		return bytes.Compare(d.starts[k], x) > 0
	})
	i := idx - 1
	if i < 0 {
		return ""
	}
	if bytes.Compare(x, d.ends[i]) <= 0 { // disjoint fast path
		return d.ccs[i]
	}
	for j := i - 1; j >= 0 && bytes.Compare(d.maxend[j], x) >= 0; j-- {
		if bytes.Compare(d.starts[j], x) <= 0 && bytes.Compare(x, d.ends[j]) <= 0 {
			return d.ccs[j]
		}
	}
	return ""
}

// geoState holds both loaded databases plus the ready flag. Guarded by mu.
type geoState struct {
	mu    sync.RWMutex
	v4    *countryDB
	v6    *countryDB
	ready bool
}

var geo geoState

// loadGeoIP parses ipv4.csv and ipv6.csv from geodir. It publishes both
// databases and sets ready=true only if BOTH parse successfully. Intended to
// run in a goroutine started by Start().
func loadGeoIP(geodir string) {
	v4, err4 := newCountryDB(filepath.Join(geodir, "ipv4.csv"), 4)
	v6, err6 := newCountryDB(filepath.Join(geodir, "ipv6.csv"), 16)
	geo.mu.Lock()
	defer geo.mu.Unlock()
	if err4 != nil || err6 != nil {
		geo.ready = false
		return
	}
	geo.v4 = v4
	geo.v6 = v6
	geo.ready = true
}

// Ready reports whether both GeoIP databases have parsed successfully.
func Ready() bool {
	geo.mu.RLock()
	defer geo.mu.RUnlock()
	return geo.ready
}

// country returns the ISO country code for ip, or "" if the DB is not ready or
// no range matches. IPv4-mapped IPv6 addresses are unwrapped to v4 first.
func country(ip string) string {
	geo.mu.RLock()
	ready := geo.ready
	v4 := geo.v4
	v6 := geo.v6
	geo.mu.RUnlock()
	if !ready {
		return ""
	}
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	if b4 := a.To4(); b4 != nil {
		if v4 == nil {
			return ""
		}
		key := make([]byte, 4)
		copy(key, b4)
		return v4.lookup(key)
	}
	if v6 == nil {
		return ""
	}
	b16 := a.To16()
	if b16 == nil {
		return ""
	}
	key := make([]byte, 16)
	copy(key, b16)
	return v6.lookup(key)
}
