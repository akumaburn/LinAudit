package netmon

import (
	"net"
	"sort"
	"testing"
)

// newTestASNv4 builds a small in-memory v4 asnDB from [start,end,asn,name] rows,
// reusing the production flat columnar layout and sort.
func newTestASNv4(t *testing.T, rows []asnRow) *asnDB {
	t.Helper()
	parsed := make([]asnRow, 0, len(rows))
	for _, r := range rows {
		parsed = append(parsed, r)
	}
	sort.Slice(parsed, func(i, j int) bool {
		return string(parsed[i].start) < string(parsed[j].start)
	})
	n := len(parsed)
	db := &asnDB{
		width:  4,
		n:      n,
		starts: make([]byte, n*4),
		ends:   make([]byte, n*4),
		maxend: make([]byte, n*4),
		nums:   make([]uint32, n),
		names:  make([]string, n),
	}
	var mx []byte
	for i, r := range parsed {
		copy(db.starts[i*4:], r.start)
		copy(db.ends[i*4:], r.end)
		if mx == nil || string(r.end) > string(mx) {
			mx = r.end
		}
		copy(db.maxend[i*4:], mx)
		db.nums[i] = r.num
		db.names[i] = r.name
	}
	return db
}

func row4(t *testing.T, s, e string, asn uint32, name string) asnRow {
	t.Helper()
	si, ei := net.ParseIP(s), net.ParseIP(e)
	if si == nil || ei == nil {
		t.Fatalf("bad test ip %q/%q", s, e)
	}
	return asnRow{start: toFixed(si, 4), end: toFixed(ei, 4), num: asn, name: name}
}

// TestASNLookup exercises disjoint ranges plus one nested (more-specific) range
// overlapping a broader one, verifying the overlap walk-back returns the
// most-specific org.
func TestASNLookup(t *testing.T) {
	db := newTestASNv4(t, []asnRow{
		row4(t, "8.0.0.0", "8.255.255.255", 100, "Broad Net"),            // broad block
		row4(t, "8.8.8.0", "8.8.8.255", 200, "Nested Net"),               // nested, more specific
		row4(t, "140.82.112.0", "140.82.127.255", 36459, "GitHub, Inc."), // disjoint
	})
	cases := []struct {
		ip      string
		wantNum uint32
		wantOrg string
	}{
		{"8.0.0.1", 100, "Broad Net"},           // broad only
		{"8.8.8.8", 200, "Nested Net"},          // nested wins
		{"8.8.9.0", 100, "Broad Net"},           // just past nested, still broad
		{"140.82.121.4", 36459, "GitHub, Inc."}, // disjoint hit
		{"9.9.9.9", 0, ""},                      // gap -> miss
	}
	for _, c := range cases {
		key := toFixed(net.ParseIP(c.ip), 4)
		i := db.find(key)
		var gotNum uint32
		var gotOrg string
		if i >= 0 {
			gotNum, gotOrg = db.nums[i], db.names[i]
		}
		if gotNum != c.wantNum || gotOrg != c.wantOrg {
			t.Errorf("find(%s) = (%d,%q), want (%d,%q)", c.ip, gotNum, gotOrg, c.wantNum, c.wantOrg)
		}
	}
}

// TestCategorize locks the provider table, the curated gov ASN list, the gov
// name heuristic, and -- critically -- the false-positive guards validated
// against the real ip-location-db dataset.
func TestCategorize(t *testing.T) {
	cases := []struct {
		asn  uint32
		org  string
		want string
	}{
		// Provider table (mixed casing is normalized).
		{8075, "Microsoft Corporation", catCorp},
		{714, "Apple Inc.", catCorp},
		{15169, "Google LLC", catCorp},
		{36459, "GitHub, Inc.", catCorp},
		{16509, "Amazon.com, Inc.", catCloud},
		{16509, "Amazon Data Services Ireland Ltd", catCloud},
		{24940, "Hetzner Online GmbH", catCloud},
		{14061, "DigitalOcean, LLC", catCloud},
		{13335, "Cloudflare, Inc.", catCDN},
		{20940, "Akamai International B.V.", catCDN},
		{7922, "Comcast Cable Communications, LLC", catTelecom},
		{3320, "Deutsche Telekom AG", catTelecom},
		// Curated government/military ASNs (name alone would not flag the DNIC ones).
		{721, "DoD Network Information Center", catGov},
		{27064, "DoD Network Information Center", catGov},
		// Government name heuristic (clear public-body names).
		{0, "Alabama Department of Transportation", catGov},
		{0, "Belgian Ministry of Defence", catGov},
		{0, "City of Norwich Department of Public Utilities", catGov},
		{0, "National Aeronautics and Space Administration", catGov},
		{0, "Administration of the Governor and Government of the Kirov region", catGov},
		{0, "County of Orange", catGov},
		// FALSE-POSITIVE GUARDS: these must NOT be classified as government.
		{0, "Governors State University", catOther},
		{0, "Federal Express Corporation Hong Kong Branch", catOther},
		{0, "Auburn University at Montgomery", catOther},
		{0, "Janney Montgomery Scott LLC", catOther},
		{0, "Level 32 Governor Macquarie Tower", catOther},
		{0, "Salvation Army", catOther},
		{0, "Navy Federal Credit Union", catOther},
		// Resolved but uncategorized org, and the empty case.
		{12345, "Some Regional ISP d.o.o.", catOther},
		{0, "", catOther},
	}
	for _, c := range cases {
		if got := categorize(c.asn, c.org); got != c.want {
			t.Errorf("categorize(%d, %q) = %q, want %q", c.asn, c.org, got, c.want)
		}
	}
}

// TestHasToken pins the word-boundary matcher used for short, ambiguous markers.
func TestHasToken(t *testing.T) {
	cases := []struct {
		s, tok string
		want   bool
	}{
		{"APPLE INC.", "APPLE", true},
		{"PINEAPPLE NETWORKS", "APPLE", false},
		{"US ARMY CORPS", "ARMY", true},
		{"SALVATION ARMY", "ARMY", true}, // token present; gov excludes bare ARMY by design
		{"GOVERNORS STATE UNIVERSITY", "GOV", false},
		{"GOV.UK", "GOV", true},
		{"INTEL CORPORATION", "INTEL", true},
		{"INTELSAT GLOBAL", "INTEL", false},
		{"BT GROUP PLC", "BT", true},
		{"DEBT COLLECTION LTD", "BT", false},
	}
	for _, c := range cases {
		if got := hasToken(c.s, c.tok); got != c.want {
			t.Errorf("hasToken(%q, %q) = %v, want %v", c.s, c.tok, got, c.want)
		}
	}
}
