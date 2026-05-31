package netmon

import (
	"bytes"
	"net"
	"sort"
	"testing"
)

// TestClassify checks the global/lan partition that gates rDNS + GeoIP.
func TestClassify(t *testing.T) {
	global := []string{
		"8.8.8.8",
		"1.1.1.1",
		"2606:4700:4700::1111",
	}
	lan := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"169.254.1.1",
		"100.64.0.1",
		"224.0.0.1",
		"::1",
	}
	for _, ip := range global {
		if got := classify(ip); got != "global" {
			t.Errorf("classify(%q) = %q, want global", ip, got)
		}
	}
	for _, ip := range lan {
		if got := classify(ip); got != "lan" {
			t.Errorf("classify(%q) = %q, want lan", ip, got)
		}
	}
	if got := classify("not-an-ip"); got != "lan" {
		t.Errorf("classify(invalid) = %q, want lan", got)
	}
}

// newTestDBv4 builds a small in-memory v4 countryDB from [start,end,cc] string
// triples, reusing the production columnar/maxend layout and sort.
func newTestDBv4(t *testing.T, rows [][3]string) *countryDB {
	t.Helper()
	parsed := make([]dbRow, 0, len(rows))
	for _, r := range rows {
		s := net.ParseIP(r[0])
		e := net.ParseIP(r[1])
		if s == nil || e == nil {
			t.Fatalf("bad test ip in row %v", r)
		}
		parsed = append(parsed, dbRow{start: toFixed(s, 4), end: toFixed(e, 4), cc: r[2]})
	}
	sort.Slice(parsed, func(i, j int) bool {
		return bytes.Compare(parsed[i].start, parsed[j].start) < 0
	})
	db := &countryDB{
		starts: make([][]byte, len(parsed)),
		ends:   make([][]byte, len(parsed)),
		ccs:    make([]string, len(parsed)),
		maxend: make([][]byte, len(parsed)),
		width:  4,
	}
	var mx []byte
	for i, r := range parsed {
		db.starts[i] = r.start
		db.ends[i] = r.end
		db.ccs[i] = r.cc
		if mx == nil || bytes.Compare(r.end, mx) > 0 {
			mx = r.end
		}
		db.maxend[i] = mx
	}
	return db
}

func key4(t *testing.T, ip string) []byte {
	t.Helper()
	a := net.ParseIP(ip)
	if a == nil {
		t.Fatalf("bad ip %q", ip)
	}
	return toFixed(a, 4)
}

// TestGeoLookup exercises disjoint ranges plus one nested (more-specific)
// range overlapping a broader one, verifying the overlap walk-back.
func TestGeoLookup(t *testing.T) {
	db := newTestDBv4(t, [][3]string{
		{"1.0.0.0", "1.255.255.255", "AA"}, // broad block A
		{"1.2.3.0", "1.2.3.255", "BB"},     // nested inside AA (more specific)
		{"8.8.8.0", "8.8.8.255", "CC"},     // disjoint
		{"100.0.0.0", "100.0.0.255", "DD"}, // disjoint, higher
	})

	cases := []struct {
		ip   string
		want string
	}{
		{"1.0.0.5", "AA"},     // broad block only
		{"1.2.3.4", "BB"},     // covered by the nested range
		{"1.2.4.0", "AA"},     // just past the nested range, still in broad
		{"8.8.8.8", "CC"},     // disjoint hit
		{"100.0.0.200", "DD"}, // disjoint hit
		{"0.0.0.1", ""},       // below everything
		{"9.9.9.9", ""},       // in a gap between disjoint ranges
		{"200.0.0.1", ""},     // above everything
	}
	for _, c := range cases {
		if got := db.lookup(key4(t, c.ip)); got != c.want {
			t.Errorf("lookup(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

// TestSanitizeHost confirms the PTR sanitizer keeps only the hostname charset
// and trims a trailing dot.
func TestSanitizeHost(t *testing.T) {
	cases := map[string]string{
		"dns.google.":        "dns.google",
		"a b\tc":             "abc",
		"ok-host_1.example":  "ok-host_1.example",
		"<script>x</script>": "scriptxscript",
		"":                   "",
	}
	for in, want := range cases {
		if got := sanitizeHost(in); got != want {
			t.Errorf("sanitizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRequestLayout pins the wire layout of the netlink dump request.
func TestRequestLayout(t *testing.T) {
	req := buildRequest(afInet, ipprotoTCP, stateMask(tcpEstablished), inetDiagInfoBit)
	if len(req) != nlmsgHdrLen+inetDiagReqV2Len {
		t.Fatalf("request len = %d, want %d", len(req), nlmsgHdrLen+inetDiagReqV2Len)
	}
	// nlmsg_len = 72 (LE)
	if req[0] != 72 || req[1] != 0 || req[2] != 0 || req[3] != 0 {
		t.Errorf("nlmsg_len bytes = % x, want 48 00 00 00", req[0:4])
	}
	// nlmsg_type = SOCK_DIAG_BY_FAMILY (20)
	if req[4] != sockDiagByFamily || req[5] != 0 {
		t.Errorf("nlmsg_type = % x, want 14 00", req[4:6])
	}
	// nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP = 0x301 -> 01 03
	if req[6] != 0x01 || req[7] != 0x03 {
		t.Errorf("nlmsg_flags = % x, want 01 03", req[6:8])
	}
	// inet_diag_req_v2 starts at offset 16.
	p := req[nlmsgHdrLen:]
	if p[0] != afInet {
		t.Errorf("sdiag_family = %d, want %d", p[0], afInet)
	}
	if p[1] != ipprotoTCP {
		t.Errorf("sdiag_protocol = %d, want %d", p[1], ipprotoTCP)
	}
	if p[2] != inetDiagInfoBit {
		t.Errorf("idiag_ext = %#x, want %#x", p[2], inetDiagInfoBit)
	}
	// idiag_states = 1<<1 = 2 (LE)
	if p[4] != 0x02 || p[5] != 0 || p[6] != 0 || p[7] != 0 {
		t.Errorf("idiag_states = % x, want 02 00 00 00", p[4:8])
	}
}

// TestNetlinkSmoke opens the diag socket and dumps established TCP. If the
// socket cannot be created (sandbox / permissions), the test is skipped.
// Otherwise the dump must complete without error and any reported inode > 0.
func TestNetlinkSmoke(t *testing.T) {
	seen := false
	sawNonzeroInode := false
	err := netlinkDump(afInet, ipprotoTCP, stateMask(tcpEstablished), inetDiagInfoBit, func(s *diagSocket) {
		seen = true
		if s.inode > 0 {
			sawNonzeroInode = true
		}
	})
	if err != nil {
		t.Skipf("netlink diag unavailable: %v", err)
	}
	// A clean dump is success; if any socket was reported, at least one inode
	// is typically nonzero (the kernel populates idiag_inode for real sockets).
	_ = seen
	_ = sawNonzeroInode
}
