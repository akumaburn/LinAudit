package netmon

import "testing"

// TestClassifyParity locks the IPv4/IPv6 special-range edge cases where Go's
// net.IP predicates diverge from Python's ipaddress module (the frozen
// /api/net contract). See review findings classify-1..5.
func TestClassifyParity(t *testing.T) {
	lan := []string{
		"0.153.187.208", "0.0.0.1", // 0.0.0.0/8 (Python _private_networks)
		"2002::1", "2002:c0a8:101::1", // 6to4
		"400::1", "f800::1", // IANA-reserved unallocated blocks
		"fc00::1",      // ULA (IsPrivate)
		"3fff::1",      // documentation
		"64:ff9b:1::1", // local-use NAT64
		"100.64.0.1",   // CGNAT
		"169.254.1.1",  // link-local
	}
	global := []string{
		"192.0.0.9", "192.0.0.10", // PCP / NAT64 anycast (Python exceptions)
		"2001:3::1", "2001:4:112::1", // AMT / AS112-v6 (Python exceptions)
		"2001:20::1", "2001:30::1", // ORCHIDv2 / Drone Remote ID (Python exceptions)
		"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", // genuinely global
	}
	for _, ip := range lan {
		if got := classify(ip); got != "lan" {
			t.Errorf("classify(%s) = %q, want lan", ip, got)
		}
	}
	for _, ip := range global {
		if got := classify(ip); got != "global" {
			t.Errorf("classify(%s) = %q, want global", ip, got)
		}
	}
}
