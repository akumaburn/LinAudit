package netmon

import "net"

// classify ports netmon.py classify(): returns "global" (worth rDNS+GeoIP) or
// "lan" (private / reserved / loopback / CGNAT / multicast / not globally
// routable). Anything that fails to parse is treated as "lan".
func classify(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return "lan"
	}
	if isLAN(a) {
		return "lan"
	}
	return "global"
}

// specialV4 and specialV6 are special-use / reserved CIDRs that some net.IP
// predicates do not flag but the Python ipaddress module treats as reserved /
// non-global. Parsed once at init.
var (
	specialV4CIDRs = []string{
		"0.0.0.0/8",          // "this host on this network" (Python _private_networks)
		"100.64.0.0/10",      // CGNAT (shared address space)
		"192.0.0.0/24",       // IETF protocol assignments
		"192.0.2.0/24",       // TEST-NET-1
		"198.18.0.0/15",      // benchmarking
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"240.0.0.0/4",        // reserved (class E)
		"255.255.255.255/32", // limited broadcast
	}
	specialV6CIDRs = []string{
		"2001:db8::/32",  // documentation
		"2001::/23",      // IETF protocol assignments
		"2002::/16",      // 6to4 (Python ipaddress treats as private)
		"3fff::/20",      // documentation (Python _private_networks)
		"64:ff9b:1::/48", // local-use NAT64 (Python _private_networks)
		// IANA-reserved (unallocated) blocks. net.IP.IsGlobalUnicast() reports
		// these as global, but Python ipaddress.is_reserved -> "lan". 100::/8
		// (covers the 100::/64 discard prefix) is in this reserved set too.
		"::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4",
		"4000::/3", "6000::/3", "8000::/3", "a000::/3", "c000::/3",
		"e000::/4", "f000::/5", "f800::/6", "fe00::/9",
	}
	// globalExceptionCIDRs mirror CPython ipaddress _private_networks_exceptions:
	// blocks nested inside the special ranges above that remain globally routable
	// (is_global == True). Checked BEFORE specialNets so they resolve to "global".
	globalExceptionCIDRs = []string{
		"192.0.0.9/32",    // Port Control Protocol anycast
		"192.0.0.10/32",   // NAT64/DNS64 service discovery
		"2001:1::1/128",   // Port Control Protocol anycast
		"2001:1::2/128",   // TURN anycast
		"2001:3::/32",     // AMT
		"2001:4:112::/48", // AS112-v6
		"2001:20::/28",    // ORCHIDv2
		"2001:30::/28",    // Drone Remote ID
	}
	specialNets   = parseCIDRs(append(append([]string{}, specialV4CIDRs...), specialV6CIDRs...))
	exceptionNets = parseCIDRs(globalExceptionCIDRs)
)

func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// isLAN reports whether ip should be considered non-global. It unwraps
// IPv4-mapped IPv6 addresses to their bare IPv4 form first, mirroring the
// Python ipv4_mapped handling.
func isLAN(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate() {
		return true
	}
	// CPython _private_networks_exceptions: nested blocks that remain globally
	// routable despite sitting inside a special range below.
	for _, n := range exceptionNets {
		if n.Contains(ip) {
			return false
		}
	}
	for _, n := range specialNets {
		if n.Contains(ip) {
			return true
		}
	}
	// Closes any remaining gap: only truly public, globally-routable unicast
	// addresses survive as "global".
	if !ip.IsGlobalUnicast() {
		return true
	}
	return false
}
