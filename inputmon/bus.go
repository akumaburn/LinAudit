package inputmon

import "strings"

// Physical-bus kinds emitted as the trailing field of each KEY record. The
// dashboard uses them to optionally hide trusted wired-keyboard noise so that
// wireless, virtual, and unidentified sources stay surfaced.
const (
	busWired    = "wired"    // USB or PS/2 (serio) -- a physically attached device
	busWireless = "wireless" // Bluetooth (EVIOCGPHYS reports the adapter MAC)
	busVirtual  = "virtual"  // no physical topology (uinput / software injector)
	busOther    = "other"    // key-capable but on an unrecognized bus
)

// busKind classifies a device's physical attachment from its EVIOCGPHYS string.
//
// The mapping is deliberately conservative about busWired: a device is labelled
// wired only when its phys unambiguously denotes a USB or PS/2 (serio/i8042)
// attachment. Anything else -- an empty phys (uinput / Wayland virtual keyboard),
// a Bluetooth MAC, or an unrecognized topology -- is reported as virtual,
// wireless, or other and therefore is NEVER hidden by the dashboard's
// "hide wired" filter. This keeps the forensic default biased toward showing
// potentially-injected input.
//
// Note that 2.4 GHz dongle receivers (e.g. Logitech Unifying) enumerate on the
// USB bus and are classified wired, matching their physical USB attachment.
func busKind(phys string) string {
	p := strings.ToLower(strings.TrimSpace(phys))
	switch {
	case p == "":
		return busVirtual
	case strings.HasPrefix(p, "usb-"):
		return busWired
	case strings.Contains(p, "serio") || strings.HasPrefix(p, "isa0060"):
		return busWired
	case looksLikeMAC(p):
		return busWireless
	default:
		return busOther
	}
}

// looksLikeMAC reports whether s begins with a colon-separated six-octet MAC
// address -- the form bluez writes into EVIOCGPHYS, optionally followed by a
// "/inputN" suffix. s is assumed already lowercased.
func looksLikeMAC(s string) bool {
	head := s
	if i := strings.IndexByte(head, '/'); i >= 0 {
		head = head[:i]
	}
	parts := strings.Split(head, ":")
	if len(parts) != 6 {
		return false
	}
	for _, oct := range parts {
		if len(oct) != 2 || !isHexByte(oct[0]) || !isHexByte(oct[1]) {
			return false
		}
	}
	return true
}

// isHexByte reports whether c is a lowercase hexadecimal digit.
func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}
