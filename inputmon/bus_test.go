package inputmon

import "testing"

func TestBusKind(t *testing.T) {
	cases := map[string]string{
		// virtual: empty phys is what uinput / Wayland virtual keyboards report.
		"":   busVirtual,
		"  ": busVirtual,
		// wired: USB attachment (including 2.4 GHz dongle receivers).
		"usb-0000:00:14.0-2/input0":   busWired,
		"USB-0000:00:1d.0-1.2/input1": busWired, // case-insensitive
		// wired: PS/2 / i8042 internal keyboards.
		"isa0060/serio0/input0":         busWired,
		"platform-i8042-serio-0/input0": busWired, // contains "serio"
		// wireless: Bluetooth adapter MAC, with and without an input suffix.
		"00:1f:20:3a:4b:5c":        busWireless,
		"a0:b1:c2:d3:e4:f5/input1": busWireless,
		// other: recognizable bus but neither wired nor wireless by our rules.
		"ip-1/input0": busOther,
		"usbweird":    busOther, // no "usb-" prefix
		"00:11:22":    busOther, // too few MAC octets
	}
	for in, want := range cases {
		if got := busKind(in); got != want {
			t.Errorf("busKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLooksLikeMAC(t *testing.T) {
	yes := []string{"00:1f:20:3a:4b:5c", "a0:b1:c2:d3:e4:f5/input0", "ff:ff:ff:ff:ff:ff"}
	no := []string{"", "00:1f:20:3a:4b", "usb-0000:00:14.0-2/input0", "gg:1f:20:3a:4b:5c", "001f:203a:4b5c"}
	for _, s := range yes {
		if !looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = true, want false", s)
		}
	}
}
