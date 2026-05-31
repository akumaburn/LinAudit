package inputmon

import "testing"

// TestKeynameAliases locks the 9 multi-alias EV_KEY codes to the same symbolic
// name python-evdev emits (verified against the live library), so the KEYNAME
// field stays byte-compatible with the pre-existing keys.log. See review
// finding inputmon-keyname-1.
func TestKeynameAliases(t *testing.T) {
	want := map[uint16]string{
		113: "KEY_MIN_INTERESTING",
		153: "KEY_DIRECTION",
		246: "KEY_WIMAX",
		288: "BTN_JOYSTICK",
		304: "BTN_A",
		305: "BTN_B",
		320: "BTN_DIGI",
		431: "KEY_BRIGHTNESS_TOGGLE",
		704: "BTN_TRIGGER_HAPPY",
		// unchanged sanity anchors
		1:  "KEY_ESC",
		30: "KEY_A",
	}
	for code, name := range want {
		if got := keyname(code); got != name {
			t.Errorf("keyname(%d) = %q, want %q", code, got, name)
		}
	}
}
