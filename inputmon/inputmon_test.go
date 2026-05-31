package inputmon

import (
	"encoding/binary"
	"testing"
)

func TestKeynameKnown(t *testing.T) {
	cases := map[uint16]string{
		30:  "KEY_A",
		1:   "KEY_ESC",
		57:  "KEY_SPACE",
		28:  "KEY_ENTER",
		272: "BTN_LEFT",
		0:   "KEY_RESERVED",
		248: "KEY_MICMUTE",
	}
	for code, want := range cases {
		if got := keyname(code); got != want {
			t.Errorf("keyname(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestKeynameUnknownFallsBackToDecimal(t *testing.T) {
	// 0x2ff is KEY_MAX itself, which is intentionally not in the table.
	if got := keyname(0x2ff); got != "767" {
		t.Errorf("keyname(0x2ff) = %q, want %q", got, "767")
	}
	// A code with no symbolic name degrades to its decimal value.
	if got := keyname(60000); got != "60000" {
		t.Errorf("keyname(60000) = %q, want %q", got, "60000")
	}
}

// buildEvent hand-assembles a 24-byte little-endian input_event.
func buildEvent(sec, usec int64, typ, code uint16, value int32) []byte {
	b := make([]byte, eventSize)
	binary.LittleEndian.PutUint64(b[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(b[8:16], uint64(usec))
	binary.LittleEndian.PutUint16(b[16:18], typ)
	binary.LittleEndian.PutUint16(b[18:20], code)
	binary.LittleEndian.PutUint32(b[20:24], uint32(value))
	return b
}

func TestDecodeEvent(t *testing.T) {
	b := buildEvent(1748707200, 123456, evKey, 30, 1)
	ev, ok := decodeEvent(b)
	if !ok {
		t.Fatalf("decodeEvent returned ok=false on a full 24-byte buffer")
	}
	if ev.Sec != 1748707200 {
		t.Errorf("Sec = %d, want 1748707200", ev.Sec)
	}
	if ev.Usec != 123456 {
		t.Errorf("Usec = %d, want 123456", ev.Usec)
	}
	if ev.Type != evKey {
		t.Errorf("Type = %d, want %d", ev.Type, evKey)
	}
	if ev.Code != 30 {
		t.Errorf("Code = %d, want 30", ev.Code)
	}
	if ev.Value != 1 {
		t.Errorf("Value = %d, want 1", ev.Value)
	}
	if name := keyname(ev.Code); name != "KEY_A" {
		t.Errorf("keyname(decoded code) = %q, want KEY_A", name)
	}
}

func TestDecodeEventNegativeAndZeroValue(t *testing.T) {
	// EV_KEY values are 0/1/2; the field is __s32 so verify signedness round-trips.
	b := buildEvent(0, 0, evKey, 1, -1)
	ev, ok := decodeEvent(b)
	if !ok {
		t.Fatal("decodeEvent ok=false")
	}
	if ev.Value != -1 {
		t.Errorf("Value = %d, want -1", ev.Value)
	}
}

func TestDecodeEventShortBuffer(t *testing.T) {
	if _, ok := decodeEvent(make([]byte, eventSize-1)); ok {
		t.Errorf("decodeEvent on a short buffer returned ok=true")
	}
	if _, ok := decodeEvent(nil); ok {
		t.Errorf("decodeEvent on nil returned ok=true")
	}
}

func TestEventTimestamp(t *testing.T) {
	ev := inputEvent{Sec: 10, Usec: 500000}
	if got := eventTimestamp(ev); got != 10.5 {
		t.Errorf("eventTimestamp = %v, want 10.5", got)
	}
}

func TestFmtTime(t *testing.T) {
	cases := map[float64]string{
		0:                  "0.000000",
		1:                  "1.000000",
		10.5:               "10.500000",
		1748707200.123456:  "1748707200.123456",
		1748707200.9999995: "1748707201.000000",
	}
	for in, want := range cases {
		if got := fmtTime(in); got != want {
			t.Errorf("fmtTime(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestReprSingle(t *testing.T) {
	cases := map[string]string{
		"":                `''`,
		"abc":             `'abc'`,
		"AT Translated":   `'AT Translated'`,
		"it's":            `"it's"`,
		`back\slash`:      `'back\\slash'`,
		`both \ and '`:    `"both \\ and '"`,
		"usb-0000:00:14.": `'usb-0000:00:14.'`,
	}
	for in, want := range cases {
		if got := reprSingle(in); got != want {
			t.Errorf("reprSingle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIocNumbers(t *testing.T) {
	// Verified against the C macros in linux/input-event-codes.h / input.h:
	//   _IOR('E', 0x06, len) etc. with dir=_IOC_READ(2), type='E'(0x45).
	if got := ioc(nrName, nameLen); got != 0x81004506 {
		t.Errorf("EVIOCGNAME(256) = %#x, want 0x81004506", got)
	}
	if got := ioc(nrPhys, physLen); got != 0x81004507 {
		t.Errorf("EVIOCGPHYS(256) = %#x, want 0x81004507", got)
	}
	if got := ioc(nrKeyBit, keyBitmapSize); got != 0x80604521 {
		t.Errorf("EVIOCGBIT(EV_KEY,96) = %#x, want 0x80604521", got)
	}
}

func TestKeyBitmapSize(t *testing.T) {
	if keyBitmapSize != 96 {
		t.Errorf("keyBitmapSize = %d, want 96", keyBitmapSize)
	}
}

func TestCString(t *testing.T) {
	buf := []byte("name\x00garbage")
	if got := cString(buf, len(buf)); got != "name" {
		t.Errorf("cString truncate-at-NUL = %q, want %q", got, "name")
	}
	if got := cString([]byte("nonul"), 5); got != "nonul" {
		t.Errorf("cString no-NUL = %q, want %q", got, "nonul")
	}
	if got := cString([]byte("abc"), 0); got != "" {
		t.Errorf("cString n=0 = %q, want empty", got)
	}
	// n larger than the buffer must be clamped, not panic.
	if got := cString([]byte("ab"), 100); got != "ab" {
		t.Errorf("cString clamp = %q, want %q", got, "ab")
	}
}
