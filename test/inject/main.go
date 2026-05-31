// Command inject is a benign simulation of a SOFTWARE keystroke injector, used
// to validate LinAudit end-to-end. It creates a /dev/uinput virtual keyboard,
// holds it long enough for linaudit-input's 3s device rescan to notice, emits a
// single harmless KEY_F20 (normally unbound), then removes the device. It
// exercises both the linaudit-input service (a new/virtual input device + a
// keystroke from it) and auditd's /dev/uinput watch (the uinput open/write).
//
// Run as root:  go run ./test/inject     (or build: go build -o inject ./test/inject)
//
// Pure-Go port of the former test/inject-test.py; uses raw uinput ioctls so it
// has no external dependency.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	uinputDev = "/dev/uinput"

	evSyn     = 0x00
	evKey     = 0x01
	synReport = 0x00
	keyF20    = 188
	busUSB    = 0x03

	uinputMaxNameSize = 80

	// ioctl encodings: _IOC(dir,type,nr,size) = dir<<30 | size<<16 | 'U'<<8 | nr.
	iocWrite       = 1
	uinputType     = 'U' // 0x55
	sizeofInt      = 4
	sizeofSetup    = 92 // struct uinput_setup: input_id(8) + name[80] + ff_effects_max(4)
	uiSetEvBitNr   = 100
	uiSetKeyBitNr  = 101
	uiDevSetupNr   = 3
	uiDevCreateNr  = 1
	uiDevDestroyNr = 2
)

func iow(nr, size uintptr) uintptr {
	return (uintptr(iocWrite) << 30) | (size << 16) | (uintptr(uinputType) << 8) | nr
}

func io(nr uintptr) uintptr {
	return (uintptr(uinputType) << 8) | nr
}

func ioctl(fd uintptr, req, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

// writeEvent writes one 24-byte input_event (amd64 layout) to fd.
func writeEvent(f *os.File, typ, code uint16, value int32) error {
	var ev [24]byte
	// sec/usec left zero; the kernel timestamps the event on receipt.
	binary.LittleEndian.PutUint16(ev[16:18], typ)
	binary.LittleEndian.PutUint16(ev[18:20], code)
	binary.LittleEndian.PutUint32(ev[20:24], uint32(value))
	_, err := f.Write(ev[:])
	return err
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "inject: must run as root (needs /dev/uinput)")
		os.Exit(1)
	}

	f, err := os.OpenFile(uinputDev, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "inject: open %s: %v\n", uinputDev, err)
		os.Exit(1)
	}
	defer f.Close()
	fd := f.Fd()

	// Enable EV_KEY and the single key we will emit.
	evbit := int32(evKey)
	if err := ioctl(fd, iow(uiSetEvBitNr, sizeofInt), uintptr(unsafe.Pointer(&evbit))); err != nil {
		fail("UI_SET_EVBIT", err)
	}
	keybit := int32(keyF20)
	if err := ioctl(fd, iow(uiSetKeyBitNr, sizeofInt), uintptr(unsafe.Pointer(&keybit))); err != nil {
		fail("UI_SET_KEYBIT", err)
	}

	// struct uinput_setup { struct input_id id; char name[80]; __u32 ff_effects_max; }
	var setup [sizeofSetup]byte
	binary.LittleEndian.PutUint16(setup[0:2], busUSB) // id.bustype
	binary.LittleEndian.PutUint16(setup[2:4], 0x1234) // id.vendor
	binary.LittleEndian.PutUint16(setup[4:6], 0x5678) // id.product
	binary.LittleEndian.PutUint16(setup[6:8], 1)      // id.version
	copy(setup[8:8+uinputMaxNameSize], []byte("linaudit-injection-test"))
	if err := ioctl(fd, iow(uiDevSetupNr, sizeofSetup), uintptr(unsafe.Pointer(&setup[0]))); err != nil {
		fail("UI_DEV_SETUP", err)
	}
	if err := ioctl(fd, io(uiDevCreateNr), 0); err != nil {
		fail("UI_DEV_CREATE", err)
	}

	// Let the linaudit-input 3s rescan register the new virtual device first.
	time.Sleep(4 * time.Second)

	// Emit one KEY_F20 down + up, each followed by a SYN_REPORT.
	for _, v := range []int32{1, 0} {
		if err := writeEvent(f, evKey, keyF20, v); err != nil {
			fail("write KEY_F20", err)
		}
		if err := writeEvent(f, evSyn, synReport, 0); err != nil {
			fail("write SYN_REPORT", err)
		}
	}
	time.Sleep(1 * time.Second)

	if err := ioctl(fd, io(uiDevDestroyNr), 0); err != nil {
		fail("UI_DEV_DESTROY", err)
	}
	fmt.Println("injection-test: created virtual device + emitted KEY_F20")
}

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "inject: %s: %v\n", stage, err)
	os.Exit(1)
}
