package inputmon

import (
	"encoding/binary"
	"strconv"
	"syscall"
	"unsafe"
)

// --- evdev event-type constants (linux/input-event-codes.h) ---

const (
	evKey = 0x01 // EV_KEY
)

// keyMax is the highest key/button code (KEY_MAX). The EV_KEY capability
// bitmap therefore needs (keyMax/8)+1 = 96 bytes.
const (
	keyMax        = 0x2ff
	keyBitmapSize = (keyMax / 8) + 1 // 96
)

// --- ioctl request numbers (asm-generic) ---
//
// req = (dir<<30) | (size<<16) | (type<<8) | nr
//
// dir _IOC_READ = 2, type 'E' = 0x45.
//   EVIOCGNAME(len): nr = 0x06
//   EVIOCGPHYS(len): nr = 0x07
//   EVIOCGBIT(EV_KEY, len): nr = 0x20 + EV_KEY(1) = 0x21
//
// We size the string queries at 256 bytes (the historical maximum used by the
// kernel uAPI and by python-evdev).

const (
	iocRead   = 2
	iocTypeE  = 0x45
	nameLen   = 256
	physLen   = 256
	nrName    = 0x06
	nrPhys    = 0x07
	nrKeyBit  = 0x20 + evKey // 0x21
	dirShift  = 30
	sizeShift = 16
	typeShift = 8
)

// ioc assembles an asm-generic ioctl request number for the read direction.
func ioc(nr, size int) uintptr {
	// Convert each operand to uintptr BEFORE shifting: as int, iocRead<<dirShift
	// is 2<<30 = 2147483648, which overflows a 32-bit int constant and fails to
	// compile on GOARCH=386/arm. uintptr is unsigned and >=32-bit on every arch.
	return uintptr(iocRead)<<dirShift |
		uintptr(size)<<sizeShift |
		uintptr(iocTypeE)<<typeShift |
		uintptr(nr)
}

// ioctlBuf issues an ioctl that fills buf and returns the kernel-reported
// length (r1). A non-positive length (or any errno) yields (0, false).
func ioctlBuf(fd int, req uintptr, buf []byte) (int, bool) {
	if len(buf) == 0 {
		return 0, false
	}
	r1, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		req,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if errno != 0 {
		return 0, false
	}
	n := int(r1)
	if n <= 0 {
		return 0, false
	}
	return n, true
}

// cString interprets buf[:n] as a C string, truncating at the first NUL.
func cString(buf []byte, n int) string {
	if n > len(buf) {
		n = len(buf)
	}
	if n <= 0 {
		return ""
	}
	b := buf[:n]
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// deviceName returns the EVIOCGNAME string for fd (empty on failure).
func deviceName(fd int) string {
	buf := make([]byte, nameLen)
	n, ok := ioctlBuf(fd, ioc(nrName, nameLen), buf)
	if !ok {
		return ""
	}
	return cString(buf, n)
}

// devicePhys returns the EVIOCGPHYS string for fd (empty on failure).
func devicePhys(fd int) string {
	buf := make([]byte, physLen)
	n, ok := ioctlBuf(fd, ioc(nrPhys, physLen), buf)
	if !ok {
		return ""
	}
	return cString(buf, n)
}

// keyCapable reports whether fd exposes any EV_KEY codes: EVIOCGBIT(EV_KEY)
// must succeed and at least one byte of the returned bitmap must be nonzero.
func keyCapable(fd int) bool {
	buf := make([]byte, keyBitmapSize)
	n, ok := ioctlBuf(fd, ioc(nrKeyBit, keyBitmapSize), buf)
	if !ok {
		return false
	}
	if n > len(buf) {
		n = len(buf)
	}
	for _, b := range buf[:n] {
		if b != 0 {
			return true
		}
	}
	return false
}

// --- input_event (amd64) ---
//
// struct input_event {
//     struct timeval time;   // __kernel_long_t tv_sec; __kernel_long_t tv_usec;
//     __u16 type;
//     __u16 code;
//     __s32 value;
// };
//
// On linux/amd64 each timeval field is 8 bytes, so the struct is 24 bytes with
// no trailing padding. Field offsets: sec 0, usec 8, type 16, code 18, value 20.

const eventSize = 24

type inputEvent struct {
	Sec   int64
	Usec  int64
	Type  uint16
	Code  uint16
	Value int32
}

// decodeEvent parses a single 24-byte input_event from b (little-endian).
// It returns false if b is too short.
func decodeEvent(b []byte) (inputEvent, bool) {
	if len(b) < eventSize {
		return inputEvent{}, false
	}
	var ev inputEvent
	ev.Sec = int64(binary.LittleEndian.Uint64(b[0:8]))
	ev.Usec = int64(binary.LittleEndian.Uint64(b[8:16]))
	ev.Type = binary.LittleEndian.Uint16(b[16:18])
	ev.Code = binary.LittleEndian.Uint16(b[18:20])
	ev.Value = int32(binary.LittleEndian.Uint32(b[20:24]))
	return ev, true
}

// eventTimestamp returns the event timeval as epoch seconds (Sec + Usec/1e6),
// mirroring python-evdev's InputEvent.timestamp().
func eventTimestamp(ev inputEvent) float64 {
	return float64(ev.Sec) + float64(ev.Usec)/1e6
}

// keyname maps an EV_KEY code to its KEY_*/BTN_* symbolic name. Codes absent
// from the table degrade to their decimal value, matching the Python logger.
func keyname(code uint16) string {
	if name, ok := keyName[code]; ok {
		return name
	}
	return strconv.Itoa(int(code))
}

// keyName is the EV_KEY code -> name table, generated from
// linux/input-event-codes.h (KEY_* and BTN_* defines, group markers such as
// BTN_MISC/BTN_MOUSE/BTN_JOYSTICK/BTN_GAMEPAD/BTN_DIGI/BTN_WHEEL excluded so
// the primary symbolic name wins, matching python-evdev's ecodes.bytype).
var keyName = map[uint16]string{
	0:   "KEY_RESERVED",
	1:   "KEY_ESC",
	2:   "KEY_1",
	3:   "KEY_2",
	4:   "KEY_3",
	5:   "KEY_4",
	6:   "KEY_5",
	7:   "KEY_6",
	8:   "KEY_7",
	9:   "KEY_8",
	10:  "KEY_9",
	11:  "KEY_0",
	12:  "KEY_MINUS",
	13:  "KEY_EQUAL",
	14:  "KEY_BACKSPACE",
	15:  "KEY_TAB",
	16:  "KEY_Q",
	17:  "KEY_W",
	18:  "KEY_E",
	19:  "KEY_R",
	20:  "KEY_T",
	21:  "KEY_Y",
	22:  "KEY_U",
	23:  "KEY_I",
	24:  "KEY_O",
	25:  "KEY_P",
	26:  "KEY_LEFTBRACE",
	27:  "KEY_RIGHTBRACE",
	28:  "KEY_ENTER",
	29:  "KEY_LEFTCTRL",
	30:  "KEY_A",
	31:  "KEY_S",
	32:  "KEY_D",
	33:  "KEY_F",
	34:  "KEY_G",
	35:  "KEY_H",
	36:  "KEY_J",
	37:  "KEY_K",
	38:  "KEY_L",
	39:  "KEY_SEMICOLON",
	40:  "KEY_APOSTROPHE",
	41:  "KEY_GRAVE",
	42:  "KEY_LEFTSHIFT",
	43:  "KEY_BACKSLASH",
	44:  "KEY_Z",
	45:  "KEY_X",
	46:  "KEY_C",
	47:  "KEY_V",
	48:  "KEY_B",
	49:  "KEY_N",
	50:  "KEY_M",
	51:  "KEY_COMMA",
	52:  "KEY_DOT",
	53:  "KEY_SLASH",
	54:  "KEY_RIGHTSHIFT",
	55:  "KEY_KPASTERISK",
	56:  "KEY_LEFTALT",
	57:  "KEY_SPACE",
	58:  "KEY_CAPSLOCK",
	59:  "KEY_F1",
	60:  "KEY_F2",
	61:  "KEY_F3",
	62:  "KEY_F4",
	63:  "KEY_F5",
	64:  "KEY_F6",
	65:  "KEY_F7",
	66:  "KEY_F8",
	67:  "KEY_F9",
	68:  "KEY_F10",
	69:  "KEY_NUMLOCK",
	70:  "KEY_SCROLLLOCK",
	71:  "KEY_KP7",
	72:  "KEY_KP8",
	73:  "KEY_KP9",
	74:  "KEY_KPMINUS",
	75:  "KEY_KP4",
	76:  "KEY_KP5",
	77:  "KEY_KP6",
	78:  "KEY_KPPLUS",
	79:  "KEY_KP1",
	80:  "KEY_KP2",
	81:  "KEY_KP3",
	82:  "KEY_KP0",
	83:  "KEY_KPDOT",
	85:  "KEY_ZENKAKUHANKAKU",
	86:  "KEY_102ND",
	87:  "KEY_F11",
	88:  "KEY_F12",
	89:  "KEY_RO",
	90:  "KEY_KATAKANA",
	91:  "KEY_HIRAGANA",
	92:  "KEY_HENKAN",
	93:  "KEY_KATAKANAHIRAGANA",
	94:  "KEY_MUHENKAN",
	95:  "KEY_KPJPCOMMA",
	96:  "KEY_KPENTER",
	97:  "KEY_RIGHTCTRL",
	98:  "KEY_KPSLASH",
	99:  "KEY_SYSRQ",
	100: "KEY_RIGHTALT",
	101: "KEY_LINEFEED",
	102: "KEY_HOME",
	103: "KEY_UP",
	104: "KEY_PAGEUP",
	105: "KEY_LEFT",
	106: "KEY_RIGHT",
	107: "KEY_END",
	108: "KEY_DOWN",
	109: "KEY_PAGEDOWN",
	110: "KEY_INSERT",
	111: "KEY_DELETE",
	112: "KEY_MACRO",
	113: "KEY_MIN_INTERESTING",
	114: "KEY_VOLUMEDOWN",
	115: "KEY_VOLUMEUP",
	116: "KEY_POWER",
	117: "KEY_KPEQUAL",
	118: "KEY_KPPLUSMINUS",
	119: "KEY_PAUSE",
	120: "KEY_SCALE",
	121: "KEY_KPCOMMA",
	122: "KEY_HANGEUL",
	123: "KEY_HANJA",
	124: "KEY_YEN",
	125: "KEY_LEFTMETA",
	126: "KEY_RIGHTMETA",
	127: "KEY_COMPOSE",
	128: "KEY_STOP",
	129: "KEY_AGAIN",
	130: "KEY_PROPS",
	131: "KEY_UNDO",
	132: "KEY_FRONT",
	133: "KEY_COPY",
	134: "KEY_OPEN",
	135: "KEY_PASTE",
	136: "KEY_FIND",
	137: "KEY_CUT",
	138: "KEY_HELP",
	139: "KEY_MENU",
	140: "KEY_CALC",
	141: "KEY_SETUP",
	142: "KEY_SLEEP",
	143: "KEY_WAKEUP",
	144: "KEY_FILE",
	145: "KEY_SENDFILE",
	146: "KEY_DELETEFILE",
	147: "KEY_XFER",
	148: "KEY_PROG1",
	149: "KEY_PROG2",
	150: "KEY_WWW",
	151: "KEY_MSDOS",
	152: "KEY_COFFEE",
	153: "KEY_DIRECTION",
	154: "KEY_CYCLEWINDOWS",
	155: "KEY_MAIL",
	156: "KEY_BOOKMARKS",
	157: "KEY_COMPUTER",
	158: "KEY_BACK",
	159: "KEY_FORWARD",
	160: "KEY_CLOSECD",
	161: "KEY_EJECTCD",
	162: "KEY_EJECTCLOSECD",
	163: "KEY_NEXTSONG",
	164: "KEY_PLAYPAUSE",
	165: "KEY_PREVIOUSSONG",
	166: "KEY_STOPCD",
	167: "KEY_RECORD",
	168: "KEY_REWIND",
	169: "KEY_PHONE",
	170: "KEY_ISO",
	171: "KEY_CONFIG",
	172: "KEY_HOMEPAGE",
	173: "KEY_REFRESH",
	174: "KEY_EXIT",
	175: "KEY_MOVE",
	176: "KEY_EDIT",
	177: "KEY_SCROLLUP",
	178: "KEY_SCROLLDOWN",
	179: "KEY_KPLEFTPAREN",
	180: "KEY_KPRIGHTPAREN",
	181: "KEY_NEW",
	182: "KEY_REDO",
	183: "KEY_F13",
	184: "KEY_F14",
	185: "KEY_F15",
	186: "KEY_F16",
	187: "KEY_F17",
	188: "KEY_F18",
	189: "KEY_F19",
	190: "KEY_F20",
	191: "KEY_F21",
	192: "KEY_F22",
	193: "KEY_F23",
	194: "KEY_F24",
	200: "KEY_PLAYCD",
	201: "KEY_PAUSECD",
	202: "KEY_PROG3",
	203: "KEY_PROG4",
	204: "KEY_ALL_APPLICATIONS",
	205: "KEY_SUSPEND",
	206: "KEY_CLOSE",
	207: "KEY_PLAY",
	208: "KEY_FASTFORWARD",
	209: "KEY_BASSBOOST",
	210: "KEY_PRINT",
	211: "KEY_HP",
	212: "KEY_CAMERA",
	213: "KEY_SOUND",
	214: "KEY_QUESTION",
	215: "KEY_EMAIL",
	216: "KEY_CHAT",
	217: "KEY_SEARCH",
	218: "KEY_CONNECT",
	219: "KEY_FINANCE",
	220: "KEY_SPORT",
	221: "KEY_SHOP",
	222: "KEY_ALTERASE",
	223: "KEY_CANCEL",
	224: "KEY_BRIGHTNESSDOWN",
	225: "KEY_BRIGHTNESSUP",
	226: "KEY_MEDIA",
	227: "KEY_SWITCHVIDEOMODE",
	228: "KEY_KBDILLUMTOGGLE",
	229: "KEY_KBDILLUMDOWN",
	230: "KEY_KBDILLUMUP",
	231: "KEY_SEND",
	232: "KEY_REPLY",
	233: "KEY_FORWARDMAIL",
	234: "KEY_SAVE",
	235: "KEY_DOCUMENTS",
	236: "KEY_BATTERY",
	237: "KEY_BLUETOOTH",
	238: "KEY_WLAN",
	239: "KEY_UWB",
	240: "KEY_UNKNOWN",
	241: "KEY_VIDEO_NEXT",
	242: "KEY_VIDEO_PREV",
	243: "KEY_BRIGHTNESS_CYCLE",
	244: "KEY_BRIGHTNESS_AUTO",
	245: "KEY_DISPLAY_OFF",
	246: "KEY_WIMAX",
	247: "KEY_RFKILL",
	248: "KEY_MICMUTE",
	256: "BTN_0",
	257: "BTN_1",
	258: "BTN_2",
	259: "BTN_3",
	260: "BTN_4",
	261: "BTN_5",
	262: "BTN_6",
	263: "BTN_7",
	264: "BTN_8",
	265: "BTN_9",
	272: "BTN_LEFT",
	273: "BTN_RIGHT",
	274: "BTN_MIDDLE",
	275: "BTN_SIDE",
	276: "BTN_EXTRA",
	277: "BTN_FORWARD",
	278: "BTN_BACK",
	279: "BTN_TASK",
	288: "BTN_JOYSTICK",
	289: "BTN_THUMB",
	290: "BTN_THUMB2",
	291: "BTN_TOP",
	292: "BTN_TOP2",
	293: "BTN_PINKIE",
	294: "BTN_BASE",
	295: "BTN_BASE2",
	296: "BTN_BASE3",
	297: "BTN_BASE4",
	298: "BTN_BASE5",
	299: "BTN_BASE6",
	303: "BTN_DEAD",
	304: "BTN_A",
	305: "BTN_B",
	306: "BTN_C",
	307: "BTN_NORTH",
	308: "BTN_WEST",
	309: "BTN_Z",
	310: "BTN_TL",
	311: "BTN_TR",
	312: "BTN_TL2",
	313: "BTN_TR2",
	314: "BTN_SELECT",
	315: "BTN_START",
	316: "BTN_MODE",
	317: "BTN_THUMBL",
	318: "BTN_THUMBR",
	320: "BTN_DIGI",
	321: "BTN_TOOL_RUBBER",
	322: "BTN_TOOL_BRUSH",
	323: "BTN_TOOL_PENCIL",
	324: "BTN_TOOL_AIRBRUSH",
	325: "BTN_TOOL_FINGER",
	326: "BTN_TOOL_MOUSE",
	327: "BTN_TOOL_LENS",
	328: "BTN_TOOL_QUINTTAP",
	329: "BTN_STYLUS3",
	330: "BTN_TOUCH",
	331: "BTN_STYLUS",
	332: "BTN_STYLUS2",
	333: "BTN_TOOL_DOUBLETAP",
	334: "BTN_TOOL_TRIPLETAP",
	335: "BTN_TOOL_QUADTAP",
	336: "BTN_GEAR_DOWN",
	337: "BTN_GEAR_UP",
	352: "KEY_OK",
	353: "KEY_SELECT",
	354: "KEY_GOTO",
	355: "KEY_CLEAR",
	356: "KEY_POWER2",
	357: "KEY_OPTION",
	358: "KEY_INFO",
	359: "KEY_TIME",
	360: "KEY_VENDOR",
	361: "KEY_ARCHIVE",
	362: "KEY_PROGRAM",
	363: "KEY_CHANNEL",
	364: "KEY_FAVORITES",
	365: "KEY_EPG",
	366: "KEY_PVR",
	367: "KEY_MHP",
	368: "KEY_LANGUAGE",
	369: "KEY_TITLE",
	370: "KEY_SUBTITLE",
	371: "KEY_ANGLE",
	372: "KEY_FULL_SCREEN",
	373: "KEY_MODE",
	374: "KEY_KEYBOARD",
	375: "KEY_ASPECT_RATIO",
	376: "KEY_PC",
	377: "KEY_TV",
	378: "KEY_TV2",
	379: "KEY_VCR",
	380: "KEY_VCR2",
	381: "KEY_SAT",
	382: "KEY_SAT2",
	383: "KEY_CD",
	384: "KEY_TAPE",
	385: "KEY_RADIO",
	386: "KEY_TUNER",
	387: "KEY_PLAYER",
	388: "KEY_TEXT",
	389: "KEY_DVD",
	390: "KEY_AUX",
	391: "KEY_MP3",
	392: "KEY_AUDIO",
	393: "KEY_VIDEO",
	394: "KEY_DIRECTORY",
	395: "KEY_LIST",
	396: "KEY_MEMO",
	397: "KEY_CALENDAR",
	398: "KEY_RED",
	399: "KEY_GREEN",
	400: "KEY_YELLOW",
	401: "KEY_BLUE",
	402: "KEY_CHANNELUP",
	403: "KEY_CHANNELDOWN",
	404: "KEY_FIRST",
	405: "KEY_LAST",
	406: "KEY_AB",
	407: "KEY_NEXT",
	408: "KEY_RESTART",
	409: "KEY_SLOW",
	410: "KEY_SHUFFLE",
	411: "KEY_BREAK",
	412: "KEY_PREVIOUS",
	413: "KEY_DIGITS",
	414: "KEY_TEEN",
	415: "KEY_TWEN",
	416: "KEY_VIDEOPHONE",
	417: "KEY_GAMES",
	418: "KEY_ZOOMIN",
	419: "KEY_ZOOMOUT",
	420: "KEY_ZOOMRESET",
	421: "KEY_WORDPROCESSOR",
	422: "KEY_EDITOR",
	423: "KEY_SPREADSHEET",
	424: "KEY_GRAPHICSEDITOR",
	425: "KEY_PRESENTATION",
	426: "KEY_DATABASE",
	427: "KEY_NEWS",
	428: "KEY_VOICEMAIL",
	429: "KEY_ADDRESSBOOK",
	430: "KEY_MESSENGER",
	431: "KEY_BRIGHTNESS_TOGGLE",
	432: "KEY_SPELLCHECK",
	433: "KEY_LOGOFF",
	434: "KEY_DOLLAR",
	435: "KEY_EURO",
	436: "KEY_FRAMEBACK",
	437: "KEY_FRAMEFORWARD",
	438: "KEY_CONTEXT_MENU",
	439: "KEY_MEDIA_REPEAT",
	440: "KEY_10CHANNELSUP",
	441: "KEY_10CHANNELSDOWN",
	442: "KEY_IMAGES",
	444: "KEY_NOTIFICATION_CENTER",
	445: "KEY_PICKUP_PHONE",
	446: "KEY_HANGUP_PHONE",
	447: "KEY_LINK_PHONE",
	448: "KEY_DEL_EOL",
	449: "KEY_DEL_EOS",
	450: "KEY_INS_LINE",
	451: "KEY_DEL_LINE",
	464: "KEY_FN",
	465: "KEY_FN_ESC",
	466: "KEY_FN_F1",
	467: "KEY_FN_F2",
	468: "KEY_FN_F3",
	469: "KEY_FN_F4",
	470: "KEY_FN_F5",
	471: "KEY_FN_F6",
	472: "KEY_FN_F7",
	473: "KEY_FN_F8",
	474: "KEY_FN_F9",
	475: "KEY_FN_F10",
	476: "KEY_FN_F11",
	477: "KEY_FN_F12",
	478: "KEY_FN_1",
	479: "KEY_FN_2",
	480: "KEY_FN_D",
	481: "KEY_FN_E",
	482: "KEY_FN_F",
	483: "KEY_FN_S",
	484: "KEY_FN_B",
	485: "KEY_FN_RIGHT_SHIFT",
	497: "KEY_BRL_DOT1",
	498: "KEY_BRL_DOT2",
	499: "KEY_BRL_DOT3",
	500: "KEY_BRL_DOT4",
	501: "KEY_BRL_DOT5",
	502: "KEY_BRL_DOT6",
	503: "KEY_BRL_DOT7",
	504: "KEY_BRL_DOT8",
	505: "KEY_BRL_DOT9",
	506: "KEY_BRL_DOT10",
	512: "KEY_NUMERIC_0",
	513: "KEY_NUMERIC_1",
	514: "KEY_NUMERIC_2",
	515: "KEY_NUMERIC_3",
	516: "KEY_NUMERIC_4",
	517: "KEY_NUMERIC_5",
	518: "KEY_NUMERIC_6",
	519: "KEY_NUMERIC_7",
	520: "KEY_NUMERIC_8",
	521: "KEY_NUMERIC_9",
	522: "KEY_NUMERIC_STAR",
	523: "KEY_NUMERIC_POUND",
	524: "KEY_NUMERIC_A",
	525: "KEY_NUMERIC_B",
	526: "KEY_NUMERIC_C",
	527: "KEY_NUMERIC_D",
	528: "KEY_CAMERA_FOCUS",
	529: "KEY_WPS_BUTTON",
	530: "KEY_TOUCHPAD_TOGGLE",
	531: "KEY_TOUCHPAD_ON",
	532: "KEY_TOUCHPAD_OFF",
	533: "KEY_CAMERA_ZOOMIN",
	534: "KEY_CAMERA_ZOOMOUT",
	535: "KEY_CAMERA_UP",
	536: "KEY_CAMERA_DOWN",
	537: "KEY_CAMERA_LEFT",
	538: "KEY_CAMERA_RIGHT",
	539: "KEY_ATTENDANT_ON",
	540: "KEY_ATTENDANT_OFF",
	541: "KEY_ATTENDANT_TOGGLE",
	542: "KEY_LIGHTS_TOGGLE",
	544: "BTN_DPAD_UP",
	545: "BTN_DPAD_DOWN",
	546: "BTN_DPAD_LEFT",
	547: "BTN_DPAD_RIGHT",
	548: "BTN_GRIPL",
	549: "BTN_GRIPR",
	550: "BTN_GRIPL2",
	551: "BTN_GRIPR2",
	560: "KEY_ALS_TOGGLE",
	561: "KEY_ROTATE_LOCK_TOGGLE",
	562: "KEY_REFRESH_RATE_TOGGLE",
	576: "KEY_BUTTONCONFIG",
	577: "KEY_TASKMANAGER",
	578: "KEY_JOURNAL",
	579: "KEY_CONTROLPANEL",
	580: "KEY_APPSELECT",
	581: "KEY_SCREENSAVER",
	582: "KEY_VOICECOMMAND",
	583: "KEY_ASSISTANT",
	584: "KEY_KBD_LAYOUT_NEXT",
	585: "KEY_EMOJI_PICKER",
	586: "KEY_DICTATE",
	587: "KEY_CAMERA_ACCESS_ENABLE",
	588: "KEY_CAMERA_ACCESS_DISABLE",
	589: "KEY_CAMERA_ACCESS_TOGGLE",
	590: "KEY_ACCESSIBILITY",
	591: "KEY_DO_NOT_DISTURB",
	592: "KEY_BRIGHTNESS_MIN",
	593: "KEY_BRIGHTNESS_MAX",
	594: "KEY_EPRIVACY_SCREEN_ON",
	595: "KEY_EPRIVACY_SCREEN_OFF",
	608: "KEY_KBDINPUTASSIST_PREV",
	609: "KEY_KBDINPUTASSIST_NEXT",
	610: "KEY_KBDINPUTASSIST_PREVGROUP",
	611: "KEY_KBDINPUTASSIST_NEXTGROUP",
	612: "KEY_KBDINPUTASSIST_ACCEPT",
	613: "KEY_KBDINPUTASSIST_CANCEL",
	614: "KEY_RIGHT_UP",
	615: "KEY_RIGHT_DOWN",
	616: "KEY_LEFT_UP",
	617: "KEY_LEFT_DOWN",
	618: "KEY_ROOT_MENU",
	619: "KEY_MEDIA_TOP_MENU",
	620: "KEY_NUMERIC_11",
	621: "KEY_NUMERIC_12",
	622: "KEY_AUDIO_DESC",
	623: "KEY_3D_MODE",
	624: "KEY_NEXT_FAVORITE",
	625: "KEY_STOP_RECORD",
	626: "KEY_PAUSE_RECORD",
	627: "KEY_VOD",
	628: "KEY_UNMUTE",
	629: "KEY_FASTREVERSE",
	630: "KEY_SLOWREVERSE",
	631: "KEY_DATA",
	632: "KEY_ONSCREEN_KEYBOARD",
	633: "KEY_PRIVACY_SCREEN_TOGGLE",
	634: "KEY_SELECTIVE_SCREENSHOT",
	635: "KEY_NEXT_ELEMENT",
	636: "KEY_PREVIOUS_ELEMENT",
	637: "KEY_AUTOPILOT_ENGAGE_TOGGLE",
	638: "KEY_MARK_WAYPOINT",
	639: "KEY_SOS",
	640: "KEY_NAV_CHART",
	641: "KEY_FISHING_CHART",
	642: "KEY_SINGLE_RANGE_RADAR",
	643: "KEY_DUAL_RANGE_RADAR",
	644: "KEY_RADAR_OVERLAY",
	645: "KEY_TRADITIONAL_SONAR",
	646: "KEY_CLEARVU_SONAR",
	647: "KEY_SIDEVU_SONAR",
	648: "KEY_NAV_INFO",
	649: "KEY_BRIGHTNESS_MENU",
	656: "KEY_MACRO1",
	657: "KEY_MACRO2",
	658: "KEY_MACRO3",
	659: "KEY_MACRO4",
	660: "KEY_MACRO5",
	661: "KEY_MACRO6",
	662: "KEY_MACRO7",
	663: "KEY_MACRO8",
	664: "KEY_MACRO9",
	665: "KEY_MACRO10",
	666: "KEY_MACRO11",
	667: "KEY_MACRO12",
	668: "KEY_MACRO13",
	669: "KEY_MACRO14",
	670: "KEY_MACRO15",
	671: "KEY_MACRO16",
	672: "KEY_MACRO17",
	673: "KEY_MACRO18",
	674: "KEY_MACRO19",
	675: "KEY_MACRO20",
	676: "KEY_MACRO21",
	677: "KEY_MACRO22",
	678: "KEY_MACRO23",
	679: "KEY_MACRO24",
	680: "KEY_MACRO25",
	681: "KEY_MACRO26",
	682: "KEY_MACRO27",
	683: "KEY_MACRO28",
	684: "KEY_MACRO29",
	685: "KEY_MACRO30",
	688: "KEY_MACRO_RECORD_START",
	689: "KEY_MACRO_RECORD_STOP",
	690: "KEY_MACRO_PRESET_CYCLE",
	691: "KEY_MACRO_PRESET1",
	692: "KEY_MACRO_PRESET2",
	693: "KEY_MACRO_PRESET3",
	696: "KEY_KBD_LCD_MENU1",
	697: "KEY_KBD_LCD_MENU2",
	698: "KEY_KBD_LCD_MENU3",
	699: "KEY_KBD_LCD_MENU4",
	700: "KEY_KBD_LCD_MENU5",
	701: "KEY_PERFORMANCE",
	704: "BTN_TRIGGER_HAPPY",
	705: "BTN_TRIGGER_HAPPY2",
	706: "BTN_TRIGGER_HAPPY3",
	707: "BTN_TRIGGER_HAPPY4",
	708: "BTN_TRIGGER_HAPPY5",
	709: "BTN_TRIGGER_HAPPY6",
	710: "BTN_TRIGGER_HAPPY7",
	711: "BTN_TRIGGER_HAPPY8",
	712: "BTN_TRIGGER_HAPPY9",
	713: "BTN_TRIGGER_HAPPY10",
	714: "BTN_TRIGGER_HAPPY11",
	715: "BTN_TRIGGER_HAPPY12",
	716: "BTN_TRIGGER_HAPPY13",
	717: "BTN_TRIGGER_HAPPY14",
	718: "BTN_TRIGGER_HAPPY15",
	719: "BTN_TRIGGER_HAPPY16",
	720: "BTN_TRIGGER_HAPPY17",
	721: "BTN_TRIGGER_HAPPY18",
	722: "BTN_TRIGGER_HAPPY19",
	723: "BTN_TRIGGER_HAPPY20",
	724: "BTN_TRIGGER_HAPPY21",
	725: "BTN_TRIGGER_HAPPY22",
	726: "BTN_TRIGGER_HAPPY23",
	727: "BTN_TRIGGER_HAPPY24",
	728: "BTN_TRIGGER_HAPPY25",
	729: "BTN_TRIGGER_HAPPY26",
	730: "BTN_TRIGGER_HAPPY27",
	731: "BTN_TRIGGER_HAPPY28",
	732: "BTN_TRIGGER_HAPPY29",
	733: "BTN_TRIGGER_HAPPY30",
	734: "BTN_TRIGGER_HAPPY31",
	735: "BTN_TRIGGER_HAPPY32",
	736: "BTN_TRIGGER_HAPPY33",
	737: "BTN_TRIGGER_HAPPY34",
	738: "BTN_TRIGGER_HAPPY35",
	739: "BTN_TRIGGER_HAPPY36",
	740: "BTN_TRIGGER_HAPPY37",
	741: "BTN_TRIGGER_HAPPY38",
	742: "BTN_TRIGGER_HAPPY39",
	743: "BTN_TRIGGER_HAPPY40",
}
