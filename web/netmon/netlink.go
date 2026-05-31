package netmon

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
)

// netlink / sock_diag constants.
const (
	netlinkSockDiag   = 4
	sockDiagByFamily  = 20
	nlmFRequest       = 1
	nlmFDump          = 0x300
	nlmsgError        = 2
	nlmsgDone         = 3
	nlmsgHdrLen       = 16
	inetDiagReqV2Len  = 56
	inetDiagMsgLen    = 72
	inetDiagInfoType  = 2     // INET_DIAG_INFO rta_type
	inetDiagInfoBit   = 0x2   // idiag_ext bit for INET_DIAG_INFO: 1<<(2-1)
	tcpInfoMinLen     = 136   // need >= 136 bytes to read bytes_acked/bytes_received
	tcpiBytesAckedOff = 120   // tx (tcpi_bytes_acked) LE u64
	tcpiBytesRecvOff  = 128   // rx (tcpi_bytes_received) LE u64
	recvBufLen        = 65536 // ~64 KiB per Recvfrom
)

// address families and protocols.
const (
	afInet     = syscall.AF_INET     // 2
	afInet6    = syscall.AF_INET6    // 10
	ipprotoTCP = syscall.IPPROTO_TCP // 6
	ipprotoUDP = syscall.IPPROTO_UDP // 17
)

// TCP state ids and masks.
const (
	tcpEstablished = 1
	tcpListen      = 10
	statesAll      = uint32(0xffffffff)
)

func stateMask(state uint32) uint32 { return uint32(1) << state }

// align4 rounds n up to a 4-byte boundary (netlink alignment).
func align4(n int) int { return (n + 3) &^ 3 }

// diagSocket is one parsed inet_diag_msg with optional tcp_info counters.
type diagSocket struct {
	family  uint8
	state   uint8
	srcIP   net.IP
	srcPort int
	dstIP   net.IP
	dstPort int
	inode   uint32
	rxOK    bool
	rx      uint64
	txOK    bool
	tx      uint64
}

// buildRequest constructs the 72-byte netlink dump request: a 16-byte nlmsghdr
// followed by a 56-byte inet_diag_req_v2, all little-endian.
func buildRequest(family uint8, protocol uint8, states uint32, ext uint8) []byte {
	total := nlmsgHdrLen + inetDiagReqV2Len // 72
	buf := make([]byte, total)

	// nlmsghdr
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))        // nlmsg_len
	binary.LittleEndian.PutUint16(buf[4:6], sockDiagByFamily)     // nlmsg_type
	binary.LittleEndian.PutUint16(buf[6:8], nlmFRequest|nlmFDump) // nlmsg_flags
	binary.LittleEndian.PutUint32(buf[8:12], 1)                   // nlmsg_seq
	binary.LittleEndian.PutUint32(buf[12:16], 0)                  // nlmsg_pid

	// inet_diag_req_v2 (offsets relative to start of the 56-byte payload)
	p := buf[nlmsgHdrLen:]
	p[0] = family                                 // sdiag_family
	p[1] = protocol                               // sdiag_protocol
	p[2] = ext                                    // idiag_ext
	p[3] = 0                                      // pad
	binary.LittleEndian.PutUint32(p[4:8], states) // idiag_states
	// p[8:56] inet_diag_sockid: all zero for a dump.
	return buf
}

// netlinkDump sends one request and reads all multipart replies, invoking fn
// for each parsed inet_diag_msg payload. fn receives the 72-byte msg plus its
// trailing rtattrs.
func netlinkDump(family uint8, protocol uint8, states uint32, ext uint8, fn func(*diagSocket)) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, netlinkSockDiag)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, lsa); err != nil {
		return err
	}

	req := buildRequest(family, protocol, states, ext)
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	buf := make([]byte, recvBufLen)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}
		if n <= 0 {
			return nil
		}
		done, perr := parseDatagram(buf[:n], family, fn)
		if perr != nil {
			return perr
		}
		if done {
			return nil
		}
	}
}

// parseDatagram walks every nlmsghdr in one received datagram. It returns
// done=true when NLMSG_DONE is seen and an error when NLMSG_ERROR carries a
// nonzero errno. Unknown / truncated trailing data is ignored.
func parseDatagram(data []byte, family uint8, fn func(*diagSocket)) (bool, error) {
	off := 0
	for off+nlmsgHdrLen <= len(data) {
		msgLen := int(binary.LittleEndian.Uint32(data[off : off+4]))
		msgType := binary.LittleEndian.Uint16(data[off+4 : off+6])
		if msgLen < nlmsgHdrLen || off+msgLen > len(data) {
			break // truncated / malformed: stop scanning this datagram
		}
		payload := data[off+nlmsgHdrLen : off+msgLen]

		switch msgType {
		case nlmsgDone:
			return true, nil
		case nlmsgError:
			// nlmsgerr: first 4 bytes are a (negative) errno; 0 == ACK.
			if len(payload) >= 4 {
				code := int32(binary.LittleEndian.Uint32(payload[0:4]))
				if code != 0 {
					return true, errors.New("netlink error: errno " + itoa(int(-code)))
				}
			}
			return true, nil
		default:
			if s, ok := parseDiagMsg(payload, family); ok {
				fn(s)
			}
		}
		off += align4(msgLen)
	}
	return false, nil
}

// parseDiagMsg decodes one inet_diag_msg (72 bytes) plus its rtattrs from a
// single nlmsg payload. Offsets are relative to the start of the payload (i.e.
// after the 16-byte nlmsghdr).
func parseDiagMsg(payload []byte, reqFamily uint8) (*diagSocket, bool) {
	if len(payload) < inetDiagMsgLen {
		return nil, false
	}
	s := &diagSocket{}
	s.family = payload[0]
	s.state = payload[1]

	// inet_diag_sockid starts at offset 4.
	s.srcPort = int(binary.BigEndian.Uint16(payload[4:6])) // idiag_sport (BE)
	s.dstPort = int(binary.BigEndian.Uint16(payload[6:8])) // idiag_dport (BE)
	s.srcIP = decodeIP(payload[8:24], s.family)            // idiag_src (16 bytes)
	s.dstIP = decodeIP(payload[24:40], s.family)           // idiag_dst (16 bytes)
	// idiag_if @40 (u32), idiag_cookie @44 (8 bytes) -- unused.
	// idiag_expires @52, rqueue @56, wqueue @60, uid @64 -- unused.
	s.inode = binary.LittleEndian.Uint32(payload[68:72]) // idiag_inode

	// rtattrs follow the 72-byte fixed struct.
	parseRtattrs(payload[inetDiagMsgLen:], s)
	return s, true
}

// parseRtattrs walks the attribute list, decoding INET_DIAG_INFO (tcp_info)
// byte counters when present and long enough.
func parseRtattrs(attrs []byte, s *diagSocket) {
	off := 0
	for off+4 <= len(attrs) {
		rtaLen := int(binary.LittleEndian.Uint16(attrs[off : off+2]))
		rtaType := binary.LittleEndian.Uint16(attrs[off+2 : off+4])
		if rtaLen < 4 || off+rtaLen > len(attrs) {
			break // malformed; rta_len includes the 4-byte header
		}
		body := attrs[off+4 : off+rtaLen]
		if rtaType == inetDiagInfoType {
			if len(body) >= tcpInfoMinLen {
				s.tx = binary.LittleEndian.Uint64(body[tcpiBytesAckedOff : tcpiBytesAckedOff+8])
				s.txOK = true
				s.rx = binary.LittleEndian.Uint64(body[tcpiBytesRecvOff : tcpiBytesRecvOff+8])
				s.rxOK = true
			}
			// Shorter than 136 bytes: counters unknown (leave rxOK/txOK false).
		}
		off += align4(rtaLen)
	}
}

// decodeIP builds a net.IP from a 16-byte field, using 4 bytes for AF_INET and
// 16 for AF_INET6. v4-mapped v6 (::ffff:a.b.c.d) collapses to bare v4.
func decodeIP(b []byte, family uint8) net.IP {
	if family == afInet {
		ip := make(net.IP, 4)
		copy(ip, b[0:4])
		return ip
	}
	ip := make(net.IP, 16)
	copy(ip, b[0:16])
	if v4 := ip.To4(); v4 != nil { // v4-mapped -> bare v4
		return v4
	}
	return ip
}

// itoa is a tiny dependency-free int-to-decimal helper for error strings.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
