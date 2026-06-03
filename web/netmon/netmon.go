// Package netmon provides a dependency-free network view for the dashboard.
//
// A background sampler diffs two native netlink INET_DIAG snapshots into
// per-process / per-connection bandwidth (rx/tx bytes per second) plus
// listening sockets. It augments outbound connections with offline GeoIP
// country lookup and non-blocking cached reverse DNS, classifying LAN /
// private / reserved / CGNAT / multicast peers so they skip rDNS and GeoIP.
//
// All lookups are local; the only outbound traffic is the system resolver
// performing PTR queries (same as normal browsing), which Start(rdns=false)
// disables.
package netmon

import (
	"sort"
	"strconv"
	"sync"
	"time"
)

// tunables (match netmon.py).
const (
	sampleInterval = 2 * time.Second
	maxRows        = 512
)

// attribution is the GeoIP / ASN / map credit string for the offline datasets.
const attribution = "GeoIP: ip-location-db geo-whois-asn-country (CC BY 4.0, NRO). " +
	"ASN/org: ip-location-db asn (CC BY 4.0, RouteViews/DB-IP/NRO). " +
	"Map: simple-world-map by Al MacDonald / flekschas (CC BY-SA 3.0)."

// ----------------------------- JSON contract types -------------------------

// listenRow is a listening socket attached to a process.
type listenRow struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
}

// processRow is one per-pid aggregate.
type processRow struct {
	PID    int         `json:"pid"`
	Name   string      `json:"name"`
	RxBps  float64     `json:"rx_bps"`
	TxBps  float64     `json:"tx_bps"`
	Conns  int         `json:"conns"`
	Listen []listenRow `json:"listen"`
}

// connRow is one established connection. ASN/Org/Cat describe the peer's owning
// network (offline ASN lookup + category classification); they are omitted for
// LAN peers and for global peers with no ASN match.
type connRow struct {
	Proc    string  `json:"proc"`
	PID     int     `json:"pid"`
	Local   string  `json:"local"`
	Peer    string  `json:"peer"`
	Port    int     `json:"port"`
	RxBps   float64 `json:"rx_bps"`
	TxBps   float64 `json:"tx_bps"`
	Scope   string  `json:"scope"`
	Host    *string `json:"host"`
	Country *string `json:"country"`
	ASN     uint32  `json:"asn,omitempty"`
	Org     string  `json:"org,omitempty"`
	Cat     string  `json:"cat,omitempty"`
}

// snapshot is the marshaled /api/net document. Categories tallies global
// (remote) connections by owning-network category (corp/cloud/cdn/gov/telecom/
// other) plus "unknown" for peers with no ASN match.
type snapshot struct {
	Processes    []processRow   `json:"processes"`
	Connections  []connRow      `json:"connections"`
	Countries    map[string]int `json:"countries"`
	Categories   map[string]int `json:"categories"`
	PrivateCount int            `json:"private_count"`
	Time         float64        `json:"time"`
	RdnsEnabled  bool           `json:"rdns_enabled"`
	GeoipReady   bool           `json:"geoip_ready"`
	ASNReady     bool           `json:"asn_ready"`
	Attribution  string         `json:"attribution"`
}

// ----------------------------- internal sample types -----------------------

// connKey uniquely identifies an established TCP socket.
type connKey struct {
	localIP   string
	localPort int
	peerIP    string
	peerPort  int
}

// connState mirrors the Python per-socket snapshot record.
type connState struct {
	pid      int
	name     string
	hasProc  bool
	rxOK     bool
	rx       uint64
	txOK     bool
	tx       uint64
	peerIP   string
	peerPort int
	local    string
}

// listenerEntry is a parsed listening socket with its attribution.
type listenerEntry struct {
	proto   string
	ip      string
	port    int
	pid     int
	name    string
	hasProc bool
}

// ----------------------------- stored state --------------------------------

var (
	stateMu sync.RWMutex
	state   = snapshot{
		Processes:   []processRow{},
		Connections: []connRow{},
		Countries:   map[string]int{},
		Categories:  map[string]int{},
	}
)

// ----------------------------- public API ----------------------------------

// Start launches the GeoIP loader, the rDNS worker pool, and the sampler. It
// returns immediately; samplers run in the background and never block callers.
func Start(geodir string, rdnsEnabled bool) {
	rdns.startRDNS(rdnsEnabled)
	go loadGeoIP(geodir)
	go loadASN(geodir)
	go sampler()
}

// SnapshotJSON returns the current network document with the live rdns/geoip
// flags and attribution attached. The returned value is a copy safe to
// marshal.
func SnapshotJSON() any {
	stateMu.RLock()
	s := state // shallow copy of the struct
	stateMu.RUnlock()

	// Defend against nil slices/maps so marshaling yields []/{} not null.
	if s.Processes == nil {
		s.Processes = []processRow{}
	}
	if s.Connections == nil {
		s.Connections = []connRow{}
	}
	if s.Countries == nil {
		s.Countries = map[string]int{}
	}
	if s.Categories == nil {
		s.Categories = map[string]int{}
	}
	s.RdnsEnabled = rdns.enabled
	s.GeoipReady = Ready()
	s.ASNReady = ASNReady()
	s.Attribution = attribution
	return s
}

// ----------------------------- sampler -------------------------------------

// sampler diffs successive established-TCP snapshots into bandwidth rows and
// publishes the result every interval. It recovers from any panic and backs
// off one interval on error, keeping the goroutine alive.
func sampler() {
	for {
		runSampler()
		// runSampler only returns if it panicked-and-recovered or could not
		// take an initial snapshot; back off before restarting.
		time.Sleep(sampleInterval)
	}
}

// runSampler holds the main loop. A recover() converts an unexpected panic
// into a return so the outer sampler() can restart cleanly.
func runSampler() {
	defer func() { _ = recover() }()

	prev, ok := snapshotEstablished()
	if !ok {
		prev = map[connKey]connState{}
	}
	tprev := time.Now()

	for {
		time.Sleep(sampleInterval)

		cur, ok := snapshotEstablished()
		if !ok {
			// transient error: back off one extra interval, keep prev/tprev.
			time.Sleep(sampleInterval)
			continue
		}
		tcur := time.Now()
		dt := tcur.Sub(tprev).Seconds()

		listeners := snapshotListeners()
		st := build(prev, cur, dt, listeners)
		st.Time = float64(time.Now().UnixNano()) / 1e9

		stateMu.Lock()
		state = st
		stateMu.Unlock()

		prev, tprev = cur, tcur
	}
}

// snapshotEstablished dumps established TCP sockets (with tcp_info byte
// counters) for both address families and keys them by 4-tuple. The returned
// bool is false only if both family dumps fail.
func snapshotEstablished() (map[connKey]connState, bool) {
	inodes := buildInodeMap()
	out := map[connKey]connState{}
	okAny := false

	for _, fam := range []uint8{afInet, afInet6} {
		err := netlinkDump(fam, ipprotoTCP, stateMask(tcpEstablished), inetDiagInfoBit, func(s *diagSocket) {
			if s.srcIP == nil || s.dstIP == nil {
				return
			}
			li := s.srcIP.String()
			pi := s.dstIP.String()
			key := connKey{localIP: li, localPort: s.srcPort, peerIP: pi, peerPort: s.dstPort}
			cs := connState{
				rxOK:     s.rxOK,
				rx:       s.rx,
				txOK:     s.txOK,
				tx:       s.tx,
				peerIP:   pi,
				peerPort: s.dstPort,
				local:    li + ":" + strconv.Itoa(s.srcPort),
				name:     "?",
			}
			if owner, ok := inodes[s.inode]; ok && s.inode != 0 {
				cs.pid = owner.pid
				cs.name = commOrUnknown(owner.name)
				cs.hasProc = true
			}
			out[key] = cs
		})
		if err == nil {
			okAny = true
		}
	}
	return out, okAny
}

// snapshotListeners dumps listening TCP and all-state UDP sockets and records
// their proto/ip/port/attribution. UDP carries no byte counters (connections
// only), matching the Python behavior.
func snapshotListeners() []listenerEntry {
	inodes := buildInodeMap()
	res := []listenerEntry{}

	dump := func(proto string, ipproto uint8, states uint32) {
		for _, fam := range []uint8{afInet, afInet6} {
			_ = netlinkDump(fam, ipproto, states, 0, func(s *diagSocket) {
				if s.srcIP == nil {
					return
				}
				e := listenerEntry{
					proto: proto,
					ip:    s.srcIP.String(),
					port:  s.srcPort,
					name:  "?",
				}
				if owner, ok := inodes[s.inode]; ok && s.inode != 0 {
					e.pid = owner.pid
					e.name = commOrUnknown(owner.name)
					e.hasProc = true
				}
				res = append(res, e)
			})
		}
	}

	dump("tcp", ipprotoTCP, stateMask(tcpListen))
	dump("udp", ipprotoUDP, statesAll)
	return res
}

// commOrUnknown maps an empty comm to "?", matching the fake-pid naming.
func commOrUnknown(comm string) string {
	if comm == "" {
		return "?"
	}
	return comm
}

// ----------------------------- build --------------------------------------

// pidAgg accumulates per-process bandwidth, connection counts, and listeners.
type pidAgg struct {
	row    processRow
	listen map[listenRow]struct{}
}

// build diffs prev/cur into connection rows and per-pid aggregates, attaches
// listeners, computes country/private tallies, sorts by total bandwidth desc,
// and caps each list to maxRows. It mirrors netmon.py _build() exactly.
func build(prev, cur map[connKey]connState, dt float64, listeners []listenerEntry) snapshot {
	conns := []connRow{}
	perpid := map[int]*pidAgg{}
	countries := map[string]int{}
	categories := map[string]int{}
	private := 0

	// aggFor fetches-or-creates the aggregate for a pid, upgrading a "?"/""
	// name once a real name is known.
	aggFor := func(pid int, name string) *pidAgg {
		a := perpid[pid]
		if a == nil {
			a = &pidAgg{
				row: processRow{
					PID:    pid,
					Name:   name,
					Listen: []listenRow{},
				},
				listen: map[listenRow]struct{}{},
			}
			perpid[pid] = a
		} else if (a.row.Name == "?" || a.row.Name == "") && name != "?" && name != "" {
			a.row.Name = name
		}
		return a
	}

	for key, c := range cur {
		var rx, tx float64
		if p, ok := prev[key]; ok && dt > 0 {
			if c.rxOK && p.rxOK {
				rx = float64(satSub(c.rx, p.rx)) / dt
			}
			if c.txOK && p.txOK {
				tx = float64(satSub(c.tx, p.tx)) / dt
			}
		}

		pid := 0
		name := "?"
		if c.hasProc {
			pid = c.pid
			name = c.name
		}

		scope := classify(c.peerIP)
		var host *string
		var cc *string
		var cAsn uint32
		var cOrg, cCat string
		if scope == "global" {
			host = rdns.resolve(c.peerIP)
			if code := country(c.peerIP); code != "" {
				cc = &code
				countries[code]++
			}
			// Owning-network classification (offline ASN -> org -> category).
			catKey := "unknown"
			if asn, org := asnLookup(c.peerIP); org != "" || asn != 0 {
				cAsn = asn
				cOrg = org
				cCat = categorize(asn, org)
				catKey = cCat
			}
			categories[catKey]++
		}
		if scope == "lan" {
			private++
		}

		conns = append(conns, connRow{
			Proc:    name,
			PID:     pid,
			Local:   c.local,
			Peer:    c.peerIP,
			Port:    c.peerPort,
			RxBps:   rx,
			TxBps:   tx,
			Scope:   scope,
			Host:    host,
			Country: cc,
			ASN:     cAsn,
			Org:     cOrg,
			Cat:     cCat,
		})

		if c.hasProc { // aggregate only attributed sockets (never merge fake pid 0)
			a := aggFor(pid, name)
			a.row.RxBps += rx
			a.row.TxBps += tx
			a.row.Conns++
		}
	}

	for _, l := range listeners {
		if !l.hasProc { // skip listeners we cannot attribute
			continue
		}
		a := aggFor(l.pid, l.name)
		lr := listenRow{Proto: l.proto, Port: l.port}
		if _, dup := a.listen[lr]; !dup {
			a.listen[lr] = struct{}{}
			a.row.Listen = append(a.row.Listen, lr)
		}
	}

	procsList := make([]processRow, 0, len(perpid))
	for _, a := range perpid {
		procsList = append(procsList, a.row)
	}
	sort.SliceStable(procsList, func(i, j int) bool {
		return (procsList[i].RxBps + procsList[i].TxBps) > (procsList[j].RxBps + procsList[j].TxBps)
	})
	sort.SliceStable(conns, func(i, j int) bool {
		return (conns[i].RxBps + conns[i].TxBps) > (conns[j].RxBps + conns[j].TxBps)
	})

	return snapshot{
		Processes:    capProcesses(procsList),
		Connections:  capConns(conns),
		Countries:    countries,
		Categories:   categories,
		PrivateCount: private,
	}
}

// capProcesses and capConns enforce the MAX_ROWS limit on the sorted lists.

// satSub is a saturating subtraction matching Python's max(0, a-b) over
// counters that only ever increase but may reset.
func satSub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func capProcesses(p []processRow) []processRow {
	if len(p) > maxRows {
		p = p[:maxRows]
	}
	return p
}

func capConns(c []connRow) []connRow {
	if len(c) > maxRows {
		c = c[:maxRows]
	}
	return c
}
