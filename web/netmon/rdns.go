package netmon

import (
	"container/list"
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// rDNS tunables (match netmon.py).
const (
	cacheCap  = 4096
	posTTL    = 6 * time.Hour
	negTTL    = 60 * time.Second
	queueCap  = 256
	poolSize  = 8
	dnsTimout = 5 * time.Second
	maxHost   = 253
)

// cacheEntry holds a resolved host (nil == negative result) and its expiry.
type cacheEntry struct {
	host *string
	exp  time.Time
}

// rdnsState is the non-blocking reverse-DNS resolver: a bounded worker pool, an
// in-flight set so a given IP is only queued once, and an LRU cache with
// positive/negative TTLs.
type rdnsState struct {
	enabled bool

	mu    sync.Mutex
	cache map[string]*list.Element // ip -> *list.Element{Value: lruItem}
	lru   *list.List               // front = most recent, back = oldest

	imu      sync.Mutex
	inflight map[string]struct{}

	queue chan string
	once  sync.Once
}

// lruItem is the value stored in each list element.
type lruItem struct {
	ip    string
	entry cacheEntry
}

var rdns = newRDNS()

func newRDNS() *rdnsState {
	return &rdnsState{
		cache:    map[string]*list.Element{},
		lru:      list.New(),
		inflight: map[string]struct{}{},
		queue:    make(chan string, queueCap),
	}
}

// startRDNS launches the worker pool once and records the enabled flag.
func (s *rdnsState) startRDNS(enabled bool) {
	s.enabled = enabled
	s.once.Do(func() {
		for i := 0; i < poolSize; i++ {
			go s.worker()
		}
	})
}

// cacheGet returns (hit, host) for a non-expired entry, refreshing its LRU
// position. Expired entries are evicted and reported as a miss.
func (s *rdnsState) cacheGet(ip string) (bool, *string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.cache[ip]
	if !ok {
		return false, nil
	}
	it := el.Value.(*lruItem)
	if now.After(it.entry.exp) {
		s.lru.Remove(el)
		delete(s.cache, ip)
		return false, nil
	}
	s.lru.MoveToFront(el)
	return true, it.entry.host
}

// cachePut stores a positive or negative result with the appropriate TTL and
// evicts oldest entries when over capacity.
func (s *rdnsState) cachePut(ip string, host *string) {
	ttl := negTTL
	if host != nil {
		ttl = posTTL
	}
	exp := time.Now().Add(ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.cache[ip]; ok {
		it := el.Value.(*lruItem)
		it.entry = cacheEntry{host: host, exp: exp}
		s.lru.MoveToFront(el)
	} else {
		el := s.lru.PushFront(&lruItem{ip: ip, entry: cacheEntry{host: host, exp: exp}})
		s.cache[ip] = el
	}
	for s.lru.Len() > cacheCap {
		back := s.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*lruItem)
		s.lru.Remove(back)
		delete(s.cache, old.ip)
	}
}

// resolve returns a cached host or nil now; it enqueues unknown IPs once and
// never blocks. nil is returned when disabled, on a miss, or when the queue is
// full (the enqueue is dropped).
func (s *rdnsState) resolve(ip string) *string {
	if !s.enabled {
		return nil
	}
	if hit, host := s.cacheGet(ip); hit {
		return host
	}
	s.imu.Lock()
	if _, busy := s.inflight[ip]; busy {
		s.imu.Unlock()
		return nil
	}
	s.inflight[ip] = struct{}{}
	s.imu.Unlock()

	select {
	case s.queue <- ip:
	default: // queue full: drop rather than grow; clear in-flight so we retry later
		s.imu.Lock()
		delete(s.inflight, ip)
		s.imu.Unlock()
	}
	return nil
}

// worker drains the queue, performs a bounded PTR lookup, sanitizes the result,
// and stores it (positive or negative) in the cache.
func (s *rdnsState) worker() {
	for ip := range s.queue {
		host := lookupHost(ip)
		s.cachePut(ip, host)
		s.imu.Lock()
		delete(s.inflight, ip)
		s.imu.Unlock()
	}
}

// lookupHost performs a single PTR lookup with a 5s timeout, taking the first
// name, sanitizing it to the hostname charset, trimming a trailing dot, and
// capping length. A negative result (no PTR, error, or empty after sanitize) is
// nil.
func lookupHost(ip string) *string {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil
	}
	h := sanitizeHost(names[0])
	if h == "" {
		return nil
	}
	return &h
}

// sanitizeHost strips characters outside [A-Za-z0-9._-] (PTR records are
// attacker-controlled), trims a trailing '.', and caps to 253 bytes.
func sanitizeHost(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b.WriteByte(c)
		}
	}
	h := b.String()
	if len(h) > maxHost {
		h = h[:maxHost]
	}
	h = strings.TrimRight(h, ".")
	return h
}
