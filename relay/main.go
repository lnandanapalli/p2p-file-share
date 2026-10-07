// p2p.py relay server (opt-in: only used when both peers run with --relay).
//
// Purpose: for networks where UDP hole punching cannot work (both peers
// behind virtualized/nested NAT, CG-NAT, strict firewalls), both peers
// connect outbound over plain HTTPS instead. This server pairs them by
// session token and acts as a dumb, in-memory, per-direction mailbox. It never sees plaintext —
// packets are already encrypted/authenticated by p2p.py's own crypto
// layer before they arrive here.
//
// No retry/ordering/ack logic lives here on purpose: p2p.py's existing
// ARQ layer already assumes an unreliable channel (it was written for
// raw UDP) and will retransmit on its own if a batch never arrives.
// This server just moves bytes between two queues.
//
// Abuse protection (see "limits" section below):
//   - global caps on session count and total queued bytes
//   - per-IP token-bucket rate limits (general + new-session creation)
//   - per-IP cap on concurrent long-poll connections
//
// Deployment assumptions (Azure App Service, single instance):
//   - State is in memory, so run exactly ONE instance.
//   - The real client IP is taken ONLY from X-Client-IP, which the App
//     Service front end sets/overwrites. X-Forwarded-For is deliberately
//     ignored. Missing/invalid values share one "unknown" bucket.
package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxBatchBytes   = 4 << 20  // 4 MiB cap on a single POST body
	maxQueueBytes   = 32 << 20 // 32 MiB cap per direction queue (backpressure)
	sessionIdleTTL  = 2 * time.Minute
	sweepInterval   = 30 * time.Second
	longPollTimeout = 20 * time.Second
)

// ---- limits ----

const (
	maxSessions   = 2000      // concurrent sessions across the whole relay
	maxTotalBytes = 512 << 20 // queued bytes across all sessions combined
	maxBuckets    = 100000    // cap on rate-limiter map size per limiter
	maxPollsPerIP = 8         // concurrent /recv long-polls per IP

	// The shared "unknown" bucket (no usable X-Client-IP) gets this many
	// times the normal rate/burst/poll limits, since many real users can
	// land in it.
	unknownKey   = "unknown"
	unknownScale = 4
)

var (
	// General request limit per IP. A normal transfer makes roughly
	// 10-20 requests/sec, so this is generous on purpose.
	reqLimiter = newLimiter(50, 100)
	// New-session creation limit per IP: 1 per 5s sustained, burst of 5.
	// Legitimate clients create exactly one session per transfer.
	newSessLimiter = newLimiter(0.2, 5)

	totalBytes atomic.Int64 // bytes currently queued, all sessions

	// Counters used only to warn when X-Client-IP looks broken.
	windowReqs    atomic.Int64
	windowUnknown atomic.Int64
)

// ---- rate limiter (token bucket, stdlib only) ----

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok && len(l.buckets) >= maxBuckets {
		// Map is full: fold new keys into the shared bucket rather than
		// growing without bound.
		key = unknownKey
		b, ok = l.buckets[key]
	}

	rate, burst := l.rate, l.burst
	if key == unknownKey {
		rate *= unknownScale
		burst *= unknownScale
	}

	now := time.Now()
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been idle long enough to be full again.
func (l *limiter) sweep(idle time.Duration) {
	cutoff := time.Now().Add(-idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.buckets {
		if b.last.Before(cutoff) {
			delete(l.buckets, k)
		}
	}
}

// ---- client IP ----

// clientIP returns a bucket key for the caller. It trusts ONLY the
// X-Client-IP header set by Azure App Service's front end. Anything
// missing or unparseable maps to the shared unknown bucket, so garbage
// can never create its own bucket key.
func clientIP(r *http.Request) string {
	v := strings.TrimSpace(r.Header.Get("X-Client-IP"))
	if v == "" {
		return unknownKey
	}
	// App Service may append a port to IPv4 values ("1.2.3.4:5678").
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	addr, err := netip.ParseAddr(strings.Trim(v, "[]"))
	if err != nil {
		return unknownKey
	}
	addr = addr.Unmap()
	if addr.Is6() {
		// One user can rotate through a whole /64, so bucket by prefix.
		p, err := addr.Prefix(64)
		if err != nil {
			return unknownKey
		}
		return p.String()
	}
	return addr.String()
}

// ---- concurrent long-poll cap per IP ----

var (
	pollsMu sync.Mutex
	polls   = map[string]int{}
)

func acquirePoll(ip string) bool {
	limit := maxPollsPerIP
	if ip == unknownKey {
		limit *= unknownScale
	}
	pollsMu.Lock()
	defer pollsMu.Unlock()
	if polls[ip] >= limit {
		return false
	}
	polls[ip]++
	return true
}

func releasePoll(ip string) {
	pollsMu.Lock()
	defer pollsMu.Unlock()
	if polls[ip] <= 1 {
		delete(polls, ip)
	} else {
		polls[ip]--
	}
}

// ---- queues and sessions ----

// direction is a one-writer, one-reader FIFO queue of raw packets
// flowing one way (sender->receiver or receiver->sender) for one session.
type direction struct {
	mu      sync.Mutex
	packets [][]byte
	bytes   int
	closed  bool // set when the session is swept; nothing more may be queued

	// notify is a doorbell for waiting /recv polls. Buffer of 1: a ring
	// that happens while nobody is waiting is remembered (so it can't be
	// missed), and repeated rings collapse into one.
	notify chan struct{}
}

func newDirection() *direction {
	return &direction{notify: make(chan struct{}, 1)}
}

// wake rings the doorbell without ever blocking.
func (d *direction) wake() {
	select {
	case d.notify <- struct{}{}:
	default: // a ring is already pending; that's enough
	}
}

// push appends a batch's packets. Returns false if it would exceed the
// per-direction cap, the global cap, or the session has been closed
// (caller responds 503; the sender's own layer will back off and retry,
// same as it would on UDP congestion).
func (d *direction) push(packets [][]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	added := 0
	for _, p := range packets {
		added += len(p)
	}
	if d.bytes+added > maxQueueBytes {
		return false
	}
	if totalBytes.Add(int64(added)) > maxTotalBytes {
		totalBytes.Add(-int64(added))
		return false
	}
	d.packets = append(d.packets, packets...)
	d.bytes += added
	d.wake()
	return true
}

// drain removes and returns everything currently queued, or nil if empty.
func (d *direction) drain() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.packets) == 0 {
		return nil
	}
	out := d.packets
	totalBytes.Add(-int64(d.bytes))
	d.packets = nil
	d.bytes = 0
	return out
}

// close discards anything queued, returns its bytes to the global
// budget, and rejects all future pushes.
func (d *direction) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	totalBytes.Add(-int64(d.bytes))
	d.packets = nil
	d.bytes = 0
}

type session struct {
	s2r     *direction // sender -> receiver
	r2s     *direction // receiver -> sender
	mu      sync.Mutex
	touched time.Time
}

func (s *session) touch() {
	s.mu.Lock()
	s.touched = time.Now()
	s.mu.Unlock()
}

func (s *session) idleSince() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.touched
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

// getSession returns the session for token, creating it if allowed.
// On failure it returns nil and the HTTP status to send:
//
//	429 - this IP is creating sessions too fast
//	503 - the relay is at its session cap
//
// Touching happens under the map lock, so the sweeper can't expire a
// session between lookup and touch.
func getSession(token, ip string) (*session, int) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	if s, ok := sessions[token]; ok {
		s.touch()
		return s, 0
	}
	if len(sessions) >= maxSessions {
		return nil, http.StatusServiceUnavailable
	}
	if !newSessLimiter.allow(ip) {
		return nil, http.StatusTooManyRequests
	}
	s := &session{s2r: newDirection(), r2s: newDirection(), touched: time.Now()}
	sessions[token] = s
	return s, 0
}

func sweepLoop() {
	for range time.Tick(sweepInterval) {
		cutoff := time.Now().Add(-sessionIdleTTL)
		sessionsMu.Lock()
		for token, s := range sessions {
			if s.idleSince().Before(cutoff) {
				// Return queued bytes to the global budget before dropping.
				s.s2r.close()
				s.r2s.close()
				delete(sessions, token)
			}
		}
		sessionsMu.Unlock()

		reqLimiter.sweep(5 * time.Minute)
		newSessLimiter.sweep(5 * time.Minute)

		// If most traffic has no usable X-Client-IP, the header name has
		// probably changed (e.g. a CDN/Front Door was added in front).
		total, unknown := windowReqs.Swap(0), windowUnknown.Swap(0)
		if total >= 50 && unknown*2 > total {
			log.Printf("WARNING: %d of %d requests had no valid X-Client-IP; rate limiting is degraded (check proxy/header config)", unknown, total)
		}
	}
}

// ---- batch wire format ----
// [2-byte count][2-byte len][packet bytes] * count
// Deliberately simple and fixed-width; matches what p2p.py's client
// side packs/unpacks. No versioning byte — bump the route path
// (e.g. /v2/...) if the format ever needs to change.

func decodeBatch(body []byte) ([][]byte, error) {
	if len(body) < 2 {
		if len(body) == 0 {
			return nil, nil
		}
		return nil, errors.New("short body")
	}
	count := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	packets := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		if off+2 > len(body) {
			return nil, errors.New("truncated length prefix")
		}
		l := int(binary.BigEndian.Uint16(body[off : off+2]))
		off += 2
		if off+l > len(body) {
			return nil, errors.New("truncated packet")
		}
		packets = append(packets, body[off:off+l])
		off += l
	}
	return packets, nil
}

func encodeBatch(packets [][]byte) []byte {
	size := 2
	for _, p := range packets {
		size += 2 + len(p)
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint16(out[0:2], uint16(len(packets)))
	off := 2
	for _, p := range packets {
		binary.BigEndian.PutUint16(out[off:off+2], uint16(len(p)))
		off += 2
		copy(out[off:], p)
		off += len(p)
	}
	return out
}

// ---- routing ----
// Path shape: /relay/{token}/{dir}/{send|recv}
// dir is "s2r" or "r2s" — fixed strings each peer already knows locally
// based on its own role (sender posts to s2r, reads r2s; receiver is
// the mirror image). No extra secret derivation needed for direction.

// tokenPattern constrains session tokens to a safe, bounded charset.
// The token itself is derived client-side (HMAC of the shared secret
// already exchanged via the word codes) — the server treats it as an
// opaque bearer credential and does no verification beyond shape.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func pickDirection(s *session, dir string) *direction {
	switch dir {
	case "s2r":
		return s.s2r
	case "r2s":
		return s.r2s
	default:
		return nil
	}
}

func relayHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	windowReqs.Add(1)
	if ip == unknownKey {
		windowUnknown.Add(1)
	}

	// 1. Cheap per-IP limit first, before any other work.
	if !reqLimiter.allow(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "slow down", http.StatusTooManyRequests)
		return
	}

	// 2. Validate everything BEFORE touching session state, so junk
	//    requests can never allocate a session.
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// expects: relay, {token}, {dir}, {send|recv}
	if len(parts) != 4 || parts[0] != "relay" {
		http.NotFound(w, r)
		return
	}
	token, dir, action := parts[1], parts[2], parts[3]
	if !tokenPattern.MatchString(token) {
		http.Error(w, "bad token", http.StatusBadRequest)
		return
	}
	if dir != "s2r" && dir != "r2s" {
		http.Error(w, "bad direction", http.StatusBadRequest)
		return
	}
	isSend := action == "send" && r.Method == http.MethodPost
	isRecv := action == "recv" && r.Method == http.MethodGet
	if !isSend && !isRecv {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// 3. Only now find or create the session (subject to caps/limits).
	s, status := getSession(token, ip)
	if s == nil {
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "too many new sessions", status)
		} else {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "relay busy", status)
		}
		return
	}
	d := pickDirection(s, dir)

	if isSend {
		handleSend(w, r, d)
		return
	}

	// Each long-poll pins a goroutine for up to longPollTimeout; a real
	// client only ever has one open per session.
	if !acquirePoll(ip) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many concurrent polls", http.StatusTooManyRequests)
		return
	}
	defer releasePoll(ip)
	handleRecv(w, r, d)
}

func handleSend(w http.ResponseWriter, r *http.Request, d *direction) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBatchBytes+1))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if len(body) > maxBatchBytes {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	packets, err := decodeBatch(body)
	if err != nil {
		http.Error(w, "malformed batch", http.StatusBadRequest)
		return
	}
	if len(packets) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !d.push(packets) {
		// Queue full (per-direction or global), or session closed — peer
		// isn't draining fast enough, or abandoned. Caller's own ARQ will
		// retry; this is equivalent to congestion on a UDP path.
		http.Error(w, "queue full", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleRecv is a long-poll: it returns as soon as packets are queued,
// or an empty batch after longPollTimeout, or silently if the client
// disconnects. It sleeps on a channel instead of polling a timer, so
// packets are delivered immediately and no CPU is spent while waiting.
func handleRecv(w http.ResponseWriter, r *http.Request, d *direction) {
	ctx := r.Context()
	timer := time.NewTimer(longPollTimeout)
	defer timer.Stop()
	for {
		// Never drain for a client that is already gone: the packets
		// would be written into a dead connection and lost. If we were
		// woken by a ring meant for a live poll, pass it on.
		if ctx.Err() != nil {
			d.wake()
			return
		}
		if packets := d.drain(); packets != nil {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(encodeBatch(packets))
			return
		}
		select {
		case <-d.notify:
			// Packets (probably) arrived; loop around and drain.
		case <-timer.C:
			// Nothing arrived within the poll window — return an empty
			// batch (count=0), not an error. The client just calls again.
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(encodeBatch(nil))
			return
		case <-ctx.Done():
			// Client disconnected. Returning here frees its poll slot
			// (releasePoll is deferred in relayHandler) right away.
			return
		}
	}
}

func main() {
	addr := os.Getenv("RELAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	go sweepLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/relay/", relayHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		// Bounds how long a client may dribble a request body. This also
		// guarantees a POST finishes (or is dropped) well inside the
		// session idle TTL.
		ReadTimeout: 30 * time.Second,
		// No global WriteTimeout: /recv intentionally holds the
		// connection open up to longPollTimeout. Per-handler deadlines
		// are enforced in handleRecv itself.
	}

	log.Printf("relay listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
