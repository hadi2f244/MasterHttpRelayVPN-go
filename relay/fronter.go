// Package relay implements the Apps Script domain-fronting relay engine.
//
// Domain-fronting trick:
//   - TCP dial to googleIP (e.g. 216.239.38.120:443)
//   - TLS SNI = frontDomain (e.g. www.google.com)  → ISP/DPI sees "google.com"
//   - HTTP Host = script.google.com                → routes to Apps Script
//   - POST JSON payload to /macros/s/{scriptID}/exec
//   - Apps Script fetches the real URL and returns JSON {s, h, b}
package relay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── static asset extensions ─────────────────────────────────────────────────

var staticExts = []string{
	".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".eot",
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
	".mp3", ".mp4", ".webm", ".wasm", ".avif",
}

var largeExts = []string{
	".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
	".exe", ".msi", ".dmg", ".deb", ".rpm", ".apk",
	".iso", ".img", ".mp4", ".mkv", ".avi", ".mov", ".webm",
	".mp3", ".flac", ".wav", ".aac",
	".pdf", ".doc", ".docx", ".ppt", ".pptx", ".wasm",
}

// ─── pre-compiled regexps ─────────────────────────────────────────────────────

var (
	reStatusCode   = regexp.MustCompile(`\d{3}`)
	reContentRange = regexp.MustCompile(`/(\d+)`)
	reJSONExtract  = regexp.MustCompile(`(?s)\{.*\}`)
	reStatus206    = regexp.MustCompile(` 206[^\r]*`)
)

// ─── buffer pools ─────────────────────────────────────────────────────────────

var (
	bufPool8k  = sync.Pool{New: func() any { b := make([]byte, 8192);  return &b }}
	bufPool64k = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)

// ─── pooled connection ────────────────────────────────────────────────────────

type poolConn struct {
	conn    net.Conn
	created time.Time
}

// ─── Fronter ─────────────────────────────────────────────────────────────────

// Fronter manages connection pooling and relaying through Google Apps Script.
type Fronter struct {
	// Dial config
	connectAddr string // host:443 to TCP-dial (the Google IP)
	sniHost     string // TLS SNI (www.google.com)
	httpHost    string // HTTP Host header (script.google.com)
	verifySSL   bool

	// Script IDs
	scriptIDs []string
	scriptIdx uint64 // atomic round-robin

	// Auth
	authKey string

	// Connection pool
	mu              sync.Mutex
	pool            []poolConn
	poolMax         int
	connTTL         time.Duration
	tlsSessionCache tls.ClientSessionCache

	// Concurrency limit
	sem chan struct{}

	// Batch collector
	batchMu      sync.Mutex
	batchPending []batchItem
	batchTimer   *time.Timer
	batchEnabled bool // disabled if server doesn't support batch

	// Request coalescing (dedup identical GETs)
	coalesceMu sync.Mutex
	coalesce   map[string][]chan coalesceResult
}

type batchItem struct {
	payload map[string]interface{}
	result  chan batchResult
}

type batchResult struct {
	resp []byte
	err  error
}

type coalesceResult struct {
	resp []byte
	err  error
}

// Config for constructing a Fronter.
type Config struct {
	ConnectAddr string // "IP:port"
	SNIHost     string
	HTTPHost    string
	AuthKey     string
	ScriptIDs   []string
	VerifySSL   bool
	PoolMax     int
	ConnTTL     time.Duration
}

// New creates a Fronter with an initialized connection pool.
func New(cfg Config) *Fronter {
	if cfg.PoolMax == 0 {
		cfg.PoolMax = 50
	}
	if cfg.ConnTTL == 0 {
		cfg.ConnTTL = 45 * time.Second
	}
	f := &Fronter{
		connectAddr:     cfg.ConnectAddr,
		sniHost:         cfg.SNIHost,
		httpHost:        cfg.HTTPHost,
		authKey:         cfg.AuthKey,
		scriptIDs:       cfg.ScriptIDs,
		verifySSL:       cfg.VerifySSL,
		poolMax:         cfg.PoolMax,
		connTTL:         cfg.ConnTTL,
		tlsSessionCache: tls.NewLRUClientSessionCache(64),
		sem:             make(chan struct{}, 50),
		batchEnabled:    true,
		coalesce:        make(map[string][]chan coalesceResult),
	}
	// Pre-fill semaphore capacity
	for i := 0; i < 50; i++ {
		f.sem <- struct{}{}
	}
	go f.poolMaintenance()
	go f.warmPool(30)
	return f
}

// ─── TLS dialing ─────────────────────────────────────────────────────────────

func (f *Fronter) dial() (net.Conn, error) {
	tlsCfg := &tls.Config{
		ServerName:         f.sniHost,
		ClientSessionCache: f.tlsSessionCache,
	}
	if !f.verifySSL {
		tlsCfg.InsecureSkipVerify = true
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", f.connectAddr, tlsCfg)
}

// ─── Connection pool ──────────────────────────────────────────────────────────

func (f *Fronter) acquire() (net.Conn, time.Time, error) {
	now := time.Now()
	f.mu.Lock()
	for len(f.pool) > 0 {
		pc := f.pool[len(f.pool)-1]
		f.pool = f.pool[:len(f.pool)-1]
		f.mu.Unlock()
		if now.Sub(pc.created) < f.connTTL {
			go f.addToPool() // eagerly replace
			return pc.conn, pc.created, nil
		}
		pc.conn.Close()
		f.mu.Lock()
	}
	f.mu.Unlock()

	conn, err := f.dial()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("dial: %w", err)
	}
	go f.refillPool(8)
	return conn, time.Now(), nil
}

func (f *Fronter) release(conn net.Conn, created time.Time) {
	if time.Since(created) >= f.connTTL {
		conn.Close()
		return
	}
	f.mu.Lock()
	if len(f.pool) < f.poolMax {
		f.pool = append(f.pool, poolConn{conn, created})
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	conn.Close()
}

func (f *Fronter) addToPool() {
	conn, err := f.dial()
	if err != nil {
		return
	}
	f.mu.Lock()
	if len(f.pool) < f.poolMax {
		f.pool = append(f.pool, poolConn{conn, time.Now()})
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()
	conn.Close()
}

func (f *Fronter) refillPool(n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.addToPool() }()
	}
	wg.Wait()
}

func (f *Fronter) warmPool(n int) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); f.addToPool() }()
	}
	wg.Wait()
	log.Printf("[Relay] Pool warm with %d connections", len(f.pool))
}

func (f *Fronter) poolMaintenance() {
	for {
		time.Sleep(5 * time.Second)
		now := time.Now()
		f.mu.Lock()
		alive := f.pool[:0]
		for _, pc := range f.pool {
			if now.Sub(pc.created) < f.connTTL {
				alive = append(alive, pc)
			} else {
				pc.conn.Close()
			}
		}
		f.pool = alive
		idle := len(f.pool)
		f.mu.Unlock()

		needed := 15 - idle
		if needed > 0 {
			go f.refillPool(min(needed, 5))
		}
	}
}

func (f *Fronter) flushPool() {
	f.mu.Lock()
	for _, pc := range f.pool {
		pc.conn.Close()
	}
	f.pool = f.pool[:0]
	f.mu.Unlock()
}

// ─── Script ID selection ──────────────────────────────────────────────────────

func (f *Fronter) nextScriptID() string {
	idx := atomic.AddUint64(&f.scriptIdx, 1) - 1
	return f.scriptIDs[int(idx)%len(f.scriptIDs)]
}

func (f *Fronter) execPath(urlOrHost string) string {
	sid := f.nextScriptID()
	return fmt.Sprintf("/macros/s/%s/exec", sid)
}

// ─── Public relay API ─────────────────────────────────────────────────────────

// Relay relays an HTTP request through Apps Script.
// Returns a raw HTTP/1.1 response (status line + headers + body).
func (f *Fronter) Relay(ctx context.Context, method, url string, headers map[string]string, body []byte) ([]byte, error) {
	payload := f.buildPayload(method, url, headers, body)

	if isStatefulRequest(method, url, headers, body) {
		return f.relayWithRetry(ctx, payload)
	}

	// Coalesce identical GETs (no Range header)
	if method == "GET" && len(body) == 0 && headerValue(headers, "range") == "" {
		return f.coalesceSubmit(ctx, url, payload)
	}

	return f.batchSubmit(ctx, payload)
}

// RelayParallel relays large downloads using parallel range requests.
func (f *Fronter) RelayParallel(ctx context.Context, method, url string, headers map[string]string, body []byte) ([]byte, error) {
	if method != "GET" || len(body) > 0 {
		return f.Relay(ctx, method, url, headers, body)
	}

	const chunkSize = 256 * 1024

	rangeHeaders := make(map[string]string)
	for k, v := range headers {
		rangeHeaders[k] = v
	}
	rangeHeaders["Range"] = fmt.Sprintf("bytes=0-%d", chunkSize-1)

	firstResp, err := f.Relay(ctx, "GET", url, rangeHeaders, nil)
	if err != nil {
		return nil, err
	}

	status, respHdrs, respBody := splitHTTPResponse(firstResp)
	if status != 206 {
		return firstResp, nil
	}

	cr := respHdrs["content-range"]
	m := reContentRange.FindStringSubmatch(cr)
	if m == nil {
		return rewrite206to200(firstResp), nil
	}
	totalSize, _ := strconv.Atoi(m[1])
	if totalSize <= chunkSize || len(respBody) >= totalSize {
		return rewrite206to200(firstResp), nil
	}

	type rangeChunk struct {
		start, end int
	}
	var ranges []rangeChunk
	start := len(respBody)
	for start < totalSize {
		end := start + chunkSize - 1
		if end >= totalSize {
			end = totalSize - 1
		}
		ranges = append(ranges, rangeChunk{start, end})
		start = end + 1
	}

	log.Printf("[Relay] Parallel download: %d B, %d chunks", totalSize, len(ranges)+1)

	sem := make(chan struct{}, 16)
	type chunkResult struct {
		idx  int
		data []byte
		err  error
	}
	results := make([]chunkResult, len(ranges))
	var wg sync.WaitGroup
	for i, r := range ranges {
		wg.Add(1)
		go func(i int, s, e int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rh := make(map[string]string)
			for k, v := range headers {
				rh[k] = v
			}
			rh["Range"] = fmt.Sprintf("bytes=%d-%d", s, e)
			raw, err := f.Relay(ctx, "GET", url, rh, nil)
			if err != nil {
				results[i] = chunkResult{i, nil, err}
				return
			}
			_, _, chunkBody := splitHTTPResponse(raw)
			results[i] = chunkResult{i, chunkBody, nil}
		}(i, r.start, r.end)
	}
	wg.Wait()

	parts := [][]byte{respBody}
	for _, r := range results {
		if r.err != nil {
			return errorResponse(502, fmt.Sprintf("Parallel download failed: %v", r.err)), nil
		}
		parts = append(parts, r.data)
	}
	fullBody := bytes.Join(parts, nil)

	var sb strings.Builder
	sb.WriteString("HTTP/1.1 200 OK\r\n")
	skip := map[string]bool{"transfer-encoding": true, "connection": true, "keep-alive": true,
		"content-length": true, "content-encoding": true, "content-range": true}
	for k, v := range respHdrs {
		if !skip[strings.ToLower(k)] {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(fullBody))
	return append([]byte(sb.String()), fullBody...), nil
}

// ─── Coalescing ───────────────────────────────────────────────────────────────

func (f *Fronter) coalesceSubmit(ctx context.Context, url string, payload map[string]interface{}) ([]byte, error) {
	f.coalesceMu.Lock()
	waiters, existing := f.coalesce[url]
	ch := make(chan coalesceResult, 1)
	if existing {
		f.coalesce[url] = append(waiters, ch)
		f.coalesceMu.Unlock()
		select {
		case r := <-ch:
			return r.resp, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.coalesce[url] = []chan coalesceResult{}
	f.coalesceMu.Unlock()

	resp, err := f.batchSubmit(ctx, payload)

	f.coalesceMu.Lock()
	waiters = f.coalesce[url]
	delete(f.coalesce, url)
	f.coalesceMu.Unlock()

	for _, w := range waiters {
		w <- coalesceResult{resp, err}
	}
	return resp, err
}

// ─── Batch collector ──────────────────────────────────────────────────────────

func (f *Fronter) batchSubmit(ctx context.Context, payload map[string]interface{}) ([]byte, error) {
	if !f.batchEnabled {
		return f.relayWithRetry(ctx, payload)
	}

	ch := make(chan batchResult, 1)
	item := batchItem{payload: payload, result: ch}

	f.batchMu.Lock()
	f.batchPending = append(f.batchPending, item)
	if len(f.batchPending) >= 50 {
		batch := f.batchPending
		f.batchPending = nil
		if f.batchTimer != nil {
			f.batchTimer.Stop()
			f.batchTimer = nil
		}
		f.batchMu.Unlock()
		go f.batchSend(ctx, batch)
	} else if f.batchTimer == nil {
		f.batchTimer = time.AfterFunc(5*time.Millisecond, func() {
			f.triggerBatch(ctx)
		})
		f.batchMu.Unlock()
	} else {
		f.batchMu.Unlock()
	}

	select {
	case r := <-ch:
		return r.resp, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (f *Fronter) triggerBatch(ctx context.Context) {
	// Two-tier: if burst, wait additional 45ms
	f.batchMu.Lock()
	if len(f.batchPending) > 1 {
		f.batchTimer = time.AfterFunc(45*time.Millisecond, func() {
			f.flushBatch(ctx)
		})
		f.batchMu.Unlock()
		return
	}
	f.flushBatchLocked(ctx)
}

func (f *Fronter) flushBatch(ctx context.Context) {
	f.batchMu.Lock()
	f.flushBatchLocked(ctx)
}

func (f *Fronter) flushBatchLocked(ctx context.Context) {
	batch := f.batchPending
	f.batchPending = nil
	f.batchTimer = nil
	f.batchMu.Unlock()
	if len(batch) > 0 {
		go f.batchSend(ctx, batch)
	}
}

func (f *Fronter) batchSend(ctx context.Context, batch []batchItem) {
	if len(batch) == 1 {
		resp, err := f.relayWithRetry(ctx, batch[0].payload)
		batch[0].result <- batchResult{resp, err}
		return
	}

	log.Printf("[Relay] Batch relay: %d requests", len(batch))
	payloads := make([]map[string]interface{}, len(batch))
	for i, it := range batch {
		payloads[i] = it.payload
	}

	results, err := f.relayBatch(ctx, payloads)
	if err != nil {
		log.Printf("[Relay] Batch failed, disabling. Error: %v", err)
		f.batchEnabled = false
		// Fallback: relay individually
		var wg sync.WaitGroup
		for _, it := range batch {
			wg.Add(1)
			go func(it batchItem) {
				defer wg.Done()
				resp, err := f.relayWithRetry(ctx, it.payload)
				it.result <- batchResult{resp, err}
			}(it)
		}
		wg.Wait()
		return
	}

	for i, it := range batch {
		it.result <- batchResult{results[i], nil}
	}
}

// ─── Core relay (single + retry) ─────────────────────────────────────────────

func (f *Fronter) relayWithRetry(ctx context.Context, payload map[string]interface{}) ([]byte, error) {
	<-f.sem
	defer func() { f.sem <- struct{}{} }()

	for attempt := 0; attempt < 2; attempt++ {
		resp, err := f.relaySingle(ctx, payload)
		if err == nil {
			return resp, nil
		}
		if attempt == 0 {
			log.Printf("[Relay] Attempt 1 failed (%v), retrying", err)
			f.flushPool()
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("relay failed after 2 attempts")
}

func (f *Fronter) relaySingle(ctx context.Context, payload map[string]interface{}) ([]byte, error) {
	full := make(map[string]interface{}, len(payload)+1)
	for k, v := range payload {
		full[k] = v
	}
	full["k"] = f.authKey

	jsonBody, err := json.Marshal(full)
	if err != nil {
		return nil, err
	}

	path := f.execPath(stringFromMap(payload, "u"))
	conn, created, err := f.acquire()
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	bw := bufio.NewWriterSize(conn, len(jsonBody)+512)
	fmt.Fprintf(bw, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
		path, f.httpHost, len(jsonBody))
	bw.Write(jsonBody)
	if err := bw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write: %w", err)
	}

	status, respHdrs, respBody, err := readHTTPResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Follow redirect chain
	for i := 0; i < 5; i++ {
		if status < 301 || status > 308 {
			break
		}
		location := respHdrs["location"]
		if location == "" {
			break
		}
		var rmethod, rbody string
		var rbodyBytes []byte
		if status == 307 || status == 308 {
			rmethod = "POST"
			rbodyBytes = jsonBody
			rbody = fmt.Sprintf("Content-Length: %d\r\n", len(jsonBody))
		} else {
			rmethod = "GET"
		}
		rpath := pathFromURL(location)
		rhost := hostFromURL(location)
		if rhost == "" {
			rhost = f.httpHost
		}
		rreq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n%s\r\n",
			rmethod, rpath, rhost, rbody)
		conn.SetDeadline(time.Now().Add(25 * time.Second))
		if _, err := conn.Write(append([]byte(rreq), rbodyBytes...)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("write redirect: %w", err)
		}
		status, respHdrs, respBody, err = readHTTPResponse(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read redirect: %w", err)
		}
	}

	f.release(conn, created)
	return parseRelayResponse(respBody)
}

func (f *Fronter) relayBatch(ctx context.Context, payloads []map[string]interface{}) ([][]byte, error) {
	batchPayload := map[string]interface{}{
		"k": f.authKey,
		"q": payloads,
	}
	jsonBody, err := json.Marshal(batchPayload)
	if err != nil {
		return nil, err
	}

	path := f.execPath("")
	<-f.sem
	defer func() { f.sem <- struct{}{} }()

	conn, created, err := f.acquire()
	if err != nil {
		return nil, err
	}

	conn.SetDeadline(time.Now().Add(35 * time.Second))
	bw := bufio.NewWriterSize(conn, len(jsonBody)+512)
	fmt.Fprintf(bw, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n",
		path, f.httpHost, len(jsonBody))
	bw.Write(jsonBody)
	if err := bw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write batch: %w", err)
	}

	status, respHdrs, respBody, err := readHTTPResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read batch: %w", err)
	}
	// Follow redirects
	for i := 0; i < 5; i++ {
		if status < 301 || status > 308 {
			break
		}
		location := respHdrs["location"]
		if location == "" {
			break
		}
		var rmethod string
		var rbodyBytes []byte
		var rbody string
		if status == 307 || status == 308 {
			rmethod, rbodyBytes = "POST", jsonBody
			rbody = fmt.Sprintf("Content-Length: %d\r\n", len(jsonBody))
		} else {
			rmethod = "GET"
		}
		rpath := pathFromURL(location)
		rhost := hostFromURL(location)
		if rhost == "" {
			rhost = f.httpHost
		}
		rreq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip\r\nConnection: keep-alive\r\n%s\r\n",
			rmethod, rpath, rhost, rbody)
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(append([]byte(rreq), rbodyBytes...)); err != nil {
			conn.Close()
			return nil, fmt.Errorf("write batch redirect: %w", err)
		}
		status, respHdrs, respBody, err = readHTTPResponse(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read batch redirect: %w", err)
		}
	}

	f.release(conn, created)
	return parseBatchBody(respBody, payloads)
}

// ─── Payload builder ──────────────────────────────────────────────────────────

func (f *Fronter) buildPayload(method, url string, headers map[string]string, body []byte) map[string]interface{} {
	payload := map[string]interface{}{
		"m": method,
		"u": url,
		"r": false,
	}
	if len(headers) > 0 {
		filt := make(map[string]string, len(headers))
		for k, v := range headers {
			if strings.ToLower(k) != "accept-encoding" {
				filt[k] = v
			}
		}
		payload["h"] = filt
	}
	if len(body) > 0 {
		payload["b"] = base64.StdEncoding.EncodeToString(body)
		if ct := headerValue(headers, "content-type"); ct != "" {
			payload["ct"] = ct
		}
	}
	return payload
}

// ─── HTTP response reader ─────────────────────────────────────────────────────

func readHTTPResponse(conn net.Conn) (status int, headers map[string]string, body []byte, err error) {
	buf := make([]byte, 0, 8192)
	tmpPtr := bufPool8k.Get().(*[]byte)
	tmp := *tmpPtr
	defer bufPool8k.Put(tmpPtr)
	headers = make(map[string]string)

	// Read until we have the header section
	for !bytes.Contains(buf, []byte("\r\n\r\n")) {
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		n, e := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if e != nil {
			if len(buf) > 0 {
				break
			}
			return 0, headers, nil, fmt.Errorf("read header: %w", e)
		}
		if len(buf) > 65536 {
			return 0, headers, nil, fmt.Errorf("header too large")
		}
	}

	sep := bytes.Index(buf, []byte("\r\n\r\n"))
	if sep < 0 {
		return 0, headers, nil, fmt.Errorf("no header end")
	}
	headerSection := buf[:sep]
	body = buf[sep+4:]

	lines := bytes.Split(headerSection, []byte("\r\n"))
	if len(lines) == 0 {
		return 0, headers, nil, fmt.Errorf("empty response")
	}
	if m := reStatusCode.Find(lines[0]); m != nil {
		status, _ = strconv.Atoi(string(m))
	}
	for _, line := range lines[1:] {
		if idx := bytes.IndexByte(line, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(string(line[:idx])))
			v := strings.TrimSpace(string(line[idx+1:]))
			headers[k] = v
		}
	}

	// Read body
	if te := headers["transfer-encoding"]; strings.Contains(te, "chunked") {
		body, err = readChunked(conn, body)
		if err != nil {
			return status, headers, nil, err
		}
	} else if cl := headers["content-length"]; cl != "" {
		remaining, _ := strconv.Atoi(cl)
		remaining -= len(body)
		if remaining > 0 {
			chunkPtr := bufPool64k.Get().(*[]byte)
			chunk := *chunkPtr
			for remaining > 0 {
				conn.SetDeadline(time.Now().Add(20 * time.Second))
				size := remaining
				if size > 65536 {
					size = 65536
				}
				n, e := conn.Read(chunk[:size])
				if n > 0 {
					body = append(body, chunk[:n]...)
					remaining -= n
				}
				if e != nil {
					break
				}
			}
			bufPool64k.Put(chunkPtr)
		}
	}

	// Decompress
	if headers["content-encoding"] == "gzip" {
		r, e2 := gzip.NewReader(bytes.NewReader(body))
		if e2 == nil {
			dec, e3 := io.ReadAll(r)
			if e3 == nil {
				body = dec
			}
		}
	}
	return
}

func readChunked(conn net.Conn, initial []byte) ([]byte, error) {
	buf := initial
	result := make([]byte, 0, len(initial))
	const maxBody = 200 * 1024 * 1024

	for {
		// Find chunk size line
		for !bytes.Contains(buf, []byte("\r\n")) {
			tmp := make([]byte, 8192)
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			n, e := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if e != nil {
				return result, nil
			}
		}

		lineEnd := bytes.Index(buf, []byte("\r\n"))
		sizeStr := strings.TrimSpace(string(buf[:lineEnd]))
		buf = buf[lineEnd+2:]

		size, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil || size == 0 {
			break
		}
		if int(size) > maxBody || len(result)+int(size) > maxBody {
			break
		}

		for int64(len(buf)) < size+2 {
			tmp := make([]byte, 65536)
			conn.SetDeadline(time.Now().Add(20 * time.Second))
			n, e := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if e != nil {
				result = append(result, buf[:min64(int64(len(buf)), size)]...)
				return result, nil
			}
		}
		result = append(result, buf[:size]...)
		buf = buf[size+2:] // skip trailing \r\n
	}
	return result, nil
}

// ─── Response parsing ─────────────────────────────────────────────────────────

func parseRelayResponse(body []byte) ([]byte, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return errorResponse(502, "Empty response from relay"), nil
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		// Try to extract JSON
		m := reJSONExtract.FindString(text)
		if m == "" {
			return errorResponse(502, fmt.Sprintf("No JSON: %.200s", text)), nil
		}
		if err2 := json.Unmarshal([]byte(m), &data); err2 != nil {
			return errorResponse(502, fmt.Sprintf("Bad JSON: %.200s", text)), nil
		}
	}

	return parseRelayJSON(data), nil
}

func parseBatchBody(body []byte, payloads []map[string]interface{}) ([][]byte, error) {
	text := strings.TrimSpace(string(body))
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		m := reJSONExtract.FindString(text)
		if m == "" {
			return nil, fmt.Errorf("bad batch response: %.200s", text)
		}
		if err2 := json.Unmarshal([]byte(m), &data); err2 != nil {
			return nil, fmt.Errorf("bad batch JSON: %.200s", text)
		}
	}

	if e, ok := data["e"]; ok {
		return nil, fmt.Errorf("batch error: %v", e)
	}

	items, _ := data["q"].([]interface{})
	if len(items) != len(payloads) {
		return nil, fmt.Errorf("batch size mismatch: %d vs %d", len(items), len(payloads))
	}

	results := make([][]byte, len(items))
	for i, item := range items {
		m, _ := item.(map[string]interface{})
		if m == nil {
			results[i] = errorResponse(502, "bad batch item")
			continue
		}
		results[i] = parseRelayJSON(m)
	}
	return results, nil
}

var statusTexts = map[int]string{
	200: "OK", 204: "No Content", 206: "Partial Content",
	301: "Moved Permanently", 302: "Found", 303: "See Other",
	304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
	400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
	404: "Not Found", 405: "Method Not Allowed", 429: "Too Many Requests",
	500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}

func parseRelayJSON(data map[string]interface{}) []byte {
	if e, ok := data["e"]; ok {
		return errorResponse(502, fmt.Sprintf("Relay error: %v", e))
	}

	status := 200
	if s, ok := data["s"]; ok {
		switch v := s.(type) {
		case float64:
			status = int(v)
		case int:
			status = v
		}
	}

	respHdrs, _ := data["h"].(map[string]interface{})
	bodyB64, _ := data["b"].(string)
	respBody, _ := base64.StdEncoding.DecodeString(bodyB64)

	txt := statusTexts[status]
	if txt == "" {
		txt = "OK"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", status, txt)

	skipHdrs := map[string]bool{
		"transfer-encoding": true, "connection": true,
		"keep-alive": true, "content-length": true, "content-encoding": true,
	}
	for k, v := range respHdrs {
		if skipHdrs[strings.ToLower(k)] {
			continue
		}
		switch val := v.(type) {
		case string:
			if strings.ToLower(k) == "set-cookie" {
				for _, part := range splitSetCookie(val) {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, part)
				}
			} else {
				fmt.Fprintf(&sb, "%s: %s\r\n", k, val)
			}
		case []interface{}:
			for _, item := range val {
				s := fmt.Sprintf("%v", item)
				if strings.ToLower(k) == "set-cookie" {
					for _, part := range splitSetCookie(s) {
						fmt.Fprintf(&sb, "%s: %s\r\n", k, part)
					}
				} else {
					fmt.Fprintf(&sb, "%s: %s\r\n", k, s)
				}
			}
		default:
			fmt.Fprintf(&sb, "%s: %v\r\n", k, v)
		}
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(respBody))
	return append([]byte(sb.String()), respBody...)
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func splitHTTPResponse(raw []byte) (status int, headers map[string]string, body []byte) {
	headers = make(map[string]string)
	sep := bytes.Index(raw, []byte("\r\n\r\n"))
	if sep < 0 {
		return 0, headers, raw
	}
	headerSection := raw[:sep]
	body = raw[sep+4:]
	lines := bytes.Split(headerSection, []byte("\r\n"))
	if m := reStatusCode.Find(lines[0]); m != nil {
		status, _ = strconv.Atoi(string(m))
	}
	for _, line := range lines[1:] {
		if idx := bytes.IndexByte(line, ':'); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(string(line[:idx])))
			v := strings.TrimSpace(string(line[idx+1:]))
			headers[k] = v
		}
	}
	return
}

func rewrite206to200(raw []byte) []byte {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return raw
	}
	headerSection := string(raw[:idx])
	body := raw[idx+4:]
	lines := strings.Split(headerSection, "\r\n")
	if len(lines) > 0 && strings.Contains(lines[0], " 206") {
		lines[0] = reStatus206.ReplaceAllString(lines[0], " 200 OK")
	}
	filtered := []string{lines[0]}
	for _, ln := range lines[1:] {
		low := strings.ToLower(ln)
		if strings.HasPrefix(low, "content-range:") || strings.HasPrefix(low, "content-length:") {
			continue
		}
		filtered = append(filtered, ln)
	}
	filtered = append(filtered, fmt.Sprintf("Content-Length: %d", len(body)))
	return append([]byte(strings.Join(filtered, "\r\n")+"\r\n\r\n"), body...)
}

func errorResponse(status int, message string) []byte {
	body := fmt.Sprintf("<html><body><h1>%d</h1><p>%s</p></body></html>", status, message)
	return []byte(fmt.Sprintf("HTTP/1.1 %d Error\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s",
		status, len(body), body))
}

func isStatefulRequest(method, url string, headers map[string]string, body []byte) bool {
	method = strings.ToUpper(method)
	if method != "GET" && method != "HEAD" || len(body) > 0 {
		return true
	}
	for k, v := range headers {
		switch strings.ToLower(k) {
		case "cookie", "authorization", "proxy-authorization", "origin", "referer",
			"if-none-match", "if-modified-since", "cache-control", "pragma":
			if v != "" {
				return true
			}
		case "accept":
			vl := strings.ToLower(v)
			if strings.Contains(vl, "text/html") || strings.Contains(vl, "application/json") {
				return true
			}
		case "sec-fetch-mode":
			vl := strings.ToLower(v)
			if vl == "navigate" || vl == "cors" {
				return true
			}
		}
	}
	return !isStaticAssetURL(url)
}

func isStaticAssetURL(url string) bool {
	path := strings.ToLower(strings.SplitN(url, "?", 2)[0])
	for _, ext := range staticExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// IsLikelyDownload heuristically decides if a URL is a large file.
func IsLikelyDownload(url string) bool {
	path := strings.ToLower(strings.SplitN(url, "?", 2)[0])
	for _, ext := range largeExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// headerValue returns the header value for the given lowercase key.
// All header maps in this package store keys in lowercase.
func headerValue(headers map[string]string, name string) string {
	return headers[name]
}

func stringFromMap(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

// tokenChar returns true for characters that can start a cookie name per RFC 6265.
func tokenChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' ||
		c == '*' || c == '+' || c == '-' || c == '.' || c == '^' || c == '_' ||
		c == '`' || c == '|' || c == '~'
}

// splitSetCookie splits a Set-Cookie string that may contain multiple cookies joined by ", ".
// Splits only on ", " when the next text looks like "token=" (cookie name=value pair).
func splitSetCookie(blob string) []string {
	if blob == "" {
		return nil
	}
	var parts []string
	start := 0
	for i := 0; i < len(blob)-1; i++ {
		if blob[i] != ',' {
			continue
		}
		// Skip optional whitespace
		j := i + 1
		for j < len(blob) && blob[j] == ' ' {
			j++
		}
		// Check if what follows is token=...
		k := j
		for k < len(blob) && tokenChar(blob[k]) {
			k++
		}
		if k > j && k < len(blob) && blob[k] == '=' {
			parts = append(parts, strings.TrimSpace(blob[start:i]))
			start = j
			i = j - 1 // continue from j
		}
	}
	parts = append(parts, strings.TrimSpace(blob[start:]))
	result := parts[:0]
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func pathFromURL(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[slash:]
		}
		return "/"
	}
	return rawURL
}

func hostFromURL(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
