# Performance Improvement Plan — v0.2.0 → v1.0.0

> Version: 0.1.0 baseline
> Date: April 2026

This document is the complete, prioritised roadmap for improving throughput and latency on both the **Go client** and the **Apps Script server**. Each item has an estimated impact rating (🔴 High / 🟡 Medium / 🟢 Low) and a target version.

---

## Table of Contents

1. [Baseline Bottlenecks](#1-baseline-bottlenecks)
2. [v0.2.0 — Quick Wins (no protocol changes)](#2-v020--quick-wins)
3. [v0.3.0 — Protocol & Server Improvements](#3-v030--protocol--server)
4. [v0.4.0 — HTTP/2 Multiplexing](#4-v040--http2-multiplexing)
5. [v1.0.0 — Binary Protocol & Streaming](#5-v100--binary-protocol--streaming)
6. [Implementation Order Cheatsheet](#6-implementation-order)

---

## 1. Baseline Bottlenecks

### What a single request costs today

```
Browser → CONNECT → proxy (MITM TLS) → batch window (5–50ms) →
  pick conn from pool → write JSON (base64 encoded body) →
  read chunked HTTP response → JSON parse → base64 decode body →
  reconstruct HTTP response → send to browser
```

Key costs per relay hop:

| Step | Cost | Issue |
|------|------|-------|
| Batch window | 5–50 ms | Fixed delay on every request |
| Pool acquire | 0–10 ms | Lock contention; cold-miss dial is 100–300 ms |
| TLS dial (cold) | 100–300 ms | No session resumption |
| JSON marshal | ~5 µs | Acceptable but allocates |
| base64 body encode | ~2–20 µs | Wasted CPU; base64 inflates payload 33% |
| Network RTT | 20–100 ms | Unavoidable (GCP latency) |
| JSON parse response | ~10–50 µs | Allocations on every call |
| Apps Script batch (server) | **sequential** | Each batched URL fetched one at a time |
| Buffer allocations | Every call | `make([]byte, 65536)` x N, no pooling |
| Regexp compile | Every call | 4 regexps inside hot paths |

### Most impactful single change: Apps Script `fetchAll()`

The Apps Script relay currently calls `UrlFetchApp.fetch()` for **each item in a batch sequentially**. Switching to `UrlFetchApp.fetchAll()` fetches all URLs in parallel on Google's infrastructure — this is the biggest single throughput gain available.

---

## 2. v0.2.0 — Quick Wins

Pure client-side changes, no protocol or server changes needed.

### 2.1 🔴 Pre-compile all regexps

**Problem:** Four `regexp.MustCompile(...)` calls inside hot functions (`readHTTPResponse`, `splitHTTPResponse`, `rewrite206to200`, `parseBatchBody`, `parseRelayResponse`) are re-compiled on every invocation.

**Fix:** Move to package-level `var`:

```go
// relay/fronter.go — top of file
var (
    reStatusCode  = regexp.MustCompile(`\d{3}`)
    reContentRange = regexp.MustCompile(`/(\d+)`)
    reJSONExtract  = regexp.MustCompile(`\{.*\}`)
    reStatus206    = regexp.MustCompile(` 206[^\r]*`)
    reMaxAge       = regexp.MustCompile(`max-age=(\d+)`)
)
```

**Effort:** 30 min
**Impact:** Eliminates ~4 allocations + GC pressure per request, measurable at high concurrency.

---

### 2.2 🔴 Buffer pools with `sync.Pool`

**Problem:** Every `readHTTPResponse`, `readChunked`, and `pipe()` call allocates fresh `[]byte` buffers of 8 KB and 64 KB.

**Fix:**

```go
var (
    buf8k  = sync.Pool{New: func() any { b := make([]byte, 8192);  return &b }}
    buf64k = sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}
)
```

Use in `readHTTPResponse`:
```go
tmp := buf8k.Get().(*[]byte)
defer buf8k.Put(tmp)
n, e := conn.Read(*tmp)
```

And in `doDirectTunnel` / `doSNIRewriteTunnel` pipe functions.

**Effort:** 2 hours
**Impact:** 🔴 Significant GC pressure reduction at high concurrency. Reduces heap churn by ~30%.

---

### 2.3 🔴 TLS session resumption (session tickets cache)

**Problem:** Every new connection does a full TLS 1.3 handshake (~2 RTTs, ~100–200 ms). Even with the pool, cold connections (after TTL expiry, pool drain, startup) pay this cost.

**Fix:** Add a shared session cache to `tls.Config`:

```go
// In Fronter struct:
tlsSessionCache tls.ClientSessionCache

// In New():
f.tlsSessionCache = tls.NewLRUClientSessionCache(64)

// In dial():
tlsCfg := &tls.Config{
    ServerName:         f.sniHost,
    ClientSessionCache: f.tlsSessionCache,  // ← add this
    InsecureSkipVerify: !f.verifySSL,
}
```

TLS 1.3 0-RTT or 1-RTT resumption cuts cold-dial cost from ~200 ms to ~50 ms.

**Effort:** 15 min
**Impact:** 🔴 Every cold connection is 100–150 ms faster.

---

### 2.4 🟡 Normalise header keys at parse time

**Problem:** `headerValue()` does a case-insensitive linear scan of every header key on every call. At 10 calls per request this is O(n) × O(calls).

**Fix:** In `parseHeaders()`, store keys in lowercase immediately:
```go
k := strings.ToLower(strings.TrimSpace(string(line[:idx])))
```
Then `headerValue()` becomes an O(1) map lookup:
```go
func headerValue(headers map[string]string, name string) string {
    return headers[name] // name is already lowercase at call sites
}
```

**Effort:** 1 hour
**Impact:** 🟡 Removes repeated string allocations in hot request path.

---

### 2.5 🟡 Coalesced write with `bufio.Writer`

**Problem:** `relaySingle` sends the HTTP request as two separate `conn.Write()` calls (header string + body bytes). Each write causes a syscall.

**Fix:**
```go
bw := bufio.NewWriterSize(conn, 4096)
bw.WriteString(req)
bw.Write(jsonBody)
bw.Flush()
```

**Effort:** 30 min
**Impact:** 🟡 Halves syscalls for every relay request.

---

### 2.6 🟡 Proper LRU eviction in response cache

**Problem:** `responseCache.put()` evicts by ranging over a Go map (random iteration order) and deleting the first item found. This is not LRU — it evicts randomly.

**Fix:** Replace with a doubly-linked list + map (standard LRU):

```go
import "container/list"

type responseCache struct {
    mu      sync.Mutex
    ll      *list.List
    items   map[string]*list.Element
    size    int
    maxSize int
    // stats...
}
```

Or use a battle-tested library: `github.com/hashicorp/golang-lru/v2`.

**Effort:** 2 hours
**Impact:** 🟡 Better cache hit rate for hot assets; avoids evicting recently-used entries.

---

### 2.7 🟢 Adaptive batch window

**Problem:** The two-tier window (5 ms fast, +45 ms slow) is fixed. At low load the 45 ms slow timer adds latency unnecessarily; at burst load 50 ms isn't enough.

**Fix:** Measure rolling average RTT and set window = `max(1ms, RTT * 0.1)`. When the pool signals it has spare connections (measured by semaphore backpressure), shrink the window; when all connections are busy, grow it.

**Effort:** 4 hours
**Impact:** 🟢 Latency improvement at low load; throughput improvement at high load.

---

### 2.8 🟢 Reduce `relayBatch` double semaphore

**Problem:** `relayBatch` calls `<-f.sem` *and* `f.acquire()` — the acquire also internally contends on the pool mutex. Under high concurrency this creates unnecessary serialisation.

**Fix:** Have `batchSend` not hold the semaphore for the batch collection phase — only acquire it just before the actual network write:

```go
func (f *Fronter) relayBatch(ctx context.Context, ...) {
    // build JSON...
    <-f.sem  // only here, right before network
    defer func() { f.sem <- struct{}{} }()
    conn, created, err := f.acquire()
    // ...
}
```

**Effort:** 1 hour
**Impact:** 🟢 Reduces lock contention at high concurrency.

---

## 3. v0.3.0 — Protocol & Server Improvements

### 3.1 🔴 Apps Script: use `UrlFetchApp.fetchAll()` for batch

**This is the biggest server-side win.**

**Problem:** The current `Code.gs` batch handler processes URLs with a loop calling `UrlFetchApp.fetch()` for each item. This is **sequential** — N requests take N × RTT time on the server.

**Fix:** Replace the loop with `UrlFetchApp.fetchAll()`:

```javascript
// Code.gs — in the batch handler
function handleBatch(items, authKey) {
  var requests = items.map(function(item) {
    return {
      url: item.u,
      method: item.m || 'GET',
      headers: item.h || {},
      payload: item.b ? Utilities.base64Decode(item.b) : undefined,
      muteHttpExceptions: true,
      followRedirects: true,
    };
  });

  var responses = UrlFetchApp.fetchAll(requests);  // ← parallel fetch

  return responses.map(function(resp, i) {
    return {
      s: resp.getResponseCode(),
      h: resp.getHeaders(),
      b: Utilities.base64Encode(resp.getContent())
    };
  });
}
```

**Effort:** 1 hour (server-side only, no Go changes)
**Impact:** 🔴 **Batch of 10 requests goes from 10× RTT to 1× RTT on the server.** This is the single highest-leverage change available.

---

### 3.2 🔴 Apps Script: server-side response caching with `CacheService`

**Problem:** Every request, even for the same static asset (`.js`, `.css`, `.png`), hits the origin server again from Apps Script.

**Fix:** Use Apps Script's built-in `CacheService` (TTL up to 6 hours, 100 KB per entry):

```javascript
function fetchWithCache(url, method, headers, body) {
  if (method !== 'GET' || body) return doFetch(url, method, headers, body);

  var cache = CacheService.getScriptCache();
  var key = 'r:' + Utilities.computeDigest(
    Utilities.DigestAlgorithm.MD5, url
  ).map(function(b) { return ('0' + (b & 0xff).toString(16)).slice(-2); }).join('');

  var cached = cache.get(key);
  if (cached) return JSON.parse(cached);

  var result = doFetch(url, method, headers, body);
  if (result.s === 200) {
    try { cache.put(key, JSON.stringify(result), 3600); } catch(e) {}
  }
  return result;
}
```

**Effort:** 2 hours (server-side only)
**Impact:** 🔴 Static assets are served from Google's RAM with ~5 ms added latency instead of a full origin fetch (~100–500 ms).

---

### 3.3 🔴 Gzip response compression from Apps Script

**Problem:** The Apps Script relay returns the response body as raw base64. For text responses (HTML, JSON, JS), this is 33% larger than necessary before base64.

**Fix:**
- Client sends `Accept-Encoding: gzip` in the relay payload
- Apps Script checks if origin returns gzip; if not, re-compresses with `Utilities.gzip()`
- Client already decompresses gzip in `readHTTPResponse`

For large text pages this reduces relay payload by **50–70%**, cutting transfer time proportionally.

**Effort:** 3 hours (server + minor client change)
**Impact:** 🔴 Major for text-heavy pages (news sites, SPAs, APIs).

---

### 3.4 🟡 Request body gzip compression (client → relay)

**Problem:** POST request bodies sent from the client to Apps Script are base64-encoded raw. For JSON API calls this adds 33% overhead.

**Fix:** In `buildPayload`, gzip the body before base64-encoding if `len(body) > 512`:

```go
func maybeGzip(b []byte) ([]byte, bool) {
    if len(b) < 512 { return b, false }
    var buf bytes.Buffer
    w := gzip.NewWriter(&buf)
    w.Write(b)
    w.Close()
    if buf.Len() < len(b) { return buf.Bytes(), true }
    return b, false
}
```

Add `"be": "gzip"` field to payload so Apps Script decodes before forwarding.

**Effort:** 2 hours
**Impact:** 🟡 Reduces upload size for JSON/form POST requests.

---

### 3.5 🟡 Multiple Google IPs (IP rotation)

**Problem:** All connections go to a single `google_ip`. If that IP is throttled or rate-limited, all traffic stalls.

**Fix:** Accept `google_ips` as a list in config. Round-robin dials across several known Google IPs:

```json
{
  "google_ips": [
    "216.239.38.120",
    "216.239.32.120",
    "216.239.34.120",
    "216.239.36.120"
  ]
}
```

**Effort:** 2 hours
**Impact:** 🟡 Increases raw bandwidth ceiling and resilience.

---

### 3.6 🟡 Prefetch DNS / IP for MITM targets

**Problem:** `doDirectTunnel` and `doSNIRewriteTunnel` do a fresh TCP dial on every request. For popular domains the lookup is cached by the OS, but cold lookups add latency.

**Fix:** Maintain a small in-memory DNS cache (TTL = 60s) for the top-N recently requested hosts. For MITM targets that repeat frequently (e.g., CDN origin, API servers), this eliminates OS resolver round-trips.

**Effort:** 3 hours
**Impact:** 🟡 ~5–30 ms saved per cold connection to a new host.

---

## 4. v0.4.0 — HTTP/2 Multiplexing

### 4.1 🔴 Use HTTP/2 for the relay connection

**Problem:** The current relay uses HTTP/1.1 keep-alive with a pool of 50 connections. Each request occupies a full connection. 50 is the concurrency ceiling.

**Fix:** Use HTTP/2, which multiplexes unlimited streams over a **single connection**:

- HTTP/2 eliminates Head-of-Line blocking at the connection level
- One connection replaces the 50-connection pool
- The `golang.org/x/net/http2` package is already in `go.mod`

```go
import "golang.org/x/net/http2"

// In Fronter:
transport := &http2.Transport{
    DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
        return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second},
            network, addr, cfg)
    },
    TLSClientConfig: &tls.Config{
        ServerName:         f.sniHost,
        ClientSessionCache: f.tlsSessionCache,
        InsecureSkipVerify: !f.verifySSL,
    },
}

client := &http.Client{Transport: transport}
```

This replaces the entire connection pool and raw socket management.

**Effort:** 1–2 days (significant refactor of `relaySingle` and `relayBatch`)
**Impact:** 🔴 **Eliminates the pool complexity entirely; concurrency is now limited only by the server-side Apps Script quota, not local connection count.**

---

### 4.2 🟡 Request pipelining within HTTP/2 streams

Once HTTP/2 is in place, the batch collector can submit all pending requests as independent HTTP/2 streams that are **automatically multiplexed** rather than assembled into a single giant JSON batch. This simplifies the batch logic and removes the batch assembly/parse overhead.

---

## 5. v1.0.0 — Binary Protocol & Streaming

### 5.1 🟡 MessagePack instead of JSON on the relay wire

**Problem:** JSON is human-readable but verbose. Every key name (`"method"`, `"headers"`, `"body"`) is repeated in full. For high-frequency small API requests, this overhead is measurable.

**Fix:** Use MessagePack (`vmihailenco/msgpack`) — ~30% smaller payload, ~3× faster encode/decode than `encoding/json`:

```go
import "github.com/vmihailenco/msgpack/v5"

data, err := msgpack.Marshal(payload)
```

Apps Script can decode MessagePack via a small JS library included in the script.

**Effort:** 1 day
**Impact:** 🟡 Reduces relay payload size by 25–35%; measurable at high request rates.

---

### 5.2 🟡 Streaming relay (chunked transfer directly to browser)

**Problem:** The proxy currently buffers the **entire** response body before writing it to the browser. Large responses (5 MB+ downloads, server-sent events, long JSON) have high time-to-first-byte.

**Fix:** Stream the body from the Apps Script response to the browser as it arrives using chunked transfer encoding. Requires the relay to return chunks rather than a complete payload.

This requires Apps Script to support streaming — which it doesn't natively, but you can use an iterative approach with multiple requests or integrate a Cloud Run sidecar.

**Effort:** 3–5 days
**Impact:** 🟡 Dramatically improves perceived performance on large pages; enables SSE/WebSockets via relay.

---

### 5.3 🟢 Connection-aware batch window (backpressure)

Replace the fixed batch timer with a **channel-backpressure-driven** scheduler: if the semaphore is fully drained (all 50 connections busy), wait; if there are idle connections, send immediately. This makes the batch window zero at low load and adaptive at high load.

---

## 6. Implementation Order

```
v0.2.0 (1–2 days of work)
  ✦ [2.1] Pre-compile regexps          — 30 min     🔴
  ✦ [2.3] TLS session resumption        — 15 min     🔴
  ✦ [2.2] sync.Pool for buffers         — 2 hr       🔴
  ✦ [2.4] Lowercase headers at parse    — 1 hr       🟡
  ✦ [2.5] Coalesced conn.Write()        — 30 min     🟡
  ✦ [2.6] Proper LRU cache             — 2 hr       🟡

v0.3.0 (3–4 days of work)
  ✦ [3.1] Apps Script fetchAll()        — 1 hr       🔴  ← highest ROI
  ✦ [3.2] Apps Script CacheService      — 2 hr       🔴
  ✦ [3.3] Gzip response compression     — 3 hr       🔴
  ✦ [3.4] Gzip request bodies           — 2 hr       🟡
  ✦ [3.5] Multiple Google IPs           — 2 hr       🟡
  ✦ [3.6] Client DNS cache             — 3 hr       🟡

v0.4.0 (2–3 days of work)
  ✦ [4.1] HTTP/2 relay transport        — 2 days     🔴
  ✦ [4.2] Drop batch, use H2 streams    — 1 day      🟡

v1.0.0
  ✦ [5.1] MessagePack wire format       — 1 day      🟡
  ✦ [5.2] Streaming relay               — 3–5 days   🟡
  ✦ [5.3] Backpressure batch window     — 4 hr       🟢
```

### Expected cumulative gains by version

| Version | Change | Latency | Throughput |
|---------|--------|---------|------------|
| v0.1.0 (baseline) | — | 150–400 ms/req | ~50 req/s |
| v0.2.0 | Quick wins (client) | -20–40 ms | +15% |
| v0.3.0 | fetchAll + gzip + cache | **-40–80% on cached/batched** | **+100–300%** |
| v0.4.0 | HTTP/2 multiplexing | -20 ms (pool overhead gone) | **+200%** (no conn ceiling) |
| v1.0.0 | Streaming + msgpack | -50–80 ms TTFB | +20% |

---

## Appendix: Key Files to Change

| Improvement | File |
|-------------|------|
| Regexp pre-compile, buffer pools | `relay/fronter.go` |
| TLS session cache | `relay/fronter.go` → `dial()` |
| Lowercase headers | `relay/fronter.go` → `parseHeaders`, `proxy/server.go` |
| LRU cache | `proxy/server.go` (new `lru.go`) |
| HTTP/2 transport | `relay/fronter.go` (major refactor) |
| Google IP rotation | `config/config.go`, `relay/fronter.go` |
| DNS cache | `proxy/server.go` (new `dnscache.go`) |
| fetchAll, CacheService, gzip | `Code.gs` (Apps Script — server only) |
