# Architecture

MasterHttpRelayVPN-go is a local proxy that tunnels all traffic through a **Google Apps Script relay** using domain-fronting, bypassing DPI/censorship without any VPN protocol or dedicated server.

---

## High-Level Flow

```
Client (browser/app)
        │
        │  HTTP CONNECT / plain HTTP / SOCKS5
        ▼
┌────────────────────┐
│  Local Proxy        │  :8085 (HTTP) and :1088 (SOCKS5)
│  proxy/server.go   │
└────────┬───────────┘
         │
    ┌────┴─────────────────────────────────────────┐
    │  Routing decision                             │
    │  • Direct tunnel   → www.google.com          │
    │  • SNI-rewrite     → youtube.com, gvt*.com … │
    │  • MITM + relay    → everything else          │
    └────┬───────────┬──────────────────────────────┘
         │           │
         │  MITM     │  MITM HTTPS
         │  tunnel   │  (intercept TLS, relay over HTTPS)
         ▼           ▼
┌────────────────────┐
│  Relay Engine       │  relay/fronter.go
│  (domain-fronting) │
└────────┬───────────┘
         │
         │  TCP → 216.239.38.120:443
         │  TLS SNI = www.google.com   ← ISP/DPI sees this
         │  HTTP Host = script.google.com
         │  POST /macros/s/{scriptID}/exec
         ▼
    Google Apps Script
         │
         │  (server-side fetch)
         ▼
    Target website
```

---

## Domain-Fronting Explained

The ISP's deep-packet inspection (DPI) sees a TLS handshake to `www.google.com`. Inside that encrypted tunnel, the HTTP request actually targets `script.google.com`. Google's infrastructure then routes the request to the Apps Script deployment, which fetches the real URL on the client's behalf.

| Layer | Value |
|-------|-------|
| TCP destination | `216.239.38.120:443` (Google IP) |
| TLS SNI | `www.google.com` |
| HTTP `Host` header | `script.google.com` |
| HTTP path | `/macros/s/{scriptID}/exec` |

---

## Package Structure

| Package | File | Responsibility |
|---------|------|----------------|
| `main` | `main.go` | CLI flags, startup, graceful shutdown |
| `config` | `config/config.go` | JSON config loading, env-var overrides, validation |
| `ws` | `ws/ws.go` | WebSocket RFC 6455 frame encoder/decoder |
| `mitm` | `mitm/certmgr.go` | MITM CA + per-domain TLS certificate generation |
| `relay` | `relay/fronter.go` | TLS connection pool, batch relay, coalescing, parallel range downloads |
| `proxy` | `proxy/server.go` | HTTP + CONNECT proxy, routing logic, response cache |
| `proxy` | `proxy/socks5.go` | SOCKS5 protocol handler |

---

## Relay Engine (`relay/fronter.go`)

### Connection Pool
- Maintains up to **50 persistent TLS connections** to Google's IP
- Connections have a **45-second TTL**; a background goroutine evicts stale ones
- Pool is **pre-warmed** to 30 connections on startup to eliminate cold-start latency

### Batch Collector
- Requests are held in a **two-tier batch window**: 5 ms (fast) or 50 ms (slow)
- Multiple requests are sent in a single HTTPS POST when the Apps Script endpoint supports it
- Falls back to single-request mode if batching is unsupported

### Request Coalescing
- Identical in-flight GET requests for the same URL are **deduplicated**: only one request is sent, and all waiters receive the same response

### Parallel Range Downloads
- Large files (detected by extension or `Content-Length`) are split into **parallel byte-range requests** for higher throughput

### Redirect Following
- Follows up to **5 HTTP redirects** server-side within the relay, avoiding extra round-trips

---

## Proxy Server (`proxy/server.go`)

### MITM (Man-in-the-Middle) HTTPS
When a client sends `CONNECT host:443`:
1. The proxy responds `200 Connection Established`
2. A TLS handshake is performed with the client using a **dynamically signed certificate** for the target domain (signed by the local MITM CA)
3. Decrypted HTTP requests are forwarded through the relay engine
4. Responses are re-encrypted and sent back to the client

### Response Cache
- LRU-style cache capped at **50 MB**
- Respects `Cache-Control: max-age`, `no-store`, and `private` headers
- Static assets without cache headers get a default **1-hour TTL**

### Routing Logic
See [routing.md](routing.md) for the full decision tree.

---

## MITM CA (`mitm/certmgr.go`)
- Generates a self-signed **4096-bit RSA CA** on first run, stored in `ca/`
- Signs per-domain **2048-bit RSA leaf certificates** on demand, cached in memory
- Leaf certs are valid for **1 year**

---

## SOCKS5 (`proxy/socks5.go`)
Implements RFC 1928 (SOCKS5) auth-negotiation and CONNECT command. After the SOCKS5 handshake the connection is handed to the same `routeTunnel()` function used by the HTTP proxy, so all routing logic is shared.
