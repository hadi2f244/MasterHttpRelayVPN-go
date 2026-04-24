# MasterHttpRelayVPN-go

A high-performance Go proxy that tunnels all traffic through **Google Apps Script** using domain-fronting. Bypasses DPI/censorship without a dedicated VPN server.

- **HTTP proxy** (port 8085) and **SOCKS5** (port 1088)
- **MITM HTTPS** — intercepts and relays encrypted traffic transparently
- **TLS connection pool** — 50 persistent connections, pre-warmed on startup
- **Batch relay** — coalesces multiple requests into a single HTTPS round-trip
- **Request deduplication** — identical in-flight GETs share one relay call
- **Parallel range downloads** — splits large files across concurrent requests
- **LRU response cache** — 50 MB, respects `Cache-Control` headers
- **Smart routing** — direct tunnel for Google, SNI-rewrite for YouTube/CDN, MITM relay for everything else

---

## Quick Start

### Prerequisites

- Go 1.22+
- A deployed [Google Apps Script relay](docs/apps-script-setup.md)

### 1. Clone and build

```bash
git clone https://github.com/youruser/MasterHttpRelayVPN-go
cd MasterHttpRelayVPN-go
go build -o masterhttprelayvpn .
```

### 2. Configure

Copy the example and fill in your Apps Script deployment ID and auth key:

```bash
cp config.example.json config.json
```

Minimum required fields:

```json
{
  "mode": "apps_script",
  "script_id": "AKfycby...",
  "auth_key": "your-secret-key"
}
```

See [docs/configuration.md](docs/configuration.md) for all options.

### 3. Install the MITM CA certificate

The proxy needs a locally-trusted CA to intercept HTTPS:

```bash
./masterhttprelayvpn --install-cert
```

Or manually on macOS:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ca/ca.crt
```

See [docs/mitm-ca.md](docs/mitm-ca.md) for Linux, Windows, and Firefox instructions.

### 4. Run

```bash
./masterhttprelayvpn --config config.json
```

```
[Main] MasterHttpRelayVPN 1.0.0 starting (mode: apps_script)
[Main] Apps Script relay : SNI=www.google.com → script.google.com
[Main] HTTP proxy         : 127.0.0.1:8085
[Main] SOCKS5 proxy       : 127.0.0.1:1088
```

### 5. Test

```bash
# HTTP
curl -x http://127.0.0.1:8085 http://httpbin.org/ip

# HTTPS (after CA is installed)
curl -x http://127.0.0.1:8085 https://httpbin.org/ip
```

### 6. Configure your browser or system

Set your system/browser proxy to:

| Protocol | Host | Port |
|----------|------|------|
| HTTP | `127.0.0.1` | `8085` |
| HTTPS | `127.0.0.1` | `8085` |
| SOCKS5 | `127.0.0.1` | `1088` |

---

## CLI Reference

```
./masterhttprelayvpn [flags]

  --config string        Config file path (default: config.json)
  --port int             Override HTTP proxy port
  --host string          Override HTTP proxy listen host
  --socks5-port int      Override SOCKS5 port
  --disable-socks5       Disable SOCKS5 listener
  --log-level string     DEBUG | INFO | WARNING | ERROR
  --install-cert         Install MITM CA into system trust store and exit
  --no-cert-check        Skip CA installation check on startup
  --version              Print version and exit
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/architecture.md](docs/architecture.md) | How domain-fronting works, package structure, relay engine internals |
| [docs/configuration.md](docs/configuration.md) | Full config reference — all JSON fields, env vars, CLI flags |
| [docs/apps-script-setup.md](docs/apps-script-setup.md) | How to deploy and configure the Google Apps Script relay |
| [docs/routing.md](docs/routing.md) | Routing decision tree — direct, SNI-rewrite, and MITM strategies |
| [docs/mitm-ca.md](docs/mitm-ca.md) | MITM CA certificate installation on macOS, Linux, Windows, and Firefox |

---

## Project Structure

```
.
├── main.go                 Entry point, CLI flags, graceful shutdown
├── config/
│   └── config.go           Config loading and validation
├── relay/
│   └── fronter.go          Domain-fronting relay engine
├── proxy/
│   ├── server.go           HTTP proxy + MITM + routing logic
│   └── socks5.go           SOCKS5 protocol handler
├── mitm/
│   └── certmgr.go          MITM CA and per-domain cert generation
├── ws/
│   └── ws.go               WebSocket frame encoder/decoder
├── ca/                     Generated CA certificate and key (git-ignored)
├── config.json             Your local config (git-ignored)
└── docs/                   Comprehensive documentation
```

---

## Performance Notes

- The connection pool is pre-warmed to 30 persistent TLS connections to Google's IP, so requests are served immediately with no dial latency
- Each connection has a 45-second TTL; stale connections are evicted in the background
- Using multiple `script_ids` (round-robin) dramatically increases throughput since each Apps Script deployment has its own request quota

---

## License

MIT
