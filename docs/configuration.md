# Configuration Reference

All configuration is read from a JSON file (default: `config.json` in the working directory).

## Example `config.json`

```json
{
  "mode": "apps_script",
  "google_ip": "216.239.38.120",
  "front_domain": "www.google.com",
  "script_id": "AKfycb...",
  "auth_key": "change-me",
  "listen_host": "127.0.0.1",
  "listen_port": 8085,
  "socks5_enabled": true,
  "socks5_host": "127.0.0.1",
  "socks5_port": 1088,
  "log_level": "INFO",
  "verify_ssl": true
}
```

---

## Fields

### Core

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"apps_script"` | Relay mode. Currently only `"apps_script"` is supported. |
| `google_ip` | string | `"216.239.38.120"` | Google IP to TCP-dial. Must serve TLS on port 443. |
| `front_domain` | string | `"www.google.com"` | TLS SNI used for the outbound connection. DPI sees this. |
| `auth_key` | string | — | **Required.** Shared secret between this client and the Apps Script relay. |

### Script IDs

Provide either `script_id` (single) or `script_ids` (round-robin across multiple deployments):

| Field | Type | Description |
|-------|------|-------------|
| `script_id` | string | Single Apps Script deployment ID. |
| `script_ids` | array of strings | Multiple deployment IDs. Requests are round-robined for higher throughput. |

### Proxy Listeners

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen_host` | string | `"127.0.0.1"` | Interface for the HTTP proxy listener. Use `"0.0.0.0"` to expose to LAN. |
| `listen_port` | int | `8085` | HTTP proxy port. |
| `socks5_enabled` | bool | `true` | Enable the SOCKS5 proxy. |
| `socks5_host` | string | same as `listen_host` | Interface for SOCKS5 listener. |
| `socks5_port` | int | `1080` | SOCKS5 port. |

### TLS

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `verify_ssl` | bool | `false` | Verify the TLS certificate of the Google IP. Normally left `false` because the IP may not match any hostname. |

### Logging

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | string | `"INFO"` | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`. |

### Advanced Routing

| Field | Type | Description |
|-------|------|-------------|
| `hosts` | object (string → string) | Custom SNI-rewrite overrides. Keys are destination hostnames, values are the SNI to present. |
| `direct_google_exclude` | array of strings | Google subdomains that should be **relayed** (not direct-tunnelled). Adds to the built-in exclusion list. |
| `direct_google_allow` | array of strings | Google subdomains that should be **direct-tunnelled**. Overrides the exclusion list. |

---

## Environment Variables

These override the corresponding JSON fields:

| Variable | Overrides |
|----------|-----------|
| `DFT_AUTH_KEY` | `auth_key` |
| `DFT_SCRIPT_ID` | `script_id` |
| `DFT_CONFIG` | Path to config file (default: `config.json`) |
| `DFT_CA_DIR` | Directory where the MITM CA certificate and key are stored (default: `ca/` in CWD) |

---

## CLI Flags

All flags override their config-file equivalents:

```
--config        Path to config file  (default: config.json)
--port          HTTP proxy port
--host          HTTP proxy listen host
--socks5-port   SOCKS5 port
--disable-socks5 Disable SOCKS5 proxy
--log-level     Log level (DEBUG|INFO|WARNING|ERROR)
--install-cert  Install MITM CA cert into the system trust store and exit
--no-cert-check Skip CA installation check on startup
--version       Print version and exit
```

---

## Multiple Script IDs

Using multiple Apps Script deployments increases throughput because requests are distributed across them:

```json
{
  "script_ids": [
    "AKfycbyAAA...",
    "AKfycbyBBB...",
    "AKfycbyCCC..."
  ]
}
```

Each deployment is hit round-robin. All deployments must share the same `auth_key`.
