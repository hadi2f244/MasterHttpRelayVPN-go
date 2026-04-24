# Routing Logic

The proxy applies a priority-ordered decision tree to every CONNECT request to choose one of three tunnel strategies.

---

## Decision Tree

```
CONNECT host:port
        │
        ▼
Is it port 80 (plain HTTP)?
   YES → Plain TCP relay → relay HTTP request via Apps Script
   NO  ↓
        │
        ▼
Is the host in the custom `hosts` map (config)?
   YES → SNI-rewrite tunnel to the mapped address
   NO  ↓
        │
        ▼
Is the host a Google-owned domain?  (*.google.com, *.googleapis.com, *.gstatic.com, …)
        │
        ├─ YES: Is it in direct_google_allow or the built-in allow list?
        │         YES → Direct tunnel (passthrough TCP, no MITM)
        │
        ├─ YES: Is it in direct_google_exclude or the built-in exclude list?
        │         YES → MITM + relay via Apps Script
        │
        └─ YES (other Google domains)
                → Direct tunnel (passthrough TCP, no MITM)
        │
        NO ↓
        │
        ▼
Is the host a YouTube / CDN / analytics domain?
(youtube.com, ytimg.com, gvt1.com, gvt2.com, doubleclick.net, …)
   YES → SNI-rewrite tunnel via Google IP (fast; no Apps Script)
   NO  ↓
        │
        ▼
→ MITM tunnel + relay via Apps Script
```

---

## Tunnel Strategies

### Direct Tunnel
The proxy performs a raw TCP passthrough directly to the target host's real IP. **No MITM, no relay.** Used for `www.google.com` and safe Google services that are already accessible.

```
Client ──TLS──▶ Proxy ──TCP──▶ Target (real IP)
```

### SNI-Rewrite Tunnel
The proxy opens a TLS connection to the **Google IP** (`216.239.38.120:443`) but presents the **target domain's SNI**. Google's network routes the connection to the target server (which must be on Google infrastructure).

Used for: `youtube.com`, `ytimg.com`, `gvt1.com`, `gvt2.com`, `doubleclick.net`, Google Fonts, Google Analytics, etc.

```
Client ──TLS──▶ Proxy ──TLS(SNI=youtube.com)──▶ Google IP ──▶ YouTube server
```

### MITM + Apps Script Relay
The proxy intercepts the TLS connection by presenting a **locally-signed certificate** for the target domain. It then reads the plain HTTP request and relays it through the Apps Script relay.

Used for: everything else (most websites).

```
Client ──TLS(MITM cert)──▶ Proxy ──HTTPS(domain-fronting)──▶ Apps Script ──▶ Target
```

---

## Built-in Domain Classification

### Always Direct (allow list)
- `www.google.com`
- `google.com`
- `safebrowsing.google.com`

### Always Relay (exclude list — Google services behind auth)
- `accounts.google.com`
- `mail.google.com`, `calendar.google.com`, `drive.google.com`
- `docs.google.com`, `meet.google.com`, `chat.google.com`
- `photos.google.com`, `maps.google.com`, `play.google.com`
- `gemini.google.com`, `aistudio.google.com`, `notebooklm.google.com`
- `classroom.google.com`, `keep.google.com`, `myaccount.google.com`

### SNI-Rewrite Domains
- `youtube.com`, `youtu.be`, `youtube-nocookie.com`
- `ytimg.com`, `ggpht.com`
- `gvt1.com`, `gvt2.com`
- `doubleclick.net`
- `googlesyndication.com`, `googleadservices.com`
- `google-analytics.com`, `googletagmanager.com`, `googletagservices.com`
- `fonts.googleapis.com`

---

## Overriding Routing in Config

```json
{
  "hosts": {
    "myservice.example.com": "216.239.38.120"
  },
  "direct_google_allow": ["translate.google.com"],
  "direct_google_exclude": ["www.googleapis.com"]
}
```

- **`hosts`** — any connection to `myservice.example.com` will use SNI-rewrite via the mapped IP
- **`direct_google_allow`** — force specified Google subdomains to use the direct tunnel
- **`direct_google_exclude`** — force specified Google subdomains to use MITM + relay

---

## Circuit Breaker

If a direct tunnel to a Google-owned domain fails, the host is added to a **5-minute circuit-breaker list** and subsequent requests fall through to MITM + relay automatically.
