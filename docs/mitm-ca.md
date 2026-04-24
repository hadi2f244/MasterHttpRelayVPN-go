# MITM CA Certificate Setup

MasterHttpRelayVPN-go intercepts HTTPS traffic by acting as a man-in-the-middle. To do this transparently, it generates a local Certificate Authority (CA) and signs per-domain certificates on demand. Your system (or browser) must trust this CA.

---

## How It Works

1. On first run the proxy creates a **4096-bit RSA CA** at `ca/ca.crt` and `ca/ca.key`
2. When a client connects to `https://example.com`, the proxy dynamically generates a **leaf certificate** for `example.com` signed by the local CA
3. The client validates the leaf certificate against the trusted CA — if the CA is trusted, the connection succeeds transparently

---

## CA File Location

| File | Purpose |
|------|---------|
| `ca/ca.crt` | CA certificate (install this into your trust store) |
| `ca/ca.key` | CA private key (keep secret, never share) |

Override the directory with the `DFT_CA_DIR` environment variable:
```bash
DFT_CA_DIR=/etc/mastervpn/ca ./masterhttprelayvpn --config config.json
```

---

## Install the CA

### macOS (System Keychain)

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ca/ca.crt
```

Or use the built-in helper flag:
```bash
./masterhttprelayvpn --install-cert
```

### macOS (user-only, no sudo)

```bash
security add-trusted-cert -r trustRoot \
  -k ~/Library/Keychains/login.keychain-db \
  ca/ca.crt
```

### Linux (system-wide)

```bash
# Debian / Ubuntu
sudo cp ca/ca.crt /usr/local/share/ca-certificates/mastervpn.crt
sudo update-ca-certificates

# Fedora / RHEL / CentOS
sudo cp ca/ca.crt /etc/pki/ca-trust/source/anchors/mastervpn.crt
sudo update-ca-trust
```

### Windows

```powershell
certutil -addstore "Root" ca\ca.crt
```

Or open `ca\ca.crt` in Explorer → Install Certificate → Local Machine → Trusted Root Certification Authorities.

### Firefox (separate trust store)

Firefox maintains its own certificate store:
1. Open **Settings** → **Privacy & Security** → **Certificates** → **View Certificates**
2. Select **Authorities** tab → **Import**
3. Choose `ca/ca.crt`
4. Check **Trust this CA to identify websites** → OK

---

## Using `curl` Without Installing

For testing only, pass the CA cert directly:

```bash
curl --cacert ca/ca.crt -x http://127.0.0.1:8085 https://example.com
```

---

## Removing the CA

### macOS
```bash
sudo security delete-certificate -c "MasterHttpRelayVPN CA" \
  /Library/Keychains/System.keychain
```

### Linux
```bash
sudo rm /usr/local/share/ca-certificates/mastervpn.crt
sudo update-ca-certificates
```

---

## "tls: unknown certificate" Errors in Logs

This message appears when a client (usually a background app) connects to the MITM proxy but **does not** trust the local CA. These are not bugs — they are expected for:
- Browser extensions that pin certificates
- System services that use a different trust store
- Apps with bundled CA bundles (Flutter, OpenSSL apps, etc.)

These connections fail gracefully; the browser/client surfaces its own certificate error.
