# Google Apps Script Relay Setup

This document explains how to create and configure the server-side Google Apps Script that acts as the relay.

---

## Overview

The Apps Script deployment is the **cloud-side component**. It runs on Google's servers and fetches URLs on your behalf. The Go client connects to it via domain-fronting.

You need a Google account. The free tier is sufficient for personal use.

---

## 1. Create the Apps Script Project

1. Go to [script.google.com](https://script.google.com) and click **New project**
2. Name it something like `vpn-relay`
3. Delete the default `myFunction()` content

---

## 2. Paste the Relay Code (`Code.gs`)

Replace the editor contents with your relay's `Code.gs`. The script must:
- Accept POST requests with JSON body `{"m", "u", "h", "b", "k"}`
- Verify the auth key (`k` field) against a hardcoded or PropertiesService-stored value
- Fetch the target URL using `UrlFetchApp.fetch()`
- Return JSON `{"s": statusCode, "h": headers, "b": base64Body}`

> **Note:** The `Code.gs` is the server-side component that was not changed in this Go rewrite. Use the same `Code.gs` from the original Python project.

---

## 3. Set the Auth Key

In the script editor, open the **Project Settings** → **Script Properties** and add:

| Property | Value |
|----------|-------|
| `AUTH_KEY` | Your chosen secret (must match `auth_key` in `config.json`) |

Alternatively, the key can be hardcoded in `Code.gs` — see the original source for details.

---

## 4. Deploy as Web App

1. Click **Deploy** → **New deployment**
2. Choose type: **Web app**
3. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
4. Click **Deploy**
5. Copy the **Deployment ID** — it looks like `AKfycby...`

---

## 5. Configure the Go Client

Paste the deployment ID into `config.json`:

```json
{
  "script_id": "AKfycby...",
  "auth_key": "your-secret-key"
}
```

---

## 6. Test the Deployment

```bash
curl -s "https://script.google.com/macros/s/AKfycby.../exec" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"m":"GET","u":"http://httpbin.org/ip","h":{},"b":"","k":"your-secret-key"}'
```

You should receive a JSON response with the IP of a Google server.

---

## Multiple Deployments (Higher Throughput)

Each Apps Script deployment is rate-limited. For faster speeds, create **multiple deployments** of the same script (redeploy with "New deployment" each time) and list all IDs:

```json
{
  "script_ids": [
    "AKfycbyAAA...",
    "AKfycbyBBB...",
    "AKfycbyCCC..."
  ]
}
```

The Go client round-robins requests across all IDs automatically.

---

## Quotas and Limits

| Limit | Value |
|-------|-------|
| Daily URL fetch quota (free) | 20,000 requests |
| Maximum response size | 50 MB |
| Execution timeout | 6 minutes |
| Concurrent executions | unlimited (each request spawns a new instance) |

For heavy usage, add more deployments or use a Google Workspace account (higher quotas).

---

## Troubleshooting

**Script returns 401 / auth error**
- Check that `auth_key` in `config.json` matches the key in `Code.gs` / Script Properties

**Script returns 302 redirect to login**
- The deployment "Who has access" setting must be **Anyone** (not "Anyone with Google account")

**Relay is slow**
- Add more deployments and use `script_ids` for round-robin
- Ensure `verify_ssl: false` if using IP-based connection (avoids unnecessary cert validation)

**`curl` test returns HTML instead of JSON**
- The deployment URL may have changed — re-deploy and copy the new ID
