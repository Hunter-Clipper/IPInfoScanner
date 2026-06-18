<div align="center">

# IP Scanner

![IP Scanner](https://img.shields.io/badge/IP%20Scanner-1.0-6b79f5?style=for-the-badge&logo=radar&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-22c55e?style=for-the-badge)

**A fast, zero-dependency IP intelligence tool powered by Cloudflare Workers.**  
Look up any IPv4, IPv6, or domain and get geo, ASN, threat flags, DNSBL, VirusTotal, Shodan, WHOIS, and an AI-powered threat summary — all in one response.

</div>

---

## Features

### Intelligence Sources
| Source | Data |
|---|---|
| **ip-api.com** | Geolocation, ISP, ASN, proxy/hosting/mobile flags |
| **ipinfo.io** | Geolocation, ASN org, hostname, postal |
| **proxycheck.io** | VPN / Proxy / Tor / Hosting detection, risk score |
| **ipapi.is** | Additional security signals |
| **VirusTotal** | 80+ AV engine scan, reputation score |
| **Shodan** | Open ports, running services & banners, CVEs |
| **WHOIS / RDAP** | IP block owner, registrant, abuse contact, dates |
| **DNSBL** | Checked against 35 real-time blacklists |
| **Gemini AI** | On-demand natural language threat analysis |

### Risk Scoring
A transparent, weighted additive model outputs a **0 – 100 risk score**:

- Tor exit node confirmed → +60 pts
- VirusTotal engines flagged → +8 to +40 pts (scaled by count)
- DNSBL listings → +18 pts per serious list, +6 per aggressive subnet list
- VPN / Proxy / Hosting signals → incremental additions
- Multiple bad signals → 20–35% amplification multiplier
- Clean VT / DNSBL results → small negative offsets

Final score maps to four levels: **Clean · Caution · Suspicious · Dangerous**

### Other Highlights
- **Domain support** — resolves hostnames to IPs, shows IPv4 + IPv6, pulls domain WHOIS and a separate VirusTotal domain report
- **"My IP" detection** — one click to scan your own public IP via Cloudflare headers
- **Scan history** — last 50 scans stored in `localStorage` with risk score, country, and timestamp
- **Shareable URLs** — every scan updates `?scan=<ip>` so links go straight to results
- **Gemini AI analysis** — plain-English threat summary generated on demand
- **Raw JSON viewer** — inspect the full API response in-page with a copy button
- **Dark / Light theme** — persists via `localStorage`
- **Optional client key overrides** — bring your own VirusTotal, Shodan, ipinfo.io, or Proxycheck keys; stored browser-side only, sent as request headers
- **Zero build step** — three static files (`index.html`, `style.css`, `app.js`); no bundler, no Node, no dependencies

---

## Architecture

```
Browser (your domain)               Your other apps
    │  Origin/Referer check              │  X-API-Key header
    │                                    │
    └─────────────┬──────────────────────┘
                  ▼
    Cloudflare Worker  (your-worker.workers.dev)
        ├── ip-api.com
        ├── ipinfo.io
        ├── proxycheck.io
        ├── ipapi.is
        ├── VirusTotal API
        ├── Shodan API
        ├── RDAP / WHOIS
        ├── DNSBL (DNS-over-HTTPS via Cloudflare 1.1.1.1)
        └── Google Gemini API  (/analyze only)
```

All intelligence source requests are fanned out in parallel via `Promise.allSettled()`. Results are aggregated, risk-scored, and cached in Cloudflare KV for 6 hours. Browser requests from your domain are authenticated via Origin/Referer check. Programmatic access from other apps uses an `X-API-Key` header checked against a worker secret.

---

## Self-Hosting

### Prerequisites

- A [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier is sufficient)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed: `npm install -g wrangler`
- API keys for the intelligence sources you want to use (all optional — the tool degrades gracefully without them)

### 1. Clone the repo

```bash
git clone https://github.com/your-username/IPInfoScanner.git
cd IPInfoScanner
```

### 2. Configure the worker

**2a. Update the allowed origin**

In `worker.js`, replace the domain checks with your own domain:

```js
// Line ~24
const ALLOWED_ORIGIN = 'https://ipscanner.yourdomain.com';

// Lines ~32–54 — replace the hardcoded domain with your own in both
// buildCorsHeaders() and isAllowedOrigin()
origin === 'https://yourdomain.com' ||
origin.endsWith('.yourdomain.com')
```

**2b. Create a `wrangler.toml`**

Wrangler needs a config file to know your account and worker name. Create `wrangler.toml` in the project root:

```toml
name = "your-worker-name"
main = "worker.js"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "SCAN_CACHE_KV"
id = "PASTE_KV_NAMESPACE_ID_HERE"

[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "PASTE_KV_NAMESPACE_ID_HERE"
```

**2c. Create the KV namespaces**

The worker uses two KV namespaces — one for scan result caching, one for rate limiting:

```bash
wrangler login
wrangler kv namespace create SCAN_CACHE_KV
wrangler kv namespace create RATE_LIMIT_KV
```

Each command outputs an `id` — paste those into your `wrangler.toml`.

> The worker will still function without KV bindings — it fails open (no cache, no rate limiting). KV is optional but recommended.

### 3. Deploy the worker

```bash
wrangler deploy
```

Your worker is now live at `https://your-worker-name.your-cf-subdomain.workers.dev`.

### 4. Add worker secrets

In the **Cloudflare Dashboard** → Workers & Pages → your worker → **Settings → Variables & Secrets**, add the following as **Secrets** (not plain variables):

| Secret name | Where to get it | Required? |
|---|---|---|
| `GEMINI_API_KEY` | [aistudio.google.com](https://aistudio.google.com) | Yes — for AI analysis |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) | Recommended |
| `SHODAN_API_KEY` | [shodan.io](https://account.shodan.io/register) | Recommended (paid for host API) |
| `IPINFO_TOKEN` | [ipinfo.io/signup](https://ipinfo.io/signup) | Recommended |
| `PROXYCHECK_API_KEY` | [proxycheck.io](https://proxycheck.io/dashboard/) | Recommended |
| `WORKER_API_KEY` | `openssl rand -hex 32` | Yes — for programmatic API access |

> All secrets are optional at the code level — the worker skips any source whose key is missing and returns `null` for that field. `WORKER_API_KEY` should be set if you want to use the REST API from other apps.

### 5. Configure the frontend

**5a. Point the frontend at your worker**

In `app.js`, update `WORKER_BASE` to your worker URL:

```js
// Line 2
const WORKER_BASE = 'https://your-worker-name.your-cf-subdomain.workers.dev';
```

**5b. Update the CSP in `index.html`**

The Content Security Policy restricts which hosts the page can connect to. Update it to match your worker URL:

```html
<!-- Line 7 — replace the connect-src value -->
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src data: https://flagcdn.com; connect-src https://your-worker-name.your-cf-subdomain.workers.dev;">
```

### 6. Deploy the frontend

**Option A — Cloudflare Pages (recommended)**

1. Push your repo to GitHub
2. In the Cloudflare Dashboard → Workers & Pages → Create → Pages → Connect to Git
3. Select your repo; set build command to *none*, output directory to `/` (or `.`)
4. Deploy — Cloudflare serves the static files and assigns a `pages.dev` subdomain

**Option B — Any static host**

The frontend is three plain files. Drop them onto any web server, S3 bucket, Netlify, Vercel, or GitHub Pages — anything that can serve static HTML.

**Option C — Local (no hosting)**

```bash
python3 -m http.server 8080
# Open http://localhost:8080
```

---

## Programmatic API Access

All three worker endpoints are accessible from any app via an `X-API-Key` header. The key is checked against the `WORKER_API_KEY` secret you set in step 4.

### `GET /lookup` — full IP / domain scan

```bash
curl -H "X-API-Key: your-key" \
  "https://your-worker-name.your-cf-subdomain.workers.dev/lookup?ip=1.2.3.4"
```

**Query parameters**

| Parameter | Description |
|---|---|
| `ip` | IPv4, IPv6, or domain name — required |
| `fresh=1` | Bypass the 6-hour cache and force a live scan |

**Optional headers** — override worker-level keys with your own:

| Header | Service |
|---|---|
| `X-VT-Key` | VirusTotal |
| `X-Shodan-Key` | Shodan |
| `X-Ipinfo-Token` | ipinfo.io |
| `X-Proxycheck-Key` | Proxycheck.io |

**Response** — full JSON scan result. Abbreviated shape:

```jsonc
{
  "ip": "1.2.3.4",
  "isDomain": false,
  "resolvedFrom": null,       // domain name if the input was a hostname
  "resolvedIpv4": null,
  "resolvedIpv6": null,
  "timestamp": 1718700000000,
  "isTorConfirmed": false,
  "torListSize": 1200,
  "_cached": false,
  "_cachedAt": 1718700000000,
  "sources": {
    "ipapi":      { "country": "US", "isp": "...", "proxy": false, "hosting": false, ... },
    "ipinfo":     { "org": "AS15169 Google LLC", ... },
    "proxycheck": { "1.2.3.4": { "type": "VPN", "risk": 67, ... } },
    "virustotal": { "data": { "attributes": { "last_analysis_stats": { "malicious": 0, "harmless": 94 }, ... } } },
    "ipapis":     { "is_vpn": false, "is_tor": false, ... },
    "whois":      { "registrant": "...", "network": "...", ... },
    "shodan":     { "ports": [80, 443], "services": [...], "vulns": [], ... },
    "dnsbl":      { "listed": 0, "checked": 34, "lists": [...] },
    "vtDomain":   null,        // populated for domain lookups
    "domainWhois": null        // populated for domain lookups
  }
}
```

### `POST /analyze` — AI threat summary

Pass a slim payload from a prior `/lookup` response. The worker calls Gemini and returns a plain-English analysis.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "country": "RU",
    "city": "Moscow",
    "isp": "Some Hosting LLC",
    "riskScore": 74,
    "vtMalCount": 6,
    "vtTotal": 94,
    "dnsblListed": 3,
    "dnsblChecked": 34
  }' \
  "https://your-worker-name.your-cf-subdomain.workers.dev/analyze"
```

**Full payload fields** (all optional beyond `ip`):

| Field | Type | Description |
|---|---|---|
| `ip` | string | Target IP — required |
| `country` | string | Country name |
| `city` | string | City |
| `isp` | string | ISP name |
| `org` | string | Organisation |
| `asn` | string | ASN string (e.g. `AS15169`) |
| `rdns` | string | Reverse DNS hostname |
| `ipType` | string | Proxy type from proxycheck |
| `isMobile` | boolean | Mobile network flag |
| `isHosting` | boolean | Data centre / hosting flag |
| `isProxy` | boolean | Proxy flag |
| `isVpn` | boolean | VPN flag |
| `isTor` | boolean | Tor flag |
| `riskScore` | number | Computed risk score 0–100 |
| `pcRisk` | number | Proxycheck risk score |
| `vtMalCount` | number | VirusTotal malicious engine count |
| `vtTotal` | number | VirusTotal total engine count |
| `dnsblListed` | number | Number of DNSBL lists the IP appears on |
| `dnsblChecked` | number | Total DNSBL lists checked |
| `dnsblNames` | string | Comma-separated names of listing DNSBL entries |
| `shodanPorts` | string | Comma-separated open port numbers |
| `shodanVulns` | string | Comma-separated CVE IDs |
| `shodanOS` | string | Detected OS from Shodan |
| `whoisRegistrant` | string | WHOIS registrant name |
| `whoisAbuse` | string | WHOIS abuse contact email |

**Response:**

```json
{
  "analysis": "**Threat Assessment**\n\n...",
  "model": "gemini-3.1-flash-lite"
}
```

### `GET /myip` — caller's public IP

Returns the IP address the worker sees for the incoming request (via Cloudflare's `CF-Connecting-IP` header).

```bash
curl -H "X-API-Key: your-key" \
  "https://your-worker-name.your-cf-subdomain.workers.dev/myip"
```

```json
{ "ip": "203.0.113.42" }
```

---

## Rate Limits

Rate limits are enforced per caller IP via the `RATE_LIMIT_KV` namespace. Defaults are set in `worker.js`:

| Endpoint | Default limit | Window |
|---|---|---|
| `/lookup` | 30 requests | 1 hour |
| `/analyze` | 10 requests | 1 hour |

To change the limits, edit these constants near the top of `worker.js`:

```js
const RATE_LIMIT_WINDOW  = 3600; // seconds
const RATE_LIMIT_LOOKUP  = 30;
const RATE_LIMIT_ANALYZE = 10;
```

The rate limiter fails open — if KV is unavailable, requests are allowed through rather than blocked.

---

## Optional Client-Side API Key Overrides

All scanning works out of the box via the server-level keys you configured. If you want to use your own quotas for a specific service, click **⚙ Manage** in the web UI and paste your keys — they are stored in your browser's `localStorage` and sent only as request headers, never persisted server-side.

| Key | Free Tier |
|---|---|
| VirusTotal | 500 lookups/day |
| Shodan | Limited (paid plan for host lookups) |
| ipinfo.io | 50,000 requests/day |
| Proxycheck.io | 1,000 requests/day |

---

## UI Sections

| Section | Description |
|---|---|
| **Threat Banner** | Top-level verdict with risk score, level badge, and primary indicator |
| **Basic Info** | IP version, reverse DNS, bogon check, domain resolution |
| **Geolocation** | Country, region, city, coordinates, timezone, postal code |
| **Network / ASN** | ASN number and org, ISP, organisation, open port |
| **Abuse / Risk** | Risk score bar, threat level, proxy type, blacklist summary |
| **Privacy & Threat Flags** | 11 boolean flags rendered as a visual grid |
| **WHOIS / RDAP** | IP block registration: owner, network range, country, dates |
| **Shodan** | Open ports, service banners, OS, CVEs, hostnames, tags |
| **Blacklist / DNSBL** | Per-list pass/fail grid across 35 real-time blocklists |
| **VirusTotal** | Per-engine results, malicious/suspicious/clean counts, reputation |
| **Domain Intelligence** | (domains only) Domain WHOIS age/registrar/nameservers + domain VT report |
| **AI Analysis** | Gemini-generated plain-English summary of all signals |
| **Raw Data** | Collapsible full JSON response with copy button |

---

## Tech Stack

- **Frontend** — Vanilla HTML/CSS/JS, no frameworks, no build step
- **Backend** — Cloudflare Workers (JavaScript), Cloudflare KV (cache + rate limiting)
- **APIs** — ip-api.com, ipinfo.io, proxycheck.io, ipapi.is, VirusTotal, Shodan, RDAP, Cloudflare DoH, Google Gemini

---

## License

MIT — do whatever you want with it.
