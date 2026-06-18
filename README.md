<div align="center">

# IP Scanner

![IP Scanner](https://img.shields.io/badge/IP%20Scanner-v2.0-6b79f5?style=for-the-badge&logo=radar&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)
![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178c6?style=for-the-badge&logo=typescript&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=for-the-badge&logo=docker&logoColor=white)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/frontend-zero%20deps-22c55e?style=for-the-badge)

**A fast IP intelligence tool with a web UI and REST API.**  
Look up any IPv4, IPv6, or domain and get geo, ASN, threat flags, DNSBL, VirusTotal, Shodan, WHOIS, and an AI-powered threat summary — all in one response.

</div>

---

## Deployment Options

| | Cloudflare (hosted) | Docker (self-hosted) |
|---|---|---|
| **Backend** | Cloudflare Worker (`worker.js`) | Node.js + Hono (`src/server/`) |
| **Frontend** | Cloudflare Pages | Served by the same container |
| **Cache** | Cloudflare KV | Redis |
| **Rate limiting** | Cloudflare KV | Redis |
| **API access** | Browser only (Origin check) | `X-API-Key` header |
| **Setup** | Zero — already deployed | `docker compose up --build` |

The public site at [ipinfo.hunterclipper.com](https://ipinfo.hunterclipper.com) runs on Cloudflare. The Docker image lets you run a private instance with full REST API access.

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
- **Domain support** — resolves hostnames to IPs, shows IPv4 + IPv6 side-by-side, pulls domain WHOIS and a separate domain VirusTotal report
- **"My IP" detection** — one click to scan your own public IP
- **Scan history** — last 50 scans stored in `localStorage` with risk score, country, and timestamp
- **Shareable URLs** — every scan updates `?scan=<ip>` so links go straight to results
- **Gemini AI analysis** — plain-English threat summary generated on demand
- **Raw JSON viewer** — inspect the full API response in-page with a copy button
- **Dark / Light theme** — persists across sessions
- **Optional API key overrides** — bring your own VirusTotal, Shodan, ipinfo.io, or Proxycheck keys; stored browser-side only

---

## Architecture

```
Browser  ──── GET /lookup?ip=…  ────────────────────────────────────────────▶  Backend
              GET /myip                                                          │
              POST /analyze                                                      ├── ip-api.com
              GET /api/v1/scan?ip=…   (REST API, X-API-Key)                    ├── ipinfo.io
              POST /api/v1/scan       (REST API, X-API-Key)                    ├── proxycheck.io
              POST /api/v1/analyze    (REST API, X-API-Key)                    ├── ipapi.is
                                                                                ├── VirusTotal API
          ┌─────────────────────────────────────────────────────────────────┐   ├── Shodan API
          │  Cloudflare Worker  OR  Node.js + Hono (Docker)                │   ├── RDAP / WHOIS
          │                                                                 │   ├── DNSBL (DoH via 1.1.1.1)
          │  All sources fanned out in parallel via Promise.allSettled()   │   └── Google Gemini API
          │  Results aggregated, risk-scored, and cached (6h TTL)          │
          └─────────────────────────────────────────────────────────────────┘
                                        │
                                   Redis (Docker)
                               or Cloudflare KV (CF)
```

---

## Quick Start

### Option A — Docker (self-hosted, includes REST API)

```bash
git clone https://github.com/Hunter-Clipper/IPInfoScanner.git
cd IPInfoScanner

cp .env.example .env
# Edit .env — add your API keys and generate an API_KEY

docker compose up --build
```

Web UI → `http://localhost:3000`  
API → `http://localhost:3000/api/v1/scan?ip=8.8.8.8`

### Option B — Local dev (no Docker)

```bash
npm install
cp .env.example .env   # fill in keys
npm run dev            # tsx watch, hot reload on http://localhost:3000
```

### Option C — Static frontend only (Cloudflare)

```bash
# Open index.html directly, or serve with any static host
python3 -m http.server 8080
```

The frontend talks to the pre-deployed Cloudflare Worker at `ipscan.hunter-clipper.workers.dev`. No backend setup required. When served from `localhost`, it automatically uses the local server instead.

---

## REST API

All API endpoints require an `X-API-Key` header. Browser requests from allowed origins work without a key (Origin/Referer check).

### Authentication

```bash
# Set your key in .env
API_KEYS=your-key-here,another-key-if-needed

# Pass it on every request
curl -H "X-API-Key: your-key-here" http://localhost:3000/api/v1/scan?ip=1.2.3.4
```

Generate a key: `openssl rand -hex 32`

---

### `GET /api/v1/scan`

Scan an IP address or domain.

**Query parameters**

| Param | Required | Description |
|---|---|---|
| `ip` | Yes | IPv4, IPv6, or domain name |
| `fresh` | No | Set to `1` to bypass the 6-hour cache |

**Request headers** (all optional — override worker defaults with your own keys)

| Header | Description |
|---|---|
| `X-VT-Key` | Your VirusTotal API key |
| `X-Shodan-Key` | Your Shodan API key |
| `X-Ipinfo-Token` | Your ipinfo.io token |
| `X-Proxycheck-Key` | Your Proxycheck.io key |

```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:3000/api/v1/scan?ip=8.8.8.8"
```

---

### `POST /api/v1/scan`

Same as GET, but IP goes in the request body. Useful when the target is sensitive and you'd prefer it not appear in server logs.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}' \
  http://localhost:3000/api/v1/scan
```

**Body**

```json
{
  "ip": "8.8.8.8",
  "fresh": false
}
```

---

### `POST /api/v1/analyze`

Run an AI threat analysis on a previous scan result. Pass the slim payload extracted from a `/scan` response.

```bash
curl -X POST \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "8.8.8.8",
    "country": "US",
    "city": "Mountain View",
    "isp": "Google LLC",
    "riskScore": 4,
    "vtMalCount": 0,
    "vtTotal": 94,
    "dnsblListed": 0,
    "dnsblChecked": 34
  }' \
  http://localhost:3000/api/v1/analyze
```

**Response**

```json
{
  "analysis": "**Threat Assessment**\n\nLow risk...",
  "model": "gemini-3.1-flash-lite"
}
```

---

### `GET /api/v1/myip`

Returns the caller's public IP as seen by the server.

```bash
curl -H "X-API-Key: your-key" http://localhost:3000/api/v1/myip
```

```json
{ "ip": "203.0.113.42" }
```

---

### `GET /health`

Health check — no authentication required.

```bash
curl http://localhost:3000/health
```

```json
{ "status": "ok", "version": "2.0.0" }
```

---

### Scan response shape

```jsonc
{
  "ip": "8.8.8.8",
  "resolvedFrom": null,          // domain name if input was a domain
  "resolvedIpv4": null,
  "resolvedIpv6": null,
  "isDomain": false,
  "timestamp": 1718700000000,
  "isTorConfirmed": false,
  "torListSize": 1234,
  "_cached": false,
  "_cachedAt": 1718700000000,
  "sources": {
    "ipapi":      { /* ip-api.com fields */ },
    "ipinfo":     { /* ipinfo.io fields */ },
    "proxycheck": { /* proxycheck.io fields */ },
    "virustotal": { /* VT analysis stats + per-engine results */ },
    "ipapis":     { /* ipapi.is security flags */ },
    "whois":      { /* RDAP registrant, network, dates */ },
    "shodan":     { /* open ports, services, CVEs */ },
    "dnsbl":      { /* per-list pass/fail across 35 blacklists */ },
    "vtDomain":   null,          // populated for domain lookups
    "domainWhois": null          // populated for domain lookups
  }
}
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values.

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `API_KEYS` | — | Comma-separated list of valid API keys |
| `ALLOWED_ORIGINS` | `http://localhost:3000,...` | Comma-separated allowed browser origins |
| `GEMINI_API_KEY` | — | Google Gemini API key (required for AI analysis) |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key |
| `SHODAN_API_KEY` | — | Shodan API key (paid plan required for host lookups) |
| `IPINFO_TOKEN` | — | ipinfo.io token |
| `PROXYCHECK_API_KEY` | — | Proxycheck.io API key |
| `SCAN_CACHE_TTL` | `21600` | Scan result cache lifetime in seconds (6h) |
| `RATE_LIMIT_WINDOW` | `3600` | Rate limit window in seconds (1h) |
| `RATE_LIMIT_LOOKUP` | `30` | Max scans per IP per window |
| `RATE_LIMIT_ANALYZE` | `10` | Max AI analyses per IP per window |

### Optional client-side API key overrides (web UI)

In the web UI, click **⚙ Settings** to enter your own keys. They are saved in your browser's `localStorage` and sent as request headers — they never touch the server's environment.

| Key | Free Tier | Get One |
|---|---|---|
| VirusTotal | 500 lookups/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| Shodan | Limited (paid for host API) | [shodan.io](https://account.shodan.io/register) |
| ipinfo.io | 50,000/day | [ipinfo.io/signup](https://ipinfo.io/signup) |
| Proxycheck.io | 1,000/day | [proxycheck.io](https://proxycheck.io/dashboard/) |

---

## Project Structure

```
IPInfoScanner/
├── src/server/               # TypeScript backend (Node.js)
│   ├── index.ts              # Entry point — starts Hono server
│   ├── app.ts                # Route registration
│   ├── types/index.ts        # All TypeScript interfaces
│   ├── middleware/
│   │   ├── auth.ts           # X-API-Key + Origin/Referer guard
│   │   └── cors.ts           # CORS with explicit header allowlist
│   ├── routes/
│   │   ├── lookup.ts         # GET /lookup, GET+POST /api/v1/scan
│   │   ├── analyze.ts        # POST /analyze, POST /api/v1/analyze
│   │   └── myip.ts           # GET /myip, GET /api/v1/myip
│   ├── services/             # One file per intelligence source
│   │   ├── ipapi.ts
│   │   ├── ipinfo.ts
│   │   ├── proxycheck.ts
│   │   ├── virustotal.ts
│   │   ├── shodan.ts
│   │   ├── whois.ts          # IP RDAP + domain RDAP
│   │   ├── dnsbl.ts          # 35 blacklists via Cloudflare DoH
│   │   ├── tor.ts            # dan.me.uk exit list (30m in-memory cache)
│   │   ├── dns.ts            # Domain → A/AAAA resolution via DoH
│   │   └── gemini.ts         # Google Gemini AI prompt + response
│   ├── cache/
│   │   └── redis.ts          # Scan cache + rate limiter
│   └── utils/
│       ├── config.ts         # Environment variable loader
│       ├── validation.ts     # IP/domain validation
│       └── scoring.ts        # Risk score calculation
│
├── public/                   # Frontend (vanilla HTML/CSS/JS)
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── worker.js                 # Cloudflare Worker (original, still deployed)
├── Dockerfile                # Multi-stage build — node:20-alpine
├── docker-compose.yml        # App + Redis 7
├── .env.example              # Config template
├── package.json
└── tsconfig.json
```

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
- **Backend (Docker)** — Node.js 20, [Hono](https://hono.dev/), TypeScript 5.5, Redis 7
- **Backend (Cloudflare)** — Cloudflare Workers (JavaScript), Cloudflare KV
- **APIs** — ip-api.com, ipinfo.io, proxycheck.io, ipapi.is, VirusTotal, Shodan, RDAP, Cloudflare DoH, Google Gemini

---

## License

MIT — do whatever you want with it.
