<div align="center">

# IP Scanner

![IP Scanner](https://img.shields.io/badge/IP%20Scanner-dev-6b79f5?style=for-the-badge&logo=radar&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-22c55e?style=for-the-badge)

**A fast, single-file IP intelligence tool powered by Cloudflare Workers.**  
Look up any IPv4, IPv6, or domain and get geo, ASN, threat flags, DNSBL, VirusTotal, Shodan, WHOIS, and an AI-powered threat summary — all in one page.

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
| **DNSBL** | Checked against dozens of real-time blacklists |
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

### Privacy & Threat Flags
VPN · Proxy · Tor Exit Node · Data Centre / Hosting · Anonymous / Masked · Mobile Network · Relay · Satellite ISP · Bogon / Private · VT Malicious · DNSBL Listed

### Other Highlights
- **Domain support** — resolves hostnames to IPs, shows IPv4 + IPv6 side-by-side, pulls domain WHOIS and a separate domain VirusTotal report
- **"My IP" detection** — one click to scan your own public IP via the Cloudflare Worker
- **Scan history** — last 50 scans stored in `localStorage` with risk score, country, and timestamp
- **Shareable URLs** — every scan updates `?scan=<ip>` so links go straight to results
- **Gemini AI analysis** — sends a slim data payload to the worker; the worker calls Gemini and streams a plain-English threat summary
- **Raw JSON viewer** — inspect the full API response in-page with a copy button
- **Dark / Light theme** — persists across sessions via `localStorage`
- **Optional API key overrides** — bring your own VirusTotal, Shodan, ipinfo.io, or Proxycheck keys to use personal quotas; stored browser-side only, never sent to the worker except as request headers
- **Zero build step** — a single `index.html` file; no bundler, no Node, no dependencies

---

## Architecture

```
Browser (hunterclipper.com)          Your other apps
    │  Origin/Referer check               │  X-API-Key header
    │                                     │
    └──────────────┬──────────────────────┘
                   │
                   ▼
     Cloudflare Worker  (ipscan.hunter-clipper.workers.dev)
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

The worker fans out all source requests in parallel and returns a single aggregated JSON response. Browser requests from hunterclipper.com are authenticated via Origin/Referer check. Programmatic access from other apps uses an `X-API-Key` header.

---

## Usage

### Self-Hosted (static)
The entire frontend is a single file:

```bash
git clone https://github.com/Hunter-Clipper/IPInfoScanner.git
cd IPInfoScanner
# Open index.html in a browser — or serve it with any static host
python3 -m http.server 8080
```

> The frontend talks to the pre-deployed Cloudflare Worker at `ipscan.hunter-clipper.workers.dev`. No backend setup is required to run the UI.

### API Keys (optional)
All scanning works out of the box via shared worker keys. To use your own quotas, click **⚙ Manage** in the app and paste your keys — they are saved in your browser's `localStorage` and sent only as request headers.

| Key | Free Tier | Get One |
|---|---|---|
| VirusTotal | 500 lookups/day | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| Shodan | Limited (paid for host API) | [shodan.io](https://account.shodan.io/register) |
| ipinfo.io | 50,000/day | [ipinfo.io/signup](https://ipinfo.io/signup) |
| Proxycheck.io | 1,000/day | [proxycheck.io](https://proxycheck.io/dashboard/) |

### Shareable Links
Every lookup updates the URL to `?scan=<ip-or-domain>` — copy from the share bar or just copy the browser URL. Opening the link loads and runs the scan automatically.

---

## Programmatic API Access

The worker exposes all three endpoints to any app via an `X-API-Key` header.

### Setup

1. Generate a key: `openssl rand -hex 32`
2. In the **Cloudflare Dashboard** → Workers & Pages → your worker → **Settings → Variables & Secrets** → Add Secret:

| Name | Value |
|---|---|
| `WORKER_API_KEY` | the key you generated |

### Endpoints

#### `GET /lookup` — full IP / domain scan

```bash
curl -H "X-API-Key: <your-key>" \
  "https://ipscan.hunter-clipper.workers.dev/lookup?ip=1.2.3.4"
```

Add `&fresh=1` to bypass the 6-hour cache. Optionally pass your own intelligence API keys as headers:

| Header | Service |
|---|---|
| `X-VT-Key` | VirusTotal |
| `X-Shodan-Key` | Shodan |
| `X-Ipinfo-Token` | ipinfo.io |
| `X-Proxycheck-Key` | Proxycheck.io |

**Response** — full JSON scan result. Key fields for threat scoring:

```jsonc
{
  "ip": "1.2.3.4",
  "isTorConfirmed": false,
  "sources": {
    "ipapi":      { "proxy": false, "hosting": false, ... },
    "proxycheck": { "1.2.3.4": { "type": "VPN", "risk": 67 } },
    "virustotal": { "data": { "attributes": { "last_analysis_stats": { "malicious": 0 } } } },
    "dnsbl":      { "listed": 0, "checked": 34 },
    ...
  }
}
```

#### `POST /analyze` — AI threat summary

Pass a slim payload extracted from a `/lookup` response. The worker calls Gemini and returns a plain-English analysis.

```bash
curl -X POST \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "country": "RU",
    "isp": "Some Hosting LLC",
    "riskScore": 74,
    "vtMalCount": 6,
    "vtTotal": 94,
    "dnsblListed": 3,
    "dnsblChecked": 34
  }' \
  "https://ipscan.hunter-clipper.workers.dev/analyze"
```

**Response:**
```json
{
  "analysis": "**Threat Assessment**\n...",
  "model": "gemini-3.1-flash-lite"
}
```

#### `GET /myip` — caller's public IP

```bash
curl -H "X-API-Key: <your-key>" \
  "https://ipscan.hunter-clipper.workers.dev/myip"
```

```json
{ "ip": "203.0.113.42" }
```

---

## Sections Explained

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
| **Blacklist / DNSBL** | Per-list pass/fail grid across dozens of real-time blocklists |
| **VirusTotal** | Per-engine results, malicious/suspicious/clean counts, reputation |
| **Domain Intelligence** | (domains only) Domain WHOIS age/registrar/nameservers + domain VT report |
| **AI Analysis** | Gemini-generated plain-English summary of all signals |
| **Raw Data** | Collapsible full JSON response with copy button |

---

## Tech Stack

- **Frontend** — Vanilla HTML/CSS/JS, Inter + JetBrains Mono (Google Fonts), no frameworks
- **Backend** — Cloudflare Workers (JavaScript)
- **APIs** — ip-api.com, ipinfo.io, proxycheck.io, ipapi.is, VirusTotal, Shodan, RDAP, Cloudflare DoH, Google Gemini

---

## License

MIT — do whatever you want with it.
