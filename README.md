<div align="center">

# IP Scanner

![IP Scanner](https://img.shields.io/badge/IP%20Scanner-v1.0.0-6b79f5?style=for-the-badge&logo=radar&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)
![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-22c55e?style=for-the-badge)

**A fast, single-file IP intelligence tool powered by Cloudflare Workers.**  
Look up any IPv4, IPv6, or domain and get geo, ASN, threat flags, DNSBL, VirusTotal, Shodan, WHOIS, and an AI-powered threat summary — all in one page.

**[https://ipinfo.hunterclipper.com](https://ipinfo.hunterclipper.com)**

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
Browser (index.html)
    │
    │  GET /lookup?ip=…   (+ optional X-VT-Key, X-Shodan-Key headers)
    │  GET /myip
    │  POST /analyze
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

The worker fans out all source requests in parallel and returns a single aggregated JSON response. API keys for all services are pre-configured in the worker — the app works out of the box with no setup.

---

## Usage

### Online
Visit the live instance at **[https://ipscan.hunter-clipper.workers.dev](https://ipscan.hunter-clipper.workers.dev)**.

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
