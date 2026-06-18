/**
 * IP Scanner Worker
 * Route: ipscan.hunter-clipper.workers.dev/*
 *
 * All API keys come from the client via request headers — never stored here.
 *
 * Endpoints:
 *   GET  /lookup?ip=1.1.1.1  — full IP + domain intelligence lookup
 *   GET  /myip               — returns caller's real IP from CF headers
 *   POST /analyze            — AI analysis of scan results via Gemini
 *
 * Secrets (set in Cloudflare Worker Settings → Variables & Secrets):
 *   GEMINI_API_KEY       — Google Gemini API key (aistudio.google.com)
 *   VIRUSTOTAL_API_KEY   — VirusTotal API key (virustotal.com)
 *   SHODAN_API_KEY       — Shodan API key (account.shodan.io)
 *   IPINFO_TOKEN         — ipinfo.io token (ipinfo.io/signup)
 *   PROXYCHECK_API_KEY   — proxycheck.io key (proxycheck.io/dashboard)
 *   WORKER_API_KEY       — secret for programmatic access; pass as X-API-Key header
 *                          Generate: openssl rand -hex 32
 *
 * Client headers take priority over worker secrets — users can supply their own keys.
 */

const ALLOWED_ORIGIN = 'https://ipinfo.hunterclipper.com';

// Reflect the exact requesting origin back if it belongs to hunterclipper.com,
// otherwise fall back to the primary domain. This lets any subdomain call the
// worker from a browser without needing to enumerate them all here.
function buildCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowed =
    origin === 'https://hunterclipper.com' ||
    origin.endsWith('.hunterclipper.com')
      ? origin
      : ALLOWED_ORIGIN;
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': '*',
    'Content-Type': 'application/json',
    'Vary': 'Origin',
  };
}

// Returns true if the request originates from hunterclipper.com or any subdomain.
// Origin/Referer headers are spoofable via curl/Postman but stop casual abuse.
function isAllowedOrigin(request) {
  const origin  = request.headers.get('Origin')  || '';
  const referer = request.headers.get('Referer') || '';
  return (
    origin  === 'https://hunterclipper.com'    ||
    origin.endsWith('.hunterclipper.com')       ||
    referer.startsWith('https://hunterclipper.com') ||
    referer.includes('.hunterclipper.com')
  );
}

// Returns true if the request carries a valid WORKER_API_KEY in X-API-Key header.
// Constant-time comparison prevents timing attacks from leaking key length/prefix.
function isValidApiKey(request, env) {
  if (!env.WORKER_API_KEY) return false;
  const provided = request.headers.get('X-API-Key') || '';
  if (provided.length === 0 || provided.length !== env.WORKER_API_KEY.length) return false;
  const enc = new TextEncoder();
  const a = enc.encode(provided);
  const b = enc.encode(env.WORKER_API_KEY);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── Scan result cache (KV-backed) ─────────────────────────────────────────
// Requires a KV namespace bound to the worker as SCAN_CACHE_KV.
// Setup: CF Dashboard → Workers & Pages → your worker →
//        Settings → Bindings → Add KV Namespace → Variable: SCAN_CACHE_KV
const SCAN_CACHE_TTL = 6 * 3600; // 6 hours in seconds

// ── Rate limiting (KV-backed) ──────────────────────────────────────────────
// Requires a KV namespace bound to the worker as RATE_LIMIT_KV.
// Setup: CF Dashboard → Workers & Pages → your worker →
//        Settings → Bindings → Add KV Namespace → Variable: RATE_LIMIT_KV
const RATE_LIMIT_WINDOW  = 3600; // sliding window in seconds (1 hour)
const RATE_LIMIT_LOOKUP  = 30;   // max /lookup requests per IP per hour
const RATE_LIMIT_ANALYZE = 10;   // max /analyze requests per IP per hour

async function checkRateLimit(ip, kv, limit, endpoint) {
  // Fail open if KV namespace is not yet bound — never block legitimate traffic
  // due to a missing binding during initial deployment.
  if (!kv) return true;
  const key = `rl:${endpoint}:${ip}`;
  try {
    const count = parseInt(await kv.get(key) || '0');
    if (count >= limit) return false;
    await kv.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW });
    return true;
  } catch { return true; } // fail open on KV errors
}

// ── Tor exit node list cache (30 min TTL) ─────────────────────────────────
let torListCache    = null;
let torListFetchedAt = 0;
const TOR_CACHE_TTL = 30 * 60 * 1000;
const TOR_LIST_URL  = 'https://www.dan.me.uk/torlist/?full';

// ── DNSBL blacklist servers to check ─────────────────────────────────────
// Only lists that:
//   1. Are still active and maintained
//   2. Work correctly via public DNS resolvers (Cloudflare DoH)
//   3. Return standard 127.x.x.x codes for listings
//
// EXCLUDED (require dedicated resolver — return 127.255.255.254 error via public DNS):
//   zen/xbl/sbl/pbl.spamhaus.org, cbl.abuseat.org
// EXCLUDED (shut down June 2024): all SORBS variants
// EXCLUDED (return wildcard/garbage): dnsbl.justspam.org, drone.abuse.ch, httpbl.abuse.ch
//
// Format: [hostname, display name]
const DNSBL_LISTS = [
  ['bl.spamcop.net',              'SpamCop'],
  ['b.barracudacentral.org',      'Barracuda'],
  ['dnsbl-1.uceprotect.net',      'UCEPROTECT L1'],
  ['dnsbl-2.uceprotect.net',      'UCEPROTECT L2'],
  ['dnsbl-3.uceprotect.net',      'UCEPROTECT L3'],
  ['ix.dnsbl.manitu.net',         'Manitu'],
  ['dnsbl.dronebl.org',           'DroneBL'],
  ['psbl.surriel.com',            'PSBL'],
  ['db.wpbl.info',                'WPBL'],
  ['bl.0spam.org',                '0spam'],
  ['rbl.0spam.org',               '0spam RBL'],
  ['all.s5h.net',                 'S5H'],
  ['spam.dnsbl.anonmails.de',     'Anonmails'],
  ['spamrbl.imp.ch',              'IMP Spam RBL'],
  ['wormrbl.imp.ch',              'IMP Worm RBL'],
  ['virus.rbl.jp',                'RBL.JP Virus'],
  ['bl.spamcop.net',              'SpamCop BL'],
  ['combined.abuse.ch',           'Abuse.ch Combined'],
  ['spam.abuse.ch',               'Abuse.ch Spam'],
  ['korea.services.net',          'Korea Services'],
  ['rbl.metunet.com',             'Metunet'],
  ['dnsbl.inps.de',               'INPS'],
  ['bogons.cymru.com',            'Bogons Cymru'],
  ['dnsbl.tornevall.org',         'Tornevall'],
  ['ubl.lashback.com',            'Lashback UBL'],
  ['ubl.unsubscore.com',          'Unsubscore'],
  ['multi.surbl.org',             'SURBL Multi'],
  ['dnsbl.cobion.com',            'Cobion'],
  ['bl.mailspike.net',            'Mailspike BL'],
  ['z.mailspike.net',             'Mailspike Z'],
  ['singular.ttk.pte.hu',         'TTK PTE'],
  ['spamsources.fabel.dk',        'Fabel Spamsources'],
  ['virbl.dnsbl.bit.nl',          'VIRBL'],
  ['rbl.spamlab.com',             'SpamLab'],
  ['dnsbl.anticaptcha.net',       'AntiCaptcha'],
  ['ips.backscatterer.org',       'Backscatterer'],
];


// ── Router ─────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: buildCorsHeaders(request) });
    }
    if (!isAllowedOrigin(request) && !isValidApiKey(request, env)) {
      return jsonResponse({ error: 'Forbidden' }, 403, request);
    }
    const clientIp = request.headers.get('CF-Connecting-IP') || 'unknown';
    const url  = new URL(request.url);
    const path = url.pathname;
    try {
      if (path === '/lookup') {
        if (!await checkRateLimit(clientIp, env.RATE_LIMIT_KV, RATE_LIMIT_LOOKUP, 'lookup'))
          return jsonResponse({ error: 'Rate limit exceeded — max 30 scans per hour.' }, 429, request);
        return handleLookup(request, url, env, ctx);
      }
      if (path === '/analyze') {
        if (!await checkRateLimit(clientIp, env.RATE_LIMIT_KV, RATE_LIMIT_ANALYZE, 'analyze'))
          return jsonResponse({ error: 'Rate limit exceeded — max 10 AI analyses per hour.' }, 429, request);
        return handleAnalyze(request, env);
      }
      if (path === '/myip')    return handleMyIp(request);
      return jsonResponse({ error: 'Not found' }, 404, request);
    } catch (e) {
      return jsonResponse({ error: 'Worker error', message: e.message }, 500, request);
    }
  }
};

// ── /myip ──────────────────────────────────────────────────────────────────
function handleMyIp(request) {
  const ip =
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown';
  // Also return the Cloudflare colo so the frontend knows where the worker is
  const colo   = request.cf?.colo   || 'Unknown';
  const country= request.cf?.country || 'Unknown';
  return jsonResponse({ ip, workerColo: colo, workerCountry: country }, 200, request);
}

// ── /lookup ────────────────────────────────────────────────────────────────
async function handleLookup(request, url, env = {}, ctx = null) {
  const input = (url.searchParams.get('ip') || request.headers.get('X-IP') || '').trim();
  if (!input) return jsonResponse({ error: 'Missing IP or domain' }, 400, request);

  const fresh    = url.searchParams.get('fresh') === '1';
  const cacheKv  = env.SCAN_CACHE_KV || null;
  const cacheKey = `scan:${input.toLowerCase()}`;

  // Cache read — skip on fresh=1 or if KV not yet bound
  if (!fresh && cacheKv) {
    try {
      const cached = await cacheKv.get(cacheKey, { type: 'json' });
      if (cached) return jsonResponse({ ...cached, _cached: true }, 200, request);
    } catch { /* fail open */ }
  }

  let ip = input;
  let resolvedFrom  = null;
  let resolvedIpv4  = null;
  let resolvedIpv6  = null;
  let isDomain      = false;

  if (!isValidIp(input)) {
    // Input is a domain — resolve both A (IPv4) and AAAA (IPv6) records in parallel
    isDomain = true;
    const [v4, v6] = await Promise.all([
      resolveDomain(input, 'A'),
      resolveDomain(input, 'AAAA'),
    ]);
    if (!v4 && !v6) return jsonResponse({ error: `Could not resolve domain: ${input}` }, 400, request);
    resolvedFrom = input;
    resolvedIpv4 = v4 || null;
    resolvedIpv6 = v6 || null;
    // Primary scan IP: prefer IPv4, fall back to IPv6
    ip = v4 || v6;
  }

  // Client-supplied keys take priority; fall back to worker secrets
  const vtKey         = request.headers.get('X-VT-Key')         || env.VIRUSTOTAL_API_KEY  || '';
  const ipinfoToken   = request.headers.get('X-Ipinfo-Token')   || env.IPINFO_TOKEN         || '';
  const proxycheckKey = request.headers.get('X-Proxycheck-Key') || env.PROXYCHECK_API_KEY   || '';
  const shodanKey     = request.headers.get('X-Shodan-Key')     || env.SHODAN_API_KEY       || '';
  const bust = Date.now();

  // Strip protocol/path from domain for clean lookups
  const cleanDomain = resolvedFrom
    ? resolvedFrom.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim()
    : null;

  const workerColo    = request.cf?.colo    || 'Unknown';
  const workerCountry = request.cf?.country || 'Unknown';

  // All sources fire in parallel — domain checks only run when input was a domain
  const [
    ipapiData, ipinfoData, proxycheckData, vtIpData, ipapisData,
    torResult, whoisData, shodanData, dnsblData,
    vtDomainData, domainWhoisData,
  ] = await Promise.allSettled([
    fetchIpApi(ip, bust),
    fetchIpinfo(ip, ipinfoToken, bust),
    fetchProxycheck(ip, proxycheckKey, bust),
    vtKey ? fetchVirusTotal(ip, vtKey)              : Promise.resolve(null),
    fetchIpapis(ip, bust),
    isTorExit(ip),
    fetchWhois(ip),
    shodanKey ? fetchShodan(ip, shodanKey)          : Promise.resolve(null),
    checkDnsbl(ip),
    // Domain-specific checks
    (isDomain && vtKey && cleanDomain) ? fetchVtDomain(cleanDomain, vtKey) : Promise.resolve(null),
    isDomain && cleanDomain            ? fetchDomainWhois(cleanDomain)     : Promise.resolve(null),
  ]);

  const ipapi       = ipapiData.status       === 'fulfilled' ? ipapiData.value       : null;
  const ipinfo      = ipinfoData.status      === 'fulfilled' ? ipinfoData.value      : null;
  const proxycheck  = proxycheckData.status  === 'fulfilled' ? proxycheckData.value  : null;
  const virustotal  = vtIpData.status        === 'fulfilled' ? vtIpData.value        : null;
  const ipapis      = ipapisData.status      === 'fulfilled' ? ipapisData.value      : null;
  const isTor       = torResult.status       === 'fulfilled' ? torResult.value       : false;
  const whois       = whoisData.status       === 'fulfilled' ? whoisData.value       : null;
  const shodan      = shodanData.status      === 'fulfilled' ? shodanData.value      : null;
  const dnsbl       = dnsblData.status       === 'fulfilled' ? dnsblData.value       : null;
  const vtDomain    = vtDomainData.status    === 'fulfilled' ? vtDomainData.value    : null;
  const domainWhois = domainWhoisData.status === 'fulfilled' ? domainWhoisData.value : null;

  const result = {
    ip,
    resolvedFrom,
    resolvedIpv4,
    resolvedIpv6,
    isDomain,
    timestamp: bust,
    isTorConfirmed: isTor,
    torListSize: torListCache ? torListCache.size : 0,
    workerColo,
    workerCountry,
    sources: { ipapi, ipinfo, proxycheck, virustotal, ipapis, whois, shodan, dnsbl, vtDomain, domainWhois },
    _cached: false,
    _cachedAt: Date.now(),
  };

  // Cache write — non-blocking so it doesn't delay the response
  if (cacheKv && ctx) {
    ctx.waitUntil(
      cacheKv.put(cacheKey, JSON.stringify(result), { expirationTtl: SCAN_CACHE_TTL }).catch(() => {})
    );
  }

  return jsonResponse(result, 200, request);
}

// ── WHOIS ──────────────────────────────────────────────────────────────────
async function fetchWhois(ip) {
  try {
    // whois.arin.net RDAP — structured JSON, no key required
    const r = await fetch(`https://rdap.arin.net/registry/ip/${ip}`, {
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(6000),
      cf: { cacheEverything: false }
    });
    if (!r.ok) {
      const r2 = await fetch(`https://rdap.db.ripe.net/ip/${ip}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(6000),
        cf: { cacheEverything: false }
      });
      if (!r2.ok) return null;
      return parseRdap(await r2.json(), 'RIPE');
    }
    return parseRdap(await r.json(), 'ARIN');
  } catch { return null; }
}

function parseRdap(data, registry) {
  // Extract useful fields from RDAP response
  const getName = (entity) => {
    const vcard = entity?.vcardArray?.[1] || [];
    const fn = vcard.find(f => f[0] === 'fn');
    return fn ? fn[3] : entity?.handle || null;
  };
  const getEmail = (entity) => {
    const vcard = entity?.vcardArray?.[1] || [];
    const email = vcard.find(f => f[0] === 'email');
    return email ? email[3] : null;
  };

  const entities    = data.entities || [];
  const registrant  = entities.find(e => e.roles?.includes('registrant'));
  const abuse       = entities.find(e => e.roles?.includes('abuse'));
  const tech        = entities.find(e => e.roles?.includes('technical'));

  return {
    registry,
    handle:        data.handle        || null,
    name:          data.name          || null,
    network:       data.cidr0_cidrs?.[0] ? `${data.cidr0_cidrs[0].v4prefix}/${data.cidr0_cidrs[0].length}` : (data.startAddress && data.endAddress ? `${data.startAddress} – ${data.endAddress}` : null),
    startAddress:  data.startAddress  || null,
    endAddress:    data.endAddress    || null,
    country:       data.country       || null,
    type:          data.type          || null,
    registrant:    registrant ? getName(registrant) : null,
    abuseContact:  abuse      ? (getEmail(abuse) || getName(abuse)) : null,
    techContact:   tech       ? (getEmail(tech)  || getName(tech))  : null,
    registered:    data.events?.find(e => e.eventAction === 'registration')?.eventDate || null,
    lastChanged:   data.events?.find(e => e.eventAction === 'last changed')?.eventDate || null,
    remarks:       data.remarks?.[0]?.description?.join(' ') || null,
  };
}

// ── Shodan ─────────────────────────────────────────────────────────────────
async function fetchShodan(ip, apiKey) {
  try {
    const r = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`,
      { cf: { cacheEverything: false } }
    );
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 404) return { error: 'not_found' };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: 'api_error', status: r.status };
    const data = await r.json();
    // Return a trimmed summary — full response can be huge
    return {
      ip:            data.ip_str,
      hostnames:     data.hostnames     || [],
      domains:       data.domains       || [],
      country:       data.country_name  || null,
      city:          data.city          || null,
      org:           data.org           || null,
      isp:           data.isp           || null,
      asn:           data.asn           || null,
      os:            data.os            || null,
      tags:          data.tags          || [],
      vulns:         data.vulns         ? Object.keys(data.vulns) : [],
      lastUpdate:    data.last_update   || null,
      ports:         data.ports         || [],
      services: (data.data || []).slice(0, 20).map(s => ({
        port:      s.port,
        transport: s.transport,
        product:   s.product   || null,
        version:   s.version   || null,
        cpe:       s.cpe       || null,
        banner:    s.data      ? s.data.substring(0, 200) : null,
      })),
    };
  } catch (e) {
    return { error: 'network', message: e.message };
  }
}

// ── DNSBL blacklist check ──────────────────────────────────────────────────
// Standard DNSBL protocol:
//   1. Reverse IP octets: 1.2.3.4 → 4.3.2.1
//   2. Prepend to list hostname: 4.3.2.1.bl.spamcop.net
//   3. A lookup: NXDOMAIN (status 3) = clean, A record = listed
//
// Validation rules to avoid false positives:
//   - Return code MUST be in 127.0.0.0/8 (anything else = defunct/broken list)
//   - 127.255.255.254 = Spamhaus "public resolver blocked" error — NOT a listing
//   - 127.255.255.255 = generic query error — NOT a listing
//   - 127.0.0.1       = reserved — NOT a valid listing code
//   - Per-list 5s timeout so dead lists don't stall everything

// Known error return codes — must NOT be counted as listings
const DNSBL_ERROR_CODES = new Set([
  '127.255.255.254', // Spamhaus/CBL public resolver restriction
  '127.255.255.255', // Generic DNSBL query error
  '127.0.0.1',       // Loopback — reserved, never a valid listing
]);

async function checkOneDnsbl(reversed, host, name) {
  const query = `${reversed}.${host}`;
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(query)}&type=A`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(3000),
        cf: { cacheEverything: false },
      }
    );
    if (!r.ok) return { name, listed: false, error: true };
    const data = await r.json();

    // Only NOERROR (0) can be a real listing; NXDOMAIN (3) = definitely clean
    if (data.Status !== 0) return { name, listed: false };

    // Filter to A records only (type 1)
    const answers = (data.Answer || []).filter(a => a.type === 1);
    if (!answers.length) return { name, listed: false };

    const returnIp = answers[0].data;

    // Must be in 127.0.0.0/8 — anything else is a misconfigured/defunct list
    if (!returnIp || !returnIp.startsWith('127.')) {
      return { name, listed: false, error: true, defunctResponse: returnIp };
    }

    // Filter known error codes
    if (DNSBL_ERROR_CODES.has(returnIp)) {
      return { name, listed: false, error: true, errorCode: returnIp };
    }

    // Real listing — decode common return codes for display
    const codeDesc = decodeDnsblCode(host, returnIp);
    return { name, listed: true, returnCode: returnIp, codeDesc };

  } catch (e) {
    // Timeout or network error
    return { name, listed: false, error: true, timeout: e.name === 'TimeoutError' };
  }
}

function decodeDnsblCode(host, code) {
  // Common return code meanings across major lists
  const generic = {
    '127.0.0.2': 'Spam source',
    '127.0.0.3': 'Spam source (confirmed)',
    '127.0.0.4': 'Exploits / botnet',
    '127.0.0.5': 'Botnet C&C',
    '127.0.0.6': 'Virus / malware',
    '127.0.0.7': 'DDoS drone',
    '127.0.0.8': 'Rogue server',
    '127.0.0.9': 'Brute force',
    '127.0.0.10': 'Dynamic IP / dialup',
    '127.0.0.11': 'Spam support service',
    '127.0.0.14': 'Proxy',
    '127.0.0.15': 'Compromised server',
  };
  return generic[code] || `Listed (${code})`;
}

async function checkDnsbl(ip) {
  // IPv4 only — DNSBL doesn't support IPv6 in this form
  if (!ip || ip.includes(':')) return { checked: 0, listed: 0, lists: [], ipv6: true };

  const reversed = ip.split('.').reverse().join('.');

  // Deduplicate the list (remove any accidental duplicates by hostname)
  const seen = new Set();
  const uniqueLists = DNSBL_LISTS.filter(([host]) => {
    if (seen.has(host)) return false;
    seen.add(host);
    return true;
  });

  const checks = await Promise.allSettled(
    uniqueLists.map(([host, name]) => checkOneDnsbl(reversed, host, name))
  );

  const results = checks.map((c, i) =>
    c.status === 'fulfilled'
      ? c.value
      : { name: uniqueLists[i][1], listed: false, error: true }
  );

  return {
    checked: results.filter(r => !r.error).length,
    listed:  results.filter(r => r.listed).length,
    total:   results.length,
    lists:   results,
  };
}

// ── Domain → IP resolution ─────────────────────────────────────────────────
async function resolveDomain(domain, type = 'A') {
  domain = domain.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
  const dnsType  = type === 'AAAA' ? 28 : 1; // DNS record type numbers
  try {
    const r = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000),
        cf: { cacheEverything: false }
      }
    );
    if (!r.ok) return null;
    const data = await r.json();
    const rec  = (data.Answer || []).find(a => a.type === dnsType);
    return rec ? rec.data : null;
  } catch { return null; }
}

// ── VirusTotal domain scan ─────────────────────────────────────────────────
async function fetchVtDomain(domain, apiKey) {
  try {
    const r = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      {
        headers: { 'x-apikey': apiKey },
        signal: AbortSignal.timeout(10000),
        cf: { cacheEverything: false }
      }
    );
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 404) return { error: 'not_found' };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: 'api_error', status: r.status };
    const data = await r.json();
    const attr = data?.data?.attributes || {};
    const stats = attr?.last_analysis_stats || {};
    return {
      domain,
      reputation:       attr.reputation             ?? null,
      categories:       attr.categories             || {},
      registrar:        attr.registrar              || null,
      creationDate:     attr.creation_date          || null,
      lastUpdate:       attr.last_modification_date || null,
      lastAnalysis:     attr.last_analysis_date     || null,
      malicious:        stats.malicious             || 0,
      suspicious:       stats.suspicious            || 0,
      harmless:         stats.harmless              || 0,
      undetected:       stats.undetected            || 0,
      tags:             attr.tags                   || [],
      popularityRanks:  attr.popularity_ranks       || {},
      lastHttpsCert:    attr.last_https_certificate ? {
        issuer:  attr.last_https_certificate?.issuer?.CN || null,
        subject: attr.last_https_certificate?.subject?.CN || null,
        validTo: attr.last_https_certificate?.validity?.not_after || null,
      } : null,
    };
  } catch (e) {
    return { error: 'network', message: e.message };
  }
}

// ── Domain WHOIS ──────────────────────────────────────────────────────────
// Uses the free whois.iana.org JSON endpoint for registrar/creation info
async function fetchDomainWhois(domain) {
  // Try multiple RDAP endpoints in order — different registrars/TLDs are
  // served by different RDAP servers. We try the most reliable ones first.
  const endpoints = [
    // rdap.org acts as a universal proxy — routes to the right RDAP server
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    // IANA bootstrap lookup (good for new gTLDs like .party, .club, etc.)
    `https://rdap.iana.org/domain/${encodeURIComponent(domain)}`,
    // Verisign handles .com, .net
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
  ];

  for (const url of endpoints) {
    try {
      const r = await fetch(url, {
        headers: { 'Accept': 'application/rdap+json, application/json' },
        signal: AbortSignal.timeout(5000),
        cf: { cacheEverything: false }
      });
      if (!r.ok) continue;
      const data = await r.json();
      // Validate we got domain data (not a TLD registry record)
      if (data.objectClassName === 'domain' || data.ldhName) {
        return parseDomainRdap(data);
      }
    } catch { /* try next */ }
  }
  return null;
}

function parseDomainRdap(data) {
  const getDate = (type) => {
    // Handle both eventAction formats (standard RDAP vs some registrar variants)
    return data.events?.find(e =>
      e.eventAction === type ||
      e.eventAction === type.replace(' ', '_')
    )?.eventDate || null;
  };

  const getVcardField = (entity, fieldName) => {
    // vcardArray can be [string, array] or just an array of objects
    const vcard = entity?.vcardArray?.[1] || entity?.vcardArray || [];
    const field = Array.isArray(vcard)
      ? vcard.find(f => Array.isArray(f) ? f[0] === fieldName : f.name === fieldName)
      : null;
    if (!field) return null;
    // Standard RDAP format: [name, params, type, value]
    if (Array.isArray(field)) return field[3] || null;
    // Object format: { name, values }
    return field.values?.[0] || null;
  };

  const getName = (entity) => {
    return getVcardField(entity, 'fn') || entity?.handle || null;
  };
  const getEmail = (entity) => {
    return getVcardField(entity, 'email');
  };

  const entities   = data.entities || [];
  const registrant = entities.find(e => e.roles?.includes('registrant'));
  const registrar  = entities.find(e => e.roles?.includes('registrar'));
  const abuse      = entities.find(e => e.roles?.includes('abuse'));

  // Nameservers can be in different formats
  const nameservers = (data.nameservers || data.nameServer || [])
    .map(ns => ns.ldhName || ns.unicodeName || ns)
    .filter(ns => typeof ns === 'string' && ns.length > 0);

  return {
    domain:      data.ldhName || data.unicodeName || null,
    status:      Array.isArray(data.status) ? data.status.join(', ') : (data.status || null),
    registrar:   registrar ? getName(registrar) : null,
    registrant:  registrant ? getName(registrant) : null,
    abuseEmail:  abuse ? getEmail(abuse) : null,
    nameservers,
    registered:  getDate('registration'),
    updated:     getDate('last changed'),
    expiry:      getDate('expiration'),
  };
}

// ── Tor exit list ──────────────────────────────────────────────────────────
async function fetchTorList() {
  const now = Date.now();
  if (torListCache && (now - torListFetchedAt) < TOR_CACHE_TTL) return torListCache;
  try {
    const r = await fetch(TOR_LIST_URL, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IPScanner/1.0)', 'Accept': 'text/plain' },
      signal: AbortSignal.timeout(8000),
      cf: { cacheEverything: false }
    });
    if (!r.ok) return torListCache || new Set();
    const text = await r.text();
    const ips  = text.split('\n').map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
    torListCache    = new Set(ips);
    torListFetchedAt = now;
    return torListCache;
  } catch { return torListCache || new Set(); }
}

async function isTorExit(ip) {
  const list = await fetchTorList();
  return list.has(ip);
}

// ── ipapi.is ───────────────────────────────────────────────────────────────
async function fetchIpApi(ip, bust) {
  // ip-api.com blocks some Cloudflare IPs on the free JSON endpoint.
  // Use the pro-fields endpoint with a fallback to the standard one.
  const urls = [
    `https://ip-api.com/json/${ip}?fields=66846719&_=${bust}`,
    `http://ip-api.com/json/${ip}?fields=66846719&_=${bust}`,
  ];
  for (const url of urls) {
    try {
      const r = await fetch(url, { cf: { cacheEverything: false }, signal: AbortSignal.timeout(6000) });
      if (r.ok) return r.json();
    } catch { /* try next */ }
  }
  return null;
}

async function fetchIpinfo(ip, token, bust) {
  const p = token ? `?token=${token}&_=${bust}` : `?_=${bust}`;
  try {
    const r = await fetch(`https://ipinfo.io/${ip}/json${p}`, {
      signal: AbortSignal.timeout(5000),
      cf: { cacheEverything: false }
    });
    if (!r.ok) return null;
    return r.json();
  } catch { return null; }
}

async function fetchProxycheck(ip, apiKey, bust) {
  const k = apiKey ? `&key=${apiKey}` : '';
  try {
    const r = await fetch(`https://proxycheck.io/v2/${ip}?vpn=1&asn=1&node=1&time=1&inf=1&risk=1&port=1&seen=1${k}&_=${bust}`, {
      signal: AbortSignal.timeout(5000),
      cf: { cacheEverything: false }
    });
    if (!r.ok) return null;
    return r.json();
  } catch { return null; }
}

async function fetchVirusTotal(ip, apiKey) {
  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(8000),
      cf: { cacheEverything: false }
    });
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: 'api_error', status: r.status };
    return r.json();
  } catch { return { error: 'timeout' }; }
}

async function fetchIpapis(ip, bust) {
  try {
    const r = await fetch(`https://api.ipapi.is/?q=${ip}&_=${bust}`, {
      signal: AbortSignal.timeout(5000),
      cf: { cacheEverything: false }
    });
    if (!r.ok) return null;
    return r.json();
  } catch { return null; }
}

// ── Helpers ────────────────────────────────────────────────────────────────
// ── /analyze — Gemini AI analysis ────────────────────────────────────────────
async function handleAnalyze(request, env) {
  // Key lives in encrypted Worker secret — never touches the browser
  const apiKey = env.GEMINI_API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: 'AI analysis not configured — GEMINI_API_KEY secret not set in worker.' }, 503, request);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400, request);
  }

  // Accept a pre-summarised payload from the frontend (not the full raw sources)
  // This keeps the Gemini prompt small and fast
  const {
    ip, resolvedFrom,
    country, city, isp, org, asn, rdns,
    ipType, isMobile, isHosting, isProxy, isVpn, isTor,
    riskScore, pcRisk,
    vtMalCount, vtTotal,
    dnsblListed, dnsblChecked, dnsblNames,
    shodanPorts, shodanVulns, shodanOS,
    whoisRegistrant, whoisAbuse,
    // Domain fields
    isDomain, resolvedIpv4, resolvedIpv6,
    domainRegistrar, domainRegistrant, domainRegistered, domainExpiry,
    domainStatus, domainNameservers, domainAbuseEmail,
    vtDomainMalicious, vtDomainSuspicious, vtDomainHarmless,
    vtDomainReputation, vtDomainCategories, vtDomainRegistrar,
    vtDomainSslIssuer, vtDomainSslExpiry, vtDomainTags,
  } = body;

  if (!ip || typeof ip !== 'string') return jsonResponse({ error: 'Missing ip field' }, 400, request);
  // Reject ip values that contain characters not valid in an IP address or domain name.
  // This is the single most important field — it appears first in the prompt.
  if (!/^[a-zA-Z0-9.\-:]+$/.test(ip)) return jsonResponse({ error: 'Invalid ip field' }, 400, request);

  // Sanitize all user-supplied string fields before prompt interpolation.
  // Strips newlines/tabs (the primary injection vector — they break prompt structure),
  // collapses whitespace runs, and caps length so the prompt stays bounded.
  const safe = (val, max = 120) =>
    typeof val === 'string'
      ? val.replace(/[\r\n\t]/g, ' ').replace(/\s{2,}/g, ' ').trim().substring(0, max)
      : (val ?? '—');

  const torFlag   = isTor   ? 'YES — confirmed Tor exit node' : 'No';
  const vpnFlag   = isVpn   ? 'YES' : 'No';
  const proxyFlag = isProxy ? 'YES' : 'No';

  const prompt = 'You are a cybersecurity analyst writing for a technical but non-specialist audience. ' +
    (isDomain
      ? 'Analyse both the domain and IP intelligence data below. The domain and its resolved IP may have different risk profiles — assess both, then give a combined verdict. '
      : 'Analyse the IP intelligence data below. '
    ) +
    'Do not just label it safe or dangerous — explain WHY based on the specific data points. ' +
    'If something is clean, explain what that means. If something is suspicious, explain what it indicates. ' +
    'Use plain English. Structure your response with exactly these four sections:\n\n' +
    '**Threat Assessment**\n' +
    'Overall risk level (Low / Medium / High / Critical) and 2-3 sentences explaining what this IP is and why it received that rating. Reference specific data to justify your conclusion.\n\n' +
    '**Key Findings**\n' +
    'Bullet points covering the most significant facts. For each finding, briefly explain what it means — e.g. do not just say "listed on SpamCop", explain that this means the IP has been reported for sending unsolicited email. Include both red flags AND reassuring findings so the reader gets a balanced picture.\n\n' +
    '**Context**\n' +
    '1-2 sentences giving broader context — what type of operator typically uses this IP range, whether the findings are consistent with each other, or any caveats worth knowing.\n\n' +
    '**Recommendation**\n' +
    '1-2 clear action sentences — what should someone do if they see this IP in their firewall logs, mail server, or web traffic?\n\n' +
    'IP data:\n' +
    '- IP: ' + safe(ip, 45) + (resolvedFrom ? ' (resolved from: ' + safe(resolvedFrom, 253) + ')' : '') + '\n' +
    '- Location: ' + safe(city) + ', ' + safe(country) + '\n' +
    '- ISP: ' + safe(isp) + ' / Org: ' + safe(org) + ' / ASN: ' + safe(asn, 40) + '\n' +
    '- Reverse DNS: ' + safe(rdns) + '\n' +
    '- IP Type: ' + safe(ipType, 40) + ' | Mobile carrier: ' + !!isMobile + ' | Hosting/DC: ' + !!isHosting + '\n' +
    '- Risk score: ' + (parseInt(riskScore)||parseInt(pcRisk)||0) + '/100\n' +
    '- VPN detected: ' + vpnFlag + ' | Proxy: ' + proxyFlag + ' | Tor exit node: ' + torFlag + '\n' +
    '- VirusTotal: ' + (parseInt(vtMalCount)||0) + ' engines flagged this IP as malicious/suspicious out of ' + (parseInt(vtTotal)||0) + ' total\n' +
    '- Blacklists: listed on ' + (parseInt(dnsblListed)||0) + ' of ' + (parseInt(dnsblChecked)||0) + ' DNSBL blacklists' + ((dnsblNames && dnsblNames !== 'none') ? ' (' + safe(dnsblNames, 200) + ')' : '') + '\n' +
    '- Shodan open ports: ' + safe(shodanPorts, 200) + ' | OS: ' + safe(shodanOS, 60) + '\n' +
    '- Known CVEs: ' + safe(shodanVulns, 200) + '\n' +
    '- WHOIS registrant: ' + safe(whoisRegistrant) + ' | Abuse contact: ' + safe(whoisAbuse) + '\n\n' +
    // Append domain section only when scanning a domain
    (isDomain ? (
      '\n\nDomain data (separate from IP):\n' +
      '- Domain: ' + safe(resolvedFrom, 253) + '\n' +
      '- IPv4: ' + safe(resolvedIpv4, 45) + ' | IPv6: ' + safe(resolvedIpv6, 45) + '\n' +
      '- Domain Registrar: ' + safe(domainRegistrar) + '\n' +
      '- Domain Registrant: ' + safe(domainRegistrant) + '\n' +
      '- Registered: ' + safe(domainRegistered, 40) + ' | Expires: ' + safe(domainExpiry, 40) + '\n' +
      '- Domain Status: ' + safe(domainStatus, 200) + '\n' +
      '- Nameservers: ' + safe(domainNameservers, 200) + '\n' +
      '- Domain Abuse Email: ' + safe(domainAbuseEmail) + '\n' +
      '- VT Domain — Malicious: ' + (parseInt(vtDomainMalicious)||0) + ' | Suspicious: ' + (parseInt(vtDomainSuspicious)||0) + ' | Clean: ' + (parseInt(vtDomainHarmless)||0) + '\n' +
      '- VT Domain Reputation: ' + (vtDomainReputation !== null && vtDomainReputation !== undefined ? parseInt(vtDomainReputation) : '—') + '\n' +
      '- VT Domain Categories: ' + safe(vtDomainCategories, 200) + '\n' +
      '- VT Domain Registrar: ' + safe(vtDomainRegistrar) + '\n' +
      '- SSL Certificate Issuer: ' + safe(vtDomainSslIssuer) + ' | Expires: ' + safe(vtDomainSslExpiry, 40) + '\n' +
      '- Domain Tags: ' + safe(vtDomainTags, 200) + '\n'
    ) : '') +
    '\nKeep the total response under 350 words. Be specific — a reader should understand exactly why this IP' + (isDomain?' and domain are':'is') + ' or are not a concern.' +
    (isDomain ? ' When a domain is present, analyse BOTH the domain reputation and the underlying IP separately, then give a combined verdict.' : '');

  try {
    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.3,   // low temp = factual, consistent
            maxOutputTokens: 1000,
          },
          safetySettings: [
            { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
            { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_NONE' },
          ],
        }),
        cf: { cacheEverything: false },
      }
    );

    if (!geminiRes.ok) {
      const err = await geminiRes.json().catch(() => ({}));
      const errMsg = err?.error?.message || err?.message || JSON.stringify(err);
      const errCode = err?.error?.code || err?.error?.status || '';

      if (geminiRes.status === 401 || errCode === 'UNAUTHENTICATED') {
        return jsonResponse({ error: 'Invalid API key — check that GEMINI_API_KEY secret is correct in your worker settings.', detail: errMsg }, 401, request);
      }
      if (geminiRes.status === 403 || errCode === 'PERMISSION_DENIED') {
        return jsonResponse({ error: 'API key does not have permission. Make sure the Gemini API is enabled in your Google Cloud project.', detail: errMsg }, 403, request);
      }
      if (geminiRes.status === 429 || errCode === 'RESOURCE_EXHAUSTED') {
        return jsonResponse({ error: 'Rate limit hit — free tier allows 15 requests/minute and 1,500/day. Wait 60 seconds and try again.', detail: errMsg }, 429, request);
      }
      if (geminiRes.status === 400) {
        return jsonResponse({ error: 'Bad request — API key may be invalid or request malformed.', detail: errMsg }, 400, request);
      }
      return jsonResponse({ error: 'Gemini API error ' + geminiRes.status, detail: errMsg }, 502, request);
    }

    const data = await geminiRes.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) return jsonResponse({ error: 'Gemini returned empty response.' }, 502, request);

    return jsonResponse({ analysis: text, model: 'gemini-3.1-flash-lite' }, 200, request);

  } catch (e) {
    return jsonResponse({ error: 'Failed to reach Gemini API', message: e.message }, 502, request);
  }
}

function jsonResponse(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), { status, headers: buildCorsHeaders(request) });
}

function isValidIp(ip) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return ip.split('.').every(n => parseInt(n) <= 255);
  if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) return true;
  return false;
}
