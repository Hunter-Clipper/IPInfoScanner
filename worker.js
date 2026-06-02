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
 *
 * Client headers take priority over worker secrets — users can supply their own keys.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Content-Type': 'application/json',
};

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
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }
    const url  = new URL(request.url);
    const path = url.pathname;
    try {
      if (path === '/myip')    return handleMyIp(request);
      if (path === '/lookup')  return handleLookup(request, url, env);
      if (path === '/analyze') return handleAnalyze(request, env);
      return jsonResponse({ error: 'Not found' }, 404);
    } catch (e) {
      return jsonResponse({ error: 'Worker error', message: e.message }, 500);
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
  return jsonResponse({ ip, workerColo: colo, workerCountry: country });
}

// ── /lookup ────────────────────────────────────────────────────────────────
async function handleLookup(request, url, env = {}) {
  const input = (url.searchParams.get('ip') || request.headers.get('X-IP') || '').trim();
  if (!input) return jsonResponse({ error: 'Missing IP or domain' }, 400);

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
    if (!v4 && !v6) return jsonResponse({ error: `Could not resolve domain: ${input}` }, 400);
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

  return jsonResponse({
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
    sources: { ipapi, ipinfo, proxycheck, virustotal, ipapis, whois, shodan, dnsbl, vtDomain, domainWhois }
  });
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
    `http://ip-api.com/json/${ip}?fields=66846719&_=${bust}`,
    `https://ip-api.com/json/${ip}?fields=66846719&_=${bust}`,
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
    return jsonResponse({ error: 'AI analysis not configured — GEMINI_API_KEY secret not set in worker.' }, 503);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: 'Invalid JSON body' }, 400);
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

  if (!ip) return jsonResponse({ error: 'Missing ip field' }, 400);

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
    '- IP: ' + ip + (resolvedFrom ? ' (resolved from: ' + resolvedFrom + ')' : '') + '\n' +
    '- Location: ' + (city||'—') + ', ' + (country||'—') + '\n' +
    '- ISP: ' + (isp||'—') + ' / Org: ' + (org||'—') + ' / ASN: ' + (asn||'—') + '\n' +
    '- Reverse DNS: ' + (rdns||'—') + '\n' +
    '- IP Type: ' + (ipType||'unknown') + ' | Mobile carrier: ' + isMobile + ' | Hosting/DC: ' + isHosting + '\n' +
    '- Risk score: ' + (riskScore||pcRisk||0) + '/100\n' +
    '- VPN detected: ' + vpnFlag + ' | Proxy: ' + proxyFlag + ' | Tor exit node: ' + torFlag + '\n' +
    '- VirusTotal: ' + (vtMalCount||0) + ' engines flagged this IP as malicious/suspicious out of ' + (vtTotal||0) + ' total\n' +
    '- Blacklists: listed on ' + (dnsblListed||0) + ' of ' + (dnsblChecked||0) + ' DNSBL blacklists' + ((dnsblNames && dnsblNames !== 'none') ? ' (' + dnsblNames + ')' : '') + '\n' +
    '- Shodan open ports: ' + (shodanPorts||'none detected') + ' | OS: ' + (shodanOS||'unknown') + '\n' +
    '- Known CVEs: ' + (shodanVulns||'none') + '\n' +
    '- WHOIS registrant: ' + (whoisRegistrant||'—') + ' | Abuse contact: ' + (whoisAbuse||'—') + '\n\n' +
    // Append domain section only when scanning a domain
    (isDomain ? (
      '\n\nDomain data (separate from IP):\n' +
      '- Domain: ' + (resolvedFrom||'—') + '\n' +
      '- IPv4: ' + (resolvedIpv4||'—') + ' | IPv6: ' + (resolvedIpv6||'—') + '\n' +
      '- Domain Registrar: ' + (domainRegistrar||'—') + '\n' +
      '- Domain Registrant: ' + (domainRegistrant||'—') + '\n' +
      '- Registered: ' + (domainRegistered||'—') + ' | Expires: ' + (domainExpiry||'—') + '\n' +
      '- Domain Status: ' + (domainStatus||'—') + '\n' +
      '- Nameservers: ' + (domainNameservers||'—') + '\n' +
      '- Domain Abuse Email: ' + (domainAbuseEmail||'—') + '\n' +
      '- VT Domain — Malicious: ' + (vtDomainMalicious||0) + ' | Suspicious: ' + (vtDomainSuspicious||0) + ' | Clean: ' + (vtDomainHarmless||0) + '\n' +
      '- VT Domain Reputation: ' + (vtDomainReputation !== null && vtDomainReputation !== undefined ? vtDomainReputation : '—') + '\n' +
      '- VT Domain Categories: ' + (vtDomainCategories||'—') + '\n' +
      '- VT Domain Registrar: ' + (vtDomainRegistrar||'—') + '\n' +
      '- SSL Certificate Issuer: ' + (vtDomainSslIssuer||'—') + ' | Expires: ' + (vtDomainSslExpiry||'—') + '\n' +
      '- Domain Tags: ' + (vtDomainTags||'none') + '\n'
    ) : '') +
    '\nKeep the total response under 350 words. Be specific — a reader should understand exactly why this IP' + (isDomain?' and domain are':'is') + ' or are not a concern.' +
    (isDomain ? ' When a domain is present, analyse BOTH the domain reputation and the underlying IP separately, then give a combined verdict.' : '');

  try {
    const geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
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
        return jsonResponse({ error: 'Invalid API key — check that GEMINI_API_KEY secret is correct in your worker settings.', detail: errMsg }, 401);
      }
      if (geminiRes.status === 403 || errCode === 'PERMISSION_DENIED') {
        return jsonResponse({ error: 'API key does not have permission. Make sure the Gemini API is enabled in your Google Cloud project.', detail: errMsg }, 403);
      }
      if (geminiRes.status === 429 || errCode === 'RESOURCE_EXHAUSTED') {
        return jsonResponse({ error: 'Rate limit hit — free tier allows 15 requests/minute and 1,500/day. Wait 60 seconds and try again.', detail: errMsg }, 429);
      }
      if (geminiRes.status === 400) {
        return jsonResponse({ error: 'Bad request — API key may be invalid or request malformed.', detail: errMsg }, 400);
      }
      return jsonResponse({ error: 'Gemini API error ' + geminiRes.status, detail: errMsg }, 502);
    }

    const data = await geminiRes.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!text) return jsonResponse({ error: 'Gemini returned empty response.' }, 502);

    return jsonResponse({ analysis: text, model: 'gemini-3.1-flash-lite' });

  } catch (e) {
    return jsonResponse({ error: 'Failed to reach Gemini API', message: e.message }, 502);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS_HEADERS });
}

function isValidIp(ip) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return ip.split('.').every(n => parseInt(n) <= 255);
  if (/^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':')) return true;
  return false;
}
