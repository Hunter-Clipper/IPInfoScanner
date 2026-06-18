import type { Context } from 'hono';
import type { AppConfig, ScanResult } from '../types/index.js';
import type Redis from 'ioredis';
import { isValidIp, looksLikeDomain, cleanDomainInput } from '../utils/validation.js';
import { checkRateLimit, cacheGet, cacheSet } from '../cache/redis.js';
import { validateClientKey } from '../middleware/auth.js';
import { fetchIpApi }      from '../services/ipapi.js';
import { fetchIpinfo }     from '../services/ipinfo.js';
import { fetchProxycheck } from '../services/proxycheck.js';
import { fetchVirusTotal, fetchVtDomain } from '../services/virustotal.js';
import { fetchIpapis }     from '../services/ipapis.js';
import { fetchShodan }     from '../services/shodan.js';
import { fetchWhois, fetchDomainWhois } from '../services/whois.js';
import { checkDnsbl }      from '../services/dnsbl.js';
import { isTorExit, getTorListSize } from '../services/tor.js';
import { resolveDomain }   from '../services/dns.js';

interface LookupOptions {
  vtKey:         string;
  ipinfoToken:   string;
  proxycheckKey: string;
  shodanKey:     string;
  fresh:         boolean;
}

/** Core scan logic — shared by GET /lookup, GET /api/v1/scan, POST /api/v1/scan */
export async function performLookup(
  input: string,
  opts: LookupOptions,
  config: AppConfig,
  redis: Redis,
): Promise<ScanResult | { error: string; status: number }> {
  if (!isValidIp(input) && !looksLikeDomain(input)) {
    return { error: 'Invalid IP address or domain name.', status: 400 };
  }

  const cacheKey = `scan:${input.toLowerCase()}`;
  if (!opts.fresh) {
    const cached = await cacheGet<ScanResult>(redis, cacheKey);
    if (cached) return { ...cached, _cached: true };
  }

  let ip = input;
  let resolvedFrom  = null as string | null;
  let resolvedIpv4  = null as string | null;
  let resolvedIpv6  = null as string | null;
  let isDomain      = false;

  if (!isValidIp(input)) {
    isDomain = true;
    const [v4, v6] = await Promise.all([
      resolveDomain(input, 'A'),
      resolveDomain(input, 'AAAA'),
    ]);
    if (!v4 && !v6) return { error: `Could not resolve domain: ${input}`, status: 400 };
    resolvedFrom = input;
    resolvedIpv4 = v4;
    resolvedIpv6 = v6;
    ip = v4 ?? v6!;
  }

  const bust = Date.now();
  const cleanDomain = resolvedFrom ? cleanDomainInput(resolvedFrom) : null;

  const [
    ipapiData, ipinfoData, proxycheckData, vtIpData, ipapisData,
    torResult, whoisData, shodanData, dnsblData,
    vtDomainData, domainWhoisData,
  ] = await Promise.allSettled([
    fetchIpApi(ip, bust),
    fetchIpinfo(ip, opts.ipinfoToken, bust),
    fetchProxycheck(ip, opts.proxycheckKey, bust),
    opts.vtKey ? fetchVirusTotal(ip, opts.vtKey) : Promise.resolve(null),
    fetchIpapis(ip, bust),
    isTorExit(ip),
    fetchWhois(ip),
    opts.shodanKey ? fetchShodan(ip, opts.shodanKey) : Promise.resolve(null),
    checkDnsbl(ip),
    isDomain && opts.vtKey && cleanDomain ? fetchVtDomain(cleanDomain, opts.vtKey) : Promise.resolve(null),
    isDomain && cleanDomain              ? fetchDomainWhois(cleanDomain)           : Promise.resolve(null),
  ]);

  const result: ScanResult = {
    ip,
    resolvedFrom,
    resolvedIpv4,
    resolvedIpv6,
    isDomain,
    timestamp:      bust,
    isTorConfirmed: torResult.status === 'fulfilled' ? torResult.value : false,
    torListSize:    getTorListSize(),
    sources: {
      ipapi:       ipapiData.status       === 'fulfilled' ? ipapiData.value       : null,
      ipinfo:      ipinfoData.status      === 'fulfilled' ? ipinfoData.value      : null,
      proxycheck:  proxycheckData.status  === 'fulfilled' ? proxycheckData.value  : null,
      virustotal:  vtIpData.status        === 'fulfilled' ? vtIpData.value        : null,
      ipapis:      ipapisData.status      === 'fulfilled' ? ipapisData.value      : null,
      whois:       whoisData.status       === 'fulfilled' ? whoisData.value       : null,
      shodan:      shodanData.status      === 'fulfilled' ? shodanData.value      : null,
      dnsbl:       dnsblData.status       === 'fulfilled' ? dnsblData.value       : null,
      vtDomain:    vtDomainData.status    === 'fulfilled' ? vtDomainData.value    : null,
      domainWhois: domainWhoisData.status === 'fulfilled' ? domainWhoisData.value : null,
    },
    _cached:   false,
    _cachedAt: bust,
  };

  cacheSet(redis, cacheKey, result, config.scanCacheTtl).catch(() => {});
  return result;
}

function resolveKeys(c: Context, config: AppConfig): LookupOptions {
  return {
    vtKey:         validateClientKey('vt',         c.req.header('X-VT-Key')         ?? '') ?? config.virustotalApiKey,
    ipinfoToken:   validateClientKey('ipinfo',     c.req.header('X-Ipinfo-Token')   ?? '') ?? config.ipinfoToken,
    proxycheckKey: validateClientKey('proxycheck', c.req.header('X-Proxycheck-Key') ?? '') ?? config.proxycheckApiKey,
    shodanKey:     validateClientKey('shodan',     c.req.header('X-Shodan-Key')     ?? '') ?? config.shodanApiKey,
    fresh:         c.req.query('fresh') === '1',
  };
}

/** GET /lookup?ip=…  and  GET /api/v1/scan?ip=… */
export function makeGetLookupHandler(config: AppConfig, redis: Redis) {
  return async (c: Context) => {
    const clientIp = c.req.header('CF-Connecting-IP') ??
                     c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ?? 'unknown';
    if (!await checkRateLimit(redis, clientIp, 'lookup', config.rateLimitLookup, config.rateLimitWindow)) {
      return c.json({ error: `Rate limit exceeded — max ${config.rateLimitLookup} scans per hour.` }, 429);
    }

    const input = (c.req.query('ip') ?? c.req.header('X-IP') ?? '').trim();
    if (!input) return c.json({ error: 'Missing ip or domain parameter.' }, 400);

    const result = await performLookup(input, resolveKeys(c, config), config, redis);
    if ('status' in result && 'error' in result) return c.json({ error: result.error }, result.status as 400);
    return c.json(result);
  };
}

/** POST /api/v1/scan  { "ip": "1.2.3.4" } */
export function makePostScanHandler(config: AppConfig, redis: Redis) {
  return async (c: Context) => {
    const clientIp = c.req.header('CF-Connecting-IP') ??
                     c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ?? 'unknown';
    if (!await checkRateLimit(redis, clientIp, 'lookup', config.rateLimitLookup, config.rateLimitWindow)) {
      return c.json({ error: `Rate limit exceeded — max ${config.rateLimitLookup} scans per hour.` }, 429);
    }

    const body = await c.req.json<{ ip?: string; fresh?: boolean }>().catch(() => null);
    if (!body?.ip) return c.json({ error: 'Missing ip field in request body.' }, 400);

    const opts = { ...resolveKeys(c, config), fresh: body.fresh ?? false };
    const result = await performLookup(body.ip.trim(), opts, config, redis);
    if ('status' in result && 'error' in result) return c.json({ error: result.error }, result.status as 400);
    return c.json(result);
  };
}
