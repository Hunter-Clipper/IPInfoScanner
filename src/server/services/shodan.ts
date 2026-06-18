import type { ShodanData, ShodanError } from '../types/index.js';

export async function fetchShodan(ip: string, apiKey: string): Promise<ShodanData | ShodanError> {
  try {
    const r = await fetch(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`,
      { signal: AbortSignal.timeout(8000) },
    );
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 404) return { error: 'not_found' };
    if (r.status === 403) return { error: 'api_error', status: 403 };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: 'api_error', status: r.status };
    const data = await r.json() as Record<string, unknown>;
    return {
      ip:         String(data['ip_str'] ?? ip),
      hostnames:  (data['hostnames'] as string[]) ?? [],
      domains:    (data['domains'] as string[]) ?? [],
      country:    (data['country_name'] as string) ?? null,
      city:       (data['city'] as string) ?? null,
      org:        (data['org'] as string) ?? null,
      isp:        (data['isp'] as string) ?? null,
      asn:        (data['asn'] as string) ?? null,
      os:         (data['os'] as string) ?? null,
      tags:       (data['tags'] as string[]) ?? [],
      vulns:      data['vulns'] ? Object.keys(data['vulns'] as object) : [],
      lastUpdate: (data['last_update'] as string) ?? null,
      ports:      (data['ports'] as number[]) ?? [],
      services: ((data['data'] as Record<string, unknown>[]) ?? []).slice(0, 20).map(s => ({
        port:      s['port'] as number,
        transport: (s['transport'] as string) ?? null,
        product:   (s['product'] as string) ?? null,
        version:   (s['version'] as string) ?? null,
        cpe:       (s['cpe'] as string) ?? null,
        banner:    s['data'] ? String(s['data']).substring(0, 200) : null,
      })),
    };
  } catch (e) {
    return { error: 'network' };
  }
}
