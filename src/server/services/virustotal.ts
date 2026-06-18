import type { VtIpResponse, VtDomainData } from '../types/index.js';

const VT_HEADERS = (apiKey: string) => ({ 'x-apikey': apiKey });

export async function fetchVirusTotal(ip: string, apiKey: string): Promise<VtIpResponse> {
  try {
    const r = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      { headers: VT_HEADERS(apiKey), signal: AbortSignal.timeout(8000) },
    );
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: `api_error_${r.status}` };
    return r.json() as Promise<VtIpResponse>;
  } catch {
    return { error: 'timeout' };
  }
}

export async function fetchVtDomain(domain: string, apiKey: string): Promise<VtDomainData | { error: string }> {
  try {
    const r = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      { headers: VT_HEADERS(apiKey), signal: AbortSignal.timeout(10000) },
    );
    if (r.status === 401) return { error: 'invalid_key' };
    if (r.status === 404) return { error: 'not_found' };
    if (r.status === 429) return { error: 'rate_limit' };
    if (!r.ok) return { error: `api_error_${r.status}` };
    const data = await r.json() as Record<string, unknown>;
    const attr = (data?.['data'] as Record<string, unknown>)?.['attributes'] as Record<string, unknown> ?? {};
    const stats = (attr['last_analysis_stats'] ?? {}) as Record<string, number>;
    const cert  = attr['last_https_certificate'] as Record<string, unknown> | undefined;
    return {
      domain,
      reputation:      (attr['reputation'] as number) ?? null,
      categories:      (attr['categories'] as Record<string, string>) ?? {},
      registrar:       (attr['registrar'] as string) ?? null,
      creationDate:    (attr['creation_date'] as number) ?? null,
      lastUpdate:      (attr['last_modification_date'] as number) ?? null,
      lastAnalysis:    (attr['last_analysis_date'] as number) ?? null,
      malicious:       stats['malicious'] ?? 0,
      suspicious:      stats['suspicious'] ?? 0,
      harmless:        stats['harmless'] ?? 0,
      undetected:      stats['undetected'] ?? 0,
      tags:            (attr['tags'] as string[]) ?? [],
      popularityRanks: (attr['popularity_ranks'] as Record<string, { rank: number }>) ?? {},
      lastHttpsCert: cert ? {
        issuer:  (cert['issuer'] as Record<string, string>)?.['CN'] ?? null,
        subject: (cert['subject'] as Record<string, string>)?.['CN'] ?? null,
        validTo: (cert['validity'] as Record<string, string>)?.['not_after'] ?? null,
      } : null,
    };
  } catch (e) {
    return { error: 'network' };
  }
}
