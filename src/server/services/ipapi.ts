import type { IpApiResponse } from '../types/index.js';

export async function fetchIpApi(ip: string, bust: number): Promise<IpApiResponse | null> {
  // HTTP fallback removed — only HTTPS (fixes M5 from security audit)
  const url = `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=66846719&_=${bust}`;
  try {
    const r = await fetch(url, {
      signal: AbortSignal.timeout(6000),
      headers: { 'Accept': 'application/json' },
    });
    if (!r.ok) return null;
    return r.json() as Promise<IpApiResponse>;
  } catch {
    return null;
  }
}
