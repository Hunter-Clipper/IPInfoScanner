import type { IpinfoResponse } from '../types/index.js';

export async function fetchIpinfo(ip: string, token: string, bust: number): Promise<IpinfoResponse | null> {
  const p = token ? `?token=${token}&_=${bust}` : `?_=${bust}`;
  try {
    const r = await fetch(`https://ipinfo.io/${encodeURIComponent(ip)}/json${p}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    return r.json() as Promise<IpinfoResponse>;
  } catch {
    return null;
  }
}
