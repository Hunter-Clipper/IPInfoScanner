import type { ProxycheckResponse } from '../types/index.js';

export async function fetchProxycheck(ip: string, apiKey: string, bust: number): Promise<ProxycheckResponse | null> {
  const k = apiKey ? `&key=${apiKey}` : '';
  try {
    const r = await fetch(
      `https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1&node=1&time=1&inf=1&risk=1&port=1&seen=1${k}&_=${bust}`,
      { signal: AbortSignal.timeout(5000) },
    );
    if (!r.ok) return null;
    return r.json() as Promise<ProxycheckResponse>;
  } catch {
    return null;
  }
}
