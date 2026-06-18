import type { IpapisResponse } from '../types/index.js';

export async function fetchIpapis(ip: string, bust: number): Promise<IpapisResponse | null> {
  try {
    const r = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}&_=${bust}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!r.ok) return null;
    return r.json() as Promise<IpapisResponse>;
  } catch {
    return null;
  }
}
