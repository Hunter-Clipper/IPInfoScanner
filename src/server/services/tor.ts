const TOR_LIST_URL = 'https://www.dan.me.uk/torlist/?full';
const TOR_CACHE_TTL = 30 * 60 * 1000;

let torListCache: Set<string> | null = null;
let torListFetchedAt = 0;

async function fetchTorList(): Promise<Set<string>> {
  const now = Date.now();
  if (torListCache && (now - torListFetchedAt) < TOR_CACHE_TTL) return torListCache;
  try {
    const r = await fetch(TOR_LIST_URL, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; IPScanner/2.0)', 'Accept': 'text/plain' },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return torListCache ?? new Set();
    const text = await r.text();
    const ips = text.split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
    torListCache    = new Set(ips);
    torListFetchedAt = now;
    return torListCache;
  } catch {
    return torListCache ?? new Set();
  }
}

export async function isTorExit(ip: string): Promise<boolean> {
  const list = await fetchTorList();
  return list.has(ip);
}

export function getTorListSize(): number {
  return torListCache?.size ?? 0;
}
