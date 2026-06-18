const DOH_BASE = 'https://cloudflare-dns.com/dns-query';

export async function resolveDomain(domain: string, type: 'A' | 'AAAA'): Promise<string | null> {
  const clean = domain.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
  const dnsType = type === 'AAAA' ? 28 : 1;
  try {
    const r = await fetch(
      `${DOH_BASE}?name=${encodeURIComponent(clean)}&type=${type}`,
      { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(5000) },
    );
    if (!r.ok) return null;
    const data = await r.json() as { Answer?: { type: number; data: string }[] };
    const rec = (data.Answer ?? []).find(a => a.type === dnsType);
    return rec?.data ?? null;
  } catch {
    return null;
  }
}
