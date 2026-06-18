import type { WhoisData, DomainWhoisData } from '../types/index.js';

// ── IP WHOIS / RDAP ───────────────────────────────────────────────────────

function getVcardField(entity: Record<string, unknown>, field: string): string | null {
  const arr = (entity?.['vcardArray'] as unknown[])?.[1] as unknown[];
  if (!Array.isArray(arr)) return null;
  const entry = arr.find((f): f is unknown[] => Array.isArray(f) && f[0] === field);
  return entry ? String(entry[3] ?? '') || null : null;
}

function getName(entity: Record<string, unknown>): string | null {
  return getVcardField(entity, 'fn') ?? (entity?.['handle'] as string) ?? null;
}

function getEmail(entity: Record<string, unknown>): string | null {
  return getVcardField(entity, 'email');
}

function parseRdap(data: Record<string, unknown>, registry: string): WhoisData {
  const entities   = (data['entities'] as Record<string, unknown>[]) ?? [];
  const registrant = entities.find(e => (e['roles'] as string[])?.includes('registrant'));
  const abuse      = entities.find(e => (e['roles'] as string[])?.includes('abuse'));
  const tech       = entities.find(e => (e['roles'] as string[])?.includes('technical'));
  const cidrs      = data['cidr0_cidrs'] as { v4prefix: string; length: number }[] | undefined;
  const events     = (data['events'] as { eventAction: string; eventDate: string }[]) ?? [];

  return {
    registry,
    handle:       (data['handle'] as string) ?? null,
    name:         (data['name'] as string) ?? null,
    network:      cidrs?.[0] ? `${cidrs[0].v4prefix}/${cidrs[0].length}`
                : (data['startAddress'] && data['endAddress'])
                  ? `${data['startAddress']} – ${data['endAddress']}`
                  : null,
    startAddress: (data['startAddress'] as string) ?? null,
    endAddress:   (data['endAddress'] as string) ?? null,
    country:      (data['country'] as string) ?? null,
    type:         (data['type'] as string) ?? null,
    registrant:   registrant ? getName(registrant) : null,
    abuseContact: abuse ? (getEmail(abuse) ?? getName(abuse)) : null,
    techContact:  tech  ? (getEmail(tech)  ?? getName(tech))  : null,
    registered:   events.find(e => e.eventAction === 'registration')?.eventDate ?? null,
    lastChanged:  events.find(e => e.eventAction === 'last changed')?.eventDate ?? null,
    remarks:      ((data['remarks'] as { description: string[] }[])?.[0]?.description?.join(' ')) ?? null,
  };
}

export async function fetchWhois(ip: string): Promise<WhoisData | null> {
  const endpoints = [
    { url: `https://rdap.arin.net/registry/ip/${ip}`, registry: 'ARIN' },
    { url: `https://rdap.db.ripe.net/ip/${ip}`,       registry: 'RIPE' },
  ];
  for (const { url, registry } of endpoints) {
    try {
      const r = await fetch(url, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(6000),
      });
      if (!r.ok) continue;
      return parseRdap(await r.json() as Record<string, unknown>, registry);
    } catch { /* try next */ }
  }
  return null;
}

// ── Domain WHOIS / RDAP ───────────────────────────────────────────────────

function parseDomainRdap(data: Record<string, unknown>): DomainWhoisData {
  const getDate = (type: string) => {
    const events = (data['events'] as { eventAction: string; eventDate: string }[]) ?? [];
    return events.find(e => e.eventAction === type || e.eventAction === type.replace(' ', '_'))?.eventDate ?? null;
  };

  const entities   = (data['entities'] as Record<string, unknown>[]) ?? [];
  const registrant = entities.find(e => (e['roles'] as string[])?.includes('registrant'));
  const registrar  = entities.find(e => (e['roles'] as string[])?.includes('registrar'));
  const abuse      = entities.find(e => (e['roles'] as string[])?.includes('abuse'));

  const rawNs = (data['nameservers'] ?? data['nameServer'] ?? []) as Record<string, string>[];
  const nameservers = rawNs
    .map(ns => ns['ldhName'] ?? ns['unicodeName'] ?? '')
    .filter((ns): ns is string => typeof ns === 'string' && ns.length > 0);

  return {
    domain:     (data['ldhName'] as string) ?? (data['unicodeName'] as string) ?? null,
    status:     Array.isArray(data['status']) ? data['status'].join(', ') : (data['status'] as string) ?? null,
    registrar:  registrar ? getName(registrar) : null,
    registrant: registrant ? getName(registrant) : null,
    abuseEmail: abuse ? getEmail(abuse) : null,
    nameservers,
    registered: getDate('registration'),
    updated:    getDate('last changed'),
    expiry:     getDate('expiration'),
  };
}

export async function fetchDomainWhois(domain: string): Promise<DomainWhoisData | null> {
  const endpoints = [
    `https://rdap.org/domain/${encodeURIComponent(domain)}`,
    `https://rdap.iana.org/domain/${encodeURIComponent(domain)}`,
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`,
  ];
  for (const url of endpoints) {
    try {
      const r = await fetch(url, {
        headers: { 'Accept': 'application/rdap+json, application/json' },
        signal: AbortSignal.timeout(5000),
      });
      if (!r.ok) continue;
      const data = await r.json() as Record<string, unknown>;
      if (data['objectClassName'] === 'domain' || data['ldhName']) {
        return parseDomainRdap(data);
      }
    } catch { /* try next */ }
  }
  return null;
}
