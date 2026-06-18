import type { DnsblEntry, DnsblResult } from '../types/index.js';

const DNSBL_LISTS: [string, string][] = [
  ['bl.spamcop.net',              'SpamCop'],
  ['b.barracudacentral.org',      'Barracuda'],
  ['dnsbl-1.uceprotect.net',      'UCEPROTECT L1'],
  ['dnsbl-2.uceprotect.net',      'UCEPROTECT L2'],
  ['dnsbl-3.uceprotect.net',      'UCEPROTECT L3'],
  ['ix.dnsbl.manitu.net',         'Manitu'],
  ['dnsbl.dronebl.org',           'DroneBL'],
  ['psbl.surriel.com',            'PSBL'],
  ['db.wpbl.info',                'WPBL'],
  ['bl.0spam.org',                '0spam'],
  ['rbl.0spam.org',               '0spam RBL'],
  ['all.s5h.net',                 'S5H'],
  ['spam.dnsbl.anonmails.de',     'Anonmails'],
  ['spamrbl.imp.ch',              'IMP Spam RBL'],
  ['wormrbl.imp.ch',              'IMP Worm RBL'],
  ['virus.rbl.jp',                'RBL.JP Virus'],
  ['combined.abuse.ch',           'Abuse.ch Combined'],
  ['spam.abuse.ch',               'Abuse.ch Spam'],
  ['korea.services.net',          'Korea Services'],
  ['rbl.metunet.com',             'Metunet'],
  ['dnsbl.inps.de',               'INPS'],
  ['bogons.cymru.com',            'Bogons Cymru'],
  ['dnsbl.tornevall.org',         'Tornevall'],
  ['ubl.lashback.com',            'Lashback UBL'],
  ['ubl.unsubscore.com',          'Unsubscore'],
  ['multi.surbl.org',             'SURBL Multi'],
  ['dnsbl.cobion.com',            'Cobion'],
  ['bl.mailspike.net',            'Mailspike BL'],
  ['z.mailspike.net',             'Mailspike Z'],
  ['singular.ttk.pte.hu',         'TTK PTE'],
  ['spamsources.fabel.dk',        'Fabel Spamsources'],
  ['virbl.dnsbl.bit.nl',          'VIRBL'],
  ['rbl.spamlab.com',             'SpamLab'],
  ['dnsbl.anticaptcha.net',       'AntiCaptcha'],
  ['ips.backscatterer.org',       'Backscatterer'],
];

const DNSBL_ERROR_CODES = new Set([
  '127.255.255.254',
  '127.255.255.255',
  '127.0.0.1',
]);

const RETURN_CODE_LABELS: Record<string, string> = {
  '127.0.0.2':  'Spam source',
  '127.0.0.3':  'Spam source (confirmed)',
  '127.0.0.4':  'Exploits / botnet',
  '127.0.0.5':  'Botnet C&C',
  '127.0.0.6':  'Virus / malware',
  '127.0.0.7':  'DDoS drone',
  '127.0.0.8':  'Rogue server',
  '127.0.0.9':  'Brute force',
  '127.0.0.10': 'Dynamic IP / dialup',
  '127.0.0.11': 'Spam support service',
  '127.0.0.14': 'Proxy',
  '127.0.0.15': 'Compromised server',
};

const DOH_BASE = 'https://cloudflare-dns.com/dns-query';

async function checkOneDnsbl(reversed: string, host: string, name: string): Promise<DnsblEntry> {
  const query = `${reversed}.${host}`;
  try {
    const r = await fetch(
      `${DOH_BASE}?name=${encodeURIComponent(query)}&type=A`,
      { headers: { 'Accept': 'application/dns-json' }, signal: AbortSignal.timeout(3000) },
    );
    if (!r.ok) return { name, listed: false, error: true };
    const data = await r.json() as { Status: number; Answer?: { type: number; data: string }[] };

    if (data.Status !== 0) return { name, listed: false };

    const answers = (data.Answer ?? []).filter(a => a.type === 1);
    if (!answers.length) return { name, listed: false };

    const returnIp = answers[0].data;
    if (!returnIp?.startsWith('127.')) return { name, listed: false, error: true, defunctResponse: returnIp };
    if (DNSBL_ERROR_CODES.has(returnIp)) return { name, listed: false, error: true, errorCode: returnIp };

    return { name, listed: true, returnCode: returnIp, codeDesc: RETURN_CODE_LABELS[returnIp] ?? `Listed (${returnIp})` };
  } catch (e) {
    return { name, listed: false, error: true, timeout: (e as Error).name === 'TimeoutError' };
  }
}

export async function checkDnsbl(ip: string): Promise<DnsblResult> {
  if (!ip || ip.includes(':')) return { checked: 0, listed: 0, total: 0, lists: [], ipv6: true };

  const reversed = ip.split('.').reverse().join('.');

  // Deduplicate by hostname (fixes L7 from security audit — bl.spamcop.net was listed twice)
  const seen = new Set<string>();
  const unique = DNSBL_LISTS.filter(([host]) => {
    if (seen.has(host)) return false;
    seen.add(host);
    return true;
  });

  const checks = await Promise.allSettled(
    unique.map(([host, name]) => checkOneDnsbl(reversed, host, name))
  );

  const results: DnsblEntry[] = checks.map((c, i) =>
    c.status === 'fulfilled' ? c.value : { name: unique[i][1], listed: false, error: true }
  );

  return {
    checked: results.filter(r => !r.error).length,
    listed:  results.filter(r => r.listed).length,
    total:   results.length,
    lists:   results,
  };
}
