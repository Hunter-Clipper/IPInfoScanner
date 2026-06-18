import type { ScanResult } from '../types/index.js';

export interface RiskBreakdown {
  score: number;
  level: 'clean' | 'caution' | 'suspicious' | 'dangerous';
  isTor: boolean;
  isVpn: boolean;
  isProxy: boolean;
  isHosting: boolean;
  isMobile: boolean;
  isRelay: boolean;
  isSatellite: boolean;
  isAnon: boolean;
  isBogon: boolean;
  vtMalCount: number;
  dnsblCount: number;
}

export function computeRisk(result: ScanResult): RiskBreakdown {
  const ipapi     = result.sources.ipapi      ?? {};
  const pcRaw     = result.sources.proxycheck ?? {};
  const ipapis    = result.sources.ipapis     ?? {};
  const vtData    = result.sources.virustotal;
  const dnsbl     = result.sources.dnsbl;

  const pc = (pcRaw as Record<string, Record<string, unknown>>)[result.ip] ?? {};
  const pcType  = String(pc['type'] ?? '');
  const pcLow   = pcType.toLowerCase();
  const pcrisk  = parseInt(String(pc['risk'] ?? '0'), 10) || 0;

  const vtStats    = (vtData as Record<string, unknown>)?.['data'] as Record<string, unknown>;
  const attrs      = vtStats?.['attributes'] as Record<string, unknown> | undefined;
  const stats      = (attrs?.['last_analysis_stats'] ?? {}) as Record<string, number>;
  const vtMalCount = (stats['malicious'] ?? 0) + (stats['suspicious'] ?? 0);
  const dnsblCount = dnsbl?.listed ?? 0;

  const isTor      = result.isTorConfirmed || pcLow.includes('tor') || ((ipapis as Record<string, unknown>)?.['security'] as Record<string, unknown>)?.['tor'] === true;
  const isVpn      = !isTor && (pcLow.includes('vpn') || ((ipapi as Record<string, unknown>)['proxy'] === true && !pcLow.includes('proxy')));
  const isProxy    = !isTor && !isVpn && (pcLow.includes('proxy') || pcType === 'PBL' || pcType === 'CBL' || (ipapi as Record<string, unknown>)['proxy'] === true);
  const isHosting  = (ipapi as Record<string, unknown>)['hosting'] === true || pcType === 'DCH' || pcLow.includes('hosting');
  const isMobile   = (ipapi as Record<string, unknown>)['mobile'] === true;
  const isRelay    = pcLow.includes('relay');
  const isSatellite = pcLow.includes('satellite');
  const isAnon     = isVpn || isTor || isProxy;
  const isBogon    = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fc|fd)/i.test(result.ip);

  let riskScore = 0;

  if (pcrisk >= 75)      riskScore += 25;
  else if (pcrisk >= 50) riskScore += 15;
  else if (pcrisk >= 25) riskScore += 8;

  if (isTor) riskScore += 60;

  if (vtMalCount > 0) {
    if (vtMalCount >= 10)     riskScore += 40;
    else if (vtMalCount >= 5) riskScore += 28;
    else if (vtMalCount >= 2) riskScore += 18;
    else                      riskScore += 8;
  }

  const dnsblLists     = dnsbl?.lists ?? [];
  const aggressiveDnsbl = new Set(['UCEPROTECT L2', 'UCEPROTECT L3']);
  const seriousHits    = dnsblLists.filter(l => l.listed && !aggressiveDnsbl.has(l.name)).length;
  const aggressiveHits = dnsblLists.filter(l => l.listed && aggressiveDnsbl.has(l.name)).length;
  riskScore += seriousHits * 18;
  riskScore += aggressiveHits * 6;

  if (isVpn)     riskScore += 10;
  if (isProxy)   riskScore += 15;
  if (isHosting) riskScore += 4;

  const badSignals = (isTor ? 1 : 0) + (isVpn ? 1 : 0) + (isProxy ? 1 : 0) +
                     (vtMalCount > 0 ? 1 : 0) + (seriousHits > 0 ? 1 : 0) + (pcrisk >= 50 ? 1 : 0);
  if (badSignals >= 3) riskScore = Math.round(riskScore * 1.2);
  if (badSignals >= 4) riskScore = Math.round(riskScore * 1.15);

  const vtTotalEngines = (stats['malicious'] ?? 0) + (stats['suspicious'] ?? 0) +
                         (stats['harmless'] ?? 0) + (stats['undetected'] ?? 0);
  if (vtMalCount === 0 && vtTotalEngines > 20) riskScore -= 5;
  if (dnsblCount === 0 && (dnsbl?.checked ?? 0) > 10) riskScore -= 5;
  if (pcrisk === 0) riskScore -= 3;

  riskScore = Math.max(0, Math.min(100, riskScore));

  const level: RiskBreakdown['level'] =
    (isTor || riskScore >= 65)                                               ? 'dangerous'
    : (riskScore >= 25 || (isVpn && vtMalCount > 0) || seriousHits > 0)     ? 'suspicious'
    : (isVpn || isProxy || riskScore >= 12)                                  ? 'caution'
    : 'clean';

  return { score: riskScore, level, isTor, isVpn, isProxy, isHosting, isMobile, isRelay, isSatellite, isAnon, isBogon, vtMalCount, dnsblCount };
}
