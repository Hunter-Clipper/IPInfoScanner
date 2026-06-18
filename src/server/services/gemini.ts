import type { AnalyzePayload } from '../types/index.js';

const MODEL = 'gemini-3.1-flash-lite';
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;

// Strips control characters and caps length — extended beyond original safe()
// to also remove angle brackets, null bytes, and Unicode bidi control chars (M2 fix)
function safe(val: unknown, max = 120): string {
  if (typeof val !== 'string') return String(val ?? '—');
  return val
    .replace(/[\r\n\t\x00-\x1F\x7F​-‏‪-‮⁠-⁤]/g, ' ')
    .replace(/\s{2,}/g, ' ')
    .trim()
    .substring(0, max);
}

function buildPrompt(d: AnalyzePayload): string {
  const torFlag   = d.isTor   ? 'YES — confirmed Tor exit node' : 'No';
  const vpnFlag   = d.isVpn   ? 'YES' : 'No';
  const proxyFlag = d.isProxy ? 'YES' : 'No';

  return (
    'You are a cybersecurity analyst writing for a technical but non-specialist audience. ' +
    (d.isDomain
      ? 'Analyse both the domain and IP intelligence data below. The domain and its resolved IP may have different risk profiles — assess both, then give a combined verdict. '
      : 'Analyse the IP intelligence data below. '
    ) +
    'Do not just label it safe or dangerous — explain WHY based on the specific data points. ' +
    'If something is clean, explain what that means. If something is suspicious, explain what it indicates. ' +
    'Use plain English. Structure your response with exactly these four sections:\n\n' +
    '**Threat Assessment**\n' +
    'Overall risk level (Low / Medium / High / Critical) and 2-3 sentences explaining what this IP is and why it received that rating. Reference specific data to justify your conclusion.\n\n' +
    '**Key Findings**\n' +
    'Bullet points covering the most significant facts. For each finding, briefly explain what it means.\n\n' +
    '**Context**\n' +
    '1-2 sentences giving broader context.\n\n' +
    '**Recommendation**\n' +
    '1-2 clear action sentences.\n\n' +
    'IP data:\n' +
    `- IP: ${safe(d.ip, 45)}${d.resolvedFrom ? ` (resolved from: ${safe(d.resolvedFrom, 253)})` : ''}\n` +
    `- Location: ${safe(d.city)}, ${safe(d.country)}\n` +
    `- ISP: ${safe(d.isp)} / Org: ${safe(d.org)} / ASN: ${safe(d.asn, 40)}\n` +
    `- Reverse DNS: ${safe(d.rdns)}\n` +
    `- IP Type: ${safe(d.ipType, 40)} | Mobile carrier: ${!!d.isMobile} | Hosting/DC: ${!!d.isHosting}\n` +
    `- Risk score: ${(d.riskScore ?? 0) + (d.pcRisk ?? 0)}/100\n` +
    `- VPN detected: ${vpnFlag} | Proxy: ${proxyFlag} | Tor exit node: ${torFlag}\n` +
    `- VirusTotal: ${d.vtMalCount ?? 0} engines flagged this IP as malicious/suspicious out of ${d.vtTotal ?? 0} total\n` +
    `- Blacklists: listed on ${d.dnsblListed ?? 0} of ${d.dnsblChecked ?? 0} DNSBL blacklists${(d.dnsblNames && d.dnsblNames !== 'none') ? ` (${safe(d.dnsblNames, 200)})` : ''}\n` +
    `- Shodan open ports: ${safe(d.shodanPorts, 200)} | OS: ${safe(d.shodanOS, 60)}\n` +
    `- Known CVEs: ${safe(d.shodanVulns, 200)}\n` +
    `- WHOIS registrant: ${safe(d.whoisRegistrant)} | Abuse contact: ${safe(d.whoisAbuse)}\n` +
    (d.isDomain ? (
      '\n\nDomain data (separate from IP):\n' +
      `- Domain: ${safe(d.resolvedFrom, 253)}\n` +
      `- IPv4: ${safe(d.resolvedIpv4, 45)} | IPv6: ${safe(d.resolvedIpv6, 45)}\n` +
      `- Domain Registrar: ${safe(d.domainRegistrar)}\n` +
      `- Domain Registrant: ${safe(d.domainRegistrant)}\n` +
      `- Registered: ${safe(d.domainRegistered, 40)} | Expires: ${safe(d.domainExpiry, 40)}\n` +
      `- Domain Status: ${safe(d.domainStatus, 200)}\n` +
      `- Nameservers: ${safe(d.domainNameservers, 200)}\n` +
      `- Domain Abuse Email: ${safe(d.domainAbuseEmail)}\n` +
      `- VT Domain — Malicious: ${d.vtDomainMalicious ?? 0} | Suspicious: ${d.vtDomainSuspicious ?? 0} | Clean: ${d.vtDomainHarmless ?? 0}\n` +
      `- VT Domain Reputation: ${d.vtDomainReputation ?? '—'}\n` +
      `- VT Domain Categories: ${safe(d.vtDomainCategories, 200)}\n` +
      `- VT Domain Registrar: ${safe(d.vtDomainRegistrar)}\n` +
      `- SSL Certificate Issuer: ${safe(d.vtDomainSslIssuer)} | Expires: ${safe(d.vtDomainSslExpiry, 40)}\n` +
      `- Domain Tags: ${safe(d.vtDomainTags, 200)}\n`
    ) : '') +
    `\nKeep the total response under 350 words. Be specific — a reader should understand exactly why this IP${d.isDomain ? ' and domain are' : ' is'} or are not a concern.` +
    (d.isDomain ? ' When a domain is present, analyse BOTH the domain reputation and the underlying IP separately, then give a combined verdict.' : '')
  );
}

export async function analyzeWithGemini(
  payload: AnalyzePayload,
  apiKey: string,
): Promise<{ analysis: string; model: string } | { error: string; detail?: string }> {
  const prompt = buildPrompt(payload);
  try {
    const res = await fetch(GEMINI_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.3, maxOutputTokens: 1000 },
        safetySettings: [
          { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
          { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_NONE' },
        ],
      }),
      signal: AbortSignal.timeout(30000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as Record<string, unknown>;
      const errMsg  = String((err?.['error'] as Record<string, unknown>)?.['message'] ?? err?.['message'] ?? 'Unknown Gemini error');
      const errCode = String((err?.['error'] as Record<string, unknown>)?.['code'] ?? (err?.['error'] as Record<string, unknown>)?.['status'] ?? '');
      // L5 fix: log detail server-side, only return a clean user message
      console.error('[gemini] API error:', errMsg);
      if (res.status === 401 || errCode === 'UNAUTHENTICATED') return { error: 'Invalid Gemini API key — check GEMINI_API_KEY.' };
      if (res.status === 403 || errCode === 'PERMISSION_DENIED') return { error: 'Gemini API key lacks permission — ensure the API is enabled in Google Cloud.' };
      if (res.status === 429 || errCode === 'RESOURCE_EXHAUSTED') return { error: 'Rate limit hit — free tier allows 15 req/min. Wait 60s and retry.' };
      return { error: `Gemini API error ${res.status}` };
    }

    const data = await res.json() as Record<string, unknown>;
    const text = ((data?.['candidates'] as Record<string, unknown>[])?.[0]?.['content'] as Record<string, unknown>)?.['parts'] as { text: string }[];
    const analysis = text?.[0]?.text;
    if (!analysis) return { error: 'Gemini returned empty response.' };
    return { analysis, model: MODEL };
  } catch (e) {
    return { error: `Failed to reach Gemini API: ${(e as Error).message}` };
  }
}
