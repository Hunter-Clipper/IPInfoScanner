// ── External API response types ───────────────────────────────────────────

export interface IpApiResponse {
  status: string;
  country?: string;
  countryCode?: string;
  region?: string;
  regionName?: string;
  city?: string;
  zip?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  org?: string;
  as?: string;
  reverse?: string;
  mobile?: boolean;
  proxy?: boolean;
  hosting?: boolean;
  query?: string;
  continent?: string;
}

export interface IpinfoResponse {
  ip?: string;
  hostname?: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string;
  org?: string;
  postal?: string;
  timezone?: string;
}

export interface ProxycheckEntry {
  asn?: string;
  provider?: string;
  organisation?: string;
  continent?: string;
  country?: string;
  isocode?: string;
  region?: string;
  regioncode?: string;
  timezone?: string;
  city?: string;
  postcode?: string;
  hostname?: string;
  type?: string;
  risk?: number | string;
  port?: number | string;
  seen?: string;
}

export type ProxycheckResponse = Record<string, ProxycheckEntry>;

export interface VtAnalysisStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  timeout?: number;
}

export interface VtAnalysisResult {
  category: string;
  result: string;
  method: string;
  engine_name: string;
}

export interface VtIpAttributes {
  last_analysis_stats?: VtAnalysisStats;
  last_analysis_results?: Record<string, VtAnalysisResult>;
  last_analysis_date?: number;
  reputation?: number;
  network?: string;
  as_owner?: string;
  country?: string;
}

export interface VtIpResponse {
  data?: {
    id?: string;
    type?: string;
    attributes?: VtIpAttributes;
  };
  error?: string;
}

export interface IpapisSecurityFlags {
  vpn?: boolean;
  proxy?: boolean;
  tor?: boolean;
  relay?: boolean;
  hosting?: boolean;
  satellite?: boolean;
}

export interface IpapisResponse {
  ip?: string;
  rir?: string;
  is_bogon?: boolean;
  is_mobile?: boolean;
  is_crawler?: boolean;
  is_datacenter?: boolean;
  is_tor?: boolean;
  is_proxy?: boolean;
  is_vpn?: boolean;
  is_abuser?: boolean;
  company?: { name?: string; abuser_score?: string; domain?: string; type?: string; network?: string; whois?: string };
  abuse?: { name?: string; address?: string; country?: string; email?: string; network?: string; phone?: string };
  asn?: { asn?: number; abuser_score?: string; route?: string; descr?: string; country?: string; active?: boolean; org?: string; domain?: string; abuse?: string; type?: string; updated?: string; rir?: string; whois?: string };
  location?: { continent?: string; country?: string; country_code?: string; state?: string; city?: string; latitude?: number; longitude?: number; zip?: string; timezone?: string; local_time?: string; local_time_unix?: number; is_dst?: boolean };
  security?: IpapisSecurityFlags;
}

export interface WhoisData {
  registry: string;
  handle: string | null;
  name: string | null;
  network: string | null;
  startAddress: string | null;
  endAddress: string | null;
  country: string | null;
  type: string | null;
  registrant: string | null;
  abuseContact: string | null;
  techContact: string | null;
  registered: string | null;
  lastChanged: string | null;
  remarks: string | null;
}

export interface ShodanService {
  port: number;
  transport: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
  banner: string | null;
}

export interface ShodanData {
  ip: string;
  hostnames: string[];
  domains: string[];
  country: string | null;
  city: string | null;
  org: string | null;
  isp: string | null;
  asn: string | null;
  os: string | null;
  tags: string[];
  vulns: string[];
  lastUpdate: string | null;
  ports: number[];
  services: ShodanService[];
}

export interface ShodanError {
  error: string;
  status?: number;
}

export interface DnsblEntry {
  name: string;
  listed: boolean;
  error?: boolean;
  timeout?: boolean;
  returnCode?: string;
  codeDesc?: string;
  errorCode?: string;
  defunctResponse?: string;
}

export interface DnsblResult {
  checked: number;
  listed: number;
  total: number;
  lists: DnsblEntry[];
  ipv6?: boolean;
}

export interface VtDomainData {
  domain: string;
  reputation: number | null;
  categories: Record<string, string>;
  registrar: string | null;
  creationDate: number | null;
  lastUpdate: number | null;
  lastAnalysis: number | null;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  tags: string[];
  popularityRanks: Record<string, { rank: number }>;
  lastHttpsCert: { issuer: string | null; subject: string | null; validTo: string | null } | null;
}

export interface DomainWhoisData {
  domain: string | null;
  status: string | null;
  registrar: string | null;
  registrant: string | null;
  abuseEmail: string | null;
  nameservers: string[];
  registered: string | null;
  updated: string | null;
  expiry: string | null;
}

// ── Aggregated scan result ────────────────────────────────────────────────

export interface ScanSources {
  ipapi: IpApiResponse | null;
  ipinfo: IpinfoResponse | null;
  proxycheck: ProxycheckResponse | null;
  virustotal: VtIpResponse | null;
  ipapis: IpapisResponse | null;
  whois: WhoisData | null;
  shodan: ShodanData | ShodanError | null;
  dnsbl: DnsblResult | null;
  vtDomain: VtDomainData | { error: string } | null;
  domainWhois: DomainWhoisData | null;
}

export interface ScanResult {
  ip: string;
  resolvedFrom: string | null;
  resolvedIpv4: string | null;
  resolvedIpv6: string | null;
  isDomain: boolean;
  timestamp: number;
  isTorConfirmed: boolean;
  torListSize: number;
  sources: ScanSources;
  _cached: boolean;
  _cachedAt: number;
}

// ── AI analysis payload ───────────────────────────────────────────────────

export interface AnalyzePayload {
  ip: string;
  resolvedFrom?: string | null;
  country?: string | null;
  city?: string | null;
  isp?: string | null;
  org?: string | null;
  asn?: string | null;
  rdns?: string | null;
  ipType?: string | null;
  isMobile?: boolean;
  isHosting?: boolean;
  isProxy?: boolean;
  isVpn?: boolean;
  isTor?: boolean;
  riskScore?: number;
  pcRisk?: number;
  vtMalCount?: number;
  vtTotal?: number;
  dnsblListed?: number;
  dnsblChecked?: number;
  dnsblNames?: string;
  shodanPorts?: string;
  shodanVulns?: string;
  shodanOS?: string | null;
  whoisRegistrant?: string | null;
  whoisAbuse?: string | null;
  isDomain?: boolean;
  resolvedIpv4?: string | null;
  resolvedIpv6?: string | null;
  domainRegistrar?: string | null;
  domainRegistrant?: string | null;
  domainRegistered?: string | null;
  domainExpiry?: string | null;
  domainStatus?: string | null;
  domainNameservers?: string | null;
  domainAbuseEmail?: string | null;
  vtDomainMalicious?: number;
  vtDomainSuspicious?: number;
  vtDomainHarmless?: number;
  vtDomainReputation?: number | null;
  vtDomainCategories?: string | null;
  vtDomainRegistrar?: string | null;
  vtDomainSslIssuer?: string | null;
  vtDomainSslExpiry?: string | null;
  vtDomainTags?: string | null;
}

// ── Config ────────────────────────────────────────────────────────────────

export interface AppConfig {
  port: number;
  redisUrl: string;
  apiKeys: Set<string>;
  allowedOrigins: string[];
  geminiApiKey: string;
  virustotalApiKey: string;
  shodanApiKey: string;
  ipinfoToken: string;
  proxycheckApiKey: string;
  scanCacheTtl: number;
  rateLimitWindow: number;
  rateLimitLookup: number;
  rateLimitAnalyze: number;
}

// ── Error types ───────────────────────────────────────────────────────────

export interface ApiError {
  error: string;
  detail?: string;
}
