import type { AppConfig } from '../types/index.js';

function required(name: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required environment variable: ${name}`);
  return val;
}

function optional(name: string, fallback = ''): string {
  return process.env[name] ?? fallback;
}

export function loadConfig(): AppConfig {
  const rawKeys = optional('API_KEYS', '');
  const apiKeys = new Set(
    rawKeys.split(',').map(k => k.trim()).filter(Boolean)
  );

  const rawOrigins = optional(
    'ALLOWED_ORIGINS',
    'http://localhost:3000,https://ipinfo.hunterclipper.com,https://hunterclipper.com'
  );
  const allowedOrigins = rawOrigins.split(',').map(o => o.trim()).filter(Boolean);

  return {
    port:               parseInt(optional('PORT', '3000'), 10),
    redisUrl:           optional('REDIS_URL', 'redis://localhost:6379'),
    apiKeys,
    allowedOrigins,
    geminiApiKey:       optional('GEMINI_API_KEY'),
    virustotalApiKey:   optional('VIRUSTOTAL_API_KEY'),
    shodanApiKey:       optional('SHODAN_API_KEY'),
    ipinfoToken:        optional('IPINFO_TOKEN'),
    proxycheckApiKey:   optional('PROXYCHECK_API_KEY'),
    scanCacheTtl:       parseInt(optional('SCAN_CACHE_TTL', String(6 * 3600)), 10),
    rateLimitWindow:    parseInt(optional('RATE_LIMIT_WINDOW', '3600'), 10),
    rateLimitLookup:    parseInt(optional('RATE_LIMIT_LOOKUP', '30'), 10),
    rateLimitAnalyze:   parseInt(optional('RATE_LIMIT_ANALYZE', '10'), 10),
  };
}
