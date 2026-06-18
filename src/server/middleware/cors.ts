import type { Context, Next } from 'hono';

const EXPLICIT_HEADERS = [
  'Content-Type',
  'X-IP',
  'X-No-Cache',
  'X-VT-Key',
  'X-Shodan-Key',
  'X-Ipinfo-Token',
  'X-Proxycheck-Key',
  'X-API-Key',
].join(', ');

export function corsMiddleware(allowedOrigins: string[]) {
  return async (c: Context, next: Next) => {
    const origin = c.req.header('Origin') ?? '';
    const allowed = allowedOrigins.includes(origin) ? origin : allowedOrigins[0] ?? '*';

    // Always set CORS headers so browser preflight works
    c.header('Access-Control-Allow-Origin', allowed);
    c.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    c.header('Access-Control-Allow-Headers', EXPLICIT_HEADERS);
    c.header('Vary', 'Origin');

    if (c.req.method === 'OPTIONS') {
      return c.body(null, 204);
    }
    await next();
  };
}

/** Returns true if the request origin is a known allowed origin (browser CSRF guard) */
export function isAllowedOrigin(request: Request, allowedOrigins: string[]): boolean {
  const origin  = request.headers.get('Origin')  ?? '';
  const referer = request.headers.get('Referer') ?? '';
  return allowedOrigins.some(o =>
    origin === o || referer.startsWith(o)
  );
}
