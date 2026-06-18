import type { Context } from 'hono';

export function handleMyIp(c: Context) {
  const ip =
    c.req.header('CF-Connecting-IP') ??
    c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ??
    // Hono node adapter exposes the socket address at c.env.incoming
    'unknown';
  return c.json({ ip });
}
