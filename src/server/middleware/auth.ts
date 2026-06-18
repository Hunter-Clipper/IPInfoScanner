import type { Context, Next } from 'hono';
import { isAllowedOrigin } from './cors.js';

/**
 * Allows requests that satisfy either:
 *  1. Browser request from an allowed origin (Origin/Referer header matches)
 *  2. API request with a valid X-API-Key header
 *
 * If neither, returns 401 for missing key or 403 for bad origin/key.
 */
export function authMiddleware(allowedOrigins: string[], apiKeys: Set<string>) {
  return async (c: Context, next: Next) => {
    const apiKey = c.req.header('X-API-Key') ?? '';

    // API key path — any origin allowed when a valid key is present
    if (apiKey) {
      if (!apiKeys.has(apiKey)) {
        return c.json({ error: 'Invalid API key.' }, 401);
      }
      await next();
      return;
    }

    // Browser path — must come from an allowed origin
    if (isAllowedOrigin(c.req.raw, allowedOrigins)) {
      await next();
      return;
    }

    // No key, wrong origin
    if (allowedOrigins.length > 0) {
      return c.json({ error: 'Forbidden — include X-API-Key header or request from an allowed origin.' }, 403);
    }
    await next();
  };
}

// ── Client-supplied key format validation (H1 fix) ────────────────────────

const KEY_PATTERNS: Record<string, RegExp> = {
  vt:         /^[a-f0-9]{64}$/i,
  shodan:     /^[a-zA-Z0-9]{16,64}$/,
  ipinfo:     /^[a-zA-Z0-9_-]{10,64}$/,
  proxycheck: /^[a-zA-Z0-9]{8,64}$/,
};

export function validateClientKey(type: keyof typeof KEY_PATTERNS, value: string): string | null {
  if (!value) return null;
  if (value.length > 256) return null;
  return KEY_PATTERNS[type]?.test(value) ? value : null;
}
