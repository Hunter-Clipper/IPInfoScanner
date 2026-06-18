import type { Context } from 'hono';
import type { AppConfig, AnalyzePayload } from '../types/index.js';
import type { Redis } from 'ioredis';
import { checkRateLimit } from '../cache/redis.js';
import { analyzeWithGemini } from '../services/gemini.js';
import { isValidAnalyzeIp } from '../utils/validation.js';

export function makeAnalyzeHandler(config: AppConfig, redis: Redis) {
  return async (c: Context) => {
    if (!config.geminiApiKey) {
      return c.json({ error: 'AI analysis not configured — GEMINI_API_KEY not set.' }, 503);
    }

    const clientIp = c.req.header('CF-Connecting-IP') ??
                     c.req.header('X-Forwarded-For')?.split(',')[0]?.trim() ??
                     'unknown';

    // /analyze fails closed on rate-limit errors (M3 fix)
    if (!await checkRateLimit(redis, clientIp, 'analyze', config.rateLimitAnalyze, config.rateLimitWindow, true)) {
      return c.json({ error: `Rate limit exceeded — max ${config.rateLimitAnalyze} AI analyses per hour.` }, 429);
    }

    let body: AnalyzePayload;
    try {
      body = await c.req.json<AnalyzePayload>();
    } catch {
      return c.json({ error: 'Invalid JSON body.' }, 400);
    }

    if (!body.ip || typeof body.ip !== 'string') return c.json({ error: 'Missing ip field.' }, 400);
    if (!isValidAnalyzeIp(body.ip)) return c.json({ error: 'Invalid ip field.' }, 400);

    const result = await analyzeWithGemini(body, config.geminiApiKey);
    if ('error' in result) {
      const status = result.error.includes('Rate limit') ? 429 : 502;
      return c.json(result, status);
    }
    return c.json(result);
  };
}
