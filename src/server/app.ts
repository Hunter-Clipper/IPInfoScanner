import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import type Redis from 'ioredis';
import type { AppConfig } from './types/index.js';
import { corsMiddleware } from './middleware/cors.js';
import { authMiddleware } from './middleware/auth.js';
import { makeGetLookupHandler, makePostScanHandler } from './routes/lookup.js';
import { makeAnalyzeHandler } from './routes/analyze.js';
import { handleMyIp } from './routes/myip.js';

export function createApp(config: AppConfig, redis: Redis) {
  const app = new Hono();

  // CORS on everything
  app.use('*', corsMiddleware(config.allowedOrigins));

  // Auth on all data endpoints
  const auth = authMiddleware(config.allowedOrigins, config.apiKeys);
  app.use('/lookup',    auth);
  app.use('/analyze',   auth);
  app.use('/myip',      auth);
  app.use('/api/*',     auth);

  // ── Browser-compatible endpoints (mirrors Cloudflare Worker API) ──────────
  app.get('/lookup',   makeGetLookupHandler(config, redis));
  app.post('/analyze', makeAnalyzeHandler(config, redis));
  app.get('/myip',     handleMyIp);

  // ── REST API v1 (programmatic / curl-friendly) ────────────────────────────
  app.get('/api/v1/scan',     makeGetLookupHandler(config, redis));
  app.post('/api/v1/scan',    makePostScanHandler(config, redis));
  app.post('/api/v1/analyze', makeAnalyzeHandler(config, redis));
  app.get('/api/v1/myip',     handleMyIp);

  // ── Health (no auth) ──────────────────────────────────────────────────────
  app.get('/health', (c) => c.json({ status: 'ok', version: '2.0.0' }));

  // ── Static frontend ───────────────────────────────────────────────────────
  app.use('/*', serveStatic({ root: './public' }));

  return app;
}
