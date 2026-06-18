import { serve } from '@hono/node-server';
import { getRedis } from './cache/redis.js';
import { loadConfig } from './utils/config.js';
import { createApp } from './app.js';

const config = loadConfig();
const redis  = getRedis(config.redisUrl);
const app    = createApp(config, redis);

serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`[ipscanner] v2.0.0 listening on http://0.0.0.0:${config.port}`);
  console.log(`[ipscanner] API keys loaded: ${config.apiKeys.size}`);
  console.log(`[ipscanner] Allowed origins: ${config.allowedOrigins.join(', ')}`);
});
