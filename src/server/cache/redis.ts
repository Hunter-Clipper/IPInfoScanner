import Redis from 'ioredis';

let client: Redis | null = null;

export function getRedis(url: string): Redis {
  if (!client) {
    client = new Redis(url, {
      lazyConnect: true,
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
    });
    client.on('error', err => {
      // Log but don't crash — cache/rate-limit failures are non-fatal
      console.error('[redis] error:', err.message);
    });
  }
  return client;
}

export async function cacheGet<T>(redis: Redis, key: string): Promise<T | null> {
  try {
    const raw = await redis.get(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function cacheSet(redis: Redis, key: string, value: unknown, ttlSeconds: number): Promise<void> {
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch {
    // non-fatal
  }
}

export async function checkRateLimit(
  redis: Redis,
  ip: string,
  endpoint: string,
  limit: number,
  windowSeconds: number,
  failClosedOnError = false,
): Promise<boolean> {
  const key = `rl:${endpoint}:${ip}`;
  try {
    const count = parseInt((await redis.get(key)) ?? '0', 10);
    if (count >= limit) return false;
    const pipeline = redis.pipeline();
    pipeline.incr(key);
    pipeline.expire(key, windowSeconds, 'NX');
    await pipeline.exec();
    return true;
  } catch {
    return !failClosedOnError;
  }
}
