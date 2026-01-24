import type { MiddlewareHandler } from 'hono';

interface RateLimitEntry {
	count: number;
	resetAt: number;
}

interface RateLimitOptions {
	windowMs: number;
	max: number;
	maxEntries?: number;
}

export function createRateLimiter(options: RateLimitOptions): MiddlewareHandler {
	const store = new Map<string, RateLimitEntry>();

	const cleanupInterval = setInterval(() => {
		const now = Date.now();
		for (const [key, entry] of store) {
			if (entry.resetAt <= now) {
				store.delete(key);
			}
		}
	}, 60_000);

	if (cleanupInterval.unref) {
		cleanupInterval.unref();
	}

	const maxEntries = options.maxEntries ?? 10_000;

	return async (c, next) => {
		const ip =
			c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ||
			c.req.header('x-real-ip') ||
			'unknown';

		const now = Date.now();
		let entry = store.get(ip);

		if (!entry || entry.resetAt <= now) {
			if (store.size >= maxEntries) {
				for (const [key, val] of store) {
					if (val.resetAt <= now) store.delete(key);
					if (store.size < maxEntries) break;
				}
			}
			entry = { count: 0, resetAt: now + options.windowMs };
			store.set(ip, entry);
		}

		entry.count++;

		const remaining = Math.max(0, options.max - entry.count);
		const resetSeconds = Math.ceil((entry.resetAt - now) / 1000);

		c.header('X-RateLimit-Limit', String(options.max));
		c.header('X-RateLimit-Remaining', String(remaining));
		c.header('X-RateLimit-Reset', String(resetSeconds));

		if (entry.count > options.max) {
			return c.json(
				{
					error: 'Too many requests',
					code: 'RATE_LIMITED',
					retryAfter: resetSeconds,
				},
				429,
			);
		}

		await next();
	};
}
