import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { createRateLimiter } from '../../src/middleware/rate-limit.js';

describe('rate-limit middleware', () => {
	let app: Hono;

	beforeEach(() => {
		vi.useFakeTimers();
		app = new Hono();
		app.use('/test/*', createRateLimiter({ windowMs: 60_000, max: 3 }));
		app.get('/test/resource', (c) => c.json({ ok: true }));
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('allows requests within limit', async () => {
		const res1 = await app.request('/test/resource');
		const res2 = await app.request('/test/resource');
		const res3 = await app.request('/test/resource');

		expect(res1.status).toBe(200);
		expect(res2.status).toBe(200);
		expect(res3.status).toBe(200);
	});

	it('returns 429 when limit exceeded', async () => {
		await app.request('/test/resource');
		await app.request('/test/resource');
		await app.request('/test/resource');

		const res = await app.request('/test/resource');
		const body = await res.json();

		expect(res.status).toBe(429);
		expect(body.error).toBe('Too many requests');
		expect(body.code).toBe('RATE_LIMITED');
		expect(body.retryAfter).toBeGreaterThan(0);
	});

	it('includes rate limit headers', async () => {
		const res = await app.request('/test/resource');

		expect(res.headers.get('X-RateLimit-Limit')).toBe('3');
		expect(res.headers.get('X-RateLimit-Remaining')).toBe('2');
		expect(res.headers.get('X-RateLimit-Reset')).toBeDefined();
	});

	it('resets after window expires', async () => {
		await app.request('/test/resource');
		await app.request('/test/resource');
		await app.request('/test/resource');

		const blocked = await app.request('/test/resource');
		expect(blocked.status).toBe(429);

		vi.advanceTimersByTime(60_001);

		const res = await app.request('/test/resource');
		expect(res.status).toBe(200);
	});

	it('tracks different IPs separately', async () => {
		const headers1 = { 'X-Forwarded-For': '1.2.3.4' };
		const headers2 = { 'X-Forwarded-For': '5.6.7.8' };

		await app.request('/test/resource', { headers: headers1 });
		await app.request('/test/resource', { headers: headers1 });
		await app.request('/test/resource', { headers: headers1 });

		const blocked = await app.request('/test/resource', { headers: headers1 });
		expect(blocked.status).toBe(429);

		const allowed = await app.request('/test/resource', { headers: headers2 });
		expect(allowed.status).toBe(200);
	});

	it('shows remaining count decreasing', async () => {
		const res1 = await app.request('/test/resource');
		expect(res1.headers.get('X-RateLimit-Remaining')).toBe('2');

		const res2 = await app.request('/test/resource');
		expect(res2.headers.get('X-RateLimit-Remaining')).toBe('1');

		const res3 = await app.request('/test/resource');
		expect(res3.headers.get('X-RateLimit-Remaining')).toBe('0');
	});
});
