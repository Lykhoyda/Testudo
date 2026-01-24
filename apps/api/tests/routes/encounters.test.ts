import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Hono } from 'hono';

vi.mock('../../src/db/index.js', () => ({
	db: {
		insert: vi.fn().mockReturnValue({
			values: vi.fn().mockReturnValue({
				returning: vi.fn().mockResolvedValue([{ id: 1 }]),
			}),
		}),
	},
}));

import { encounterRoutes } from '../../src/routes/encounters.js';
import { db } from '../../src/db/index.js';

const app = new Hono();
app.route('/api/v1/encounters', encounterRoutes);

beforeEach(() => {
	vi.clearAllMocks();
});

describe('POST /api/v1/encounters', () => {
	const validBody = {
		address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
		chainId: 1,
		action: 'blocked',
		extensionVersion: '0.1.0',
	};

	it('creates encounter with address', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(validBody),
		});
		const body = await res.json();

		expect(res.status).toBe(201);
		expect(body.success).toBe(true);
		expect(body.id).toBe(1);
	});

	it('creates encounter with domain', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				domain: 'fake-uniswap.com',
				chainId: 1,
				action: 'dismissed',
				extensionVersion: '0.1.0',
			}),
		});

		expect(res.status).toBe(201);
	});

	it('creates encounter with both address and domain', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
				domain: 'evil-site.com',
				chainId: 1,
				action: 'proceeded',
				extensionVersion: '0.2.0',
			}),
		});

		expect(res.status).toBe(201);
	});

	it('rejects missing both address and domain with 400', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				chainId: 1,
				action: 'blocked',
				extensionVersion: '0.1.0',
			}),
		});
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.code).toBe('MISSING_IDENTIFIER');
	});

	it('rejects invalid address format with 400', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				address: 'not-an-address',
				chainId: 1,
				action: 'blocked',
				extensionVersion: '0.1.0',
			}),
		});
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.code).toBe('INVALID_ADDRESS');
	});

	it('rejects invalid action value with 400', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
				chainId: 1,
				action: 'invalid_action',
				extensionVersion: '0.1.0',
			}),
		});
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.code).toBe('INVALID_ACTION');
	});

	it('rejects missing extensionVersion with 400', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
				chainId: 1,
				action: 'blocked',
			}),
		});
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.code).toBe('MISSING_VERSION');
	});

	it('normalizes address to lowercase before insert', async () => {
		const upperAddr = '0x930FCC37D6042C79211EE18A02857CB1FD7F0D0B';
		await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				address: upperAddr,
				chainId: 1,
				action: 'blocked',
				extensionVersion: '0.1.0',
			}),
		});

		const insertMock = vi.mocked(db.insert);
		const valuesMock = insertMock.mock.results[0]?.value?.values;
		expect(valuesMock).toHaveBeenCalledWith(
			expect.objectContaining({ address: upperAddr.toLowerCase() }),
		);
	});

	it('rejects invalid JSON body with 400', async () => {
		const res = await app.request('/api/v1/encounters', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: 'not json',
		});
		const body = await res.json();

		expect(res.status).toBe(400);
		expect(body.code).toBe('INVALID_BODY');
	});
});
