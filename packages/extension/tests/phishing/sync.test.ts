import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PhishingSync } from '../../src/phishing/sync';

let storageData: Record<string, unknown> = {};

const chromeMock = {
	storage: {
		local: {
			get: vi.fn(async (keys: string | string[]) => {
				const result: Record<string, unknown> = {};
				const keyArr = Array.isArray(keys) ? keys : [keys];
				for (const k of keyArr) {
					if (k in storageData) result[k] = storageData[k];
				}
				return result;
			}),
			set: vi.fn(async (items: Record<string, unknown>) => {
				Object.assign(storageData, items);
			}),
		},
	},
	alarms: {
		create: vi.fn(),
	},
	declarativeNetRequest: {
		updateDynamicRules: vi.fn(async () => {}),
		getDynamicRules: vi.fn(async () => []),
	},
};

vi.stubGlobal('chrome', chromeMock);
vi.stubGlobal('navigator', { onLine: true });

beforeEach(() => {
	storageData = {};
	vi.clearAllMocks();
	vi.stubGlobal('navigator', { onLine: true });
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.stubGlobal('chrome', chromeMock);
	vi.stubGlobal('navigator', { onLine: true });
});

describe('PhishingSync', () => {
	it('rejects manifest with invalid signature — unknown keyId returns false', async () => {
		vi.stubGlobal('navigator', { onLine: true });

		const manifest = {
			version: '2026-04-01',
			sequence: 1,
			hash: 'sha256:abc123',
			dnrHash: 'sha256:def456',
			count: 100,
			topDomains: 10,
			keyId: 'unknown-key-999',
			signature: 'dGVzdA==',
		};

		const fetchMock = vi.fn().mockResolvedValueOnce({
			ok: true,
			json: async () => manifest,
		});
		vi.stubGlobal('fetch', fetchMock);

		const sync = new PhishingSync('https://cdn.example.com');
		const result = await sync.syncFromCDN();

		expect(result).toBe(false);
	});

	it('rejects manifest with rollback sequence — stored sequence 5, manifest sequence 3 returns false', async () => {
		vi.stubGlobal('navigator', { onLine: true });

		// Pre-store a sequence of 5
		storageData.phishingFilterSequence = 5;

		const manifest = {
			version: '2026-03-01',
			sequence: 3,
			hash: 'sha256:abc123',
			dnrHash: 'sha256:def456',
			count: 100,
			topDomains: 10,
			keyId: 'key-001',
			signature: 'dGVzdA==',
		};

		// Mock verifyManifestSignature to return true so we reach rollback check
		const fetchMock = vi.fn().mockResolvedValueOnce({
			ok: true,
			json: async () => manifest,
		});
		vi.stubGlobal('fetch', fetchMock);

		// Mock crypto.subtle so signature check passes — we want to test rollback logic
		vi.stubGlobal('crypto', {
			subtle: {
				importKey: vi.fn().mockResolvedValue('mock-key'),
				verify: vi.fn().mockResolvedValue(true),
				digest: vi.fn().mockResolvedValue(new ArrayBuffer(0)),
			},
		});

		const sync = new PhishingSync('https://cdn.example.com');
		const result = await sync.syncFromCDN();

		expect(result).toBe(false);
	});

	it('skips sync when offline — returns false', async () => {
		vi.stubGlobal('navigator', { onLine: false });

		const fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);

		const sync = new PhishingSync('https://cdn.example.com');
		const result = await sync.syncFromCDN();

		expect(result).toBe(false);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('sets up alarm with 6-hour interval', () => {
		PhishingSync.setupAlarm();

		expect(chromeMock.alarms.create).toHaveBeenCalledWith('sync-phishing-filter', {
			periodInMinutes: 360,
		});
	});
});
