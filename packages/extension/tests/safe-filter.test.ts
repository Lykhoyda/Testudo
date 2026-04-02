import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleSafeFilterAlarm, SafeFilter, setupSafeFilterAlarm } from '../src/safe-filter';

const FALLBACK_ADDRESSES = [
	'0x63c0c19a282a1b52b07dd5a65b58948a07dae32b',
	'0x41675c099f32341bf84bfc5382af534df5c7461a',
	'0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67',
	'0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad',
	'0x1111111254eeb25477b68fb85ed929f73a960582',
];

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
			remove: vi.fn(async () => {}),
		},
	},
	alarms: {
		create: vi.fn(),
	},
};

vi.stubGlobal('chrome', chromeMock);

function makeManifest(overrides: Record<string, unknown> = {}) {
	return {
		version: '2026-04-01',
		sequence: 2,
		hash: 'sha256:abc123',
		count: 3,
		keyId: 'key-001',
		signature: 'dGVzdHNpZw==',
		...overrides,
	};
}

function makeAddresses() {
	return ['0xaaaa', '0xbbbb', '0xcccc'];
}

function encodedAddresses() {
	return new TextEncoder().encode(JSON.stringify(makeAddresses()));
}

function mockFetchSequence(
	responses: Array<{
		ok: boolean;
		json?: () => Promise<unknown>;
		arrayBuffer?: () => Promise<ArrayBuffer>;
	}>,
) {
	const fetchMock = vi.fn();
	for (const r of responses) {
		fetchMock.mockResolvedValueOnce(r);
	}
	vi.stubGlobal('fetch', fetchMock);
	return fetchMock;
}

function mockCryptoSubtle(
	opts: { importKey?: boolean; verify?: boolean; digestHash?: string } = {},
) {
	const subtle = {
		importKey: vi.fn().mockResolvedValue('mock-crypto-key'),
		verify: vi.fn().mockResolvedValue(opts.verify ?? true),
		digest: vi.fn().mockImplementation(async (_algo: string, _data: ArrayBuffer) => {
			const hex = opts.digestHash ?? 'abc123';
			const bytes = new Uint8Array(hex.length / 2);
			for (let i = 0; i < hex.length; i += 2) {
				bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
			}
			return bytes.buffer;
		}),
	};
	vi.stubGlobal('crypto', { subtle });
	return subtle;
}

beforeEach(() => {
	storageData = {};
	vi.clearAllMocks();
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.stubGlobal('chrome', chromeMock);
});

describe('SafeFilter', () => {
	describe('constructor', () => {
		it('creates instance with default CDN URL', () => {
			const filter = new SafeFilter();
			expect(filter).toBeInstanceOf(SafeFilter);
		});

		it('accepts custom CDN URL', () => {
			const filter = new SafeFilter('https://custom-cdn.example.com');
			expect(filter).toBeInstanceOf(SafeFilter);
		});
	});

	describe('isKnownSafe', () => {
		it('returns true for fallback addresses', () => {
			const filter = new SafeFilter();
			for (const addr of FALLBACK_ADDRESSES) {
				expect(filter.isKnownSafe(addr)).toBe(true);
			}
		});

		it('returns true for fallback addresses with mixed case', () => {
			const filter = new SafeFilter();
			expect(filter.isKnownSafe('0x63C0C19A282A1B52B07DD5A65B58948A07DAE32B')).toBe(true);
			expect(filter.isKnownSafe('0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD')).toBe(true);
		});

		it('returns false for unknown addresses', () => {
			const filter = new SafeFilter();
			expect(filter.isKnownSafe('0x0000000000000000000000000000000000000000')).toBe(false);
		});

		it('returns false for empty safeSet when not a fallback address', () => {
			const filter = new SafeFilter();
			expect(filter.isKnownSafe('0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')).toBe(false);
		});
	});

	describe('load', () => {
		it('loads addresses from chrome.storage.local into safeSet', async () => {
			storageData.safeFilter = {
				addresses: ['0xaaaa', '0xbbbb'],
				count: 2,
			};
			const filter = new SafeFilter();
			await filter.load();
			expect(filter.isKnownSafe('0xaaaa')).toBe(true);
			expect(filter.isKnownSafe('0xbbbb')).toBe(true);
		});

		it('isKnownSafe returns true for loaded addresses after load()', async () => {
			storageData.safeFilter = {
				addresses: ['0x1234567890abcdef1234567890abcdef12345678'],
				count: 1,
			};
			const filter = new SafeFilter();
			expect(filter.isKnownSafe('0x1234567890abcdef1234567890abcdef12345678')).toBe(false);
			await filter.load();
			expect(filter.isKnownSafe('0x1234567890abcdef1234567890abcdef12345678')).toBe(true);
		});

		it('empty storage results in empty safeSet without error', async () => {
			const filter = new SafeFilter();
			await filter.load();
			expect(filter.isKnownSafe('0xaaaa')).toBe(false);
		});

		it('storage error results in empty safeSet without throwing', async () => {
			chromeMock.storage.local.get.mockRejectedValueOnce(new Error('storage fail'));
			const filter = new SafeFilter();
			await expect(filter.load()).resolves.toBeUndefined();
			expect(filter.isKnownSafe('0xaaaa')).toBe(false);
		});
	});

	describe('syncFromCDN', () => {
		it('returns false when offline', async () => {
			Object.defineProperty(navigator, 'onLine', { value: false, configurable: true });
			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when already syncing (concurrent prevention)', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true });

			let resolveFetch!: (value: unknown) => void;
			const pendingFetch = new Promise((r) => {
				resolveFetch = r;
			});
			vi.stubGlobal('fetch', vi.fn().mockReturnValue(pendingFetch));

			const filter = new SafeFilter();
			const first = filter.syncFromCDN();
			const second = await filter.syncFromCDN();

			expect(second).toBe(false);

			resolveFetch({ ok: false, status: 500 });
			await first;
		});

		it('returns false when manifest fetch fails', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockFetchSequence([{ ok: false }]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when manifest missing signing fields', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockFetchSequence([
				{
					ok: true,
					json: async () => ({ version: '1', hash: 'h', count: 1 }),
				},
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when signature verification fails', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: false });
			mockFetchSequence([
				{
					ok: true,
					json: async () => makeManifest(),
				},
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when sequence < stored sequence (rollback protection)', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true });
			storageData.safeFilterSequence = 10;
			mockFetchSequence([
				{
					ok: true,
					json: async () => makeManifest({ sequence: 5 }),
				},
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns true when sequence == stored sequence AND same version (already up to date)', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true });
			storageData.safeFilterSequence = 2;
			storageData.safeFilterVersion = '2026-04-01';
			mockFetchSequence([
				{
					ok: true,
					json: async () => makeManifest({ sequence: 2, version: '2026-04-01' }),
				},
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(true);
		});

		it('returns false when sequence == stored sequence AND different version (collision)', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true });
			storageData.safeFilterSequence = 2;
			storageData.safeFilterVersion = '2026-03-01';
			mockFetchSequence([
				{
					ok: true,
					json: async () => makeManifest({ sequence: 2, version: '2026-04-01' }),
				},
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when address list fetch fails', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true });
			mockFetchSequence([{ ok: true, json: async () => makeManifest() }, { ok: false }]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when hash mismatch', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true, digestHash: 'ff00ff' });
			mockFetchSequence([
				{ ok: true, json: async () => makeManifest({ hash: 'sha256:aabbcc' }) },
				{ ok: true, arrayBuffer: async () => encodedAddresses().buffer },
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns false when count mismatch', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true, digestHash: 'aabb' });
			const addresses = encodedAddresses();
			mockFetchSequence([
				{ ok: true, json: async () => makeManifest({ hash: 'sha256:aabb', count: 999 }) },
				{ ok: true, arrayBuffer: async () => addresses.buffer },
			]);

			const filter = new SafeFilter();
			expect(await filter.syncFromCDN()).toBe(false);
		});

		it('returns true on successful sync and updates safeSet', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			mockCryptoSubtle({ verify: true, digestHash: 'aabb' });
			const addresses = encodedAddresses();
			mockFetchSequence([
				{ ok: true, json: async () => makeManifest({ hash: 'sha256:aabb', count: 3 }) },
				{ ok: true, arrayBuffer: async () => addresses.buffer },
			]);

			const filter = new SafeFilter();
			const result = await filter.syncFromCDN();

			expect(result).toBe(true);
			expect(filter.isKnownSafe('0xaaaa')).toBe(true);
			expect(filter.isKnownSafe('0xbbbb')).toBe(true);
			expect(filter.isKnownSafe('0xcccc')).toBe(true);
			expect(storageData.safeFilter).toBeDefined();
			expect(storageData.safeFilterVersion).toBe('2026-04-01');
			expect(storageData.safeFilterSequence).toBe(2);
		});

		it('resets isSyncing flag even on failure (finally block)', async () => {
			Object.defineProperty(navigator, 'onLine', { value: true, configurable: true });
			vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('network error')));

			const filter = new SafeFilter();
			await filter.syncFromCDN();

			// Second call with fresh fetch mock — should proceed past isSyncing guard
			const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 500 });
			vi.stubGlobal('fetch', fetchMock);
			await filter.syncFromCDN();
			expect(fetchMock).toHaveBeenCalled();
		});
	});

	describe('getStats', () => {
		it('returns correct stats from storage', async () => {
			storageData.safeFilterVersion = '2026-04-01';
			storageData.safeFilterLastSync = 1712000000000;
			storageData.safeFilter = {
				addresses: ['0xaaaa', '0xbbbb'],
				count: 2,
			};

			const filter = new SafeFilter();
			await filter.load();

			const stats = await filter.getStats();
			expect(stats.loaded).toBe(true);
			expect(stats.version).toBe('2026-04-01');
			expect(stats.lastSync).toBe(1712000000000);
			expect(stats.fallbackCount).toBe(5);
			expect(stats.loadedCount).toBe(2);
		});

		it('returns defaults when storage is empty', async () => {
			const filter = new SafeFilter();
			const stats = await filter.getStats();
			expect(stats.loaded).toBe(false);
			expect(stats.version).toBeNull();
			expect(stats.lastSync).toBeNull();
			expect(stats.fallbackCount).toBe(5);
			expect(stats.loadedCount).toBe(0);
		});
	});
});

describe('setupSafeFilterAlarm', () => {
	it('calls chrome.alarms.create with correct name and interval', () => {
		setupSafeFilterAlarm();
		expect(chromeMock.alarms.create).toHaveBeenCalledWith('sync-safe-filter', {
			periodInMinutes: 60 * 24 * 7,
		});
	});
});

describe('handleSafeFilterAlarm', () => {
	it('calls syncFromCDN when alarm name matches', async () => {
		const filter = new SafeFilter();
		const syncSpy = vi.spyOn(filter, 'syncFromCDN').mockResolvedValue(true);

		await handleSafeFilterAlarm({ name: 'sync-safe-filter' } as chrome.alarms.Alarm, filter);
		expect(syncSpy).toHaveBeenCalled();
	});

	it('ignores other alarms', async () => {
		const filter = new SafeFilter();
		const syncSpy = vi.spyOn(filter, 'syncFromCDN').mockResolvedValue(true);

		await handleSafeFilterAlarm({ name: 'some-other-alarm' } as chrome.alarms.Alarm, filter);
		expect(syncSpy).not.toHaveBeenCalled();
	});
});
