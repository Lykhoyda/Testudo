import type { Address, PublicClient } from 'viem';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchDeployerStaticInfo } from '../../src/services/deployer-lookup';

const CONTRACT = '0xabcdef1234567890abcdef1234567890abcdef12' as Address;
const DEPLOYER = '0x000085BAD5B016E5448A530cb3D4840D2CfD15BC';
const CREATION_TX = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function makeMockClient(overrides: Partial<Record<string, unknown>> = {}): PublicClient {
	return {
		getTransaction: vi.fn().mockResolvedValue({ nonce: 3 }),
		getTransactionReceipt: vi.fn().mockResolvedValue({ blockNumber: 100n }),
		getBlock: vi.fn().mockResolvedValue({ timestamp: 1699990000n }),
		...overrides,
	} as unknown as PublicClient;
}

describe('fetchDeployerStaticInfo', () => {
	beforeEach(() => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: true,
				json: () =>
					Promise.resolve({
						creator_address_hash: DEPLOYER,
						creation_transaction_hash: CREATION_TX,
					}),
			}),
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('returns static deployer info on successful lookup', async () => {
		const client = makeMockClient();
		const result = await fetchDeployerStaticInfo(CONTRACT, client);

		expect(result).not.toBeNull();
		expect(result?.deployerAddress).toBe(DEPLOYER);
		expect(result?.deployerNonce).toBe(3);
		expect(result?.contractCreationTimestamp).toBe(1699990000);
		expect(result).not.toHaveProperty('currentTimestamp');
	});

	it('uses tx.nonce (deployment-time) not getTransactionCount', async () => {
		const mockGetTx = vi.fn().mockResolvedValue({ nonce: 7 });
		const client = makeMockClient({ getTransaction: mockGetTx });
		const result = await fetchDeployerStaticInfo(CONTRACT, client);

		expect(result?.deployerNonce).toBe(7);
		expect(mockGetTx).toHaveBeenCalledWith({ hash: CREATION_TX });
	});

	it('returns null when Blockscout returns non-OK', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }));
		const result = await fetchDeployerStaticInfo(CONTRACT, makeMockClient());
		expect(result).toBeNull();
	});

	it('returns null for EOA (no creator)', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: true,
				json: () => Promise.resolve({}),
			}),
		);
		const result = await fetchDeployerStaticInfo(CONTRACT, makeMockClient());
		expect(result).toBeNull();
	});

	it('returns null on Blockscout timeout', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new DOMException('Aborted', 'AbortError')));
		const result = await fetchDeployerStaticInfo(CONTRACT, makeMockClient());
		expect(result).toBeNull();
	});

	it('returns null on RPC failure', async () => {
		const client = makeMockClient({
			getTransaction: vi.fn().mockRejectedValue(new Error('RPC down')),
		});
		const result = await fetchDeployerStaticInfo(CONTRACT, client);
		expect(result).toBeNull();
	});

	it('validates Blockscout response types', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue({
				ok: true,
				json: () =>
					Promise.resolve({
						creator_address_hash: 123,
						creation_transaction_hash: CREATION_TX,
					}),
			}),
		);
		const result = await fetchDeployerStaticInfo(CONTRACT, makeMockClient());
		expect(result).toBeNull();
	});

	it('calls Blockscout with correct URL', async () => {
		const mockFetch = vi.fn().mockResolvedValue({
			ok: true,
			json: () =>
				Promise.resolve({
					creator_address_hash: DEPLOYER,
					creation_transaction_hash: CREATION_TX,
				}),
		});
		vi.stubGlobal('fetch', mockFetch);

		await fetchDeployerStaticInfo(CONTRACT, makeMockClient());

		expect(mockFetch).toHaveBeenCalledWith(
			`https://eth.blockscout.com/api/v2/addresses/${CONTRACT}`,
			expect.objectContaining({ signal: expect.any(AbortSignal) }),
		);
	});
});
