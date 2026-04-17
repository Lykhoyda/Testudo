import { beforeEach, describe, expect, it, vi } from 'vitest';

const getCode = vi.fn();
const getStorageAt = vi.fn();

vi.mock('viem', async () => {
	const actual = await vi.importActual<typeof import('viem')>('viem');
	return {
		...actual,
		createPublicClient: () => ({ getCode, getStorageAt }),
		http: () => ({}),
	};
});

describe('fetchBytecode', () => {
	beforeEach(() => {
		getCode.mockReset();
		getStorageAt.mockReset();
		vi.resetModules();
	});

	it('returns bytecode as-is on success', async () => {
		getCode.mockResolvedValueOnce('0x60ff');
		const { fetchBytecode } = await import('../src/fetcher');
		const result = await fetchBytecode('0x1234567890abcdef1234567890abcdef12345678', 'https://x');
		expect(result).toBe('0x60ff');
	});

	it('returns null when RPC reports empty bytecode (EOA / undeployed)', async () => {
		getCode.mockResolvedValueOnce('0x');
		const { fetchBytecode } = await import('../src/fetcher');
		const result = await fetchBytecode('0x1234567890abcdef1234567890abcdef12345678', 'https://y');
		expect(result).toBeNull();
	});

	it('returns null when RPC returns undefined', async () => {
		getCode.mockResolvedValueOnce(undefined);
		const { fetchBytecode } = await import('../src/fetcher');
		const result = await fetchBytecode('0x1234567890abcdef1234567890abcdef12345678', 'https://z');
		expect(result).toBeNull();
	});

	it('throws BytecodeFetchError on RPC rejection (not silent null)', async () => {
		getCode.mockRejectedValueOnce(new Error('rate limit'));
		const { fetchBytecode, BytecodeFetchError } = await import('../src/fetcher');
		await expect(
			fetchBytecode('0x1234567890abcdef1234567890abcdef12345678', 'https://w'),
		).rejects.toThrow(BytecodeFetchError);
	});

	it('BytecodeFetchError preserves original cause', async () => {
		const original = new Error('timeout');
		getCode.mockRejectedValueOnce(original);
		const { fetchBytecode, BytecodeFetchError } = await import('../src/fetcher');
		try {
			await fetchBytecode('0x1234567890abcdef1234567890abcdef12345678', 'https://t');
			expect.fail('expected throw');
		} catch (err) {
			expect(err).toBeInstanceOf(BytecodeFetchError);
			expect((err as InstanceType<typeof BytecodeFetchError>).cause).toBe(original);
			expect((err as Error).message).toContain('timeout');
		}
	});
});

describe('resolveProxyImplementation', () => {
	beforeEach(() => {
		getCode.mockReset();
		getStorageAt.mockReset();
		vi.resetModules();
	});

	it('returns null when slot is empty', async () => {
		getStorageAt.mockResolvedValueOnce(`0x${'0'.repeat(64)}`);
		const { resolveProxyImplementation } = await import('../src/fetcher');
		const result = await resolveProxyImplementation(
			'0x1234567890abcdef1234567890abcdef12345678',
			'https://x',
		);
		expect(result).toBeNull();
	});

	it('returns null and does NOT throw when RPC fails', async () => {
		getStorageAt.mockRejectedValueOnce(new Error('rpc down'));
		const { resolveProxyImplementation } = await import('../src/fetcher');
		const result = await resolveProxyImplementation(
			'0x1234567890abcdef1234567890abcdef12345678',
			'https://x',
		);
		// Proxy resolution stays fail-open — absence of implementation ≠ failure.
		expect(result).toBeNull();
	});

	it('extracts rightmost 20 bytes when slot is populated', async () => {
		getStorageAt.mockResolvedValueOnce(
			'0x000000000000000000000000abcdefabcdefabcdefabcdefabcdefabcdefabcd',
		);
		const { resolveProxyImplementation } = await import('../src/fetcher');
		const result = await resolveProxyImplementation(
			'0x1234567890abcdef1234567890abcdef12345678',
			'https://x',
		);
		expect(result?.toLowerCase()).toBe('0xabcdefabcdefabcdefabcdefabcdefabcdefabcd');
	});
});
