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

const ADDR_A = '0x1111111111111111111111111111111111111111';
const ADDR_B = '0x2222222222222222222222222222222222222222';

const EIP1967_SLOT = (addr: string) =>
	`0x000000000000000000000000${addr.replace(/^0x/, '').toLowerCase()}`;

// Minimal bytecode that trips the EIP-1967 proxy detector:
// includes all three slot constants + DELEGATECALL.
// We rely on `extractMinimalProxyTarget` not matching, so only EIP-1967
// storage-based resolution drives recursion.
// Instead, use a handcrafted snippet that lands `proxy.isProxy === true`:
//   PUSH32 <impl slot> + PUSH32 <admin slot> + PUSH32 <beacon slot> + DELEGATECALL
const IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';
const ADMIN_SLOT = 'b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103';
const BEACON_SLOT = 'a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50';
const PROXY_BYTECODE = `0x7f${IMPL_SLOT}7f${ADMIN_SLOT}7f${BEACON_SLOT}f4`;

describe('analyzeContract — proxy cycle detection', () => {
	beforeEach(() => {
		getCode.mockReset();
		getStorageAt.mockReset();
		vi.resetModules();
	});

	it('returns a cycle result when the same address is visited twice (A → A)', async () => {
		// 1) Fetch bytecode for A → returns proxy bytecode.
		// 2) Proxy resolution for A → returns A itself (self-loop).
		// 3) Recursive call with _visitedAddresses = { A } → early return.
		getCode.mockResolvedValue(PROXY_BYTECODE);
		getStorageAt.mockResolvedValue(EIP1967_SLOT(ADDR_A));

		const { analyzeContract } = await import('../src/analyzer');
		const result = await analyzeContract(ADDR_A);

		expect(result.implementationAnalysis?.threats).toContain('proxy_cycle_detected');
		expect(result.implementationAnalysis?.error).toMatch(/cycle/i);
	});

	it('returns a cycle result on A → B → A chain', async () => {
		// First call: fetch A's code. Second: fetch B's code. Third would fetch A again
		// but the cycle guard catches it before `fetchBytecode` runs.
		getCode.mockResolvedValueOnce(PROXY_BYTECODE); // A
		getCode.mockResolvedValueOnce(PROXY_BYTECODE); // B
		getStorageAt.mockResolvedValueOnce(EIP1967_SLOT(ADDR_B)); // A → B
		getStorageAt.mockResolvedValueOnce(EIP1967_SLOT(ADDR_A)); // B → A (would cycle)

		const { analyzeContract } = await import('../src/analyzer');
		const result = await analyzeContract(ADDR_A);

		const inner = result.implementationAnalysis?.implementationAnalysis;
		expect(inner?.threats).toContain('proxy_cycle_detected');
	});
});

describe('analyzeContract — fetch error classification', () => {
	beforeEach(() => {
		getCode.mockReset();
		getStorageAt.mockReset();
		vi.resetModules();
	});

	it('tags network errors as bytecode_fetch_failed', async () => {
		getCode.mockRejectedValueOnce(new Error('socket hang up'));
		const { analyzeContract } = await import('../src/analyzer');
		const result = await analyzeContract(ADDR_A);
		expect(result.risk).toBe('UNKNOWN');
		expect(result.threats).toContain('bytecode_fetch_failed');
		expect(result.error).toContain('socket hang up');
	});

	it('tags non-hex RPC responses as invalid_bytecode', async () => {
		getCode.mockResolvedValueOnce('0xZZZZ');
		const { analyzeContract } = await import('../src/analyzer');
		const result = await analyzeContract(ADDR_A);
		expect(result.risk).toBe('UNKNOWN');
		expect(result.threats).toContain('invalid_bytecode');
	});

	it('still returns "No bytecode found" for EOAs (0x response)', async () => {
		getCode.mockResolvedValueOnce('0x');
		const { analyzeContract } = await import('../src/analyzer');
		const result = await analyzeContract(ADDR_A);
		expect(result.risk).toBe('UNKNOWN');
		expect(result.threats).toEqual(['No bytecode found']);
	});
});
