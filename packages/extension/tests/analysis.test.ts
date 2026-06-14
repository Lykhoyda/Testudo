import type { AnalysisResult, DeployerRiskAssessment, Warning } from '@testudo/core';
import { describe, expect, it, vi } from 'vitest';
import type { AnalysisDeps } from '../src/analysis';
import { createAnalysisPipeline } from '../src/analysis';
import type { ApiClientResult } from '../src/api-client';

const ADDR = '0xabcdef1234567890abcdef1234567890abcdef12';
const URL = 'https://app.uniswap.org';

function makeDeps(overrides: Partial<AnalysisDeps> = {}): AnalysisDeps {
	return {
		safeFilter: { isKnownSafe: vi.fn().mockReturnValue(false) },
		checkAddressThreat: vi.fn().mockResolvedValue({ success: false, error: 'unavailable' }),
		analyzeContract: vi.fn().mockResolvedValue({
			risk: 'LOW',
			threats: [],
			address: ADDR,
			blocked: false,
		} satisfies AnalysisResult),
		checkKnownMalicious: vi.fn().mockReturnValue(null),
		assessDeployerRisk: vi
			.fn()
			.mockReturnValue({ risk: 'LOW', contractAge: 999999, deployerNonce: 100, reasons: [] }),
		generateDeployerWarnings: vi.fn().mockReturnValue([]),
		deriveRiskFromWarnings: vi.fn().mockReturnValue({ risk: 'LOW', blocked: false }),
		fetchDeployerStaticInfo: vi.fn().mockResolvedValue(null),
		isWhitelisted: vi.fn().mockResolvedValue(false),
		getSettings: vi.fn().mockResolvedValue({
			apiUrl: null,
			rpcUrl: null,
			showMediumRiskToast: true,
			autoRecordScans: true,
		}),
		recordScan: vi.fn().mockResolvedValue(undefined),
		incrementScanned: vi.fn().mockResolvedValue(undefined),
		getOrCreateClient: vi.fn().mockReturnValue({} as never),
		...overrides,
	};
}

function makeApiClean(): ApiClientResult {
	return { success: true, data: { isMalicious: false, address: ADDR } };
}

function makeApiMalicious(): ApiClientResult {
	return { success: true, data: { isMalicious: true, address: ADDR, threatType: 'ETH_DRAINER' } };
}

function makeLocalResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
	return { risk: 'LOW', threats: [], address: ADDR, blocked: false, ...overrides };
}

function makeWarning(
	severity: Warning['severity'],
	type: Warning['type'] = 'AUTO_FORWARDER',
): Warning {
	return { type, severity, title: 'Test', description: 'Test warning' };
}

// ============================================================================
// analyzeWithCache (full delegation analysis)
// ============================================================================

describe('analyzeWithCache', () => {
	it('returns whitelist result immediately when whitelisted', async () => {
		const deps = makeDeps({ isWhitelisted: vi.fn().mockResolvedValue(true) });
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.whitelisted).toBe(true);
		expect(result.source).toBe('whitelist');
		expect(deps.checkAddressThreat).not.toHaveBeenCalled();
		expect(deps.analyzeContract).not.toHaveBeenCalled();
	});

	it('returns safe-filter result and skips all other layers', async () => {
		const deps = makeDeps({
			safeFilter: { isKnownSafe: vi.fn().mockReturnValue(true) },
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.source).toBe('safe-filter');
		expect(deps.checkAddressThreat).not.toHaveBeenCalled();
		expect(deps.analyzeContract).not.toHaveBeenCalled();
	});

	it('returns local-malicious-db result and skips API/bytecode', async () => {
		const deps = makeDeps({
			checkKnownMalicious: vi.fn().mockReturnValue({ type: 'ETH_DRAINER' }),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('CRITICAL');
		expect(result.blocked).toBe(true);
		expect(result.source).toBe('local-malicious-db');
		expect(deps.checkAddressThreat).not.toHaveBeenCalled();
		expect(deps.analyzeContract).not.toHaveBeenCalled();
	});

	it('serves cache for full analysis results (source includes local)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const first = await analyzeWithCache(ADDR, URL);
		expect(first.source).toMatch(/local/);

		const second = await analyzeWithCache(ADDR, URL);
		expect(second.cached).toBe(true);
		expect(deps.analyzeContract).toHaveBeenCalledTimes(1);
	});

	it('does NOT serve cache for address-only results (source: api)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { analyzeWithCache, addressCheckWithCache, analysisCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL);
		// Cache is partitioned by chainId — default is chain 1 (S-16)
		const cached = analysisCache.get(`1:${ADDR}`);
		expect(cached?.result.source).toBe('api');

		await analyzeWithCache(ADDR, URL);
		expect(deps.analyzeContract).toHaveBeenCalledTimes(1);
	});

	it('runs API + bytecode + deployer in parallel via Promise.allSettled', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
			fetchDeployerStaticInfo: vi.fn().mockResolvedValue(null),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(ADDR, URL);

		expect(deps.checkAddressThreat).toHaveBeenCalledTimes(1);
		expect(deps.analyzeContract).toHaveBeenCalledTimes(1);
		expect(deps.fetchDeployerStaticInfo).toHaveBeenCalledTimes(1);
	});

	it('handles API rejection gracefully (fail-open to local)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockRejectedValue(new Error('network error')),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.apiUnavailable).toBe(true);
	});

	it('handles local analysis rejection gracefully (UNKNOWN, fail-open)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockRejectedValue(new Error('RPC error')),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('UNKNOWN');
		expect(result.blocked).toBe(false);
	});

	it('handles deployer rejection gracefully (skips deployer merge)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
			fetchDeployerStaticInfo: vi.fn().mockRejectedValue(new Error('Blockscout down')),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(deps.assessDeployerRisk).not.toHaveBeenCalled();
	});

	it('merges deployer warnings into local result and escalates risk', async () => {
		const deployerWarning = makeWarning('HIGH', 'DEPLOYER_LOW_NONCE');
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
			fetchDeployerStaticInfo: vi.fn().mockResolvedValue({
				deployerAddress: '0xdead',
				deployerNonce: 2,
				contractCreationTimestamp: Math.floor(Date.now() / 1000) - 3600,
			}),
			assessDeployerRisk: vi.fn().mockReturnValue({
				risk: 'HIGH',
				contractAge: 3600,
				deployerNonce: 2,
				reasons: ['Low nonce'],
			} satisfies DeployerRiskAssessment),
			generateDeployerWarnings: vi.fn().mockReturnValue([deployerWarning]),
			deriveRiskFromWarnings: vi.fn().mockReturnValue({ risk: 'HIGH', blocked: true }),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(deps.assessDeployerRisk).toHaveBeenCalled();
		expect(deps.deriveRiskFromWarnings).toHaveBeenCalledWith([deployerWarning]);
		expect(result.blocked).toBe(true);
	});

	it('skips deployer merge when generateDeployerWarnings returns empty', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
			fetchDeployerStaticInfo: vi.fn().mockResolvedValue({
				deployerAddress: '0xdead',
				deployerNonce: 100,
				contractCreationTimestamp: 0,
			}),
			assessDeployerRisk: vi.fn().mockReturnValue({
				risk: 'LOW',
				contractAge: 999999,
				deployerNonce: 100,
				reasons: [],
			} satisfies DeployerRiskAssessment),
			generateDeployerWarnings: vi.fn().mockReturnValue([]),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(deps.deriveRiskFromWarnings).not.toHaveBeenCalled();
		expect(result.risk).toBe('LOW');
	});

	it('records scan and increments counter after full analysis', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(ADDR, URL);

		expect(deps.recordScan).toHaveBeenCalledWith(
			expect.objectContaining({ address: ADDR, url: URL }),
		);
		expect(deps.incrementScanned).toHaveBeenCalledTimes(1);
	});

	it('deduplicates concurrent requests for the same address', async () => {
		let resolveAnalysis!: (value: AnalysisResult) => void;
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockReturnValue(
				new Promise<AnalysisResult>((r) => {
					resolveAnalysis = r;
				}),
			),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const p1 = analyzeWithCache(ADDR, URL);
		const p2 = analyzeWithCache(ADDR, URL);

		resolveAnalysis(makeLocalResult());

		const [r1, r2] = await Promise.all([p1, p2]);
		expect(r1).toEqual(r2);
		expect(deps.analyzeContract).toHaveBeenCalledTimes(1);
	});

	it('returns UNKNOWN on global analysis timeout (5s)', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockReturnValue(new Promise(() => {})),
			analyzeContract: vi.fn().mockReturnValue(new Promise(() => {})),
			fetchDeployerStaticInfo: vi.fn().mockReturnValue(new Promise(() => {})),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL);

		expect(result.risk).toBe('UNKNOWN');
		expect(result.threats).toContain('Analysis timeout');
		expect(result.apiUnavailable).toBe(true);
		expect(result.blocked).toBe(false);
		expect(deps.recordScan).toHaveBeenCalled();
	}, 10_000);

	it('normalizes address to lowercase', async () => {
		const mixedCase = '0xABCDEF1234567890ABCDEF1234567890ABCDEF12';
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(mixedCase, URL);

		expect(deps.analyzeContract).toHaveBeenCalledWith(mixedCase.toLowerCase(), expect.any(Object));
	});
});

// ============================================================================
// addressCheckWithCache (address-only check, no bytecode)
// ============================================================================

describe('addressCheckWithCache', () => {
	it('returns whitelist result immediately when whitelisted', async () => {
		const deps = makeDeps({ isWhitelisted: vi.fn().mockResolvedValue(true) });
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.whitelisted).toBe(true);
		expect(result.source).toBe('whitelist');
		expect(deps.checkAddressThreat).not.toHaveBeenCalled();
	});

	it('returns cached result within TTL', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const _first = await addressCheckWithCache(ADDR, URL);
		const second = await addressCheckWithCache(ADDR, URL);

		expect(second.cached).toBe(true);
		expect(deps.checkAddressThreat).toHaveBeenCalledTimes(1);
	});

	it('returns safe-filter result for known safe address', async () => {
		const deps = makeDeps({
			safeFilter: { isKnownSafe: vi.fn().mockReturnValue(true) },
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.source).toBe('safe-filter');
		expect(deps.checkAddressThreat).not.toHaveBeenCalled();
	});

	it('returns CRITICAL for local malicious DB hit', async () => {
		const deps = makeDeps({
			checkKnownMalicious: vi.fn().mockReturnValue({ type: 'PHISHING' }),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('CRITICAL');
		expect(result.blocked).toBe(true);
		expect(result.source).toBe('local-malicious-db');
	});

	it('returns CRITICAL when API flags malicious', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiMalicious()),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('CRITICAL');
		expect(result.blocked).toBe(true);
		expect(result.source).toBe('api');
		expect(result.threats).toContain('ETH_DRAINER');
	});

	it('returns LOW when API flags clean', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('LOW');
		expect(result.blocked).toBe(false);
		expect(result.source).toBe('api');
	});

	it('returns UNKNOWN when API unavailable', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue({ success: false, error: 'timeout' }),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('UNKNOWN');
		expect(result.blocked).toBe(false);
		expect(result.source).toBe('fallback');
		expect(result.apiUnavailable).toBe(true);
	});

	it('returns UNKNOWN when API rejects', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockRejectedValue(new Error('network')),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const result = await addressCheckWithCache(ADDR, URL);

		expect(result.risk).toBe('UNKNOWN');
		expect(result.apiUnavailable).toBe(true);
	});

	it('records scan and increments counter', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL);

		expect(deps.recordScan).toHaveBeenCalledWith(
			expect.objectContaining({ address: ADDR, url: URL }),
		);
		expect(deps.incrementScanned).toHaveBeenCalledTimes(1);
	});

	it('does NOT record scan for safe-filter hit', async () => {
		const deps = makeDeps({
			safeFilter: { isKnownSafe: vi.fn().mockReturnValue(true) },
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL);

		expect(deps.recordScan).not.toHaveBeenCalled();
		expect(deps.incrementScanned).not.toHaveBeenCalled();
	});

	it('deduplicates concurrent requests', async () => {
		let resolveApi!: (value: ApiClientResult) => void;
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockReturnValue(
				new Promise<ApiClientResult>((r) => {
					resolveApi = r;
				}),
			),
		});
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		const p1 = addressCheckWithCache(ADDR, URL);
		const p2 = addressCheckWithCache(ADDR, URL);

		resolveApi(makeApiClean());

		const [r1, r2] = await Promise.all([p1, p2]);
		expect(r1).toEqual(r2);
		expect(deps.checkAddressThreat).toHaveBeenCalledTimes(1);
	});
});

// ============================================================================
// Cross-concern: shared pendingAnalysis deduplication
// ============================================================================

describe('cross-request isolation', () => {
	it('analyzeWithCache and addressCheckWithCache use separate pending maps', async () => {
		const deps = makeDeps({
			checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()),
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
		});
		const { analyzeWithCache, addressCheckWithCache } = createAnalysisPipeline(deps);

		const [full, addressOnly] = await Promise.all([
			analyzeWithCache(ADDR, URL),
			addressCheckWithCache(ADDR, URL),
		]);

		// Full analysis runs bytecode; address-only does not
		expect(deps.analyzeContract).toHaveBeenCalledTimes(1);
		// Both resolve independently
		expect(full.source).toMatch(/local/);
		expect(addressOnly.source).toBe('api');
	});
});

// ============================================================================
// Cache isolation: each pipeline has independent state
// ============================================================================

describe('pipeline isolation', () => {
	it('two pipelines do not share cache', async () => {
		const deps1 = makeDeps({ checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()) });
		const deps2 = makeDeps({ checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()) });
		const pipeline1 = createAnalysisPipeline(deps1);
		const pipeline2 = createAnalysisPipeline(deps2);

		await pipeline1.addressCheckWithCache(ADDR, URL);

		// Cache is keyed `${chainId}:${address}` — default chainId 1 (S-16)
		expect(pipeline1.analysisCache.has(`1:${ADDR}`)).toBe(true);
		expect(pipeline2.analysisCache.has(`1:${ADDR}`)).toBe(false);
	});
});

// ============================================================================
// S-16: chainId threading + per-chain cache partitioning
// ============================================================================

describe('chainId threading (S-16)', () => {
	it('forwards chainId into checkAddressThreat for address-only checks', async () => {
		const api = vi.fn().mockResolvedValue(makeApiClean());
		const deps = makeDeps({ checkAddressThreat: api });
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL, 8453);

		expect(api).toHaveBeenCalledWith(ADDR, expect.objectContaining({ chainId: 8453 }));
	});

	it('forwards chainId into checkAddressThreat for full three-layer analysis', async () => {
		const api = vi.fn().mockResolvedValue(makeApiClean());
		const deps = makeDeps({
			checkAddressThreat: api,
			analyzeContract: vi.fn().mockResolvedValue(makeLocalResult()),
		});
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(ADDR, URL, 42161);

		expect(api).toHaveBeenCalledWith(ADDR, expect.objectContaining({ chainId: 42161 }));
	});

	it('partitions the cache by chainId — same address on different chains', async () => {
		const api = vi.fn().mockResolvedValue(makeApiClean());
		const deps = makeDeps({ checkAddressThreat: api });
		const { addressCheckWithCache, analysisCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL, 1);
		await addressCheckWithCache(ADDR, URL, 8453);

		expect(analysisCache.has(`1:${ADDR}`)).toBe(true);
		expect(analysisCache.has(`8453:${ADDR}`)).toBe(true);
		expect(api).toHaveBeenCalledTimes(2);
	});

	it('uses chainId=1 as default cache key when no chainId is passed', async () => {
		const deps = makeDeps({ checkAddressThreat: vi.fn().mockResolvedValue(makeApiClean()) });
		const { addressCheckWithCache, analysisCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL);

		expect(analysisCache.has(`1:${ADDR}`)).toBe(true);
	});

	it('returns cached result for the same chainId but not across chains', async () => {
		const api = vi.fn().mockResolvedValue(makeApiClean());
		const deps = makeDeps({ checkAddressThreat: api });
		const { addressCheckWithCache } = createAnalysisPipeline(deps);

		await addressCheckWithCache(ADDR, URL, 10);
		const second = await addressCheckWithCache(ADDR, URL, 10);
		expect(second.cached).toBe(true);
		expect(api).toHaveBeenCalledTimes(1);

		await addressCheckWithCache(ADDR, URL, 8453);
		expect(api).toHaveBeenCalledTimes(2);
	});
});

// ============================================================================
// chain-aware bytecode/deployer gating (AUDIT-5)
// ============================================================================

describe('chain-aware bytecode/deployer gating (AUDIT-5)', () => {
	it('skips bytecode + deployer analysis on non-mainnet chains (fail-secure)', async () => {
		const deps = makeDeps();
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL, 8453); // Base

		expect(deps.analyzeContract).not.toHaveBeenCalled();
		expect(deps.fetchDeployerStaticInfo).not.toHaveBeenCalled();
		// API unavailable (default) + skipped local → UNKNOWN: never a wrong-chain
		// verdict and never a false "clean".
		expect(result.risk).toBe('UNKNOWN');
		expect(result.blocked).toBe(false);
	});

	it('still BLOCKS on non-mainnet when the chain-aware API flags malicious', async () => {
		const deps = makeDeps({ checkAddressThreat: vi.fn().mockResolvedValue(makeApiMalicious()) });
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		const result = await analyzeWithCache(ADDR, URL, 10); // Optimism

		expect(deps.analyzeContract).not.toHaveBeenCalled();
		expect(result.risk).toBe('CRITICAL');
		expect(result.blocked).toBe(true);
	});

	it('runs bytecode + deployer analysis on mainnet (chainId 1)', async () => {
		const deps = makeDeps();
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(ADDR, URL, 1);

		expect(deps.analyzeContract).toHaveBeenCalled();
	});

	it('runs bytecode analysis when chainId is undefined (defaults to mainnet)', async () => {
		const deps = makeDeps();
		const { analyzeWithCache } = createAnalysisPipeline(deps);

		await analyzeWithCache(ADDR, URL);

		expect(deps.analyzeContract).toHaveBeenCalled();
	});
});
