import type { AnalysisResult, DeployerRiskAssessment, Warning } from '@testudo/core';
import type { Address } from 'viem';
import type { ApiClientResult } from './api-client';
import type { ExtendedAnalysisResult } from './decision-matrix';
import { applyDecisionMatrix } from './decision-matrix';
import type { DeployerStaticInfo } from './services/deployer-lookup';
import type { Settings } from './storage';

export type { ExtendedAnalysisResult } from './decision-matrix';

const CACHE_TTL = 60 * 60 * 1000; // 60 minutes
const DEFAULT_RPC = 'https://eth.llamarpc.com';
const ANALYSIS_TIMEOUT = 5_000; // 5s global timeout for three-layer analysis

export interface AnalysisDeps {
	safeFilter: { isKnownSafe(address: string): boolean };
	checkAddressThreat(address: string, options?: { baseUrl?: string }): Promise<ApiClientResult>;
	analyzeContract(address: `0x${string}`, options?: { rpcUrl?: string }): Promise<AnalysisResult>;
	checkKnownMalicious(address: string): { type: string } | null;
	assessDeployerRisk(
		info: DeployerStaticInfo & { currentTimestamp: number },
	): DeployerRiskAssessment;
	generateDeployerWarnings(assessment: DeployerRiskAssessment): Warning[];
	deriveRiskFromWarnings(warnings: Warning[]): { risk: AnalysisResult['risk']; blocked: boolean };
	fetchDeployerStaticInfo(address: Address, client: unknown): Promise<DeployerStaticInfo | null>;
	isWhitelisted(address: string): Promise<boolean>;
	getSettings(): Promise<Settings>;
	recordScan(scan: {
		address: string;
		risk: string;
		threats: string[];
		url?: string;
		blocked: boolean;
	}): Promise<unknown>;
	incrementScanned(): Promise<unknown>;
	getOrCreateClient(rpcUrl: string): unknown;
}

export interface AnalysisPipeline {
	analyzeWithCache(address: string, url?: string): Promise<ExtendedAnalysisResult>;
	addressCheckWithCache(address: string, url?: string): Promise<ExtendedAnalysisResult>;
	readonly analysisCache: Map<string, { result: ExtendedAnalysisResult; timestamp: number }>;
}

export function createAnalysisPipeline(deps: AnalysisDeps): AnalysisPipeline {
	const analysisCache = new Map<string, { result: ExtendedAnalysisResult; timestamp: number }>();
	const deployerCache = new Map<string, DeployerStaticInfo>();
	const pendingFullAnalysis = new Map<string, Promise<ExtendedAnalysisResult>>();
	const pendingAddressCheck = new Map<string, Promise<ExtendedAnalysisResult>>();

	async function getApiUrl(): Promise<string> {
		const settings = await deps.getSettings();
		return settings.apiUrl || process.env.TESTUDO_API_URL;
	}

	async function performAddressOnlyCheck(
		normalizedAddress: string,
		url?: string,
	): Promise<ExtendedAnalysisResult> {
		const baseResult = { address: normalizedAddress as `0x${string}` };

		if (deps.safeFilter.isKnownSafe(normalizedAddress)) {
			const result: ExtendedAnalysisResult = {
				...baseResult,
				risk: 'LOW',
				threats: [],
				blocked: false,
				source: 'safe-filter',
			};
			analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
			return result;
		}

		const knownMalicious = deps.checkKnownMalicious(normalizedAddress);
		if (knownMalicious) {
			const result: ExtendedAnalysisResult = {
				...baseResult,
				risk: 'CRITICAL',
				threats: [knownMalicious.type],
				blocked: true,
				source: 'local-malicious-db',
			};
			analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
			return result;
		}

		const apiUrl = await getApiUrl();
		const api = await deps
			.checkAddressThreat(normalizedAddress, { baseUrl: apiUrl })
			.catch(() => ({ success: false, error: 'API call failed' }) as ApiClientResult);

		let result: ExtendedAnalysisResult;

		if (api.success && api.data?.isMalicious === true) {
			result = {
				...baseResult,
				risk: 'CRITICAL',
				threats: [api.data.threatType || 'KNOWN_MALICIOUS'],
				blocked: true,
				source: 'api',
			};
		} else if (api.success && api.data != null && api.data.isMalicious === false) {
			result = {
				...baseResult,
				risk: 'LOW',
				threats: [],
				blocked: false,
				source: 'api',
			};
		} else {
			result = {
				...baseResult,
				risk: 'UNKNOWN',
				threats: [],
				blocked: false,
				source: 'fallback',
				apiUnavailable: true,
			};
		}

		analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });

		await deps.recordScan({
			address: normalizedAddress,
			risk: result.risk,
			threats: result.threats,
			url,
			blocked: result.blocked,
		});
		await deps.incrementScanned();

		return result;
	}

	async function performThreeLayerAnalysis(
		normalizedAddress: string,
		url?: string,
	): Promise<ExtendedAnalysisResult> {
		// LAYER 0: Safe Filter (local Set - instant)
		if (deps.safeFilter.isKnownSafe(normalizedAddress)) {
			const result: ExtendedAnalysisResult = {
				risk: 'LOW',
				threats: [],
				address: normalizedAddress as `0x${string}`,
				blocked: false,
				source: 'safe-filter',
			};
			analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
			return result;
		}

		// LAYER 0.5: Known Malicious DB (local, instant)
		const knownMalicious = deps.checkKnownMalicious(normalizedAddress);
		if (knownMalicious) {
			const result: ExtendedAnalysisResult = {
				risk: 'CRITICAL',
				threats: [knownMalicious.type],
				address: normalizedAddress as `0x${string}`,
				blocked: true,
				source: 'local-malicious-db',
			};
			analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
			return result;
		}

		// LAYER 1 + LAYER 2: Run API and Local Analysis in parallel
		const apiUrl = await getApiUrl();
		const settings = await deps.getSettings();
		const rpcUrl = settings.rpcUrl || DEFAULT_RPC;
		const client = deps.getOrCreateClient(rpcUrl);

		async function fetchDeployerStaticCached(addr: string): Promise<DeployerStaticInfo | null> {
			const cached = deployerCache.get(addr);
			if (cached) return cached;
			const info = await deps.fetchDeployerStaticInfo(addr as Address, client);
			if (info) deployerCache.set(addr, info);
			return info;
		}

		let timeoutId: ReturnType<typeof setTimeout>;
		const timeoutSignal = new Promise<'timeout'>((resolve) => {
			timeoutId = setTimeout(() => resolve('timeout'), ANALYSIS_TIMEOUT);
		});

		const settled = await Promise.race([
			Promise.allSettled([
				deps.checkAddressThreat(normalizedAddress, { baseUrl: apiUrl }),
				deps.analyzeContract(normalizedAddress as `0x${string}`, { rpcUrl }),
				fetchDeployerStaticCached(normalizedAddress),
			]).then((results) => {
				clearTimeout(timeoutId);
				return results;
			}),
			timeoutSignal,
		]);

		if (settled === 'timeout') {
			const result: ExtendedAnalysisResult = {
				risk: 'UNKNOWN',
				threats: ['Analysis timeout'],
				address: normalizedAddress as `0x${string}`,
				blocked: false,
				source: 'fallback',
				apiUnavailable: true,
			};
			analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });
			await deps.recordScan({
				address: normalizedAddress,
				risk: result.risk,
				threats: result.threats,
				url,
				blocked: result.blocked,
			});
			await deps.incrementScanned();
			return result;
		}

		const [apiResult, localResult, deployerResult] = settled;

		const api =
			apiResult.status === 'fulfilled'
				? apiResult.value
				: ({ success: false, error: 'Promise rejected' } as ApiClientResult);

		let local =
			localResult.status === 'fulfilled'
				? localResult.value
				: ({
						risk: 'UNKNOWN',
						threats: ['Local analysis failed'],
						address: normalizedAddress,
						blocked: false,
					} as AnalysisResult);

		const deployerStatic = deployerResult.status === 'fulfilled' ? deployerResult.value : null;

		// Merge deployer warnings into local result
		if (deployerStatic) {
			const assessment = deps.assessDeployerRisk({
				...deployerStatic,
				currentTimestamp: Math.floor(Date.now() / 1000),
			});
			const deployerWarnings = deps.generateDeployerWarnings(assessment);
			if (deployerWarnings.length > 0) {
				const allWarnings = [...(local.warnings || []), ...deployerWarnings];
				const derived = deps.deriveRiskFromWarnings(allWarnings);
				local = {
					...local,
					warnings: allWarnings,
					risk: derived.risk,
					blocked: derived.blocked,
					deployerRisk: assessment,
					threats: allWarnings
						.filter((w) => w.severity !== 'INFO')
						.map((w) => w.type.toLowerCase()),
				};
			} else if (assessment.risk === 'LOW') {
				local = { ...local, deployerRisk: assessment };
			}
		}

		// DECISION MATRIX (ADR-006)
		const finalResult = applyDecisionMatrix(api, local, normalizedAddress);

		analysisCache.set(normalizedAddress, { result: finalResult, timestamp: Date.now() });

		await deps.recordScan({
			address: normalizedAddress,
			risk: finalResult.risk,
			threats: finalResult.threats,
			url,
			blocked: finalResult.blocked,
		});

		await deps.incrementScanned();

		return finalResult;
	}

	async function addressCheckWithCache(
		address: string,
		url?: string,
	): Promise<ExtendedAnalysisResult> {
		const normalizedAddress = address.toLowerCase();

		const whitelisted = await deps.isWhitelisted(normalizedAddress);
		if (whitelisted) {
			return {
				risk: 'LOW',
				threats: [],
				address: normalizedAddress as `0x${string}`,
				blocked: false,
				whitelisted: true,
				source: 'whitelist',
			};
		}

		const cached = analysisCache.get(normalizedAddress);
		if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
			return { ...cached.result, cached: true };
		}

		const pending = pendingAddressCheck.get(normalizedAddress);
		if (pending) return pending;

		const checkPromise = performAddressOnlyCheck(normalizedAddress, url);
		pendingAddressCheck.set(normalizedAddress, checkPromise);

		try {
			return await checkPromise;
		} finally {
			pendingAddressCheck.delete(normalizedAddress);
		}
	}

	async function analyzeWithCache(address: string, url?: string): Promise<ExtendedAnalysisResult> {
		const normalizedAddress = address.toLowerCase();

		const whitelisted = await deps.isWhitelisted(normalizedAddress);
		if (whitelisted) {
			return {
				risk: 'LOW',
				threats: [],
				address: normalizedAddress as `0x${string}`,
				blocked: false,
				whitelisted: true,
				source: 'whitelist',
			};
		}

		// Only trust full analysis results or global allows — not address-only (source: 'api')
		const cached = analysisCache.get(normalizedAddress);
		if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
			const source = cached.result.source || '';
			const isFullAnalysis = source.includes('local') || source === 'api+local';
			const isGlobalAllow = source === 'whitelist' || source === 'safe-filter';

			if (isFullAnalysis || isGlobalAllow) {
				return { ...cached.result, cached: true };
			}
		}

		const pending = pendingFullAnalysis.get(normalizedAddress);
		if (pending) return pending;

		const analysisPromise = performThreeLayerAnalysis(normalizedAddress, url);
		pendingFullAnalysis.set(normalizedAddress, analysisPromise);

		try {
			return await analysisPromise;
		} finally {
			pendingFullAnalysis.delete(normalizedAddress);
		}
	}

	return { analyzeWithCache, addressCheckWithCache, analysisCache };
}
