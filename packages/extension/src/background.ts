import type { AnalysisResult } from '@testudo/core';
import { analyzeContract, checkKnownMalicious, KNOWN_MALICIOUS, KNOWN_SAFE } from '@testudo/core';
import type { Address, Hex } from 'viem';
import { createPublicClient, hexToString, http } from 'viem';
import { mainnet } from 'viem/chains';
import type { ApiClientResult } from './api-client';
import { checkAddressThreat } from './api-client';
import {
	getSafeFilter,
	handleSafeFilterAlarm,
	initializeSafeFilterOnInstall,
	setupSafeFilterAlarm,
} from './safe-filter';
import {
	getSettings,
	getStats,
	getWhitelist,
	incrementBlocked,
	incrementScanned,
	isWhitelisted,
	recordScan,
} from './storage';

const analysisCache = new Map<string, { result: ExtendedAnalysisResult; timestamp: number }>();
const CACHE_TTL = 60 * 60 * 1000; // 60 minutes

// Pending analysis requests to prevent duplicate concurrent requests for the same address
const pendingAnalysis = new Map<string, Promise<ExtendedAnalysisResult>>();

interface ExtendedAnalysisResult extends AnalysisResult {
	whitelisted?: boolean;
	cached?: boolean;
	source?: string;
	apiUnavailable?: boolean;
}

// Get API URL from settings or use build-time default
async function getApiUrl(): Promise<string> {
	const settings = await getSettings();
	return settings.apiUrl || process.env.TESTUDO_API_URL;
}

const DEFAULT_RPC = 'https://eth.llamarpc.com';

const erc20StringAbi = [
	{
		inputs: [],
		name: 'name',
		outputs: [{ name: '', type: 'string' }],
		stateMutability: 'view',
		type: 'function',
	},
	{
		inputs: [],
		name: 'symbol',
		outputs: [{ name: '', type: 'string' }],
		stateMutability: 'view',
		type: 'function',
	},
	{
		inputs: [],
		name: 'decimals',
		outputs: [{ name: '', type: 'uint8' }],
		stateMutability: 'view',
		type: 'function',
	},
] as const;

const erc20Bytes32Abi = [
	{
		inputs: [],
		name: 'name',
		outputs: [{ name: '', type: 'bytes32' }],
		stateMutability: 'view',
		type: 'function',
	},
	{
		inputs: [],
		name: 'symbol',
		outputs: [{ name: '', type: 'bytes32' }],
		stateMutability: 'view',
		type: 'function',
	},
] as const;

interface TokenResult {
	name: string | null;
	symbol: string | null;
	decimals: number | null;
}

let cachedClient: ReturnType<typeof createPublicClient> | null = null;
let cachedRpcUrl: string | null = null;

function getOrCreateClient(rpcUrl: string): ReturnType<typeof createPublicClient> {
	if (cachedClient && cachedRpcUrl === rpcUrl) return cachedClient;
	cachedClient = createPublicClient({
		chain: mainnet,
		transport: http(rpcUrl, { timeout: 5_000 }),
	});
	cachedRpcUrl = rpcUrl;
	return cachedClient;
}

async function resolveTokenViaRpc(address: string): Promise<TokenResult> {
	const fallback: TokenResult = { name: null, symbol: null, decimals: null };
	try {
		const settings = await getSettings();
		const rpc = settings.customRpcUrl || DEFAULT_RPC;
		const tokenAddress = address.toLowerCase() as Address;
		const client = getOrCreateClient(rpc);

		const results = await client.multicall({
			contracts: [
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'name' },
				{ address: tokenAddress, abi: erc20Bytes32Abi, functionName: 'name' },
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'symbol' },
				{ address: tokenAddress, abi: erc20Bytes32Abi, functionName: 'symbol' },
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'decimals' },
			],
			allowFailure: true,
		});

		const name =
			results[0].status === 'success'
				? results[0].result
				: results[1].status === 'success'
					? hexToString(results[1].result as Hex, { size: 32 }).replace(/\0+$/, '') || null
					: null;

		const symbol =
			results[2].status === 'success'
				? results[2].result
				: results[3].status === 'success'
					? hexToString(results[3].result as Hex, { size: 32 }).replace(/\0+$/, '') || null
					: null;

		const decimals = results[4].status === 'success' ? results[4].result : null;

		return { name, symbol, decimals };
	} catch {
		return fallback;
	}
}

// Initialize Safe Filter
let safeFilter: ReturnType<typeof getSafeFilter>;
try {
	safeFilter = getSafeFilter();
} catch (error) {
	console.error('[Testudo Background] Failed to create safe filter:', error);
	throw error;
}

async function initializeSafeFilter(): Promise<void> {
	await safeFilter.load();
	setupSafeFilterAlarm();
}

// Run on startup
// Note: Message listener registers immediately. If ANALYZE_DELEGATION arrives before
// load() completes, only fallbackSet is checked (fail-safe: triggers API/bytecode analysis)
initializeSafeFilter().catch((error) => {
	console.error('[Testudo Background] Safe filter initialization failed:', error);
});

// Handle extension install
chrome.runtime.onInstalled.addListener(async (details) => {
	if (details.reason === 'install') {
		console.log('[Testudo Background] Extension installed, initializing Safe Filter');
		await initializeSafeFilterOnInstall(safeFilter);
	}
});

// Handle alarms
chrome.alarms.onAlarm.addListener(async (alarm) => {
	await handleSafeFilterAlarm(alarm, safeFilter);
});

async function addressCheckWithCache(
	address: string,
	url?: string,
): Promise<ExtendedAnalysisResult> {
	const normalizedAddress = address.toLowerCase();

	const whitelisted = await isWhitelisted(normalizedAddress);
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

	const pending = pendingAnalysis.get(normalizedAddress);
	if (pending) {
		return pending;
	}

	const checkPromise = performAddressOnlyCheck(normalizedAddress, url);
	pendingAnalysis.set(normalizedAddress, checkPromise);

	try {
		return await checkPromise;
	} finally {
		pendingAnalysis.delete(normalizedAddress);
	}
}

async function performAddressOnlyCheck(
	normalizedAddress: string,
	url?: string,
): Promise<ExtendedAnalysisResult> {
	const baseResult = { address: normalizedAddress as `0x${string}` };

	if (safeFilter.isKnownSafe(normalizedAddress)) {
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

	const knownMalicious = checkKnownMalicious(normalizedAddress);
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
	const api = await checkAddressThreat(normalizedAddress, { baseUrl: apiUrl }).catch(
		() => ({ success: false, error: 'API call failed' }) as ApiClientResult,
	);

	let result: ExtendedAnalysisResult;

	if (api.success && api.data?.isMalicious) {
		result = {
			...baseResult,
			risk: 'CRITICAL',
			threats: [api.data.threatType || 'KNOWN_MALICIOUS'],
			blocked: true,
			source: 'api',
		};
	} else if (api.success) {
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

	await recordScan({
		address: normalizedAddress,
		risk: result.risk,
		threats: result.threats,
		url,
		blocked: result.blocked,
	});
	await incrementScanned();

	return result;
}

async function analyzeWithCache(address: string, url?: string): Promise<ExtendedAnalysisResult> {
	const normalizedAddress = address.toLowerCase();

	// Check whitelist first (fail-secure: returns false on error)
	const whitelisted = await isWhitelisted(normalizedAddress);
	if (whitelisted) {
		console.log('[Testudo Background] Whitelisted address:', normalizedAddress);
		return {
			risk: 'LOW',
			threats: [],
			address: normalizedAddress as `0x${string}`,
			blocked: false,
			whitelisted: true,
			source: 'whitelist',
		};
	}

	// Check cache - only trust full analysis results or global allows
	// Address-only checks (source: 'api') should NOT skip bytecode analysis for delegations
	const cached = analysisCache.get(normalizedAddress);
	if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
		const source = cached.result.source || '';
		const isFullAnalysis = source.includes('local') || source === 'api+local';
		const isGlobalAllow = source === 'whitelist' || source === 'safe-filter';

		if (isFullAnalysis || isGlobalAllow) {
			console.log('[Testudo Background] Cache hit (full analysis):', normalizedAddress);
			return { ...cached.result, cached: true };
		}
		// Address-only cached result - need to run full analysis for delegation
		console.log(
			'[Testudo Background] Cache miss (address-only, need bytecode):',
			normalizedAddress,
		);
	}

	// Check if analysis is already in progress for this address (deduplication)
	const pending = pendingAnalysis.get(normalizedAddress);
	if (pending) {
		console.log('[Testudo Background] Deduplicating request:', normalizedAddress);
		return pending;
	}

	// Create and track the analysis promise
	const analysisPromise = performThreeLayerAnalysis(normalizedAddress, url);
	pendingAnalysis.set(normalizedAddress, analysisPromise);

	try {
		return await analysisPromise;
	} finally {
		pendingAnalysis.delete(normalizedAddress);
	}
}

async function performThreeLayerAnalysis(
	normalizedAddress: string,
	url?: string,
): Promise<ExtendedAnalysisResult> {
	// ========================================================================
	// LAYER 0: Safe Filter (local Set - instant, ADR-007)
	// ========================================================================
	if (safeFilter.isKnownSafe(normalizedAddress)) {
		console.log('[Testudo Background] Safe Filter hit:', normalizedAddress);
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

	// ========================================================================
	// LAYER 1 + LAYER 2: Run API and Local Analysis in parallel
	// ========================================================================
	const apiUrl = await getApiUrl();
	const settings = await getSettings();
	const rpcUrl = settings.customRpcUrl || undefined;

	const [apiResult, localResult] = await Promise.allSettled([
		// Layer 1: API Lookup (includes GoPlus fallback server-side)
		checkAddressThreat(normalizedAddress, { baseUrl: apiUrl }),
		// Layer 2: Local Bytecode Analysis
		analyzeContract(normalizedAddress as `0x${string}`, { rpcUrl }),
	]);

	// Extract results
	const api =
		apiResult.status === 'fulfilled'
			? apiResult.value
			: ({ success: false, error: 'Promise rejected' } as ApiClientResult);

	const local =
		localResult.status === 'fulfilled'
			? localResult.value
			: ({
					risk: 'UNKNOWN',
					threats: ['Local analysis failed'],
					address: normalizedAddress,
					blocked: false,
				} as AnalysisResult);

	// ========================================================================
	// DECISION MATRIX (from ADR-006)
	// ========================================================================
	const finalResult = applyDecisionMatrix(api, local, normalizedAddress);

	// Cache the result
	analysisCache.set(normalizedAddress, { result: finalResult, timestamp: Date.now() });

	// Record scan
	await recordScan({
		address: normalizedAddress,
		risk: finalResult.risk,
		threats: finalResult.threats,
		url,
		blocked: finalResult.blocked,
	});

	await incrementScanned();

	return finalResult;
}

function applyDecisionMatrix(
	api: ApiClientResult,
	local: AnalysisResult,
	address: string,
): ExtendedAnalysisResult {
	const baseResult = {
		address: address as `0x${string}`,
		warnings: local.warnings,
	};

	// API returned malicious → BLOCK (highest priority)
	if (api.success && api.data?.isMalicious) {
		console.log('[Testudo Background] API flagged as malicious:', address);
		return {
			...baseResult,
			risk: 'CRITICAL',
			threats: [api.data.threatType || 'KNOWN_MALICIOUS'],
			blocked: true,
			source: 'api',
		};
	}

	// API available and clean
	if (api.success && !api.data?.isMalicious) {
		// API Clean + Local Clean → ALLOW
		if (local.risk === 'LOW' || local.risk === 'UNKNOWN') {
			console.log('[Testudo Background] Both API and local clean:', address);
			return {
				...baseResult,
				risk: 'LOW',
				threats: [],
				blocked: false,
				source: 'api+local',
			};
		}

		// API Clean + Local Suspicious → WARN (local caught new pattern)
		// Per ADR-006: API clean verdict is authoritative (includes GoPlus fallback)
		// We warn the user but don't block (blocked: false)
		console.log('[Testudo Background] API clean but local suspicious:', address);
		return {
			...baseResult,
			risk: local.risk,
			threats: local.threats,
			blocked: false, // ADR-006: WARN, not BLOCK - trust API verdict
			source: 'local',
		};
	}

	// API unavailable (timeout, offline, error)
	const apiUnavailable = !api.success;

	if (apiUnavailable) {
		// API Timeout + Local Clean → ALLOW (degraded mode)
		if (local.risk === 'LOW' || local.risk === 'UNKNOWN') {
			console.log('[Testudo Background] API unavailable, local clean:', address);
			return {
				...baseResult,
				risk: 'LOW',
				threats: [],
				blocked: false,
				source: 'local',
				apiUnavailable: true,
			};
		}

		// API Timeout + Local Suspicious → BLOCK (fail-safe)
		console.log('[Testudo Background] API unavailable, local suspicious:', address);
		return {
			...baseResult,
			risk: local.risk,
			threats: local.threats,
			blocked: true, // More aggressive when API unavailable
			source: 'local',
			apiUnavailable: true,
		};
	}

	// Fallback (shouldn't reach here)
	return {
		...baseResult,
		risk: 'UNKNOWN',
		threats: ['Analysis inconclusive'],
		blocked: false,
		source: 'fallback',
	};
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	if (message.type === 'ANALYZE_DELEGATION') {
		console.log('[Testudo Background] Analyzing:', message.delegateAddress);

		// Use real URL from sender tab, not from message (security)
		const url = sender.tab?.url ? new URL(sender.tab.url).origin : undefined;

		analyzeWithCache(message.delegateAddress, url)
			.then((result) => {
				console.log('[Testudo Background] Result:', result);
				sendResponse(result);
			})
			.catch((error) => {
				console.error('[Testudo Background] Error:', error);
				sendResponse({
					risk: 'UNKNOWN',
					threats: ['Analysis error'],
					address: message.delegateAddress,
					blocked: false,
				});
			});

		return true;
	}

	if (message.type === 'CHECK_ADDRESS') {
		const address = (message.address as string).toLowerCase();
		const url = sender.tab?.url ? new URL(sender.tab.url).origin : undefined;

		addressCheckWithCache(address, url)
			.then((result) => sendResponse(result))
			.catch((error) => {
				console.error('[Testudo Background] Address check error:', error);
				sendResponse({
					risk: 'UNKNOWN',
					threats: [],
					address,
					blocked: false,
				});
			});

		return true;
	}

	if (message.type === 'RECORD_BLOCKED') {
		console.log('[Testudo Background] Recording blocked delegation');
		incrementBlocked().then(() => sendResponse({ success: true }));
		return true;
	}

	if (message.type === 'WHITELIST_FROM_MODAL') {
		console.log('[Testudo Background] Quick whitelist:', message.address);

		// Validate address format (security)
		if (!/^0x[a-fA-F0-9]{40}$/.test(message.address)) {
			sendResponse({ success: false, error: 'Invalid address format' });
			return true;
		}

		// Use real URL from sender, not from message (security)
		const url = sender.tab?.url ? new URL(sender.tab.url).origin : undefined;

		import('./storage').then(({ addToWhitelist }) => {
			addToWhitelist(message.address, message.label || 'Quick whitelist', url).then((success) => {
				// Clear cache so next analysis uses whitelist
				analysisCache.delete(message.address.toLowerCase());
				sendResponse({ success });
			});
		});

		return true;
	}

	if (message.type === 'GET_STATS') {
		Promise.all([getStats(), getWhitelist(), safeFilter.getStats()]).then(
			([stats, whitelist, safeFilterStats]) => {
				sendResponse({
					cacheSize: analysisCache.size,
					knownMalicious: Object.keys(KNOWN_MALICIOUS).length,
					knownSafe: KNOWN_SAFE.size,
					whitelistSize: whitelist.length,
					safeFilter: safeFilterStats,
					...stats,
				});
			},
		);
		return true;
	}

	if (message.type === 'GET_SETTINGS') {
		getSettings().then((settings) => sendResponse(settings));
		return true;
	}

	if (message.type === 'SYNC_SAFE_FILTER') {
		console.log('[Testudo Background] Manual Safe Filter sync requested');
		safeFilter.syncFromCDN().then((success) => {
			sendResponse({ success });
		});
		return true;
	}

	if (message.type === 'RESOLVE_TOKEN') {
		const { address } = message;
		resolveTokenViaRpc(address).then((tokenInfo) => sendResponse(tokenInfo));
		return true;
	}

	if (message.type === 'RELOAD_SAFE_FILTER') {
		console.log('[Testudo Background] Reloading Safe Filter from storage');
		safeFilter.load().then(() => {
			sendResponse({ success: true });
		});
		return true;
	}
});

console.log('[Testudo Background] Service worker started');
