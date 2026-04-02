import {
	analyzeContract,
	assessDeployerRisk,
	checkKnownMalicious,
	deriveRiskFromWarnings,
	generateDeployerWarnings,
	KNOWN_MALICIOUS,
	KNOWN_SAFE,
} from '@testudo/core';
import type { Address, Hex } from 'viem';
import { createPublicClient, hexToString, http } from 'viem';
import { mainnet } from 'viem/chains';
import type { AnalysisPipeline } from './analysis';
import { createAnalysisPipeline } from './analysis';
import { checkAddressThreat } from './api-client';
import {
	getSafeFilter,
	handleSafeFilterAlarm,
	initializeSafeFilterOnInstall,
	setupSafeFilterAlarm,
} from './safe-filter';
import { fetchDeployerStaticInfo } from './services/deployer-lookup';
import {
	getSettings,
	getStats,
	getWhitelist,
	incrementBlocked,
	incrementScanned,
	isWhitelisted,
	recordScan,
} from './storage';

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

const DEFAULT_RPC = 'https://eth.llamarpc.com';
const TOKEN_RESOLVE_TIMEOUT = 3_000;

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
		const tokenAddress = address.toLowerCase() as Address;
		const settings = await getSettings();
		const rpcUrl = settings.rpcUrl || DEFAULT_RPC;
		const client = getOrCreateClient(rpcUrl);

		const multicallPromise = client.multicall({
			contracts: [
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'name' },
				{ address: tokenAddress, abi: erc20Bytes32Abi, functionName: 'name' },
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'symbol' },
				{ address: tokenAddress, abi: erc20Bytes32Abi, functionName: 'symbol' },
				{ address: tokenAddress, abi: erc20StringAbi, functionName: 'decimals' },
			],
			allowFailure: true,
		});
		let timeoutId: ReturnType<typeof setTimeout>;
		const timeoutPromise = new Promise<never>((_, reject) => {
			timeoutId = setTimeout(
				() => reject(new Error('Token resolve timeout')),
				TOKEN_RESOLVE_TIMEOUT,
			);
		});
		const results = await Promise.race([
			multicallPromise.then((r) => {
				clearTimeout(timeoutId);
				return r;
			}),
			timeoutPromise,
		]);

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

// Wire analysis pipeline with all concrete dependencies
const pipeline: AnalysisPipeline = createAnalysisPipeline({
	safeFilter,
	checkAddressThreat,
	analyzeContract,
	checkKnownMalicious,
	assessDeployerRisk,
	generateDeployerWarnings,
	deriveRiskFromWarnings,
	fetchDeployerStaticInfo,
	isWhitelisted,
	getSettings,
	recordScan,
	incrementScanned,
	getOrCreateClient,
});

const { analyzeWithCache, addressCheckWithCache, analysisCache } = pipeline;

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	if (message.type === 'HEARTBEAT') {
		sendResponse({ alive: true });
		return false;
	}

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
