import { type AnalysisResult, analyzeContract, KNOWN_MALICIOUS, KNOWN_SAFE } from '@testudo/core';
import {
	getSettings,
	getStats,
	getWhitelist,
	incrementBlocked,
	incrementScanned,
	isWhitelisted,
	recordScan,
} from './storage';

const analysisCache = new Map<string, { result: AnalysisResult; timestamp: number }>();
const CACHE_TTL = 60 * 60 * 1000;

// Pending analysis requests to prevent duplicate concurrent requests for the same address
const pendingAnalysis = new Map<string, Promise<ExtendedAnalysisResult>>();

interface ExtendedAnalysisResult extends AnalysisResult {
	whitelisted?: boolean;
	cached?: boolean;
}

async function analyzeWithCache(
	address: string,
	url?: string,
): Promise<ExtendedAnalysisResult> {
	const normalizedAddress = address.toLowerCase();

	// Check whitelist first (fail-secure: returns false on error)
	const whitelisted = await isWhitelisted(normalizedAddress);
	if (whitelisted) {
		console.log('[Testudo Background] Whitelisted address:', normalizedAddress);
		return {
			risk: 'LOW',
			threats: [],
			address: normalizedAddress,
			blocked: false,
			whitelisted: true,
		};
	}

	// Check cache
	const cached = analysisCache.get(normalizedAddress);
	if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
		console.log('[Testudo Background] Cache hit:', normalizedAddress);
		return { ...cached.result, cached: true };
	}

	// Check if analysis is already in progress for this address (deduplication)
	const pending = pendingAnalysis.get(normalizedAddress);
	if (pending) {
		console.log('[Testudo Background] Deduplicating request:', normalizedAddress);
		return pending;
	}

	// Create and track the analysis promise
	const analysisPromise = performAnalysis(normalizedAddress, url);
	pendingAnalysis.set(normalizedAddress, analysisPromise);

	try {
		return await analysisPromise;
	} finally {
		pendingAnalysis.delete(normalizedAddress);
	}
}

async function performAnalysis(
	normalizedAddress: string,
	url?: string,
): Promise<ExtendedAnalysisResult> {
	// Get custom RPC from settings
	const settings = await getSettings();
	const rpcUrl = settings.customRpcUrl || undefined;

	// Run analysis
	const result = await analyzeContract(normalizedAddress as `0x${string}`, { rpcUrl });
	analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });

	// Record scan
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
			addToWhitelist(message.address, message.label || 'Quick whitelist', url).then(
				(success) => {
					// Clear cache so next analysis uses whitelist
					analysisCache.delete(message.address.toLowerCase());
					sendResponse({ success });
				},
			);
		});

		return true;
	}

	if (message.type === 'GET_STATS') {
		getStats().then((stats) => {
			getWhitelist().then((whitelist) => {
				sendResponse({
					cacheSize: analysisCache.size,
					knownMalicious: Object.keys(KNOWN_MALICIOUS).length,
					knownSafe: KNOWN_SAFE.size,
					whitelistSize: whitelist.length,
					...stats,
				});
			});
		});
		return true;
	}

	if (message.type === 'GET_SETTINGS') {
		getSettings().then((settings) => sendResponse(settings));
		return true;
	}
});

console.log('[Testudo Background] Service worker started');
console.log(`[Testudo Background] Known malicious: ${Object.keys(KNOWN_MALICIOUS).length}`);
console.log(`[Testudo Background] Known safe: ${KNOWN_SAFE.size}`);
