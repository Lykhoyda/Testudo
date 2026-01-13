import { type AnalysisResult, analyzeContract, KNOWN_MALICIOUS, KNOWN_SAFE } from '@testudo/core';

const analysisCache = new Map<string, { result: AnalysisResult; timestamp: number }>();
const CACHE_TTL = 60 * 60 * 1000;

async function analyzeWithCache(address: string): Promise<AnalysisResult> {
	const normalizedAddress = address.toLowerCase();

	const cached = analysisCache.get(normalizedAddress);
	if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
		console.log('[Testudo Background] Cache hit:', normalizedAddress);
		return { ...cached.result, cached: true };
	}

	const result = await analyzeContract(normalizedAddress as `0x${string}`);
	analysisCache.set(normalizedAddress, { result, timestamp: Date.now() });

	return result;
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message.type === 'ANALYZE_DELEGATION') {
		console.log('[Testudo Background] Analyzing:', message.delegateAddress);

		analyzeWithCache(message.delegateAddress)
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

	if (message.type === 'GET_STATS') {
		sendResponse({
			cacheSize: analysisCache.size,
			knownMalicious: Object.keys(KNOWN_MALICIOUS).length,
			knownSafe: KNOWN_SAFE.size,
		});
		return true;
	}
});

console.log('[Testudo Background] Service worker started');
console.log(`[Testudo Background] Known malicious: ${Object.keys(KNOWN_MALICIOUS).length}`);
console.log(`[Testudo Background] Known safe: ${KNOWN_SAFE.size}`);
