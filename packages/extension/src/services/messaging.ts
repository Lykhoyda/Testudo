import type { AnalysisResult, ExtractedAddress } from '../utils/types';

function sendTestudoRequest<T>(
	requestType: string,
	responseType: string,
	payload: Record<string, unknown>,
	timeoutMs = 10000,
): Promise<T> {
	return new Promise((resolve, reject) => {
		const requestId = Math.random().toString(36).substring(7);

		const handler = (event: MessageEvent) => {
			if (event.data?.type === responseType && event.data?.requestId === requestId) {
				window.removeEventListener('message', handler);
				resolve(event.data.result);
			}
		};

		window.addEventListener('message', handler);

		window.postMessage({ type: requestType, requestId, ...payload }, '*');

		setTimeout(() => {
			window.removeEventListener('message', handler);
			reject(new Error(`${requestType} timeout`));
		}, timeoutMs);
	});
}

export function requestAddressCheck(address: string): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>(
		'TESTUDO_CHECK_ADDRESS',
		'TESTUDO_ADDRESS_CHECK_RESULT',
		{ address },
	);
}

export interface BatchCheckResult {
	malicious: ExtractedAddress[];
	results: Map<string, AnalysisResult>;
}

export async function batchCheckAddresses(
	addresses: ExtractedAddress[],
): Promise<BatchCheckResult> {
	const uniqueMap = new Map<string, ExtractedAddress[]>();
	for (const entry of addresses) {
		const key = entry.address.toLowerCase();
		if (!uniqueMap.has(key)) uniqueMap.set(key, []);
		uniqueMap.get(key)?.push(entry);
	}

	const results = new Map<string, AnalysisResult>();
	const malicious: ExtractedAddress[] = [];

	const checks = Array.from(uniqueMap.entries()).map(async ([addr, entries]) => {
		try {
			const result = await requestAddressCheck(addr);
			results.set(addr, result);
			if (result.risk === 'CRITICAL' || result.risk === 'HIGH') {
				malicious.push(...entries);
			}
		} catch {
			// fail-open: treat check failure as UNKNOWN
		}
	});

	await Promise.all(checks);

	return { malicious, results };
}

export function requestAnalysis(delegateAddress: string): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>('TESTUDO_ANALYZE_REQUEST', 'TESTUDO_ANALYSIS_RESULT', {
		delegateAddress,
	});
}

export function recordBlocked(): void {
	window.postMessage({ type: 'TESTUDO_RECORD_BLOCKED' }, '*');
}

export interface TokenResolveResult {
	name: string | null;
	symbol: string | null;
	decimals: number | null;
}

export function requestTokenResolve(address: string): Promise<TokenResolveResult> {
	return sendTestudoRequest<TokenResolveResult>(
		'TESTUDO_RESOLVE_TOKEN',
		'TESTUDO_TOKEN_RESULT',
		{ address },
		3000,
	).catch(() => ({ name: null, symbol: null, decimals: null }));
}

export function requestSettings(): Promise<Record<string, unknown>> {
	return sendTestudoRequest<Record<string, unknown>>(
		'TESTUDO_GET_SETTINGS',
		'TESTUDO_SETTINGS_RESULT',
		{},
		3000,
	).catch(() => ({}));
}
