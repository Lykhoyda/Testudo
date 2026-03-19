import { MessageTypes } from '../utils/message-types';
import type { AnalysisResult, ExtractedAddress } from '../utils/types';
import { createChannel, readNonce } from './channel';

const channel = createChannel(readNonce());

function sendTestudoRequest<T>(
	requestType: string,
	responseType: string,
	payload: Record<string, unknown>,
	timeoutMs = 10000,
): Promise<T> {
	return new Promise((resolve, reject) => {
		const requestId = crypto.randomUUID();

		const unsubscribe = channel.onResponse((msg) => {
			if (msg.type === responseType && msg.requestId === requestId) {
				unsubscribe();
				clearTimeout(timer);
				resolve(msg.result as T);
			}
		});

		channel.sendRequest({ type: requestType, requestId, ...payload });

		const timer = setTimeout(() => {
			unsubscribe();
			reject(new Error(`${requestType} timeout`));
		}, timeoutMs);
	});
}

export function requestAddressCheck(address: string): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>(
		MessageTypes.CHECK_ADDRESS,
		MessageTypes.ADDRESS_CHECK_RESULT,
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
	return sendTestudoRequest<AnalysisResult>(
		MessageTypes.ANALYZE_REQUEST,
		MessageTypes.ANALYZE_RESULT,
		{ delegateAddress },
	);
}

export function recordBlocked(): void {
	channel.sendRequest({ type: MessageTypes.RECORD_BLOCKED, requestId: crypto.randomUUID() });
}

export interface TokenResolveResult {
	name: string | null;
	symbol: string | null;
	decimals: number | null;
}

export function requestTokenResolve(address: string): Promise<TokenResolveResult> {
	return sendTestudoRequest<TokenResolveResult>(
		MessageTypes.RESOLVE_TOKEN,
		MessageTypes.TOKEN_RESULT,
		{ address },
		3000,
	).catch(() => ({ name: null, symbol: null, decimals: null }));
}
