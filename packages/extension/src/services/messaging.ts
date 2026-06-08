import { MessageTypes } from '../utils/message-types';
import type { AnalysisResult, ExtractedAddress } from '../utils/types';
import { connectMainBridge } from './channel';

// Connect to the ISOLATED content script over the private MessagePort (ADR-016).
// Resolves once the port is transferred; NEVER throws synchronously, so a failed
// bridge can never abort module evaluation and leave the provider unwrapped
// (AUDIT-2). Each request still bounds its own wait below (fail-secure, the
// caller decides what to do on timeout — it must not silently fail open).
const channelPromise = connectMainBridge();

function sendTestudoRequest<T>(
	requestType: string,
	responseType: string,
	payload: Record<string, unknown>,
	timeoutMs = 10000,
): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error(`${requestType} timeout`)), timeoutMs);
		channelPromise.then(
			(channel) => {
				channel.request<T>(requestType, responseType, payload, timeoutMs).then(
					(value) => {
						clearTimeout(timer);
						resolve(value);
					},
					(error) => {
						clearTimeout(timer);
						reject(error as Error);
					},
				);
			},
			(error) => {
				clearTimeout(timer);
				reject(error as Error);
			},
		);
	});
}

export function requestAddressCheck(address: string, chainId?: number): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>(
		MessageTypes.CHECK_ADDRESS,
		MessageTypes.ADDRESS_CHECK_RESULT,
		{ address, chainId },
	);
}

export interface BatchCheckResult {
	malicious: ExtractedAddress[];
	results: Map<string, AnalysisResult>;
}

export async function batchCheckAddresses(
	addresses: ExtractedAddress[],
	chainId?: number,
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
			const result = await requestAddressCheck(addr, chainId);
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

export function requestAnalysis(
	delegateAddress: string,
	chainId?: number,
): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>(
		MessageTypes.ANALYZE_REQUEST,
		MessageTypes.ANALYZE_RESULT,
		{ delegateAddress, chainId },
	);
}

export function recordBlocked(): void {
	channelPromise.then((channel) => channel.post(MessageTypes.RECORD_BLOCKED)).catch(() => {});
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
