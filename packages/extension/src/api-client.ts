const DEFAULT_API_URL = process.env.TESTUDO_API_URL;
const DEFAULT_TIMEOUT = 800; // ms
const MAX_RETRIES = 1;

export interface ThreatResponse {
	isMalicious: boolean;
	address: string;
	threatType?: string;
	threatLevel?: string;
	confidence?: number;
	sources?: string[];
	firstSeen?: string;
}

export interface ApiClientOptions {
	baseUrl?: string;
	timeout?: number;
}

export type ApiErrorCategory =
	| 'offline'
	| 'timeout'
	| 'rate_limited'
	| 'http_error'
	| 'invalid_response'
	| 'network_error'
	| 'unknown';

export interface ApiClientResult {
	success: boolean;
	data?: ThreatResponse;
	error?: string;
	errorCategory?: ApiErrorCategory;
	offline?: boolean;
	rateLimited?: boolean;
}

async function fetchWithTimeout(
	url: string,
	timeout: number,
	signal?: AbortSignal,
): Promise<Response> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeout);

	// Combine with external signal if provided
	if (signal) {
		signal.addEventListener('abort', () => controller.abort(), { once: true });
	}

	try {
		const response = await fetch(url, {
			signal: controller.signal,
			headers: {
				'Content-Type': 'application/json',
			},
		});
		clearTimeout(timeoutId);
		return response;
	} catch (error) {
		clearTimeout(timeoutId);
		throw error;
	}
}

export async function checkAddressThreat(
	address: string,
	options?: ApiClientOptions,
): Promise<ApiClientResult> {
	const baseUrl = options?.baseUrl || DEFAULT_API_URL;
	const timeout = options?.timeout || DEFAULT_TIMEOUT;

	// Check if online before making request
	if (!navigator.onLine) {
		console.log('[API Client] Offline, skipping API call');
		return {
			success: false,
			offline: true,
			error: 'Offline',
			errorCategory: 'offline',
		};
	}

	const url = `${baseUrl}/api/v1/threats/address/${address.toLowerCase()}`;
	let lastError: string = '';
	let lastCategory: ApiErrorCategory = 'unknown';

	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		try {
			if (attempt > 0) {
				console.log(`[API Client] Retry attempt ${attempt} for ${address}`);
			}

			const response = await fetchWithTimeout(url, timeout);

			// Handle rate limiting
			if (response.status === 429) {
				console.warn('[API Client] Rate limited');
				return {
					success: false,
					rateLimited: true,
					error: 'Rate limited',
					errorCategory: 'rate_limited',
				};
			}

			// Handle other errors
			if (!response.ok) {
				lastError = `HTTP ${response.status}`;
				lastCategory = 'http_error';
				continue;
			}

			const rawData = await response.json();

			// Validate response structure (security: prevent malformed API responses)
			if (typeof rawData.isMalicious !== 'boolean' || typeof rawData.address !== 'string') {
				console.warn('[API Client] Invalid API response structure:', rawData);
				lastError = 'Invalid API response';
				lastCategory = 'invalid_response';
				continue;
			}

			const data: ThreatResponse = rawData;

			return {
				success: true,
				data,
			};
		} catch (error) {
			if (error instanceof Error) {
				if (error.name === 'AbortError') {
					lastError = 'Timeout';
					lastCategory = 'timeout';
					console.warn(`[API Client] Request timed out (attempt ${attempt + 1})`);
				} else {
					lastError = error.message;
					lastCategory = 'network_error';
					console.warn(`[API Client] Request failed (attempt ${attempt + 1}):`, error.message);
				}
			} else {
				lastError = 'Unknown error';
				lastCategory = 'unknown';
			}
		}
	}

	return {
		success: false,
		error: lastError,
		errorCategory: lastCategory,
	};
}
