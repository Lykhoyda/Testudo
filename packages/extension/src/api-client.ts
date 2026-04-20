const DEFAULT_API_URL = process.env.TESTUDO_API_URL;
const DEFAULT_API_KEY = process.env.TESTUDO_API_KEY;
const DEFAULT_TIMEOUT = 800; // ms
const MAX_RETRIES = 1;

export interface DomainThreatResponse {
	isMalicious: boolean;
	domain: string;
	threatType?: string;
	sources?: string[];
	matchedLegitimate?: string;
	firstSeen?: string;
}

export interface DomainApiResult {
	success: boolean;
	data?: DomainThreatResponse;
	error?: string;
	errorCategory?: ApiErrorCategory;
	offline?: boolean;
}

export interface ThreatResponse {
	isMalicious: boolean;
	address: string;
	threatType?: string;
	threatLevel?: string;
	confidence?: number;
	sources?: string[];
	firstSeen?: string;
	/** Chain the threat was found on, if returned by API (S-16 response field). */
	matchedChainId?: number;
	/** True when the match came from a different chain than requested. */
	crossChainMatch?: boolean;
}

export interface ApiClientOptions {
	baseUrl?: string;
	timeout?: number;
	apiKey?: string;
	/** EVM chain id for threat lookup. Defaults to 1 (mainnet) if omitted. */
	chainId?: number;
}

/** Mainnet fallback — matches api-server's current behavior for missing chainId. */
const DEFAULT_CHAIN_ID = 1;

function resolveChainId(chainId: number | undefined): number {
	return chainId && Number.isFinite(chainId) && chainId > 0 ? chainId : DEFAULT_CHAIN_ID;
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

interface FetchResult {
	response: Response;
	bodyJson: () => Promise<unknown>;
	cleanup: () => void;
}

async function fetchWithTimeout(
	url: string,
	timeout: number,
	apiKey?: string,
	signal?: AbortSignal,
): Promise<FetchResult> {
	const controller = new AbortController();

	if (signal) {
		signal.addEventListener('abort', () => controller.abort(), { once: true });
	}

	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
	};

	const key = apiKey || DEFAULT_API_KEY;
	if (key) {
		headers['X-API-Key'] = key;
	}

	let timeoutId: ReturnType<typeof setTimeout>;
	const timeoutPromise = new Promise<never>((_, reject) => {
		timeoutId = setTimeout(() => {
			controller.abort();
			reject(new DOMException('The operation was aborted', 'AbortError'));
		}, timeout);
	});

	const response = await Promise.race([
		fetch(url, { signal: controller.signal, headers }),
		timeoutPromise,
	]);

	return {
		response,
		bodyJson: () => Promise.race([response.json(), timeoutPromise]),
		cleanup: () => clearTimeout(timeoutId),
	};
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

	const apiKey = options?.apiKey;
	const chainId = resolveChainId(options?.chainId);
	const url = `${baseUrl}/api/v1/chains/${chainId}/threats/address/${address.toLowerCase()}`;
	let lastError: string = '';
	let lastCategory: ApiErrorCategory = 'unknown';

	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		try {
			if (attempt > 0) {
				console.log(`[API Client] Retry attempt ${attempt} for ${address}`);
			}

			const { response, bodyJson, cleanup } = await fetchWithTimeout(url, timeout, apiKey);

			// Handle rate limiting
			if (response.status === 429) {
				cleanup();
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
				cleanup();
				lastError = `HTTP ${response.status}`;
				lastCategory = 'http_error';
				continue;
			}

			const rawData = (await bodyJson()) as Record<string, unknown>;
			cleanup();

			// Validate response structure (security: prevent malformed API responses)
			if (typeof rawData.isMalicious !== 'boolean' || typeof rawData.address !== 'string') {
				console.warn('[API Client] Invalid API response structure:', rawData);
				lastError = 'Invalid API response';
				lastCategory = 'invalid_response';
				continue;
			}

			const data = rawData as unknown as ThreatResponse;

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

export async function checkDomainThreat(
	domain: string,
	options?: ApiClientOptions,
): Promise<DomainApiResult> {
	const baseUrl = options?.baseUrl || DEFAULT_API_URL;
	const timeout = options?.timeout || DEFAULT_TIMEOUT;

	if (!navigator.onLine) {
		console.log('[API Client] Offline, skipping API call');
		return {
			success: false,
			offline: true,
			error: 'Offline',
			errorCategory: 'offline',
		};
	}

	const apiKey = options?.apiKey;
	const url = `${baseUrl}/api/v1/threats/domain/${encodeURIComponent(domain)}`;
	let lastError: string = '';
	let lastCategory: ApiErrorCategory = 'unknown';

	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		try {
			if (attempt > 0) {
				console.log(`[API Client] Retry attempt ${attempt} for ${domain}`);
			}

			const { response, bodyJson, cleanup } = await fetchWithTimeout(url, timeout, apiKey);

			if (response.status === 429) {
				cleanup();
				console.warn('[API Client] Rate limited');
				return {
					success: false,
					error: 'Rate limited',
					errorCategory: 'rate_limited',
				};
			}

			if (!response.ok) {
				cleanup();
				lastError = `HTTP ${response.status}`;
				lastCategory = 'http_error';
				continue;
			}

			const rawData = (await bodyJson()) as Record<string, unknown>;
			cleanup();

			if (typeof rawData.isMalicious !== 'boolean' || typeof rawData.domain !== 'string') {
				console.warn('[API Client] Invalid API response structure:', rawData);
				lastError = 'Invalid API response';
				lastCategory = 'invalid_response';
				continue;
			}

			const data = rawData as unknown as DomainThreatResponse;

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

export type ApiHealthStatus = 'healthy' | 'auth_error' | 'unavailable' | 'unchecked';

export async function pingApi(options?: ApiClientOptions): Promise<ApiHealthStatus> {
	const baseUrl = options?.baseUrl || DEFAULT_API_URL;
	const timeout = options?.timeout || 3000;
	const chainId = resolveChainId(options?.chainId);

	if (!navigator.onLine) return 'unavailable';

	try {
		const { response, cleanup } = await fetchWithTimeout(
			`${baseUrl}/api/v1/chains/${chainId}/threats/address/0x0000000000000000000000000000000000000000`,
			timeout,
			options?.apiKey,
		);
		cleanup();

		if (response.status === 401 || response.status === 403) return 'auth_error';
		if (!response.ok) return 'unavailable';
		return 'healthy';
	} catch {
		return 'unavailable';
	}
}
