// Set-based safe filter for known-safe addresses (ADR-007)
// Replaces bloom-filters which uses Node.js Buffer (incompatible with service workers)

const STORAGE_KEYS = {
	FILTER: 'safeFilter',
	VERSION: 'safeFilterVersion',
	LAST_SYNC: 'safeFilterLastSync',
} as const;

const ALARM_NAME = 'sync-safe-filter';
const SYNC_INTERVAL_MINUTES = 60 * 24 * 7; // 7 days

const DEFAULT_CDN_URL = 'https://pub-76c6347fe0fc49d7b1497bc741c11d24.r2.dev';

// Fallback safe addresses for development/offline mode
// These are well-known legitimate contracts that should never be flagged
const FALLBACK_SAFE_ADDRESSES = new Set([
	// MetaMask Delegation
	'0x63c0c19a282a1b52b07dd5a65b58948a07dae32b',
	// Safe (Gnosis) Singleton
	'0x41675c099f32341bf84bfc5382af534df5c7461a',
	// Safe ProxyFactory
	'0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67',
	// Uniswap Universal Router
	'0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad',
	// 1inch Aggregation Router v5
	'0x1111111254eeb25477b68fb85ed929f73a960582',
]);

interface SafeFilterManifest {
	version: string;
	hash: string;
	count: number;
}

interface StoredFilterData {
	addresses: string[];
	count: number;
}

export class SafeFilter {
	private safeSet: Set<string> = new Set();
	private readonly fallbackSet: Set<string>;
	private readonly cdnUrl: string;
	private isSyncing = false;

	constructor(cdnUrl?: string) {
		this.cdnUrl = cdnUrl || DEFAULT_CDN_URL;
		// Normalize fallback addresses at runtime (defense in depth)
		this.fallbackSet = new Set(Array.from(FALLBACK_SAFE_ADDRESSES).map((a) => a.toLowerCase()));
	}

	async load(): Promise<void> {
		try {
			const data = await chrome.storage.local.get(STORAGE_KEYS.FILTER);
			const stored = data[STORAGE_KEYS.FILTER] as StoredFilterData | undefined;

			if (stored?.addresses && Array.isArray(stored.addresses)) {
				this.safeSet = new Set(
					stored.addresses
						.filter((a): a is string => typeof a === 'string')
						.map((a) => a.toLowerCase()),
				);
				console.log(`[SafeFilter] Loaded ${this.safeSet.size} addresses`);
			} else {
				console.log('[SafeFilter] No stored filter, using fallback set');
				// Clear version to force re-sync on next attempt (self-heal from corruption)
				await chrome.storage.local.remove(STORAGE_KEYS.VERSION);
			}
		} catch (error) {
			console.warn('[SafeFilter] Failed to load filter:', error);
			this.safeSet = new Set();
		}
	}

	isKnownSafe(address: string): boolean {
		const normalized = address.toLowerCase();

		// Check fallback set first (always available)
		if (this.fallbackSet.has(normalized)) {
			return true;
		}

		// Check loaded safe set
		return this.safeSet.has(normalized);
	}

	async syncFromCDN(): Promise<boolean> {
		// Prevent concurrent sync operations
		if (this.isSyncing) {
			console.log('[SafeFilter] Sync already in progress');
			return false;
		}
		this.isSyncing = true;

		try {
			// Check if online
			if (!navigator.onLine) {
				console.log('[SafeFilter] Offline, skipping sync');
				return false;
			}

			// Fetch manifest to check version
			const manifestUrl = `${this.cdnUrl}/safe-filter.json`;
			const manifestResponse = await fetch(manifestUrl, {
				cache: 'no-cache',
			});

			if (!manifestResponse.ok) {
				console.warn('[SafeFilter] Failed to fetch manifest:', manifestResponse.status);
				return false;
			}

			const manifest: SafeFilterManifest = await manifestResponse.json();

			// Check if we need to update
			const stored = await chrome.storage.local.get(STORAGE_KEYS.VERSION);
			const currentVersion = stored[STORAGE_KEYS.VERSION] as string | undefined;

			if (currentVersion === manifest.version) {
				console.log('[SafeFilter] Already up to date:', manifest.version);
				await this.updateLastSync();
				return true;
			}

			// Fetch the address list
			const filterUrl = `${this.cdnUrl}/safe-addresses.json`;
			const filterResponse = await fetch(filterUrl, {
				cache: 'no-cache',
			});

			if (!filterResponse.ok) {
				console.warn('[SafeFilter] Failed to fetch addresses:', filterResponse.status);
				return false;
			}

			const filterData = await filterResponse.arrayBuffer();

			// Verify hash integrity before using (security: prevent MITM/CDN compromise)
			const calculatedHash = await this.calculateHash(filterData);
			if (calculatedHash !== manifest.hash) {
				console.error(
					'[SafeFilter] Hash mismatch! Expected:',
					manifest.hash,
					'Got:',
					calculatedHash,
				);
				return false;
			}

			// Parse and validate
			const addresses: string[] = JSON.parse(new TextDecoder().decode(filterData));
			if (!Array.isArray(addresses)) {
				console.error('[SafeFilter] Invalid address list format');
				return false;
			}

			// Store the addresses
			await chrome.storage.local.set({
				[STORAGE_KEYS.FILTER]: {
					addresses,
					count: addresses.length,
				} as StoredFilterData,
				[STORAGE_KEYS.VERSION]: manifest.version,
			});

			// Check for storage errors
			if (chrome.runtime.lastError) {
				console.error('[SafeFilter] Storage error:', chrome.runtime.lastError);
				return false;
			}

			await this.updateLastSync();

			// Update in-memory set
			this.safeSet = new Set(addresses.map((a) => a.toLowerCase()));

			console.log(
				`[SafeFilter] Updated to version ${manifest.version} (${addresses.length} addresses)`,
			);
			return true;
		} catch (error) {
			console.error('[SafeFilter] Sync failed:', error);
			return false;
		} finally {
			this.isSyncing = false;
		}
	}

	private async updateLastSync(): Promise<void> {
		await chrome.storage.local.set({
			[STORAGE_KEYS.LAST_SYNC]: Date.now(),
		});
	}

	private async calculateHash(data: ArrayBuffer): Promise<string> {
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return `sha256:${hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')}`;
	}

	async getStats(): Promise<{
		loaded: boolean;
		version: string | null;
		lastSync: number | null;
		fallbackCount: number;
		loadedCount: number;
	}> {
		const stored = await chrome.storage.local.get([STORAGE_KEYS.VERSION, STORAGE_KEYS.LAST_SYNC]);

		return {
			loaded: this.safeSet.size > 0,
			version: (stored[STORAGE_KEYS.VERSION] as string) || null,
			lastSync: (stored[STORAGE_KEYS.LAST_SYNC] as number) || null,
			fallbackCount: this.fallbackSet.size,
			loadedCount: this.safeSet.size,
		};
	}
}

// Setup chrome.alarms for periodic sync
export function setupSafeFilterAlarm(): void {
	// Create alarm for weekly sync
	chrome.alarms.create(ALARM_NAME, {
		periodInMinutes: SYNC_INTERVAL_MINUTES,
	});

	console.log(`[SafeFilter] Alarm set for every ${SYNC_INTERVAL_MINUTES / 60 / 24} days`);
}

// Handle alarm event
export async function handleSafeFilterAlarm(
	alarm: chrome.alarms.Alarm,
	safeFilter: SafeFilter,
): Promise<void> {
	if (alarm.name === ALARM_NAME) {
		console.log('[SafeFilter] Sync alarm triggered');
		await safeFilter.syncFromCDN();
	}
}

// Initialize on extension install
export async function initializeSafeFilterOnInstall(safeFilter: SafeFilter): Promise<void> {
	console.log('[SafeFilter] Initializing on install');
	await safeFilter.syncFromCDN();
}

// Singleton instance
let safeFilterInstance: SafeFilter | null = null;

export function getSafeFilter(cdnUrl?: string): SafeFilter {
	if (!safeFilterInstance) {
		safeFilterInstance = new SafeFilter(cdnUrl);
	}
	return safeFilterInstance;
}
