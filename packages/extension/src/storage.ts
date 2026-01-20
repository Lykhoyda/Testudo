/**
 * STORAGE UTILITIES
 *
 * Centralized storage management with fail-secure pattern.
 * For a security tool: blocking safe contracts is recoverable,
 * allowing malicious contracts causes real harm.
 */

export interface WhitelistEntry {
	address: string;
	label: string;
	addedAt: number;
	addedFrom?: string; // URL origin where it was added
}

export interface Settings {
	protectionLevel: 'strict' | 'standard' | 'permissive';
	customRpcUrl: string | null;
	showMediumRiskToast: boolean;
	autoRecordScans: boolean;
}

export interface ScanRecord {
	address: string;
	risk: string;
	threats: string[];
	timestamp: number;
	url?: string;
	blocked: boolean;
}

const MAX_LABEL_LENGTH = 64;
const MAX_WHITELIST_SIZE = 500;
const MAX_HISTORY_SIZE = 100;

const DEFAULT_SETTINGS: Settings = {
	protectionLevel: 'standard',
	customRpcUrl: null,
	showMediumRiskToast: true,
	autoRecordScans: true,
};

/**
 * Sanitize user-provided label to prevent XSS
 */
export function sanitizeLabel(label: string): string {
	return label.slice(0, MAX_LABEL_LENGTH).replace(/[<>'"&]/g, '');
}

/**
 * Validate Ethereum address format
 */
export function isValidAddress(address: string): boolean {
	return /^0x[a-fA-F0-9]{40}$/.test(address);
}

/**
 * Normalize address to lowercase
 */
export function normalizeAddress(address: string): string {
	return address.toLowerCase();
}

// ============================================================================
// WHITELIST OPERATIONS (Fail Secure)
// ============================================================================

/**
 * Check if an address is whitelisted.
 * FAIL SECURE: Returns false on any error.
 */
export async function isWhitelisted(address: string): Promise<boolean> {
	try {
		if (!isValidAddress(address)) return false;

		const { whitelist = [] } = await chrome.storage.local.get('whitelist');
		const normalized = normalizeAddress(address);

		return (whitelist as WhitelistEntry[]).some(
			(entry) => normalizeAddress(entry.address) === normalized,
		);
	} catch (error) {
		console.error('[Testudo Storage] Error checking whitelist:', error);
		return false; // Fail secure: treat as NOT whitelisted
	}
}

/**
 * Get all whitelist entries.
 * FAIL SECURE: Returns empty array on error.
 */
export async function getWhitelist(): Promise<WhitelistEntry[]> {
	try {
		const { whitelist = [] } = await chrome.storage.local.get('whitelist');
		return whitelist as WhitelistEntry[];
	} catch (error) {
		console.error('[Testudo Storage] Error getting whitelist:', error);
		return []; // Fail secure: return empty list
	}
}

/**
 * Add an address to the whitelist.
 * Returns true if added, false on error or invalid input.
 */
export async function addToWhitelist(
	address: string,
	label: string,
	addedFrom?: string,
): Promise<boolean> {
	try {
		if (!isValidAddress(address)) {
			console.error('[Testudo Storage] Invalid address format');
			return false;
		}

		const whitelist = await getWhitelist();
		const normalized = normalizeAddress(address);

		// Check if already exists
		if (whitelist.some((entry) => normalizeAddress(entry.address) === normalized)) {
			console.log('[Testudo Storage] Address already whitelisted');
			return true;
		}

		// Check size limit
		if (whitelist.length >= MAX_WHITELIST_SIZE) {
			console.error('[Testudo Storage] Whitelist size limit reached');
			return false;
		}

		const entry: WhitelistEntry = {
			address: normalized,
			label: sanitizeLabel(label),
			addedAt: Date.now(),
			addedFrom,
		};

		await chrome.storage.local.set({
			whitelist: [...whitelist, entry],
		});

		return true;
	} catch (error) {
		console.error('[Testudo Storage] Error adding to whitelist:', error);
		return false;
	}
}

/**
 * Remove an address from the whitelist.
 */
export async function removeFromWhitelist(address: string): Promise<boolean> {
	try {
		if (!isValidAddress(address)) return false;

		const whitelist = await getWhitelist();
		const normalized = normalizeAddress(address);

		const filtered = whitelist.filter((entry) => normalizeAddress(entry.address) !== normalized);

		await chrome.storage.local.set({ whitelist: filtered });
		return true;
	} catch (error) {
		console.error('[Testudo Storage] Error removing from whitelist:', error);
		return false;
	}
}

/**
 * Import whitelist entries (merge with existing).
 */
export async function importWhitelist(entries: WhitelistEntry[]): Promise<number> {
	try {
		const existing = await getWhitelist();
		const existingAddresses = new Set(existing.map((e) => normalizeAddress(e.address)));

		let imported = 0;
		const toAdd: WhitelistEntry[] = [];

		for (const entry of entries) {
			if (!isValidAddress(entry.address)) continue;

			const normalized = normalizeAddress(entry.address);
			if (existingAddresses.has(normalized)) continue;
			if (existing.length + toAdd.length >= MAX_WHITELIST_SIZE) break;

			toAdd.push({
				address: normalized,
				label: sanitizeLabel(entry.label || ''),
				addedAt: entry.addedAt || Date.now(),
				addedFrom: entry.addedFrom,
			});

			existingAddresses.add(normalized);
			imported++;
		}

		if (toAdd.length > 0) {
			await chrome.storage.local.set({
				whitelist: [...existing, ...toAdd],
			});
		}

		return imported;
	} catch (error) {
		console.error('[Testudo Storage] Error importing whitelist:', error);
		return 0;
	}
}

/**
 * Export whitelist for backup.
 */
export async function exportWhitelist(): Promise<string> {
	const whitelist = await getWhitelist();
	return JSON.stringify(whitelist, null, 2);
}

// ============================================================================
// SETTINGS OPERATIONS
// ============================================================================

/**
 * Get current settings.
 * Returns default settings on error.
 */
export async function getSettings(): Promise<Settings> {
	try {
		const { settings } = await chrome.storage.local.get('settings');
		return { ...DEFAULT_SETTINGS, ...(settings || {}) };
	} catch (error) {
		console.error('[Testudo Storage] Error getting settings:', error);
		return DEFAULT_SETTINGS;
	}
}

/**
 * Update settings.
 */
export async function updateSettings(updates: Partial<Settings>): Promise<boolean> {
	try {
		const current = await getSettings();
		const updated = { ...current, ...updates };

		// Validate RPC URL if provided
		if (updated.customRpcUrl) {
			try {
				new URL(updated.customRpcUrl);
			} catch {
				console.error('[Testudo Storage] Invalid RPC URL');
				return false;
			}
		}

		await chrome.storage.local.set({ settings: updated });
		return true;
	} catch (error) {
		console.error('[Testudo Storage] Error updating settings:', error);
		return false;
	}
}

// ============================================================================
// SCAN HISTORY OPERATIONS
// ============================================================================

/**
 * Record a scan to history.
 */
export async function recordScan(scan: Omit<ScanRecord, 'timestamp'>): Promise<boolean> {
	try {
		const settings = await getSettings();
		if (!settings.autoRecordScans) return true;

		const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');

		const record: ScanRecord = {
			...scan,
			timestamp: Date.now(),
		};

		const updated = [record, ...(scanHistory as ScanRecord[])].slice(0, MAX_HISTORY_SIZE);

		await chrome.storage.local.set({ scanHistory: updated });
		return true;
	} catch (error) {
		console.error('[Testudo Storage] Error recording scan:', error);
		return false;
	}
}

/**
 * Get scan history.
 */
export async function getScanHistory(): Promise<ScanRecord[]> {
	try {
		const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
		return scanHistory as ScanRecord[];
	} catch (error) {
		console.error('[Testudo Storage] Error getting scan history:', error);
		return [];
	}
}

/**
 * Clear scan history.
 */
export async function clearScanHistory(): Promise<boolean> {
	try {
		await chrome.storage.local.set({ scanHistory: [] });
		return true;
	} catch (error) {
		console.error('[Testudo Storage] Error clearing scan history:', error);
		return false;
	}
}

// ============================================================================
// STATS OPERATIONS
// ============================================================================

/**
 * Increment blocked count.
 */
export async function incrementBlocked(): Promise<void> {
	try {
		const { blocked = 0 } = await chrome.storage.local.get('blocked');
		await chrome.storage.local.set({ blocked: blocked + 1 });
	} catch (error) {
		console.error('[Testudo Storage] Error incrementing blocked:', error);
	}
}

/**
 * Increment scanned count.
 */
export async function incrementScanned(): Promise<void> {
	try {
		const { scanned = 0 } = await chrome.storage.local.get('scanned');
		await chrome.storage.local.set({ scanned: scanned + 1 });
	} catch (error) {
		console.error('[Testudo Storage] Error incrementing scanned:', error);
	}
}

/**
 * Get stats.
 */
export async function getStats(): Promise<{ blocked: number; scanned: number }> {
	try {
		const { blocked = 0, scanned = 0 } = await chrome.storage.local.get(['blocked', 'scanned']);
		return { blocked, scanned };
	} catch (error) {
		console.error('[Testudo Storage] Error getting stats:', error);
		return { blocked: 0, scanned: 0 };
	}
}

/**
 * Get storage usage info.
 */
export async function getStorageUsage(): Promise<{ bytesUsed: number; quota: number }> {
	try {
		const bytesUsed = await chrome.storage.local.getBytesInUse();
		return {
			bytesUsed,
			quota: chrome.storage.local.QUOTA_BYTES || 5242880, // 5MB default
		};
	} catch (error) {
		console.error('[Testudo Storage] Error getting storage usage:', error);
		return { bytesUsed: 0, quota: 5242880 };
	}
}
