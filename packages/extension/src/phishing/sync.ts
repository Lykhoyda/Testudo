// PhishingSync — CDN fetch + DNR rule update for phishing bloom filter.
// Mirrors safe-filter.ts patterns: Ed25519 signature verification, SHA-256
// hash check, rollback protection, exponential backoff, concurrent sync guard.

import type { PhishingBloomFilter } from './bloom';
import { PhishingBloomFilter as BloomImpl } from './bloom';
import { SEED_FILTER_B64, SEED_NUM_HASHES } from './seed-filter';

const STORAGE_KEYS = {
	BLOOM: 'phishingFilterBloom',
	SEQUENCE: 'phishingFilterSequence',
	VERSION: 'phishingFilterVersion',
	LAST_SYNC: 'phishingFilterLastSync',
} as const;

const ALARM_NAME = 'sync-phishing-filter';
const SYNC_INTERVAL_MINUTES = 360; // 6 hours

const MAX_RETRIES = 3;
const BASE_BACKOFF_MS = 2_000;

// Ed25519 public key (SPKI DER, base64) for manifest signature verification.
// Shared with safe-filter.ts — same key-pair signs both manifests.
const TRUSTED_PUBLIC_KEYS: Record<string, string> = {
	'key-001': 'MCowBQYDK2VwAyEA/zRv2JLNd+dBKrQd4nVRg35FesTHz6Cy4hV9D4kZZyg=',
};

interface PhishingManifest {
	version: string;
	sequence: number;
	hash: string;
	dnrHash: string;
	count: number;
	topDomains: number;
	keyId: string;
	signature: string;
}

export class PhishingSync {
	private bloom: PhishingBloomFilter | null = null;
	private readonly cdnUrl: string;
	private isSyncing = false;

	constructor(cdnUrl: string) {
		this.cdnUrl = cdnUrl;
	}

	getBloom(): PhishingBloomFilter | null {
		return this.bloom;
	}

	async loadFromStorage(): Promise<void> {
		try {
			const data = await chrome.storage.local.get(STORAGE_KEYS.BLOOM);
			const b64 = data[STORAGE_KEYS.BLOOM] as string | undefined;

			if (b64 && typeof b64 === 'string' && b64.length > 0) {
				this.bloom = BloomImpl.fromBase64(b64, SEED_NUM_HASHES);
				console.log('[PhishingSync] Loaded bloom filter from storage');
			} else if (SEED_FILTER_B64.length > 0) {
				this.bloom = BloomImpl.fromBase64(SEED_FILTER_B64, SEED_NUM_HASHES);
				console.log('[PhishingSync] Using seed filter');
			} else {
				console.log('[PhishingSync] No stored filter, CDN sync required');
			}
		} catch (error) {
			console.warn('[PhishingSync] Failed to load from storage:', error);
			this.bloom = null;
		}
	}

	async syncFromCDN(): Promise<boolean> {
		if (this.isSyncing) {
			console.log('[PhishingSync] Sync already in progress');
			return false;
		}
		this.isSyncing = true;

		try {
			if (!navigator.onLine) {
				console.log('[PhishingSync] Offline, skipping sync');
				return false;
			}

			const manifestUrl = `${this.cdnUrl}/phishing-filter.json`;
			const manifestResponse = await fetch(manifestUrl, { cache: 'no-cache' });

			if (!manifestResponse.ok) {
				console.warn('[PhishingSync] Failed to fetch manifest:', manifestResponse.status);
				return false;
			}

			const manifest: PhishingManifest = await manifestResponse.json();

			if (
				!manifest.signature ||
				!manifest.keyId ||
				typeof manifest.sequence !== 'number' ||
				!manifest.dnrHash
			) {
				console.error('[PhishingSync] Manifest missing required fields');
				return false;
			}

			const signatureValid = await this.verifyManifestSignature(manifest);
			if (!signatureValid) {
				console.error('[PhishingSync] Manifest signature verification FAILED');
				return false;
			}

			const stored = await chrome.storage.local.get([
				STORAGE_KEYS.VERSION,
				STORAGE_KEYS.SEQUENCE,
			]);
			const storedSequence = (stored[STORAGE_KEYS.SEQUENCE] as number) ?? 0;

			if (manifest.sequence < storedSequence) {
				console.error(
					`[PhishingSync] Rollback rejected: manifest seq ${manifest.sequence} < stored ${storedSequence}`,
				);
				return false;
			}

			if (manifest.sequence === storedSequence) {
				const currentVersion = stored[STORAGE_KEYS.VERSION] as string | undefined;
				if (currentVersion === manifest.version) {
					console.log('[PhishingSync] Already up to date:', manifest.version);
					await this.updateLastSync();
					return true;
				}
				console.error(
					`[PhishingSync] Sequence collision: seq=${manifest.sequence} but version mismatch`,
				);
				return false;
			}

			// Fetch bloom filter binary
			const bloomUrl = `${this.cdnUrl}/phishing-filter.bin`;
			const bloomResponse = await fetch(bloomUrl, { cache: 'no-cache' });

			if (!bloomResponse.ok) {
				console.warn('[PhishingSync] Failed to fetch bloom filter:', bloomResponse.status);
				return false;
			}

			const bloomData = await bloomResponse.arrayBuffer();

			const bloomHash = await this.calculateHash(bloomData);
			if (bloomHash !== manifest.hash) {
				console.error('[PhishingSync] Bloom hash mismatch! Expected:', manifest.hash, 'Got:', bloomHash);
				return false;
			}

			// Fetch DNR rules JSON
			const dnrUrl = `${this.cdnUrl}/phishing-dnr-rules.json`;
			const dnrResponse = await fetch(dnrUrl, { cache: 'no-cache' });

			if (!dnrResponse.ok) {
				console.warn('[PhishingSync] Failed to fetch DNR rules:', dnrResponse.status);
				return false;
			}

			const dnrData = await dnrResponse.arrayBuffer();

			const dnrHash = await this.calculateHash(dnrData);
			if (dnrHash !== manifest.dnrHash) {
				console.error('[PhishingSync] DNR hash mismatch! Expected:', manifest.dnrHash, 'Got:', dnrHash);
				return false;
			}

			const dnrRules = JSON.parse(new TextDecoder().decode(dnrData));
			if (!Array.isArray(dnrRules)) {
				console.error('[PhishingSync] Invalid DNR rules format');
				return false;
			}

			// Update DNR rules — remove old dynamic rules, add new
			const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
			const removeRuleIds = existingRules.map((r: chrome.declarativeNetRequest.Rule) => r.id);

			await chrome.declarativeNetRequest.updateDynamicRules({
				removeRuleIds,
				addRules: dnrRules,
			});

			// Build and store bloom filter
			const newBloom = BloomImpl.fromBinary(bloomData, SEED_NUM_HASHES);
			const b64 = newBloom.toBase64();

			await chrome.storage.local.set({
				[STORAGE_KEYS.BLOOM]: b64,
				[STORAGE_KEYS.VERSION]: manifest.version,
				[STORAGE_KEYS.SEQUENCE]: manifest.sequence,
			});

			await this.updateLastSync();

			this.bloom = newBloom;

			console.log(
				`[PhishingSync] Updated to version ${manifest.version} seq=${manifest.sequence} (${manifest.count} domains, ${dnrRules.length} DNR rules)`,
			);
			return true;
		} catch (error) {
			console.error('[PhishingSync] Sync failed:', error);
			return false;
		} finally {
			this.isSyncing = false;
		}
	}

	async initializeWithBackoff(): Promise<void> {
		console.log('[PhishingSync] Initializing with backoff');
		for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
			const success = await this.syncFromCDN();
			if (success) return;
			if (attempt < MAX_RETRIES) {
				const delay = BASE_BACKOFF_MS * 2 ** attempt;
				console.warn(`[PhishingSync] Sync failed, retrying in ${delay}ms (attempt ${attempt + 1})`);
				await new Promise((r) => setTimeout(r, delay));
			}
		}
		console.error('[PhishingSync] All sync retries exhausted');
	}

	static setupAlarm(): void {
		chrome.alarms.create(ALARM_NAME, {
			periodInMinutes: SYNC_INTERVAL_MINUTES,
		});
		console.log(`[PhishingSync] Alarm set for every ${SYNC_INTERVAL_MINUTES / 60} hours`);
	}

	static isPhishingAlarm(alarm: chrome.alarms.Alarm): boolean {
		return alarm.name === ALARM_NAME;
	}

	private async verifyManifestSignature(manifest: PhishingManifest): Promise<boolean> {
		const publicKeyBase64 = TRUSTED_PUBLIC_KEYS[manifest.keyId];
		if (!publicKeyBase64) {
			console.error(`[PhishingSync] Unknown keyId: ${manifest.keyId}`);
			return false;
		}

		try {
			const publicKeyDer = Uint8Array.from(atob(publicKeyBase64), (c) => c.charCodeAt(0));

			const cryptoKey = await crypto.subtle.importKey(
				'spki',
				publicKeyDer,
				{ name: 'Ed25519' },
				false,
				['verify'],
			);

			// Reconstruct signed payload (alphabetical key order — must match signing script)
			const payload = {
				count: manifest.count,
				dnrHash: manifest.dnrHash,
				hash: manifest.hash,
				keyId: manifest.keyId,
				sequence: manifest.sequence,
				topDomains: manifest.topDomains,
				version: manifest.version,
			};
			const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
			const signatureBytes = Uint8Array.from(atob(manifest.signature), (c) => c.charCodeAt(0));

			return await crypto.subtle.verify('Ed25519', cryptoKey, signatureBytes, payloadBytes);
		} catch (error) {
			console.error('[PhishingSync] Signature verification error:', error);
			return false;
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
}
