/**
 * PhishingBloomFilter — pure browser-compatible bloom filter for phishing domain detection.
 *
 * Uses Uint8Array exclusively (no Node.js Buffer) so it runs correctly in Chrome MV3
 * service workers. Prior attempt using `bloom-filters` npm package failed at runtime
 * because that library calls Buffer internally (see ADR-007).
 *
 * Optimal parameters for 250K domains at 0.1% FPR:
 *   - ~3.6M bits  (~450 KB)
 *   - ~10 hash functions
 */

// ---------------------------------------------------------------------------
// MurmurHash3 32-bit (pure JS, browser-compatible)
// Based on the public domain reference implementation by Austin Appleby.
// ---------------------------------------------------------------------------

function murmurhash3_32(key: string, seed: number): number {
	let h = seed >>> 0;
	const len = key.length;

	// Process 4 bytes at a time
	let i = 0;
	while (i + 4 <= len) {
		let k =
			((key.charCodeAt(i) & 0xff)) |
			((key.charCodeAt(i + 1) & 0xff) << 8) |
			((key.charCodeAt(i + 2) & 0xff) << 16) |
			((key.charCodeAt(i + 3) & 0xff) << 24);

		k = Math.imul(k, 0xcc9e2d51);
		k = ((k << 15) | (k >>> 17)) >>> 0;
		k = Math.imul(k, 0x1b873593);

		h ^= k;
		h = ((h << 13) | (h >>> 19)) >>> 0;
		h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;

		i += 4;
	}

	// Remaining bytes
	let remaining = 0;
	switch (len - i) {
		case 3:
			remaining ^= (key.charCodeAt(i + 2) & 0xff) << 16;
		// fallthrough
		case 2:
			remaining ^= (key.charCodeAt(i + 1) & 0xff) << 8;
		// fallthrough
		case 1:
			remaining ^= key.charCodeAt(i) & 0xff;
			remaining = Math.imul(remaining, 0xcc9e2d51);
			remaining = ((remaining << 15) | (remaining >>> 17)) >>> 0;
			remaining = Math.imul(remaining, 0x1b873593);
			h ^= remaining;
	}

	// Finalize
	h ^= len;
	h ^= h >>> 16;
	h = Math.imul(h, 0x85ebca6b);
	h ^= h >>> 13;
	h = Math.imul(h, 0xc2b2ae35);
	h ^= h >>> 16;

	return h >>> 0;
}

// ---------------------------------------------------------------------------
// Optimal bloom filter parameter calculation
// ---------------------------------------------------------------------------

/**
 * Calculate optimal number of bits for a given item count and false positive rate.
 * Formula: m = -n * ln(p) / (ln(2)^2)
 */
function optimalBitCount(expectedCount: number, fpRate: number): number {
	const n = Math.max(1, expectedCount);
	const m = Math.ceil(-n * Math.log(fpRate) / (Math.LN2 * Math.LN2));
	return Math.max(8, m);
}

/**
 * Calculate optimal number of hash functions for given bit-per-item ratio.
 * Formula: k = (m/n) * ln(2)
 */
function optimalHashCount(bitCount: number, expectedCount: number): number {
	const n = Math.max(1, expectedCount);
	const k = Math.round((bitCount / n) * Math.LN2);
	return Math.max(1, Math.min(k, 20));
}

// ---------------------------------------------------------------------------
// PhishingBloomFilter
// ---------------------------------------------------------------------------

export class PhishingBloomFilter {
	/** Packed bit array stored as Uint8Array (one bit per domain slot). */
	readonly bits: Uint8Array;
	/** Number of hash functions applied per element. */
	readonly numHashes: number;
	/** Total number of bits in the filter. */
	private readonly bitCount: number;

	private constructor(bits: Uint8Array, numHashes: number) {
		this.bits = bits;
		this.numHashes = numHashes;
		this.bitCount = bits.length * 8;
	}

	// -------------------------------------------------------------------------
	// Factory methods
	// -------------------------------------------------------------------------

	/**
	 * Build a bloom filter from a list of domains.
	 *
	 * @param domains - Domain strings to insert
	 * @param expectedCount - Expected total number of domains (used to size filter optimally).
	 *   Pass `domains.length` if exact, or a larger number (e.g. 250_000) for production sizing.
	 * @param fpRate - Desired false-positive rate (default 0.001 = 0.1%)
	 */
	static fromDomains(
		domains: readonly string[],
		expectedCount: number,
		fpRate = 0.001,
	): PhishingBloomFilter {
		const bitCount = optimalBitCount(expectedCount, fpRate);
		const numHashes = optimalHashCount(bitCount, expectedCount);
		const byteCount = Math.ceil(bitCount / 8);
		const bits = new Uint8Array(byteCount);

		const filter = new PhishingBloomFilter(bits, numHashes);
		for (const domain of domains) {
			filter.insert(domain);
		}
		return filter;
	}

	/**
	 * Deserialize a bloom filter from an ArrayBuffer.
	 *
	 * @param data - Binary data produced by `toBinary()`
	 * @param numHashes - Number of hash functions (must match the original filter)
	 */
	static fromBinary(data: ArrayBuffer, numHashes: number): PhishingBloomFilter {
		const bits = new Uint8Array(data.byteLength);
		bits.set(new Uint8Array(data));
		return new PhishingBloomFilter(bits, numHashes);
	}

	/**
	 * Deserialize a bloom filter from a base64 string.
	 *
	 * @param b64 - Base64 string produced by `toBase64()`
	 * @param numHashes - Number of hash functions (must match the original filter)
	 */
	static fromBase64(b64: string, numHashes: number): PhishingBloomFilter {
		const binaryStr = atob(b64);
		const bits = new Uint8Array(binaryStr.length);
		for (let i = 0; i < binaryStr.length; i++) {
			bits[i] = binaryStr.charCodeAt(i);
		}
		return new PhishingBloomFilter(bits, numHashes);
	}

	// -------------------------------------------------------------------------
	// Core operations
	// -------------------------------------------------------------------------

	/**
	 * Check membership. Returns true if the domain was (probably) inserted.
	 * False positives are possible; false negatives are not.
	 */
	has(domain: string): boolean {
		for (let i = 0; i < this.numHashes; i++) {
			const bit = murmurhash3_32(domain, i) % this.bitCount;
			const byteIndex = (bit / 8) | 0;
			const bitIndex = bit % 8;
			if (!((this.bits[byteIndex] >> bitIndex) & 1)) {
				return false;
			}
		}
		return true;
	}

	// -------------------------------------------------------------------------
	// Serialization
	// -------------------------------------------------------------------------

	/**
	 * Serialize to an ArrayBuffer (zero-copy view of underlying Uint8Array).
	 */
	toBinary(): ArrayBuffer {
		return this.bits.buffer.slice(
			this.bits.byteOffset,
			this.bits.byteOffset + this.bits.byteLength,
		);
	}

	/**
	 * Serialize to a base64 string (suitable for JSON storage or CDN transfer).
	 */
	toBase64(): string {
		let binaryStr = '';
		for (let i = 0; i < this.bits.length; i++) {
			binaryStr += String.fromCharCode(this.bits[i]);
		}
		return btoa(binaryStr);
	}

	// -------------------------------------------------------------------------
	// Properties
	// -------------------------------------------------------------------------

	/** Byte size of the underlying bit array. */
	get byteLength(): number {
		return this.bits.byteLength;
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	private insert(domain: string): void {
		for (let i = 0; i < this.numHashes; i++) {
			const bit = murmurhash3_32(domain, i) % this.bitCount;
			const byteIndex = (bit / 8) | 0;
			const bitIndex = bit % 8;
			this.bits[byteIndex] |= 1 << bitIndex;
		}
	}
}
