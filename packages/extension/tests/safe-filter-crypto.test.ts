/**
 * Tests for Safe Filter cryptographic signing verification.
 *
 * These tests use Node.js crypto to generate keys, sign manifests,
 * and verify that the extension's verification logic works correctly.
 */
import { createHash, type createPrivateKey, generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';

// Reproduce the extension's verification logic in a testable form
// (the SafeFilter class requires Chrome APIs, so we test the crypto directly)

async function verifyManifestSignature(
	manifest: {
		version: string;
		sequence: number;
		hash: string;
		count: number;
		keyId: string;
		signature: string;
	},
	trustedKeys: Record<string, string>,
): Promise<boolean> {
	const publicKeyBase64 = trustedKeys[manifest.keyId];
	if (!publicKeyBase64) return false;

	try {
		const publicKeyDer = Uint8Array.from(atob(publicKeyBase64), (c) => c.charCodeAt(0));

		const cryptoKey = await crypto.subtle.importKey(
			'spki',
			publicKeyDer,
			{ name: 'Ed25519' },
			false,
			['verify'],
		);

		// Alphabetical key order — must match signing script and extension
		const payload = {
			count: manifest.count,
			hash: manifest.hash,
			keyId: manifest.keyId,
			sequence: manifest.sequence,
			version: manifest.version,
		};
		const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));

		const signatureBytes = Uint8Array.from(atob(manifest.signature), (c) => c.charCodeAt(0));

		return await crypto.subtle.verify('Ed25519', cryptoKey, signatureBytes, payloadBytes);
	} catch {
		return false;
	}
}

function generateTestKeyPair() {
	const { publicKey, privateKey } = generateKeyPairSync('ed25519');
	const publicDer = publicKey.export({ type: 'spki', format: 'der' });
	const publicBase64 = Buffer.from(publicDer).toString('base64');
	return { publicBase64, privateKey };
}

function signManifestPayload(
	payload: { version: string; sequence: number; hash: string; count: number; keyId: string },
	privateKeyObj: ReturnType<typeof createPrivateKey>,
): string {
	const payloadString = JSON.stringify(payload);
	const payloadBytes = Buffer.from(payloadString, 'utf-8');
	const signature = sign(null, payloadBytes, privateKeyObj);
	return signature.toString('base64');
}

function computeHash(data: string): string {
	const hex = createHash('sha256').update(Buffer.from(data, 'utf-8')).digest('hex');
	return `sha256:${hex}`;
}

describe('Safe Filter cryptographic signing', () => {
	const { publicBase64, privateKey } = generateTestKeyPair();
	const trustedKeys = { 'test-key': publicBase64 };

	const addresses = JSON.stringify(['0xabc123', '0xdef456']);
	const hash = computeHash(addresses);

	function makeManifest(overrides: Record<string, unknown> = {}) {
		const merged = {
			version: '2026-03-29',
			sequence: 1,
			hash,
			count: 2,
			keyId: 'test-key',
			...overrides,
		};
		// Alphabetical key order — must match extension and signing script
		const signable = {
			count: merged.count as number,
			hash: merged.hash as string,
			keyId: merged.keyId as string,
			sequence: merged.sequence as number,
			version: merged.version as string,
		};
		const signature = signManifestPayload(signable, privateKey);
		return { ...signable, signature };
	}

	describe('valid signatures', () => {
		it('verifies a correctly signed manifest', async () => {
			const manifest = makeManifest();
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(true);
		});

		it('verifies with different sequence numbers', async () => {
			const manifest = makeManifest({ sequence: 42 });
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(true);
		});

		it('verifies with different versions', async () => {
			const manifest = makeManifest({ version: '2026-12-31' });
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(true);
		});
	});

	describe('invalid signatures', () => {
		it('rejects when signature is tampered', async () => {
			const manifest = makeManifest();
			manifest.signature = `AAAA${manifest.signature.slice(4)}`;
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when hash is tampered after signing', async () => {
			const manifest = makeManifest();
			manifest.hash = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when version is tampered after signing', async () => {
			const manifest = makeManifest();
			manifest.version = '2020-01-01';
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when sequence is tampered after signing', async () => {
			const manifest = makeManifest();
			manifest.sequence = 999;
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when count is tampered after signing', async () => {
			const manifest = makeManifest();
			manifest.count = 9999;
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when keyId is tampered after signing', async () => {
			const manifest = makeManifest();
			manifest.keyId = 'different-key';
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects signature from a different key', async () => {
			const { publicBase64: otherPub } = generateTestKeyPair();
			const manifest = makeManifest();
			// Verify with the wrong public key
			const result = await verifyManifestSignature(manifest, { 'test-key': otherPub });
			expect(result).toBe(false);
		});
	});

	describe('missing/unknown keys', () => {
		it('rejects unknown keyId', async () => {
			const manifest = makeManifest({ keyId: 'unknown-key' });
			// Re-sign with the unknown keyId in the payload
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects when no trusted keys configured', async () => {
			const manifest = makeManifest();
			const result = await verifyManifestSignature(manifest, {});
			expect(result).toBe(false);
		});
	});

	describe('malformed input', () => {
		it('rejects empty signature', async () => {
			const manifest = makeManifest();
			manifest.signature = '';
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});

		it('rejects non-base64 signature', async () => {
			const manifest = makeManifest();
			manifest.signature = '!!!not-valid-base64!!!';
			const result = await verifyManifestSignature(manifest, trustedKeys);
			expect(result).toBe(false);
		});
	});

	describe('key rotation', () => {
		it('supports multiple trusted keys', async () => {
			const { publicBase64: key2Pub, privateKey: key2Priv } = generateTestKeyPair();
			const multiKeys = { 'test-key': publicBase64, 'key-002': key2Pub };

			// Sign with key-002 (alphabetical key order)
			const payload = { count: 2, hash, keyId: 'key-002', sequence: 2, version: '2026-03-29' };
			const signature = signManifestPayload(payload, key2Priv);
			const manifest = { ...payload, signature };

			const result = await verifyManifestSignature(manifest, multiKeys);
			expect(result).toBe(true);
		});

		it('rejects revoked key (removed from trusted)', async () => {
			const manifest = makeManifest();
			// Remove the key from trusted set
			const result = await verifyManifestSignature(manifest, { 'other-key': publicBase64 });
			expect(result).toBe(false);
		});
	});
});
