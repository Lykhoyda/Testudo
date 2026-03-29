#!/usr/bin/env node
/**
 * Generate an Ed25519 key pair for Safe Filter manifest signing.
 *
 * Usage:
 *   node scripts/generate-safe-filter-keys.mjs
 *
 * Outputs:
 *   - safe-filter-private.pem  (keep secret — add to GitHub secrets as SAFE_FILTER_SIGNING_KEY)
 *   - safe-filter-public.pem   (embed in extension source)
 *   - Also prints the raw base64 public key for hardcoding
 */

import { writeFileSync } from 'node:fs';
import { generateKeyPair, createPublicKey, createPrivateKey } from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPairAsync = promisify(generateKeyPair);

const { publicKey, privateKey } = await generateKeyPairAsync('ed25519');

const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

const publicDer = publicKey.export({ type: 'spki', format: 'der' });
const publicBase64 = Buffer.from(publicDer).toString('base64');

writeFileSync('safe-filter-private.pem', privatePem);
writeFileSync('safe-filter-public.pem', publicPem);

console.log('Key pair generated:');
console.log('  safe-filter-private.pem  (KEEP SECRET — add to GitHub secrets)');
console.log('  safe-filter-public.pem   (public, safe to share)');
console.log('');
console.log('Base64 public key (SPKI DER) for hardcoding in safe-filter.ts:');
console.log(`  ${publicBase64}`);
console.log('');
console.log('Add to .gitignore: safe-filter-private.pem');
