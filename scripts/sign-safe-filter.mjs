#!/usr/bin/env node
/**
 * Sign a safe-addresses.json file and produce a signed safe-filter.json manifest.
 *
 * Usage:
 *   node scripts/sign-safe-filter.mjs <safe-addresses.json> [options]
 *
 * Options:
 *   --key <path>       Path to Ed25519 private key PEM (default: safe-filter-private.pem)
 *   --key-id <id>      Key identifier for rotation (default: key-001)
 *   --version <ver>    Manifest version string (default: YYYY-MM-DD)
 *   --sequence <n>     Monotonic sequence number (required)
 *   --output <path>    Output manifest path (default: safe-filter.json)
 *
 * Example:
 *   node scripts/sign-safe-filter.mjs safe-addresses.json --sequence 1
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, createPrivateKey, sign } from 'node:crypto';

function parseArgs(args) {
	const parsed = { positional: null, key: 'safe-filter-private.pem', keyId: 'key-001', version: null, sequence: null, output: 'safe-filter.json' };
	let i = 0;
	while (i < args.length) {
		const arg = args[i];
		if (arg === '--key') { parsed.key = args[++i]; }
		else if (arg === '--key-id') { parsed.keyId = args[++i]; }
		else if (arg === '--version') { parsed.version = args[++i]; }
		else if (arg === '--sequence') { parsed.sequence = parseInt(args[++i], 10); }
		else if (arg === '--output') { parsed.output = args[++i]; }
		else if (!arg.startsWith('-')) { parsed.positional = arg; }
		i++;
	}
	return parsed;
}

const args = parseArgs(process.argv.slice(2));

if (!args.positional) {
	console.error('Usage: node scripts/sign-safe-filter.mjs <safe-addresses.json> --sequence <n>');
	process.exit(1);
}

if (args.sequence == null || isNaN(args.sequence)) {
	console.error('Error: --sequence <n> is required (monotonic integer)');
	process.exit(1);
}

const addressData = readFileSync(args.positional);
const addresses = JSON.parse(addressData.toString());

if (!Array.isArray(addresses)) {
	console.error('Error: input file must be a JSON array of addresses');
	process.exit(1);
}

const hashHex = createHash('sha256').update(addressData).digest('hex');
const hash = `sha256:${hashHex}`;

const version = args.version || new Date().toISOString().split('T')[0];

// Alphabetical key order — must match extension's verifyManifestSignature()
const payload = {
	count: addresses.length,
	hash,
	keyId: args.keyId,
	sequence: args.sequence,
	version,
};

const payloadString = JSON.stringify(payload);
const payloadBytes = Buffer.from(payloadString, 'utf-8');

const privateKeyPem = readFileSync(args.key, 'utf-8');
const privateKey = createPrivateKey(privateKeyPem);

const signature = sign(null, payloadBytes, privateKey);
const signatureBase64 = signature.toString('base64');

const manifest = {
	...payload,
	signature: signatureBase64,
};

writeFileSync(args.output, JSON.stringify(manifest, null, 2) + '\n');

console.log('Signed manifest written to:', args.output);
console.log('  version:', version);
console.log('  sequence:', args.sequence);
console.log('  hash:', hash);
console.log('  count:', addresses.length);
console.log('  keyId:', args.keyId);
console.log('  signature:', signatureBase64.slice(0, 32) + '...');
