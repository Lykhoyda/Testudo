import type { KnownMaliciousContract } from './types';

export const KNOWN_MALICIOUS: Record<string, KnownMaliciousContract> = {
	'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b': {
		type: 'ETH_AUTO_FORWARDER',
		source: 'SunSec Report May 2025',
		stolen: '$2.3M+',
		description:
			'Auto-redirects all incoming ETH to attacker address 0x000085bad5b016e5448a530cb3d4840d2cfd15bc',
	},
	'0xa85d90b8febc092e11e75bf8f93a7090e2ed04de': {
		type: 'INFERNO_DRAINER',
		source: 'SlowMist Analysis May 2025',
		stolen: '$146K+ (single victim)',
		description: 'Batch authorization exploit draining multiple tokens simultaneously',
	},
	'0x0000db5c8b030ae20308ac975898e09741e70000': {
		type: 'INFERNO_DRAINER',
		source: 'SlowMist Analysis May 2025',
		stolen: 'Part of $12M campaign',
		description: 'Fraudulent batch approval address',
	},
	'0x00008c22f9f6f3101533f520e229bbb54be90000': {
		type: 'INFERNO_DRAINER',
		source: 'SlowMist Analysis May 2025',
		stolen: 'Part of $12M campaign',
		description: 'Fraudulent batch approval address',
	},
};

export const KNOWN_SAFE: Set<string> = new Set(['0x63c0c19a282a1b52b07dd5a65b58948a07dae32b']);

export function checkKnownMalicious(address: string): KnownMaliciousContract | null {
	const normalizedAddress = address.toLowerCase();
	return KNOWN_MALICIOUS[normalizedAddress] || null;
}

export function isKnownSafe(address: string): boolean {
	return KNOWN_SAFE.has(address.toLowerCase());
}
