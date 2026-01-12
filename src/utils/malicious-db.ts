type KnownMaliciousContract = {
	type: string;
	source: string;
	stolen: string;
	description: string;
};

const KNOWN_MALICIOUS: Record<string, KnownMaliciousContract> = {
	'0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b': {
		type: 'ETH_AUTO_FORWARDER',
		source: 'SunSec Report May 2025',
		stolen: '$2.3M+',
		description:
			'Auto-redirects all incoming ETH to attacker address 0x000085bad5b016e5448a530cb3d4840d2cfd15bc',
	},
	// Add one of the actual Inferno Drainer addresses from your research doc 4:
	'0xa85d90b8febc092e11e75bf8f93a7090e2ed04de': {
		type: 'INFERNO_DRAINER',
		source: 'SlowMist Analysis May 2025',
		stolen: '$146K+ (single victim)',
		description: 'Batch authorization exploit draining multiple tokens simultaneously',
	},
};

function checkKnownMalicious(address: string): KnownMaliciousContract | null {
	const normalizedAddress = address.toLowerCase();
	return KNOWN_MALICIOUS[normalizedAddress] || null;
}

export { checkKnownMalicious, type KnownMaliciousContract };
