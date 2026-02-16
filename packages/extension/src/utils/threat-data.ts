interface ThreatEntry {
	icon: string;
	shortDesc: string;
	format: string;
}

const THREAT_REGISTRY: Record<string, ThreatEntry> = {
	auto_forwarder: {
		icon: 'currency_exchange',
		shortDesc: 'Redirects incoming assets to external address',
		format: 'Auto-forwards ETH',
	},
	delegate_call: {
		icon: 'call_split',
		shortDesc: 'Executes code in context of your wallet',
		format: 'Uses DELEGATECALL',
	},
	self_destruct: {
		icon: 'delete_forever',
		shortDesc: 'Can destroy itself after draining funds',
		format: 'Can self-destruct',
	},
	unlimited_approval: {
		icon: 'all_inclusive',
		shortDesc: 'Requests access to all your tokens',
		format: 'Unlimited token approval',
	},
	create2: {
		icon: 'add_box',
		shortDesc: 'Can deploy contracts at predictable addresses',
		format: 'Uses CREATE2',
	},
	metamorphic: {
		icon: 'swap_horiz',
		shortDesc: 'Code can change while keeping same address',
		format: 'Metamorphic contract',
	},
	chainid_branching: {
		icon: 'public',
		shortDesc: 'Behavior changes based on network',
		format: 'Cross-chain behavior',
	},
	chainid_comparison: {
		icon: 'public',
		shortDesc: 'May restrict behavior on specific chains',
		format: 'Network ID comparison',
	},
	chainid_read: {
		icon: 'public',
		shortDesc: 'Reads network ID for conditional logic',
		format: 'Reads network ID',
	},
	token_drain_fallback: {
		icon: 'token',
		shortDesc: 'Auto-drains tokens on any interaction',
		format: 'Token drain in fallback',
	},
	token_hardcoded_dest: {
		icon: 'token',
		shortDesc: 'Sends funds to hardcoded attacker address',
		format: 'Hardcoded destination',
	},
	token_no_auth: {
		icon: 'token',
		shortDesc: 'No signature verification for transfers',
		format: 'No access control',
	},
	token_replay_risk: {
		icon: 'replay',
		shortDesc: 'Same signature can be reused multiple times',
		format: 'Replay attack risk',
	},
	token_approval_no_auth: {
		icon: 'token',
		shortDesc: 'Unlimited access without verification',
		format: 'Unprotected approvals',
	},
	token_with_auth: {
		icon: 'token',
		shortDesc: 'Has some security controls in place',
		format: 'Token transfers enabled',
	},
	nft_full_collection_access: {
		icon: 'collections',
		shortDesc: 'Grants control over ALL NFTs in this collection',
		format: 'Full NFT collection access',
	},
	eth_sign_deprecated: {
		icon: 'dangerous',
		shortDesc: 'eth_sign is deprecated and signs raw hashes without safety prefix',
		format: 'Deprecated: eth_sign',
	},
	blind_signature: {
		icon: 'visibility_off',
		shortDesc: 'Signing arbitrary data without visibility into its purpose',
		format: 'Blind signature',
	},
	airdrop_scam: {
		icon: 'card_giftcard',
		shortDesc: 'Message contains airdrop/reward scam language',
		format: 'Airdrop scam pattern',
	},
	verification_scam: {
		icon: 'verified_user',
		shortDesc: 'Message impersonates wallet verification request',
		format: 'Verification scam pattern',
	},
	urgency: {
		icon: 'timer',
		shortDesc: 'Message uses urgency pressure tactics',
		format: 'Urgency pressure tactic',
	},
	impersonation: {
		icon: 'person_alert',
		shortDesc: 'Message impersonates a known brand or protocol',
		format: 'Brand impersonation',
	},
	financial_lure: {
		icon: 'payments',
		shortDesc: 'Message contains financial lure language',
		format: 'Financial lure',
	},
	typed_data_malicious_address: {
		icon: 'gpp_bad',
		shortDesc: 'A known malicious address is embedded in the signed data',
		format: 'Malicious address in signed data',
	},
	deployer_fresh: {
		icon: 'new_releases',
		shortDesc: 'Deployed by a brand-new account with almost no history',
		format: 'Fresh deployer account',
	},
	deployer_low_nonce: {
		icon: 'person_alert',
		shortDesc: 'Deployer account has very few transactions',
		format: 'Low-activity deployer',
	},
	deployer_new_contract: {
		icon: 'schedule',
		shortDesc: 'Contract was deployed very recently',
		format: 'Recently deployed',
	},
	ETH_AUTO_FORWARDER: {
		icon: 'currency_exchange',
		shortDesc: 'Known malicious ETH drainer contract',
		format: 'Known ETH drainer',
	},
	INFERNO_DRAINER: {
		icon: 'local_fire_department',
		shortDesc: 'Known Inferno Drainer attack contract',
		format: 'Inferno Drainer',
	},
};

export function getThreatIcon(threat: string): string {
	return THREAT_REGISTRY[threat]?.icon || 'warning';
}

export function getThreatShortDesc(threat: string): string {
	return THREAT_REGISTRY[threat]?.shortDesc || 'Suspicious behavior detected';
}

export function formatThreat(threat: string): string {
	return THREAT_REGISTRY[threat]?.format || threat.replace(/_/g, ' ');
}
