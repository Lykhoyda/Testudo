interface PhishingPattern {
	category: string;
	regex: RegExp;
	score: number;
}

const PHISHING_PATTERNS: PhishingPattern[] = [
	{ category: 'airdrop_scam', regex: /claim\s+(your\s+)?airdrop/i, score: 3 },
	{ category: 'airdrop_scam', regex: /free\s+tokens?/i, score: 3 },
	{ category: 'airdrop_scam', regex: /claim\s+(your\s+)?reward/i, score: 3 },
	{ category: 'verification_scam', regex: /verify\s+(your\s+)?wallet/i, score: 3 },
	{ category: 'verification_scam', regex: /confirm\s+(your\s+)?ownership/i, score: 3 },
	{ category: 'verification_scam', regex: /security\s+(check|verification)/i, score: 3 },
	{ category: 'urgency', regex: /expires?\s+in/i, score: 2 },
	{ category: 'urgency', regex: /act\s+now/i, score: 2 },
	{ category: 'urgency', regex: /limited\s+time/i, score: 2 },
	{ category: 'urgency', regex: /within\s+\d+\s+(hour|minute)/i, score: 2 },
	{ category: 'impersonation', regex: /opensea/i, score: 2 },
	{ category: 'impersonation', regex: /metamask/i, score: 2 },
	{ category: 'impersonation', regex: /uniswap/i, score: 2 },
	{ category: 'impersonation', regex: /coinbase/i, score: 2 },
	{ category: 'financial_lure', regex: /you\s+(have\s+)?won/i, score: 2 },
	{ category: 'financial_lure', regex: /prize/i, score: 2 },
	{ category: 'financial_lure', regex: /bonus\s+token/i, score: 2 },
];

export interface PhishingResult {
	score: number;
	patterns: string[];
	risk: 'INFO' | 'MEDIUM' | 'HIGH';
}

export function detectPhishingPatterns(messageText: string): PhishingResult {
	let score = 0;
	const matchedCategories = new Set<string>();

	for (const pattern of PHISHING_PATTERNS) {
		if (pattern.regex.test(messageText)) {
			score += pattern.score;
			matchedCategories.add(pattern.category);
		}
	}

	const patterns = Array.from(matchedCategories);
	const risk: PhishingResult['risk'] = score >= 3 ? 'HIGH' : score >= 1 ? 'MEDIUM' : 'INFO';

	return { score, patterns, risk };
}
