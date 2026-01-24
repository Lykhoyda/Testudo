import type { AdapterResult, RawDomainEntry } from './types.js';

const CONFIG_URL =
	'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json';

const SOURCE_NAME = 'eth-phishing-detect';
const FUZZY_TOLERANCE = 3;

interface PhishingConfig {
	blacklist: string[];
	fuzzylist: string[];
	whitelist: string[];
}

function levenshtein(a: string, b: string): number {
	const m = a.length;
	const n = b.length;

	if (m === 0) return n;
	if (n === 0) return m;

	const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0) as number[]);

	for (let i = 0; i <= m; i++) dp[i][0] = i;
	for (let j = 0; j <= n; j++) dp[0][j] = j;

	for (let i = 1; i <= m; i++) {
		for (let j = 1; j <= n; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
		}
	}

	return dp[m][n];
}

function findFuzzyMatch(domain: string, fuzzylist: string[]): string | null {
	for (const legitimate of fuzzylist) {
		if (Math.abs(domain.length - legitimate.length) > FUZZY_TOLERANCE) continue;
		if (levenshtein(domain, legitimate) <= FUZZY_TOLERANCE) {
			return legitimate;
		}
	}
	return null;
}

export async function fetchDomains(): Promise<AdapterResult<RawDomainEntry>> {
	const response = await fetch(CONFIG_URL);

	if (!response.ok) {
		throw new Error(`eth-phishing-detect fetch failed: ${response.status} ${response.statusText}`);
	}

	const config = (await response.json()) as PhishingConfig;

	if (!Array.isArray(config.blacklist)) {
		throw new Error('eth-phishing-detect config.blacklist is not an array');
	}

	const whiteset = new Set((config.whitelist ?? []).map((d: string) => d.toLowerCase().trim()));
	const fuzzylist = (config.fuzzylist ?? []).map((d: string) => d.toLowerCase().trim());

	const filtered = config.blacklist
		.filter((entry): entry is string => typeof entry === 'string' && entry.length > 0)
		.map((raw) => raw.toLowerCase().trim())
		.filter((domain) => domain.length > 0)
		.filter((domain) => !whiteset.has(domain));

	const entries: RawDomainEntry[] = [];
	const CHUNK_SIZE = 5000;

	for (let i = 0; i < filtered.length; i += CHUNK_SIZE) {
		const chunk = filtered.slice(i, i + CHUNK_SIZE);
		for (const domain of chunk) {
			const matched = findFuzzyMatch(domain, fuzzylist);
			entries.push({
				domain,
				threatType: 'PHISHING',
				isFuzzyMatch: matched !== null,
				matchedLegitimate: matched,
			});
		}
		if (i + CHUNK_SIZE < filtered.length) {
			await new Promise((resolve) => setTimeout(resolve, 0));
		}
	}

	return {
		source: SOURCE_NAME,
		entries,
		fetchedAt: new Date(),
	};
}
