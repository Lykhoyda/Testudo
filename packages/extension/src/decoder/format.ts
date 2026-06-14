import { MAX_UINT160, MAX_UINT256 } from '../utils/constants';

const MAX_UINT256_BI = BigInt(MAX_UINT256);
const MAX_UINT160_BI = BigInt(MAX_UINT160);

// ERC-20 `decimals` is attacker-controlled on-chain metadata. Genuine tokens use
// 0–18 (a few outliers go a little higher); anything beyond this is treated as
// untrusted so a hostile `decimals` (e.g. 77) cannot silently scale a real
// approval down to "0.000000". (AUDIT-16)
const MAX_SANE_DECIMALS = 36;
const DISPLAY_DECIMALS = 6;

export function isNeverExpiry(deadline: string): boolean {
	try {
		return BigInt(deadline) >= MAX_UINT160_BI;
	} catch {
		return false;
	}
}

export function formatTokenAmount(
	raw: string,
	decimals: number | null,
	symbol: string | null,
): string {
	let val: bigint;
	try {
		val = BigInt(raw);
	} catch {
		return symbol ? `? ${symbol}` : raw;
	}

	// AUDIT-13: only the canonical max-uint sentinels are unequivocally
	// "unlimited" (consistent with isUnlimitedValue). A merely-large finite value
	// is rendered as its real scaled amount, not mislabeled "Unlimited" — a
	// 10-billion-token approval is large, but it is not infinite.
	if (val === MAX_UINT256_BI || val === MAX_UINT160_BI) {
		return symbol ? `Unlimited ${symbol}` : 'Unlimited';
	}

	// AUDIT-15 / AUDIT-16: without trustworthy decimals we cannot compute a real
	// amount. Show the raw base units with an explicit caveat rather than a
	// misleading number (a bare integer reads as a token count; a hostile
	// `decimals` would round the amount to "0.000000").
	const decimalsUsable =
		decimals !== null &&
		Number.isInteger(decimals) &&
		decimals >= 0 &&
		decimals <= MAX_SANE_DECIMALS;
	if (!decimalsUsable) {
		const base = val.toLocaleString('en-US');
		const withSymbol = symbol ? `${base} ${symbol}` : base;
		return `${withSymbol} (raw, decimals unknown)`;
	}

	if (decimals > 0) {
		const divisor = BigInt(10) ** BigInt(decimals);
		const whole = val / divisor;
		const remainder = val % divisor;

		if (remainder === 0n) {
			return formatWithSymbol(whole.toLocaleString('en-US'), symbol);
		}

		const remainderStr = remainder.toString().padStart(decimals, '0');
		const display = remainderStr.replace(/0+$/, '').slice(0, DISPLAY_DECIMALS);

		// AUDIT-16: a nonzero value whose first 6 fractional digits are all zero
		// would render as "0.000000" and hide that anything is being approved.
		if (whole === 0n && /^0*$/.test(display)) {
			return formatWithSymbol('<0.000001', symbol);
		}

		return formatWithSymbol(`${whole.toLocaleString('en-US')}.${display}`, symbol);
	}

	return formatWithSymbol(val.toLocaleString('en-US'), symbol);
}

function formatWithSymbol(amount: string, symbol: string | null): string {
	return symbol ? `${amount} ${symbol}` : amount;
}

export function formatDeadline(unix: string): string {
	if (isNeverExpiry(unix)) return 'Never';

	try {
		const ts = Number(unix);
		if (Number.isNaN(ts) || ts <= 0) return unix;

		const date = new Date(ts * 1000);
		const now = Date.now();
		const diffMs = date.getTime() - now;

		const formatted = date.toLocaleString('en-US', {
			month: 'short',
			day: 'numeric',
			year: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
		});

		if (diffMs < 0) return `${formatted} (expired)`;

		const diffMin = Math.floor(diffMs / 60_000);
		if (diffMin < 60) return `${formatted} (in ${diffMin}m)`;

		const diffHours = Math.floor(diffMin / 60);
		if (diffHours < 24) return `${formatted} (in ${diffHours}h)`;

		const diffDays = Math.floor(diffHours / 24);
		return `${formatted} (in ${diffDays}d)`;
	} catch {
		return unix;
	}
}

const CHAIN_NAMES: Record<number, string> = {
	0: 'All Networks (Replay Risk)',
	1: 'Ethereum',
	10: 'Optimism',
	56: 'BNB Chain',
	100: 'Gnosis',
	137: 'Polygon',
	250: 'Fantom',
	324: 'zkSync Era',
	420: 'Optimism Goerli',
	8453: 'Base',
	42161: 'Arbitrum One',
	42170: 'Arbitrum Nova',
	43114: 'Avalanche',
	59144: 'Linea',
	534352: 'Scroll',
	7777777: 'Zora',
	11155111: 'Sepolia',
};

export function getChainName(chainId: number | string | undefined): string | undefined {
	if (chainId === undefined || chainId === null) return undefined;
	const id = typeof chainId === 'string' ? Number(chainId) : chainId;
	return CHAIN_NAMES[id];
}
