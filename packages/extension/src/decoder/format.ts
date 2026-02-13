import { MAX_UINT160, MAX_UINT256 } from '../utils/constants';

const MAX_UINT256_BI = BigInt(MAX_UINT256);
const MAX_UINT160_BI = BigInt(MAX_UINT160);
const UNLIMITED_THRESHOLD = BigInt(10) ** BigInt(28);

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
	try {
		const val = BigInt(raw);

		if (val >= UNLIMITED_THRESHOLD || val === MAX_UINT256_BI || val === MAX_UINT160_BI) {
			return symbol ? `Unlimited ${symbol}` : 'Unlimited';
		}

		if (decimals !== null && decimals > 0) {
			const divisor = BigInt(10) ** BigInt(decimals);
			const whole = val / divisor;
			const remainder = val % divisor;

			if (remainder === 0n) {
				return formatWithSymbol(whole.toLocaleString('en-US'), symbol);
			}

			const remainderStr = remainder.toString().padStart(decimals, '0');
			const trimmed = remainderStr.replace(/0+$/, '');
			const display = trimmed.length > 6 ? trimmed.slice(0, 6) : trimmed;
			return formatWithSymbol(`${whole.toLocaleString('en-US')}.${display}`, symbol);
		}

		return formatWithSymbol(val.toLocaleString('en-US'), symbol);
	} catch {
		return symbol ? `? ${symbol}` : raw;
	}
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
