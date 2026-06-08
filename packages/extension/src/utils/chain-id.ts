/**
 * Parse a chain ID from the many shapes wallets and dApps use:
 *   - a number (1)
 *   - a bigint (1n)
 *   - a 0x-prefixed hex string ("0x1") — `eth_chainId` returns this
 *   - a plain decimal string ("137") — EIP-712 / EIP-7702 typed data often does this
 *
 * Returns a positive integer, or `undefined` when the value is missing, invalid,
 * or `<= 0` (chainId 0 = "all networks" / replay-risk, which is never a real
 * lookup target).
 *
 * AUDIT-4: the previous `parseChainIdHex` always parsed strings as base 16, so a
 * decimal string like "137" became 311 and per-chain threat lookups were routed
 * to a non-existent chain — a silent false negative on every L2/L3 where the
 * domain serialized chainId as a decimal string.
 */
export function parseChainId(value: unknown): number | undefined {
	if (typeof value === 'bigint') {
		return value > 0n && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : undefined;
	}
	if (typeof value === 'number') {
		return Number.isInteger(value) && value > 0 ? value : undefined;
	}
	if (typeof value !== 'string') return undefined;

	const trimmed = value.trim();
	if (trimmed === '') return undefined;

	const isHex = trimmed.startsWith('0x') || trimmed.startsWith('0X');
	const parsed = Number.parseInt(trimmed, isHex ? 16 : 10);
	return Number.isInteger(parsed) && parsed > 0 ? parsed : undefined;
}
