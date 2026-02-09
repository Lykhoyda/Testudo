import {
	APPROVAL_SELECTORS,
	KNOWN_MARKETPLACES,
	MAX_UINT160,
	MAX_UINT256,
	NFT_APPROVAL_SELECTORS,
} from '../utils/constants';
import type { ApprovalInfo, NftApprovalInfo } from '../utils/types';

export function isApprovalTransaction(data: string | undefined): boolean {
	if (!data || data.length < 10) return false;
	const selector = data.slice(0, 10).toLowerCase();
	return Object.values(APPROVAL_SELECTORS).includes(
		selector as (typeof APPROVAL_SELECTORS)[keyof typeof APPROVAL_SELECTORS],
	);
}

export function parseApprovalData(data: string, tokenAddress: string): ApprovalInfo | null {
	const selector = data.slice(0, 10).toLowerCase();
	if (data.length < 138) return null;

	const spenderPadded = data.slice(10, 74);
	const amountHex = data.slice(74, 138);

	const spender = `0x${spenderPadded.slice(24).toLowerCase()}`;
	if (!/^0x[a-fA-F0-9]{40}$/.test(spender)) return null;

	const type =
		selector === APPROVAL_SELECTORS.approve
			? 'approve'
			: selector === APPROVAL_SELECTORS.increaseAllowance
				? 'increaseAllowance'
				: 'decreaseAllowance';

	return { type, spender, amount: `0x${amountHex}`, tokenAddress: tokenAddress.toLowerCase() };
}

export function isUnlimitedValue(value?: string): boolean {
	if (!value) return false;
	const normalized = value.toLowerCase();
	if (normalized === MAX_UINT256 || normalized === MAX_UINT160 || normalized === 'unlimited')
		return true;
	if (/[eE]/.test(value)) {
		const num = Number(value);
		if (!Number.isNaN(num) && num > 1e30) return true;
	}
	try {
		return BigInt(value) > BigInt(10) ** BigInt(30);
	} catch {
		return false;
	}
}

export function formatApprovalAmount(hexAmount: string): string {
	if (isUnlimitedValue(hexAmount)) {
		return 'UNLIMITED';
	}
	try {
		const amount = BigInt(hexAmount);
		return amount.toLocaleString();
	} catch {
		return 'Invalid Amount Data';
	}
}

export function isZeroApproval(hexAmount: string): boolean {
	try {
		return BigInt(hexAmount) === BigInt(0);
	} catch {
		return false;
	}
}

export function isNftApprovalTransaction(data: string | undefined): boolean {
	if (!data || data.length < 10) return false;
	const selector = data.slice(0, 10).toLowerCase();
	return selector === NFT_APPROVAL_SELECTORS.setApprovalForAll;
}

export function parseNftApprovalData(
	data: string,
	collectionAddress: string,
): NftApprovalInfo | null {
	if (data.length < 138) return null;

	const operatorPadded = data.slice(10, 74);
	const approvedHex = data.slice(74, 138);

	const operator = `0x${operatorPadded.slice(24).toLowerCase()}`;
	if (!/^0x[a-fA-F0-9]{40}$/.test(operator)) return null;

	const approved = BigInt(`0x${approvedHex}`) !== BigInt(0);

	return {
		type: 'setApprovalForAll',
		operator,
		approved,
		collectionAddress: collectionAddress.toLowerCase(),
	};
}

export function isKnownMarketplace(address: string): string | null {
	return KNOWN_MARKETPLACES[address.toLowerCase()] || null;
}
