import { isUnlimitedValue } from '../parsers/transaction';
import { truncateAddress } from '../utils/formatters';
import type {
	ApprovalInfo,
	BlindSignatureInfo,
	HumanReadableIntent,
	IntentDetail,
	NftApprovalInfo,
	PermitInfo,
	TokenInfo,
	TypedDataScanInfo,
} from '../utils/types';
import { formatDeadline, formatTokenAmount, getChainName, isNeverExpiry } from './format';

export function buildPermitIntent(
	info: PermitInfo,
	tokenInfo?: TokenInfo | null,
): HumanReadableIntent {
	const spender = truncateAddress(info.spender);
	const unlimited = isUnlimitedValue(info.value);
	const symbol = tokenInfo?.symbol ?? info.tokenName ?? null;
	const decimals = tokenInfo?.decimals ?? null;

	let amountText: string;
	if (info.value === 'batch') {
		amountText = 'Multiple tokens (batch)';
	} else if (unlimited) {
		amountText = symbol ? `Unlimited ${symbol}` : 'Unlimited';
	} else if (info.value && decimals !== null) {
		amountText = formatTokenAmount(info.value, decimals, symbol);
	} else if (info.value) {
		amountText = symbol ? `${info.value} (raw) ${symbol}` : info.value;
	} else {
		amountText = 'Unknown amount';
	}

	const details: IntentDetail[] = [
		{
			label: 'Spender',
			value: spender,
			emphasis: 'danger',
			mono: true,
		},
		{
			label: 'Amount',
			value: amountText,
			emphasis: unlimited ? 'danger' : 'warning',
		},
	];

	if (info.token) {
		details.push({
			label: 'Token Contract',
			value: truncateAddress(info.token),
			mono: true,
		});
	}

	if (info.deadline) {
		const deadlineText = formatDeadline(info.deadline);
		details.push({
			label: 'Expires',
			value: deadlineText,
			emphasis: isNeverExpiry(info.deadline) ? 'danger' : 'info',
		});
	}

	const headline = unlimited
		? `Unlimited ${symbol ?? 'Token'} Permit`
		: `${symbol ?? 'Token'} Permit Request`;

	return {
		headline,
		action: `Allow ${spender} to spend ${amountText}`,
		details,
	};
}

export function buildApprovalIntent(
	info: ApprovalInfo,
	tokenInfo?: TokenInfo | null,
): HumanReadableIntent {
	const spender = truncateAddress(info.spender);
	const unlimited = isUnlimitedValue(info.amount);
	const symbol = tokenInfo?.symbol ?? null;
	const decimals = tokenInfo?.decimals ?? null;

	const amountText = unlimited
		? symbol
			? `Unlimited ${symbol}`
			: 'Unlimited'
		: formatTokenAmount(info.amount, decimals, symbol);

	const details: IntentDetail[] = [
		{
			label: 'Spender',
			value: spender,
			emphasis: 'danger',
			mono: true,
		},
		{
			label: 'Amount',
			value: amountText,
			emphasis: unlimited ? 'danger' : 'warning',
		},
		{
			label: 'Token Contract',
			value: truncateAddress(info.tokenAddress),
			mono: true,
		},
		{
			label: 'Operation',
			value: info.type === 'approve'
				? 'approve()'
				: info.type === 'increaseAllowance'
					? 'increaseAllowance()'
					: 'decreaseAllowance()',
			emphasis: 'info',
		},
	];

	const headline = unlimited
		? `Unlimited ${symbol ?? 'Token'} Approval`
		: `${symbol ?? 'Token'} Approval Request`;

	return {
		headline,
		action: `Allow ${spender} to spend ${amountText}`,
		details,
	};
}

export function buildNftApprovalIntent(info: NftApprovalInfo): HumanReadableIntent {
	const operator = truncateAddress(info.operator);
	const collection = info.collectionName ?? truncateAddress(info.collectionAddress);

	const details: IntentDetail[] = [
		{
			label: 'Operator',
			value: operator,
			emphasis: 'danger',
			mono: true,
		},
		{
			label: 'Collection',
			value: collection,
		},
		{
			label: 'Access Level',
			value: 'Full Collection',
			emphasis: 'danger',
		},
	];

	return {
		headline: 'NFT Collection Approval',
		action: `Grant ${operator} full access to your ${collection}`,
		details,
	};
}

export function buildDelegationIntent(
	address: string,
	chainId?: number | string,
): HumanReadableIntent {
	const delegate = truncateAddress(address);
	const chainName = getChainName(chainId);

	const details: IntentDetail[] = [
		{
			label: 'Delegate',
			value: delegate,
			emphasis: 'danger',
			mono: true,
		},
	];

	if (chainName) {
		details.push({ label: 'Network', value: chainName });
	}

	return {
		headline: 'Wallet Delegation Request',
		action: `Delegate wallet control to ${delegate}${chainName ? ` on ${chainName}` : ''}`,
		details,
		chainName,
	};
}

export function buildTransactionIntent(address: string): HumanReadableIntent {
	const recipient = truncateAddress(address);

	return {
		headline: 'Suspicious Transaction',
		action: `Send funds to ${recipient}`,
		details: [
			{
				label: 'Recipient',
				value: recipient,
				emphasis: 'danger',
				mono: true,
			},
		],
	};
}

export function buildBlindSignatureIntent(info: BlindSignatureInfo): HumanReadableIntent {
	const details: IntentDetail[] = [
		{
			label: 'Method',
			value: info.type,
			emphasis: 'warning',
		},
		{
			label: `Message${info.isHex ? ' (hex)' : ''}`,
			value: info.messagePreview,
			mono: true,
		},
	];

	return {
		headline: 'Blind Signature Request',
		action: `Sign arbitrary data with ${info.type}`,
		details,
	};
}

export function buildTypedDataScanIntent(info: TypedDataScanInfo): HumanReadableIntent {
	const details: IntentDetail[] = [
		{
			label: 'Primary Type',
			value: info.primaryType,
		},
	];

	if (info.domainName) {
		details.push({ label: 'Domain', value: info.domainName });
	}

	for (const addr of info.maliciousAddresses.slice(0, 3)) {
		details.push({
			label: `Found in: ${addr.fieldPath}`,
			value: truncateAddress(addr.address),
			emphasis: 'danger',
			mono: true,
		});
	}

	return {
		headline: 'Malicious Address in Signed Data',
		action: `Known malicious address found in ${info.primaryType}`,
		details,
	};
}

export function buildEthSignIntent(info: BlindSignatureInfo): HumanReadableIntent {
	return {
		headline: 'Dangerous: eth_sign Detected',
		action: `Sign raw hash via deprecated eth_sign`,
		details: [
			{
				label: 'Method',
				value: 'eth_sign (deprecated)',
				emphasis: 'danger',
			},
			{
				label: 'Message',
				value: info.messagePreview,
				mono: true,
			},
		],
	};
}
