import type { HumanReadableIntent, TokenInfo, WarningOptions } from '../utils/types';
import {
	buildApprovalIntent,
	buildBlindSignatureIntent,
	buildDelegationIntent,
	buildEthSignIntent,
	buildNftApprovalIntent,
	buildPermitIntent,
	buildTransactionIntent,
	buildTypedDataScanIntent,
} from './intent-builder';

export function buildIntent(
	opts: WarningOptions,
	tokenInfo?: TokenInfo | null,
): HumanReadableIntent | null {
	const context = opts.context ?? 'delegation';

	switch (context) {
		case 'permit':
			return opts.permitInfo ? buildPermitIntent(opts.permitInfo, tokenInfo) : null;

		case 'approval':
			return opts.approvalInfo ? buildApprovalIntent(opts.approvalInfo, tokenInfo) : null;

		case 'nft-approval':
			return opts.nftApprovalInfo ? buildNftApprovalIntent(opts.nftApprovalInfo) : null;

		case 'delegation':
			return buildDelegationIntent(opts.analysis.address);

		case 'transaction':
			return buildTransactionIntent(opts.analysis.address);

		case 'blind-signature':
			return opts.blindSignatureInfo ? buildBlindSignatureIntent(opts.blindSignatureInfo) : null;

		case 'typed-data-scan':
			return opts.typedDataScanInfo ? buildTypedDataScanIntent(opts.typedDataScanInfo) : null;

		case 'eth-sign-danger':
			return opts.blindSignatureInfo ? buildEthSignIntent(opts.blindSignatureInfo) : null;

		default:
			return null;
	}
}

export { formatDeadline, formatTokenAmount, getChainName, isNeverExpiry } from './format';
export {
	buildApprovalIntent,
	buildBlindSignatureIntent,
	buildDelegationIntent,
	buildEthSignIntent,
	buildNftApprovalIntent,
	buildPermitIntent,
	buildTransactionIntent,
	buildTypedDataScanIntent,
} from './intent-builder';
