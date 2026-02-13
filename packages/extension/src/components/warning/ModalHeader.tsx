import type { ComponentChildren } from 'preact';
import type { AnalysisResult, HumanReadableIntent, WarningContext } from '../../utils/types';

interface Props {
	context: WarningContext;
	analysis: AnalysisResult;
	intent?: HumanReadableIntent;
}

function getTitle(context: WarningContext): string {
	switch (context) {
		case 'eth-sign-danger':
			return 'Dangerous: eth_sign Detected';
		case 'blind-signature':
			return 'Blind Signature Request';
		case 'typed-data-scan':
			return 'Malicious Address in Signed Data';
		case 'nft-approval':
			return 'NFT Collection Approval Detected';
		case 'approval':
			return 'Token Approval Detected';
		case 'permit':
			return 'Permit Signature Detected';
		case 'transaction':
			return 'Malicious Recipient Detected';
		default:
			return 'Dangerous Contract Detected';
	}
}

function getBlindSignatureTitle(risk: string): string {
	return risk === 'HIGH' ? 'Suspicious Message Detected' : 'Blind Signature Request';
}

export function ModalHeader({ context, analysis, intent }: Props) {
	const title =
		intent?.headline ??
		(context === 'blind-signature' ? getBlindSignatureTitle(analysis.risk) : getTitle(context));

	return (
		<div class="testudo-header">
			<div class="testudo-header-icon">
				<span class="testudo-material-icon">gpp_maybe</span>
			</div>
			<div class="testudo-header-text">
				<h2 class="testudo-title">{title}</h2>
				<p class="testudo-subtitle">{getSubtitle(context, analysis)}</p>
			</div>
		</div>
	);
}

function getSubtitle(context: WarningContext, analysis: AnalysisResult): ComponentChildren {
	switch (context) {
		case 'eth-sign-danger':
			return (
				<>
					<strong>eth_sign</strong> is deprecated and signs raw hashes. An attacker can craft a
					valid <strong>transaction hash</strong> — signing it gives them full control of your
					wallet.
				</>
			);
		case 'blind-signature':
			return analysis.risk === 'HIGH' ? (
				<>
					This message contains <strong>phishing patterns</strong> commonly used in scams.
				</>
			) : (
				<>
					You are signing <strong>arbitrary data</strong> that cannot be verified.
				</>
			);
		case 'typed-data-scan':
			return (
				<>
					A <strong>known malicious address</strong> was found in the data you are about to sign.
				</>
			);
		case 'nft-approval':
			return (
				<>
					You are granting <strong>full collection access</strong> to another address.
				</>
			);
		case 'approval':
			return (
				<>
					You are granting <strong>token spending rights</strong> to another address.
				</>
			);
		case 'permit':
			return (
				<>
					This signature grants <strong>token spending rights</strong>!
				</>
			);
		case 'transaction':
			return (
				<>
					You are about to send funds to a <strong>known scammer</strong> address.
				</>
			);
		default:
			return (
				<>
					We have intercepted a malicious <strong>EIP-7702</strong> delegation request.
				</>
			);
	}
}
