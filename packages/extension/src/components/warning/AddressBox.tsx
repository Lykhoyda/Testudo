import type { ReadonlySignal } from '@preact/signals';
import { truncateAddress } from '../../utils/formatters';
import type { WarningContext } from '../../utils/types';

interface Props {
	address: string;
	context: WarningContext;
	copyIcon: ReadonlySignal<string>;
	onCopy: () => void;
}

function getAddressLabel(context: WarningContext): string {
	switch (context) {
		case 'eth-sign-danger':
		case 'blind-signature':
			return 'Signer Address';
		case 'typed-data-scan':
			return 'Malicious Address';
		case 'nft-approval':
			return 'Operator Address';
		case 'approval':
		case 'permit':
			return 'Spender Address';
		case 'transaction':
			return 'Recipient Address';
		default:
			return 'Target Contract';
	}
}

export function AddressBox({ address, context, copyIcon, onCopy }: Props) {
	return (
		<div class="testudo-address-section">
			<div class="testudo-address-box">
				<span class="testudo-address-label">{getAddressLabel(context)}</span>
				<div class="testudo-address-value">
					<span class="testudo-address-text">{truncateAddress(address)}</span>
					<button
						type="button"
						class="testudo-copy-btn"
						id="testudo-copy"
						title="Copy Address"
						onClick={onCopy}
					>
						<span class="testudo-material-icon">{copyIcon}</span>
					</button>
				</div>
			</div>
		</div>
	);
}
