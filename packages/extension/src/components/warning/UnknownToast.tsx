import * as vm from '../../hooks/warningVM';
import { truncateAddress } from '../../utils/formatters';

export function UnknownToast() {
	const { visible, address } = vm.unknownToast.value;
	if (!visible) return null;

	return (
		<div class="testudo-toast-unknown" id="testudo-unknown-toast">
			<span class="testudo-toast-unknown-icon">help_outline</span>
			<div class="testudo-toast-unknown-content">
				<div class="testudo-toast-unknown-title">Unverified Contract</div>
				<div class="testudo-toast-unknown-text">
					This contract has no bytecode or doesn't exist on-chain. It may be an EOA (regular wallet)
					or undeployed contract.
				</div>
				<div class="testudo-toast-unknown-address">{truncateAddress(address)}</div>
				<button
					type="button"
					class="testudo-toast-unknown-dismiss"
					id="testudo-unknown-dismiss"
					onClick={vm.dismissUnknownToast}
				>
					Dismiss
				</button>
			</div>
		</div>
	);
}
