import type { WarningContext } from '../../utils/types';

interface Props {
	context: WarningContext;
	address: string;
}

function getLoadingSubtitle(context: WarningContext): string {
	switch (context) {
		case 'delegation':
			return 'Checking delegation contract for threats...';
		case 'approval':
			return 'Checking spender address...';
		case 'permit':
			return 'Checking permit spender...';
		case 'transaction':
			return 'Checking recipient address...';
		case 'nft-approval':
			return 'Checking operator address...';
		default:
			return 'Running security analysis...';
	}
}

function truncateAddress(address: string): string {
	if (address.length <= 13) return address;
	return `${address.slice(0, 6)}...${address.slice(-4)}`;
}

export function LoadingState({ context, address }: Props) {
	return (
		<div id="testudo-warning-overlay">
			<div class="testudo-modal">
				<div class="testudo-header">
					<div class="testudo-header-icon testudo-loading-icon">
						<span class="testudo-material-icon testudo-spin">shield</span>
					</div>
					<div class="testudo-header-text">
						<h2 class="testudo-title">Analyzing Contract</h2>
						<p class="testudo-subtitle">{getLoadingSubtitle(context)}</p>
					</div>
				</div>

				<div class="testudo-address-section">
					<div class="testudo-address-box">
						<span class="testudo-address-label">Contract</span>
						<div class="testudo-address-value">
							<span class="testudo-address-text">{truncateAddress(address)}</span>
						</div>
					</div>
				</div>

				<div class="testudo-loading-bar-container">
					<div class="testudo-loading-bar" />
				</div>

				<div class="testudo-buttons">
					<button
						type="button"
						class="testudo-btn-cancel"
						disabled
						style={{ opacity: 0.5, cursor: 'wait' }}
					>
						<span class="testudo-material-icon">hourglass_top</span>
						Analyzing...
					</button>
				</div>
			</div>
		</div>
	);
}
