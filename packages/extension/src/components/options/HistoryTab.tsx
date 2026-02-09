import type { ReadonlySignal } from '@preact/signals';
import { formatDate, getRiskEmoji, truncateAddress } from '../../utils/formatters';
import type { ScanRecord } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	history: ReadonlySignal<ScanRecord[]>;
	onClear: () => void;
}

export function HistoryTab({ history: h, onClear }: Props) {
	return (
		<div class="section">
			<div class="whitelist-header">
				<h2 class="section-title">
					<MaterialIcon name="history" />
					Scan History
				</h2>
				<button type="button" class="btn btn-danger" id="btn-clear-history" onClick={onClear}>
					<MaterialIcon name="delete" />
					Clear History
				</button>
			</div>

			<div id="history-list">
				{h.value.length === 0 ? (
					<div class="whitelist-empty">No scan history</div>
				) : (
					h.value.map((scan) => (
						<div class="history-item" key={`${scan.address}-${scan.timestamp}`}>
							<span class="history-icon">{getRiskEmoji(scan.risk)}</span>
							<div class="history-details">
								<div class="history-address">{truncateAddress(scan.address, 10, 8)}</div>
								<div class="history-meta">
									{formatDate(scan.timestamp)}
									{scan.blocked ? ' \u2022 Blocked' : ''}
									{scan.url ? ` \u2022 ${new URL(scan.url).hostname}` : ''}
								</div>
							</div>
							<span class={`history-risk ${scan.risk.toLowerCase()}`}>{scan.risk}</span>
						</div>
					))
				)}
			</div>
		</div>
	);
}
