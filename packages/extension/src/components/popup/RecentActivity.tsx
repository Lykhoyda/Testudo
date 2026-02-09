import type { ReadonlySignal } from '@preact/signals';
import {
	formatRelativeTime,
	getRiskIcon,
	getRiskLabel,
	truncateAddress,
} from '../../utils/formatters';
import type { RecentScan } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	scans: ReadonlySignal<RecentScan[]>;
	onViewAll: () => void;
}

export function RecentActivity({ scans, onViewAll }: Props) {
	return (
		<div class="activity-section">
			<div class="activity-header">
				<h3 class="activity-title">Recent Activity</h3>
				<button type="button" class="activity-view-all" id="view-all-btn" onClick={onViewAll}>
					View All
				</button>
			</div>
			<div class="activity-list" id="recent-list">
				{scans.value.length === 0 ? (
					<div class="empty-state">No recent scans</div>
				) : (
					scans.value.map((scan) => (
						<div class="activity-item" key={`${scan.address}-${scan.timestamp}`}>
							<div class={`activity-icon-wrapper ${scan.risk.toLowerCase()}`}>
								<MaterialIcon name={getRiskIcon(scan.risk)} class="activity-icon" />
							</div>
							<div class="activity-content">
								<div class="activity-row">
									<span class={`activity-badge ${scan.risk.toLowerCase()}`}>
										{getRiskLabel(scan.risk)}
									</span>
									<span class="activity-time">{formatRelativeTime(scan.timestamp)}</span>
								</div>
								<span class="activity-address">{truncateAddress(scan.address, 8, 6)}</span>
							</div>
						</div>
					))
				)}
			</div>
		</div>
	);
}
