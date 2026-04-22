import { type ReadonlySignal, signal } from '@preact/signals';
import {
	formatDate,
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

// Module-level state keeps the expanded scan sticky across popup re-renders.
const expandedKey = signal<string | null>(null);

function scanKey(scan: RecentScan): string {
	return `${scan.address}-${scan.timestamp}`;
}

function hostnameFromUrl(url: string | undefined): string | null {
	if (!url) return null;
	try {
		return new URL(url).hostname;
	} catch {
		return url;
	}
}

function toggleExpanded(key: string): void {
	expandedKey.value = expandedKey.value === key ? null : key;
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
					scans.value.map((scan) => {
						const key = scanKey(scan);
						const isExpanded = expandedKey.value === key;
						const hostname = hostnameFromUrl(scan.url);
						const threats = scan.threats?.filter(Boolean) ?? [];
						return (
							<div class={`activity-item${isExpanded ? ' expanded' : ''}`} key={key}>
								<button
									type="button"
									class="activity-main"
									onClick={() => toggleExpanded(key)}
									aria-expanded={isExpanded}
								>
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
									<MaterialIcon
										name="expand_more"
										class={`activity-chevron${isExpanded ? ' open' : ''}`}
									/>
								</button>

								{isExpanded && (
									<div class="activity-details" data-risk={scan.risk.toLowerCase()}>
										<dl class="activity-details-grid">
											<dt>Address</dt>
											<dd class="activity-details-mono">{scan.address}</dd>

											<dt>Seen</dt>
											<dd>{formatDate(scan.timestamp)}</dd>

											{hostname && (
												<>
													<dt>Site</dt>
													<dd class="activity-details-mono">{hostname}</dd>
												</>
											)}

											<dt>Status</dt>
											<dd>
												<span class={`activity-status ${scan.blocked ? 'blocked' : 'allowed'}`}>
													<span class="activity-status-dot" aria-hidden="true" />
													{scan.blocked ? 'Blocked' : 'Allowed'}
												</span>
											</dd>

											{threats.length > 0 && (
												<>
													<dt>Threats</dt>
													<dd>
														<div class="activity-threats">
															{threats.map((t) => (
																<span class="activity-threat-chip" key={t}>
																	{t.toUpperCase()}
																</span>
															))}
														</div>
													</dd>
												</>
											)}
										</dl>
									</div>
								)}
							</div>
						);
					})
				)}
			</div>
		</div>
	);
}
