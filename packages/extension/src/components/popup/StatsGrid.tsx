import type { ReadonlySignal } from '@preact/signals';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	blocked: ReadonlySignal<number>;
	scanned: ReadonlySignal<number>;
}

export function StatsGrid({ blocked, scanned }: Props) {
	return (
		<div class="stats-grid">
			<div class="stat-card">
				<div class="stat-header">
					<MaterialIcon name="security" class="stat-icon" />
					<span class="stat-label">Blocked</span>
				</div>
				<p class="stat-value" id="stat-blocked">
					{blocked}
				</p>
			</div>
			<div class="stat-card">
				<div class="stat-header">
					<MaterialIcon name="find_in_page" class="stat-icon" />
					<span class="stat-label">Scanned</span>
				</div>
				<p class="stat-value" id="stat-scanned">
					{scanned}
				</p>
			</div>
		</div>
	);
}
