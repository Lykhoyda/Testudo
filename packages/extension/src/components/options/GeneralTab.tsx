import type { ReadonlySignal } from '@preact/signals';
import type { Settings } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	settings: ReadonlySignal<Settings>;
	onChangeProtection: (value: Settings['protectionLevel']) => void;
	onToggleMediumToast: () => void;
	onToggleAutoRecord: () => void;
}

export function GeneralTab({
	settings: s,
	onChangeProtection,
	onToggleMediumToast,
	onToggleAutoRecord,
}: Props) {
	return (
		<>
			<div class="section">
				<h2 class="section-title">
					<MaterialIcon name="security" />
					Protection Level
				</h2>
				<div class="form-group">
					<label class="form-label" htmlFor="protection-level">
						Security Mode
					</label>
					<select
						id="protection-level"
						value={s.value.protectionLevel}
						onChange={(e) =>
							onChangeProtection(
								(e.target as HTMLSelectElement).value as Settings['protectionLevel'],
							)
						}
					>
						<option value="strict">Strict - Block MEDIUM and above</option>
						<option value="standard">Standard - Block HIGH and CRITICAL</option>
						<option value="permissive">Permissive - Block CRITICAL only</option>
					</select>
					<p class="form-description">
						Choose how aggressively Testudo blocks potentially risky delegations.
					</p>
				</div>
			</div>

			<div class="section">
				<h2 class="section-title">
					<MaterialIcon name="notifications" />
					Notifications
				</h2>
				<div class="toggle-group">
					<div>
						<div class="toggle-label">Show Medium Risk Toast</div>
						<div class="toggle-description">Display a notification for medium-risk contracts</div>
					</div>
					<div
						class={`toggle${s.value.showMediumRiskToast ? ' active' : ''}`}
						id="toggle-medium-toast"
						role="switch"
						aria-checked={s.value.showMediumRiskToast}
						tabIndex={0}
						onClick={onToggleMediumToast}
						onKeyDown={(e) => {
							if (e.key === 'Enter' || e.key === ' ') {
								e.preventDefault();
								onToggleMediumToast();
							}
						}}
					/>
				</div>
				<div class="toggle-group">
					<div>
						<div class="toggle-label">Auto-record Scans</div>
						<div class="toggle-description">Save scan history for later review</div>
					</div>
					<div
						class={`toggle${s.value.autoRecordScans ? ' active' : ''}`}
						id="toggle-auto-record"
						role="switch"
						aria-checked={s.value.autoRecordScans}
						tabIndex={0}
						onClick={onToggleAutoRecord}
						onKeyDown={(e) => {
							if (e.key === 'Enter' || e.key === ' ') {
								e.preventDefault();
								onToggleAutoRecord();
							}
						}}
					/>
				</div>
			</div>
		</>
	);
}
