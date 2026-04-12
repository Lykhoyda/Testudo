import type { ReadonlySignal } from '@preact/signals';
import type { Settings } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	settings: ReadonlySignal<Settings>;
	onToggleMediumToast: () => void;
	onToggleAutoRecord: () => void;
}

export function GeneralTab({ settings: s, onToggleMediumToast, onToggleAutoRecord }: Props) {
	return (
		<>
			<div class="info-card">
				<div class="info-card-icon">
					<MaterialIcon name="security" />
				</div>
				<div>
					<div class="info-card-title">3-layer defense is active</div>
					<div class="info-card-desc">Safe filter → Threat API → Local bytecode analysis.</div>
				</div>
			</div>

			<section class="opt-group">
				<h2 class="opt-group-title">Detection</h2>
				<div class="opt-list">
					<div class="opt-row">
						<div class="opt-row-text">
							<div class="opt-row-title" id="label-medium-toast">
								Show medium-risk warnings
							</div>
							<div class="opt-row-desc">
								Display non-blocking toasts for medium severity threats.
							</div>
						</div>
						<div
							class={`toggle${s.value.showMediumRiskToast ? ' active' : ''}`}
							id="toggle-medium-toast"
							role="switch"
							aria-checked={s.value.showMediumRiskToast}
							aria-labelledby="label-medium-toast"
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
					<div class="opt-row">
						<div class="opt-row-text">
							<div class="opt-row-title" id="label-auto-record">
								Auto-record scans
							</div>
							<div class="opt-row-desc">Keep local history of analyzed contracts for review.</div>
						</div>
						<div
							class={`toggle${s.value.autoRecordScans ? ' active' : ''}`}
							id="toggle-auto-record"
							role="switch"
							aria-checked={s.value.autoRecordScans}
							aria-labelledby="label-auto-record"
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
			</section>
		</>
	);
}
