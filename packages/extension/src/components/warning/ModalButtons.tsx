import type { ReadonlySignal } from '@preact/signals';
import type { WarningContext } from '../../utils/types';
import { EthSignConfirm } from './EthSignConfirm';

interface Props {
	context: WarningContext;
	confirmInput: ReadonlySignal<string>;
	isConfirmValid: ReadonlySignal<boolean>;
	onCancel: () => void;
	onProceed: () => void;
	onEthSignProceed: () => void;
	onConfirmInput: (value: string) => void;
}

export function ModalButtons({
	context,
	confirmInput,
	isConfirmValid,
	onCancel,
	onProceed,
	onEthSignProceed,
	onConfirmInput,
}: Props) {
	return (
		<div class="testudo-buttons">
			<button type="button" class="testudo-btn-cancel" id="testudo-cancel" onClick={onCancel}>
				<span class="testudo-material-icon">shield</span>
				Cancel (Safe)
			</button>
			{context === 'eth-sign-danger' ? (
				<EthSignConfirm
					confirmInput={confirmInput}
					isConfirmValid={isConfirmValid}
					onInput={onConfirmInput}
					onProceed={onEthSignProceed}
				/>
			) : (
				<div class="testudo-secondary-actions">
					<button type="button" class="testudo-btn-danger" id="testudo-proceed" onClick={onProceed}>
						<span>Proceed Anyway</span>
						<span class="testudo-material-icon">arrow_forward</span>
					</button>
				</div>
			)}
		</div>
	);
}
