import type { ReadonlySignal } from '@preact/signals';

interface Props {
	confirmInput: ReadonlySignal<string>;
	isConfirmValid: ReadonlySignal<boolean>;
	onInput: (value: string) => void;
	onProceed: () => void;
}

export function EthSignConfirm({
	confirmInput: ci,
	isConfirmValid: valid,
	onInput,
	onProceed,
}: Props) {
	return (
		<div class="testudo-confirm-section">
			<label class="testudo-confirm-label" for="testudo-confirm-input">
				Type <strong class="testudo-text-danger">I ACCEPT THE RISK</strong> to proceed
			</label>
			<input
				type="text"
				class="testudo-confirm-input"
				id="testudo-confirm-input"
				placeholder="I ACCEPT THE RISK"
				autocomplete="off"
				spellcheck={false}
				value={ci.value}
				onInput={(e) => onInput((e.target as HTMLInputElement).value)}
			/>
			<button
				type="button"
				class={`testudo-btn-danger-confirm${valid.value ? ' enabled' : ''}`}
				id="testudo-eth-sign-proceed"
				disabled={!valid.value}
				onClick={onProceed}
			>
				<span class="testudo-material-icon">warning</span>
				Proceed with eth_sign
			</button>
		</div>
	);
}
