import * as vm from '../../hooks/warningVM';

export function InfoToast() {
	const { visible, title, text } = vm.infoToast.value;
	if (!visible) return null;

	return (
		<div class="testudo-toast" id="testudo-info-toast">
			<span class="testudo-toast-icon">info</span>
			<div class="testudo-toast-content">
				<div class="testudo-toast-title">
					<span class="testudo-toast-icon-inline">bolt</span>
					{title}
				</div>
				<div class="testudo-toast-text">{text}</div>
				<button
					type="button"
					class="testudo-toast-dismiss"
					id="testudo-toast-dismiss"
					onClick={vm.dismissInfoToast}
				>
					Dismiss
				</button>
			</div>
		</div>
	);
}
