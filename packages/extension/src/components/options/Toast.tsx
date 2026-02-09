import type { ReadonlySignal } from '@preact/signals';
import { MaterialIcon } from '../shared/MaterialIcon';

interface ToastState {
	message: string;
	isError: boolean;
	visible: boolean;
}

interface Props {
	toast: ReadonlySignal<ToastState>;
}

export function Toast({ toast: toastSignal }: Props) {
	const { message, isError, visible } = toastSignal.value;
	return (
		<div id="toast" class={`toast${isError ? ' error' : ''}${visible ? ' show' : ''}`}>
			<MaterialIcon name={isError ? 'error' : 'check_circle'} />
			<span id="toast-message">{message}</span>
		</div>
	);
}
