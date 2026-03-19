export interface ChannelMessage {
	requestId: string;
	type: string;
	[key: string]: unknown;
}

export interface Channel {
	sendRequest(msg: ChannelMessage): void;
	sendResponse(msg: ChannelMessage): void;
	onRequest(handler: (msg: ChannelMessage) => void): () => void;
	onResponse(handler: (msg: ChannelMessage) => void): () => void;
}

export function createChannel(nonce: string): Channel {
	if (!nonce) {
		throw new Error('[Testudo] Channel nonce is empty — aborting to prevent insecure channel');
	}
	const reqEvent = `testudo-req-${nonce}`;
	const resEvent = `testudo-res-${nonce}`;

	return {
		sendRequest(msg: ChannelMessage): void {
			document.dispatchEvent(
				new CustomEvent(reqEvent, { detail: msg, bubbles: false, cancelable: false }),
			);
		},

		sendResponse(msg: ChannelMessage): void {
			document.dispatchEvent(
				new CustomEvent(resEvent, { detail: msg, bubbles: false, cancelable: false }),
			);
		},

		onRequest(handler: (msg: ChannelMessage) => void): () => void {
			const listener = (e: Event) => handler((e as CustomEvent<ChannelMessage>).detail);
			document.addEventListener(reqEvent, listener);
			return () => document.removeEventListener(reqEvent, listener);
		},

		onResponse(handler: (msg: ChannelMessage) => void): () => void {
			const listener = (e: Event) => handler((e as CustomEvent<ChannelMessage>).detail);
			document.addEventListener(resEvent, listener);
			return () => document.removeEventListener(resEvent, listener);
		},
	};
}

export function readNonce(): string {
	const el = document.querySelector('script[data-testudo-nonce]');
	const nonce = (el as HTMLScriptElement | null)?.dataset.testudoNonce ?? '';
	if (el) {
		delete (el as HTMLScriptElement).dataset.testudoNonce;
	}
	return nonce;
}
