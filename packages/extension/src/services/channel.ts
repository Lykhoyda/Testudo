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

/**
 * Obtain the channel nonce via a synchronous CustomEvent handshake with the
 * content script. The injected script generates a random token, dispatches
 * 'testudo-handshake' with that token, and the content script responds on a
 * token-specific event with the actual channel nonce. All synchronous — the
 * nonce never touches the DOM as an attribute, closing the MutationObserver
 * race window (QA-005).
 *
 * Falls back to the legacy DOM attribute approach for backwards compatibility.
 */
export function readNonce(): string {
	const token = crypto.randomUUID();
	let nonce = '';

	const handler = (e: Event) => {
		nonce = (e as CustomEvent<string>).detail;
	};
	document.addEventListener(`testudo-hs-${token}`, handler, { once: true });
	document.dispatchEvent(
		new CustomEvent('testudo-handshake', {
			detail: token,
			bubbles: false,
			cancelable: false,
		}),
	);
	document.removeEventListener(`testudo-hs-${token}`, handler);

	if (nonce) return nonce;

	// Legacy fallback: read from DOM attribute (content script versions before handshake)
	const el = document.querySelector('script[data-testudo-nonce]');
	const fallback = (el as HTMLScriptElement | null)?.dataset.testudoNonce ?? '';
	if (el) {
		delete (el as HTMLScriptElement).dataset.testudoNonce;
	}
	return fallback;
}
