/**
 * TRUST-BOUNDARY BRIDGE (ADR-016, supersedes the ADR-011 nonce handshake)
 *
 * The page MAIN world (injected.js) and the ISOLATED content script communicate
 * over a private MessagePort. The port is created in the ISOLATED world and
 * transferred to MAIN exactly once at document_start — before any page script
 * runs — so the page never receives it and cannot observe or inject channel
 * traffic afterwards.
 *
 * There is NO shared secret/nonce. Authority is the port capability itself: a
 * transferred MessagePort cannot be forged by, or enumerated off `window` by,
 * other MAIN-world (page) scripts. This closes both ADR-011 handshake bugs —
 * the nonce can no longer leak to the page, and there is no top-level throw that
 * could disable all interception (AUDIT-1 / AUDIT-2).
 *
 * The handshake is order-resilient: each side announces readiness AND listens
 * for the other, so it works regardless of which world's content script runs
 * first (Chrome gives no cross-world ordering guarantee at document_start).
 */

export const BRIDGE_EVENTS = {
	ISO_READY: 'testudo:v1:isolated-ready',
	MAIN_READY: 'testudo:v1:main-ready',
} as const;

const PORT_TRANSFER = 'testudo:v1:port';

export interface BridgeMessage {
	requestId: string;
	type: string;
	[key: string]: unknown;
}

export type RequestReply = (responseType: string, requestId: string, result: unknown) => void;
export type RequestHandler = (msg: BridgeMessage, reply: RequestReply) => void;

export interface MainChannel {
	request<T>(
		requestType: string,
		responseType: string,
		payload: Record<string, unknown>,
		timeoutMs?: number,
	): Promise<T>;
	post(type: string, payload?: Record<string, unknown>): void;
}

interface PendingRequest {
	responseType: string;
	resolve: (value: unknown) => void;
	reject: (reason: Error) => void;
	timer: ReturnType<typeof setTimeout>;
}

/** MAIN-world side: request/response correlation over an established port. */
export function createMainChannel(port: MessagePort): MainChannel {
	const pending = new Map<string, PendingRequest>();

	port.onmessage = (event: MessageEvent) => {
		const msg = event.data as BridgeMessage | undefined;
		if (!msg || typeof msg.requestId !== 'string') return;
		const entry = pending.get(msg.requestId);
		if (!entry) return;
		// Correlation requires BOTH the requestId AND the expected response type.
		if (msg.type !== entry.responseType) return;
		clearTimeout(entry.timer);
		pending.delete(msg.requestId);
		entry.resolve((msg as { result?: unknown }).result);
	};
	port.start?.();

	return {
		request<T>(
			requestType: string,
			responseType: string,
			payload: Record<string, unknown>,
			timeoutMs = 10000,
		): Promise<T> {
			return new Promise<T>((resolve, reject) => {
				const requestId = crypto.randomUUID();
				const timer = setTimeout(() => {
					pending.delete(requestId);
					reject(new Error(`${requestType} timeout`));
				}, timeoutMs);
				pending.set(requestId, {
					responseType,
					resolve: resolve as (value: unknown) => void,
					reject,
					timer,
				});
				port.postMessage({ type: requestType, requestId, ...payload });
			});
		},

		post(type: string, payload: Record<string, unknown> = {}): void {
			port.postMessage({ type, requestId: crypto.randomUUID(), ...payload });
		},
	};
}

/** ISOLATED-world side: dispatch each inbound request to `onRequest`. */
export function attachIsolatedPort(port: MessagePort, onRequest: RequestHandler): void {
	const reply: RequestReply = (responseType, requestId, result) => {
		port.postMessage({ type: responseType, requestId, result });
	};
	port.onmessage = (event: MessageEvent) => {
		const msg = event.data as BridgeMessage | undefined;
		if (!msg || typeof msg.type !== 'string' || typeof msg.requestId !== 'string') return;
		onRequest(msg, reply);
	};
	port.start?.();
}

/**
 * MAIN world: resolve once the ISOLATED world transfers the private port.
 * Never throws — if the bridge never connects the promise simply stays pending,
 * and callers MUST apply their own timeout (fail-secure), never fail-open.
 */
export function connectMainBridge(): Promise<MainChannel> {
	return new Promise<MainChannel>((resolve) => {
		const announce = () => document.dispatchEvent(new CustomEvent(BRIDGE_EVENTS.MAIN_READY));

		const onMessage = (event: MessageEvent) => {
			if (event.source !== window) return;
			const data = event.data as { source?: string; type?: string } | undefined;
			if (data?.source !== 'testudo' || data.type !== PORT_TRANSFER) return;
			const port = event.ports?.[0];
			if (!port) return;
			window.removeEventListener('message', onMessage);
			document.removeEventListener(BRIDGE_EVENTS.ISO_READY, announce);
			resolve(createMainChannel(port));
		};

		window.addEventListener('message', onMessage);
		// If the ISOLATED script announces after us, re-announce so it transfers the port.
		document.addEventListener(BRIDGE_EVENTS.ISO_READY, announce);
		// Announce immediately in case the ISOLATED script is already listening.
		announce();
	});
}

/**
 * ISOLATED world: create the channel, keep port1, and transfer port2 to MAIN
 * exactly once when MAIN announces readiness. The transfer happens at
 * document_start before page scripts exist, so the page cannot grab the port.
 */
export function acceptIsolatedBridge(onRequest: RequestHandler): void {
	const { port1, port2 } = new MessageChannel();
	attachIsolatedPort(port1, onRequest);

	let transferred = false;
	const transfer = () => {
		if (transferred) return;
		transferred = true;
		document.removeEventListener(BRIDGE_EVENTS.MAIN_READY, transfer);
		window.postMessage({ source: 'testudo', type: PORT_TRANSFER }, window.location.origin, [port2]);
	};
	document.addEventListener(BRIDGE_EVENTS.MAIN_READY, transfer);
	// Announce readiness in case MAIN is already waiting.
	document.dispatchEvent(new CustomEvent(BRIDGE_EVENTS.ISO_READY));
}
