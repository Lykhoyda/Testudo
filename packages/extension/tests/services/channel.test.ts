// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	acceptIsolatedBridge,
	attachIsolatedPort,
	BRIDGE_EVENTS,
	connectMainBridge,
	createMainChannel,
	type RequestHandler,
} from '../../src/services/channel';

/**
 * A linked pair of fake MessagePorts that deliver messages to each other
 * asynchronously (microtask), mirroring real MessagePort semantics. Lets us
 * exercise the request/response correlation logic deterministically without
 * relying on jsdom's transferable support.
 */
function linkedPorts(): readonly [MessagePort, MessagePort] {
	const a = { start() {} } as unknown as MessagePort & {
		onmessage: ((e: { data: unknown }) => void) | null;
	};
	const b = { start() {} } as unknown as MessagePort & {
		onmessage: ((e: { data: unknown }) => void) | null;
	};
	a.postMessage = ((data: unknown) =>
		queueMicrotask(() => b.onmessage?.({ data }))) as MessagePort['postMessage'];
	b.postMessage = ((data: unknown) =>
		queueMicrotask(() => a.onmessage?.({ data }))) as MessagePort['postMessage'];
	return [a, b] as const;
}

describe('createMainChannel + attachIsolatedPort (port-backed channel)', () => {
	it('round-trips a request to a matching response by requestId + type', async () => {
		const [mainPort, isoPort] = linkedPorts();
		const main = createMainChannel(mainPort);
		attachIsolatedPort(isoPort, (msg, reply) => {
			reply('RES', msg.requestId, { ok: true, echo: msg.value });
		});

		const result = await main.request<{ ok: boolean; echo: unknown }>('REQ', 'RES', { value: 42 });
		expect(result).toEqual({ ok: true, echo: 42 });
	});

	it('correlates concurrent requests even when responses arrive out of order', async () => {
		const [mainPort, isoPort] = linkedPorts();
		const main = createMainChannel(mainPort);
		const pending: Array<{ requestId: string; value: unknown }> = [];
		attachIsolatedPort(isoPort, (msg) => {
			pending.push({ requestId: msg.requestId, value: msg.value });
		});

		const p1 = main.request<number>('REQ', 'RES', { value: 'a' });
		const p2 = main.request<number>('REQ', 'RES', { value: 'b' });

		// Flush so both requests reach the isolated side.
		await Promise.resolve();
		await Promise.resolve();
		expect(pending).toHaveLength(2);

		// Reply to the SECOND request first, then the first.
		isoPort.postMessage({ type: 'RES', requestId: pending[1].requestId, result: 'B' });
		isoPort.postMessage({ type: 'RES', requestId: pending[0].requestId, result: 'A' });

		expect(await p1).toBe('A');
		expect(await p2).toBe('B');
	});

	it('ignores a response whose type does not match the expected responseType', async () => {
		const [mainPort, isoPort] = linkedPorts();
		const main = createMainChannel(mainPort);
		attachIsolatedPort(isoPort, (msg, reply) => {
			// Wrong response type — must NOT resolve the request (forgery/mismatch guard).
			reply('WRONG_TYPE', msg.requestId, 'leaked');
		});

		vi.useFakeTimers();
		const p = main.request('REQ', 'RES', {}, 100);
		const assertion = expect(p).rejects.toThrow(/timeout/i);
		await vi.advanceTimersByTimeAsync(150);
		await assertion;
		vi.useRealTimers();
	});

	it('rejects a request after the timeout when no response arrives', async () => {
		const [mainPort] = linkedPorts();
		const main = createMainChannel(mainPort);

		vi.useFakeTimers();
		const p = main.request('REQ', 'RES', {}, 100);
		const assertion = expect(p).rejects.toThrow(/timeout/i);
		await vi.advanceTimersByTimeAsync(150);
		await assertion;
		vi.useRealTimers();
	});

	it('post() delivers a fire-and-forget message (no response expected)', async () => {
		const [mainPort, isoPort] = linkedPorts();
		const main = createMainChannel(mainPort);
		const received: unknown[] = [];
		attachIsolatedPort(isoPort, (msg) => received.push(msg));

		main.post('RECORD_BLOCKED');
		await Promise.resolve();
		await Promise.resolve();

		expect(received).toHaveLength(1);
		expect((received[0] as { type: string }).type).toBe('RECORD_BLOCKED');
	});
});

describe('bridge handshake wiring (order-resilient, no nonce)', () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('connectMainBridge announces MAIN_READY on start and again when ISOLATED announces', () => {
		const dispatched: string[] = [];
		const orig = document.dispatchEvent.bind(document);
		vi.spyOn(document, 'dispatchEvent').mockImplementation((e: Event) => {
			dispatched.push(e.type);
			return orig(e);
		});

		connectMainBridge();
		expect(dispatched).toContain(BRIDGE_EVENTS.MAIN_READY);

		dispatched.length = 0;
		// Simulate the ISOLATED side announcing readiness after MAIN.
		document.dispatchEvent(new CustomEvent(BRIDGE_EVENTS.ISO_READY));
		expect(dispatched).toContain(BRIDGE_EVENTS.MAIN_READY);
	});

	it('acceptIsolatedBridge announces ISO_READY and transfers a port on MAIN_READY', () => {
		const postSpy = vi.spyOn(window, 'postMessage').mockImplementation(() => {});
		const dispatched: string[] = [];
		const orig = document.dispatchEvent.bind(document);
		vi.spyOn(document, 'dispatchEvent').mockImplementation((e: Event) => {
			dispatched.push(e.type);
			return orig(e);
		});

		const handler: RequestHandler = () => {};
		acceptIsolatedBridge(handler);
		expect(dispatched).toContain(BRIDGE_EVENTS.ISO_READY);

		// MAIN announces → ISOLATED must transfer exactly one MessagePort.
		document.dispatchEvent(new CustomEvent(BRIDGE_EVENTS.MAIN_READY));
		expect(postSpy).toHaveBeenCalledTimes(1);
		const transfer = postSpy.mock.calls[0][2] as Transferable[] | undefined;
		expect(Array.isArray(transfer)).toBe(true);
		expect(transfer).toHaveLength(1);

		// A second MAIN_READY must NOT transfer another port (single handoff).
		document.dispatchEvent(new CustomEvent(BRIDGE_EVENTS.MAIN_READY));
		expect(postSpy).toHaveBeenCalledTimes(1);
	});
});
