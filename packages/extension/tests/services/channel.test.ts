// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createChannel, readNonce } from '../../src/services/channel';

describe('createChannel', () => {
	const nonce = 'test-nonce-abc';

	it('throws when nonce is empty', () => {
		expect(() => createChannel('')).toThrow('Channel nonce is empty');
	});

	it('sendRequest dispatches CustomEvent on document with correct event name', () => {
		const spy = vi.fn();
		document.addEventListener(`testudo-req-${nonce}`, spy);

		const channel = createChannel(nonce);
		channel.sendRequest({ type: 'TEST', requestId: '1' });

		expect(spy).toHaveBeenCalledOnce();
		const event = spy.mock.calls[0][0] as CustomEvent;
		expect(event.detail).toEqual({ type: 'TEST', requestId: '1' });
		expect(event.bubbles).toBe(false);
		expect(event.cancelable).toBe(false);

		document.removeEventListener(`testudo-req-${nonce}`, spy);
	});

	it('sendResponse dispatches CustomEvent on response event name', () => {
		const spy = vi.fn();
		document.addEventListener(`testudo-res-${nonce}`, spy);

		const channel = createChannel(nonce);
		channel.sendResponse({ type: 'RESULT', requestId: '2', data: 42 });

		expect(spy).toHaveBeenCalledOnce();
		expect((spy.mock.calls[0][0] as CustomEvent).detail).toEqual({
			type: 'RESULT',
			requestId: '2',
			data: 42,
		});

		document.removeEventListener(`testudo-res-${nonce}`, spy);
	});

	it('onRequest receives messages sent via sendRequest', () => {
		const channel = createChannel(nonce);
		const received: unknown[] = [];
		const unsub = channel.onRequest((msg) => received.push(msg));

		channel.sendRequest({ type: 'A', requestId: '1' });
		channel.sendRequest({ type: 'B', requestId: '2' });

		expect(received).toEqual([
			{ type: 'A', requestId: '1' },
			{ type: 'B', requestId: '2' },
		]);

		unsub();
	});

	it('onResponse receives messages sent via sendResponse', () => {
		const channel = createChannel(nonce);
		const received: unknown[] = [];
		const unsub = channel.onResponse((msg) => received.push(msg));

		channel.sendResponse({ type: 'R', requestId: '3' });

		expect(received).toHaveLength(1);
		expect(received[0]).toEqual({ type: 'R', requestId: '3' });

		unsub();
	});

	it('unsubscribe stops receiving messages', () => {
		const channel = createChannel(nonce);
		const received: unknown[] = [];
		const unsub = channel.onRequest((msg) => received.push(msg));

		channel.sendRequest({ type: 'BEFORE', requestId: '1' });
		unsub();
		channel.sendRequest({ type: 'AFTER', requestId: '2' });

		expect(received).toHaveLength(1);
		expect(received[0]).toEqual({ type: 'BEFORE', requestId: '1' });
	});

	it('different nonces create isolated channels', () => {
		const channelA = createChannel('nonce-a');
		const channelB = createChannel('nonce-b');

		const receivedA: unknown[] = [];
		const receivedB: unknown[] = [];
		const unsubA = channelA.onRequest((msg) => receivedA.push(msg));
		const unsubB = channelB.onRequest((msg) => receivedB.push(msg));

		channelA.sendRequest({ type: 'FOR_A', requestId: '1' });
		channelB.sendRequest({ type: 'FOR_B', requestId: '2' });

		expect(receivedA).toHaveLength(1);
		expect(receivedA[0]).toEqual({ type: 'FOR_A', requestId: '1' });
		expect(receivedB).toHaveLength(1);
		expect(receivedB[0]).toEqual({ type: 'FOR_B', requestId: '2' });

		unsubA();
		unsubB();
	});

	it('request events do not trigger response handlers and vice versa', () => {
		const channel = createChannel(nonce);
		const reqMsgs: unknown[] = [];
		const resMsgs: unknown[] = [];
		const unsub1 = channel.onRequest((msg) => reqMsgs.push(msg));
		const unsub2 = channel.onResponse((msg) => resMsgs.push(msg));

		channel.sendRequest({ type: 'REQ', requestId: '1' });
		channel.sendResponse({ type: 'RES', requestId: '2' });

		expect(reqMsgs).toHaveLength(1);
		expect(resMsgs).toHaveLength(1);
		expect(reqMsgs[0]).toEqual({ type: 'REQ', requestId: '1' });
		expect(resMsgs[0]).toEqual({ type: 'RES', requestId: '2' });

		unsub1();
		unsub2();
	});
});

describe('readNonce', () => {
	afterEach(() => {
		for (const el of document.querySelectorAll('script[data-testudo-nonce]')) {
			el.remove();
		}
	});

	it('reads nonce from script element and deletes the attribute', () => {
		const script = document.createElement('script');
		script.dataset.testudoNonce = 'secret-123';
		document.head.appendChild(script);

		const result = readNonce();

		expect(result).toBe('secret-123');
		expect(script.dataset.testudoNonce).toBeUndefined();
	});

	it('returns empty string when no script element exists', () => {
		expect(readNonce()).toBe('');
	});

	it('returns empty string on second call (nonce consumed)', () => {
		const script = document.createElement('script');
		script.dataset.testudoNonce = 'one-time';
		document.head.appendChild(script);

		readNonce();
		const second = readNonce();

		expect(second).toBe('');
	});
});
