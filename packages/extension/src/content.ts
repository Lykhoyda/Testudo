/**
 * CONTENT SCRIPT
 *
 * Runs in isolated content script context.
 * Bridges communication between:
 * - Injected script (page context) via CustomEvent channel (nonce-gated)
 * - Background script (extension context) via chrome.runtime.sendMessage
 *
 * Also responsible for injecting the injected.js script into the page.
 */

import { createChannel } from './services/channel';
import { MessageTypes } from './utils/message-types';

// Inject bundled fonts into the page so the warning modal can use them
function injectFonts() {
	const style = document.createElement('style');
	style.id = 'testudo-fonts';
	const base = chrome.runtime.getURL('fonts/');
	style.textContent = `
@font-face {
  font-family: 'Material Symbols Outlined';
  font-style: normal;
  font-weight: 100 700;
  font-display: swap;
  src: url(${base}material-symbols-outlined.woff2) format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400 700;
  font-display: swap;
  src: url(${base}inter-latin-ext.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400 700;
  font-display: swap;
  src: url(${base}inter-latin.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: 'Roboto Mono';
  font-style: normal;
  font-weight: 400 500;
  font-display: swap;
  src: url(${base}roboto-mono-latin.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}`;
	(document.head || document.documentElement).appendChild(style);
}

// Inject the injected.js script into the page with a nonce for secure channel
function injectScript(): string {
	const nonce = crypto.randomUUID();
	const script = document.createElement('script');
	script.src = chrome.runtime.getURL('injected.js');
	script.type = 'module';
	script.dataset.testudoNonce = nonce;

	// Insert at document_start to ensure we intercept before any dApp code runs
	(document.head || document.documentElement).appendChild(script);

	script.onload = () => {
		script.remove(); // Clean up after injection
	};

	return nonce;
}

// Inject immediately
injectFonts();
const nonce = injectScript();

// Fire-and-forget wake-up ping — pre-warms the SW on every page load
chrome.runtime.sendMessage({ type: 'HEARTBEAT' }).catch(() => {});

// Keep SW alive on known dApp domains via periodic heartbeat
const DAPP_DOMAINS = [
	'app.uniswap.org',
	'opensea.io',
	'blur.io',
	'lido.fi',
	'curve.fi',
	'app.1inch.io',
	'pancakeswap.finance',
	'app.aave.com',
	'raydium.io',
	'app.sushi.com',
];
const HEARTBEAT_MS = 20_000;

if (DAPP_DOMAINS.some((d) => location.hostname === d || location.hostname.endsWith(`.${d}`))) {
	const heartbeatId = setInterval(() => {
		chrome.runtime.sendMessage({ type: 'HEARTBEAT' }).catch(() => clearInterval(heartbeatId));
	}, HEARTBEAT_MS);
}

// Set up nonce-gated channel to communicate with injected script
function initChannel(channelNonce: string) {
	const channel = createChannel(channelNonce);

	function reply(type: string, requestId: string, result: unknown) {
		channel.sendResponse({ type, requestId, result });
	}

	channel.onRequest(async (msg) => {
		const { requestId } = msg;

		switch (msg.type) {
			case MessageTypes.ANALYZE_REQUEST: {
				const delegateAddress = msg.delegateAddress as string;
				if (!/^0x[a-fA-F0-9]{40}$/.test(delegateAddress)) {
					reply(MessageTypes.ANALYZE_RESULT, requestId, {
						risk: 'UNKNOWN',
						threats: [],
						address: delegateAddress,
					});
					return;
				}
				try {
					const result = await chrome.runtime.sendMessage({
						type: 'ANALYZE_DELEGATION',
						delegateAddress,
					});
					reply(MessageTypes.ANALYZE_RESULT, requestId, result);
				} catch (error) {
					reply(MessageTypes.ANALYZE_RESULT, requestId, {
						risk: 'UNKNOWN',
						threats: [],
						address: delegateAddress,
						error: String(error),
					});
				}
				break;
			}

			case MessageTypes.CHECK_ADDRESS: {
				const address = msg.address as string;
				if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
					reply(MessageTypes.ADDRESS_CHECK_RESULT, requestId, {
						risk: 'UNKNOWN',
						threats: [],
						address,
						blocked: false,
					});
					return;
				}
				try {
					const result = await chrome.runtime.sendMessage({ type: 'CHECK_ADDRESS', address });
					reply(MessageTypes.ADDRESS_CHECK_RESULT, requestId, result);
				} catch {
					reply(MessageTypes.ADDRESS_CHECK_RESULT, requestId, {
						risk: 'UNKNOWN',
						threats: [],
						address,
						blocked: false,
					});
				}
				break;
			}

			case MessageTypes.RESOLVE_TOKEN: {
				const address = msg.address as string;
				const nullResult = { name: null, symbol: null, decimals: null };
				if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
					reply(MessageTypes.TOKEN_RESULT, requestId, nullResult);
					return;
				}
				chrome.runtime
					.sendMessage({ type: 'RESOLVE_TOKEN', address })
					.then((result) => reply(MessageTypes.TOKEN_RESULT, requestId, result ?? nullResult))
					.catch(() => reply(MessageTypes.TOKEN_RESULT, requestId, nullResult));
				break;
			}

			case MessageTypes.GET_SETTINGS: {
				chrome.runtime
					.sendMessage({ type: 'GET_SETTINGS' })
					.then((result) => reply(MessageTypes.SETTINGS_RESULT, requestId, result ?? {}))
					.catch(() => reply(MessageTypes.SETTINGS_RESULT, requestId, {}));
				break;
			}

			case MessageTypes.RECORD_BLOCKED: {
				chrome.runtime.sendMessage({ type: 'RECORD_BLOCKED' }).catch(() => {});
				break;
			}
		}
	});
}

initChannel(nonce);

// Listen for messages from background script (e.g., for popup updates)
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message.type === 'GET_PAGE_STATUS') {
		sendResponse({ active: true, url: window.location.href });
	}
});
