/**
 * CONTENT SCRIPT (ISOLATED world)
 *
 * Bridges communication between:
 * - The MAIN-world injected script, over a private MessagePort (ADR-016).
 *   injected.js is declared as a MAIN-world content script in the manifest, so
 *   this script no longer DOM-injects it.
 * - The background service worker, via chrome.runtime.sendMessage.
 *
 * Also injects the warning-modal fonts and runs the navigation-time phishing check.
 */

import { acceptIsolatedBridge, type BridgeMessage, type RequestReply } from './services/channel';
import { MessageTypes } from './utils/message-types';

// Layer A+ & B: Phishing domain check (top-level frame only)
if (window === window.top) {
	checkPhishingDomain();
}

async function checkPhishingDomain(): Promise<void> {
	const url = window.location.href;
	if (url.startsWith('chrome-extension://') || url.startsWith('about:')) return;

	try {
		const hostname = window.location.hostname.toLowerCase().replace(/^www\./, '');

		// Layer A+: Ask background to check bloom filter
		const response = await chrome.runtime.sendMessage({
			type: 'TESTUDO_CHECK_DOMAIN_BLOOM',
			hostname,
		});

		if (response?.inBloom) {
			injectPhishingOverlay(hostname);
		}

		// Layer B: Async API check for zero-day domains
		chrome.runtime.sendMessage({
			type: 'TESTUDO_CHECK_DOMAIN_API',
			hostname,
			url,
		});
	} catch {
		// Extension context invalidated — fail silently
	}
}

function injectPhishingOverlay(domain: string): void {
	const overlay = document.createElement('div');
	overlay.id = 'testudo-phishing-block';
	overlay.style.cssText = `
    position: fixed; inset: 0; z-index: 2147483647;
    background: #07070c; color: #f0f0f5;
    display: flex; align-items: center; justify-content: center;
    font-family: monospace; font-size: 16px;
  `;
	overlay.textContent = `[TESTUDO] Phishing domain blocked: ${domain}. Verifying...`;
	document.documentElement.appendChild(overlay);
}

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
  font-family: 'Geist';
  font-style: normal;
  font-weight: 300 700;
  font-display: swap;
  src: url(${base}geist-latin.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: 'Geist';
  font-style: normal;
  font-weight: 300 700;
  font-display: swap;
  src: url(${base}geist-latin-ext.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}
@font-face {
  font-family: 'Geist Mono';
  font-style: normal;
  font-weight: 400 600;
  font-display: swap;
  src: url(${base}geist-mono-latin.woff2) format('woff2');
  unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
}
@font-face {
  font-family: 'Geist Mono';
  font-style: normal;
  font-weight: 400 600;
  font-display: swap;
  src: url(${base}geist-mono-latin-ext.woff2) format('woff2');
  unicode-range: U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+0304, U+0308, U+0329, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF;
}`;
	(document.head || document.documentElement).appendChild(style);
}

// injected.js is declared as a MAIN-world content script in the manifest (ADR-016),
// so the browser injects it at document_start — no DOM <script> tag, no nonce
// handshake. The content script only injects the shared fonts the warning modal
// reads from the page DOM.
injectFonts();

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

// Bridge requests from the MAIN-world injected script to the background worker,
// over the private MessagePort established by acceptIsolatedBridge (ADR-016).
async function handleBridgeRequest(msg: BridgeMessage, reply: RequestReply): Promise<void> {
	const { requestId } = msg;

	switch (msg.type) {
		case MessageTypes.ANALYZE_REQUEST: {
			const delegateAddress = msg.delegateAddress as string;
			const chainId = typeof msg.chainId === 'number' ? msg.chainId : undefined;
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
					chainId,
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
			const chainId = typeof msg.chainId === 'number' ? msg.chainId : undefined;
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
				const result = await chrome.runtime.sendMessage({
					type: 'CHECK_ADDRESS',
					address,
					chainId,
				});
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
}

acceptIsolatedBridge(handleBridgeRequest);

// Listen for messages from background script (e.g., for popup updates)
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message.type === 'GET_PAGE_STATUS') {
		sendResponse({ active: true, url: window.location.href });
	}
});
