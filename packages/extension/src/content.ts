/**
 * CONTENT SCRIPT
 *
 * Runs in isolated content script context.
 * Bridges communication between:
 * - Injected script (page context) via window.postMessage
 * - Background script (extension context) via chrome.runtime.sendMessage
 *
 * Also responsible for injecting the injected.js script into the page.
 */

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

// Inject the injected.js script into the page
function injectScript() {
	const script = document.createElement('script');
	script.src = chrome.runtime.getURL('injected.js');
	script.type = 'module';

	// Insert at document_start to ensure we intercept before any dApp code runs
	(document.head || document.documentElement).appendChild(script);

	script.onload = () => {
		script.remove(); // Clean up after injection
	};
}

// Inject immediately
injectFonts();
injectScript();

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

// Listen for messages from injected script
window.addEventListener('message', async (event) => {
	// Only accept messages from same window
	if (event.source !== window) return;

	// Handle analysis request
	if (event.data?.type === 'TESTUDO_ANALYZE_REQUEST') {
		const { requestId, delegateAddress } = event.data;

		console.log('[Testudo Content] Received analysis request:', delegateAddress);

		try {
			// Send to background script for analysis
			const result = await chrome.runtime.sendMessage({
				type: 'ANALYZE_DELEGATION',
				delegateAddress,
			});

			console.log('[Testudo Content] Analysis result:', result);

			// Send result back to injected script
			window.postMessage(
				{
					type: 'TESTUDO_ANALYSIS_RESULT',
					requestId,
					result,
				},
				window.location.origin,
			);
		} catch (error) {
			console.error('[Testudo Content] Analysis error:', error);

			// Send error result
			window.postMessage(
				{
					type: 'TESTUDO_ANALYSIS_RESULT',
					requestId,
					result: {
						risk: 'UNKNOWN',
						threats: [],
						address: delegateAddress,
						error: String(error),
					},
				},
				window.location.origin,
			);
		}
	}

	// Handle address check request (eth_sendTransaction)
	if (event.data?.type === 'TESTUDO_CHECK_ADDRESS') {
		const { requestId, address } = event.data;

		if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
			window.postMessage(
				{
					type: 'TESTUDO_ADDRESS_CHECK_RESULT',
					requestId,
					result: {
						risk: 'UNKNOWN',
						threats: [],
						address,
						blocked: false,
					},
				},
				window.location.origin,
			);
			return;
		}

		try {
			const result = await chrome.runtime.sendMessage({
				type: 'CHECK_ADDRESS',
				address,
			});

			window.postMessage(
				{
					type: 'TESTUDO_ADDRESS_CHECK_RESULT',
					requestId,
					result,
				},
				window.location.origin,
			);
		} catch (error) {
			console.error('[Testudo Content] Address check error:', error);
			window.postMessage(
				{
					type: 'TESTUDO_ADDRESS_CHECK_RESULT',
					requestId,
					result: {
						risk: 'UNKNOWN',
						threats: [],
						address,
						blocked: false,
					},
				},
				window.location.origin,
			);
		}
	}

	// Handle token resolution request (runs in background to avoid CSP)
	if (event.data?.type === 'TESTUDO_RESOLVE_TOKEN') {
		const { requestId, address } = event.data;
		const nullResult = { name: null, symbol: null, decimals: null };

		if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
			window.postMessage(
				{ type: 'TESTUDO_TOKEN_RESULT', requestId, result: nullResult },
				window.location.origin,
			);
			return;
		}

		chrome.runtime
			.sendMessage({ type: 'RESOLVE_TOKEN', address })
			.then((result) => {
				window.postMessage(
					{ type: 'TESTUDO_TOKEN_RESULT', requestId, result: result ?? nullResult },
					window.location.origin,
				);
			})
			.catch(() => {
				window.postMessage(
					{ type: 'TESTUDO_TOKEN_RESULT', requestId, result: nullResult },
					window.location.origin,
				);
			});
	}

	// Handle settings request
	if (event.data?.type === 'TESTUDO_GET_SETTINGS') {
		const { requestId } = event.data;
		chrome.runtime
			.sendMessage({ type: 'GET_SETTINGS' })
			.then((result) => {
				window.postMessage(
					{ type: 'TESTUDO_SETTINGS_RESULT', requestId, result: result ?? {} },
					window.location.origin,
				);
			})
			.catch(() => {
				window.postMessage(
					{ type: 'TESTUDO_SETTINGS_RESULT', requestId, result: {} },
					window.location.origin,
				);
			});
	}

	// Handle blocked record
	if (event.data?.type === 'TESTUDO_RECORD_BLOCKED') {
		console.log('[Testudo Content] Recording blocked delegation');
		await chrome.runtime.sendMessage({ type: 'RECORD_BLOCKED' });
	}
});

// Listen for messages from background script (e.g., for popup updates)
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
	if (message.type === 'GET_PAGE_STATUS') {
		// Could be used by popup to show current page status
		sendResponse({
			active: true,
			url: window.location.href,
		});
	}
	return true;
});

console.log('[Testudo Content] Content script loaded');

export {};
