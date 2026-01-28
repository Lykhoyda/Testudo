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
injectScript();

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
				'*',
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
				'*',
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
				'*',
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
				'*',
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
				'*',
			);
		}
	}

	// Handle blocked record
	if (event.data?.type === 'TESTUDO_RECORD_BLOCKED') {
		console.log('[Testudo Content] Recording blocked delegation');
		await chrome.runtime.sendMessage({ type: 'RECORD_BLOCKED' });
	}

	// Handle whitelist request from modal
	if (event.data?.type === 'TESTUDO_WHITELIST_REQUEST') {
		const { requestId, address, label } = event.data;

		console.log('[Testudo Content] Whitelist request:', address);

		// Validate address format (security)
		if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
			window.postMessage(
				{
					type: 'TESTUDO_WHITELIST_RESULT',
					requestId,
					success: false,
				},
				'*',
			);
			return;
		}

		// Send to background - URL will be derived from sender.tab (security)
		chrome.runtime
			.sendMessage({
				type: 'WHITELIST_FROM_MODAL',
				address: address.toLowerCase(),
				label,
			})
			.then((response) => {
				window.postMessage(
					{
						type: 'TESTUDO_WHITELIST_RESULT',
						requestId,
						success: response?.success ?? false,
					},
					'*',
				);
			})
			.catch(() => {
				window.postMessage(
					{
						type: 'TESTUDO_WHITELIST_RESULT',
						requestId,
						success: false,
					},
					'*',
				);
			});
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
