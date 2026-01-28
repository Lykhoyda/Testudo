/**
 * INJECTED SCRIPT
 *
 * This script runs in the PAGE context (not extension context).
 * It intercepts window.ethereum.request calls to detect EIP-7702 authorization requests.
 *
 * Flow:
 * 1. Wrap window.ethereum.request
 * 2. Detect eth_signTypedData_v4 with Authorization type
 * 3. Send delegate address to content script for analysis
 * 4. Wait for risk assessment
 * 5. Block or allow based on result
 */

import type { Warning } from '@testudo/core';

interface EIP7702Authorization {
	chainId: string;
	address: string; // The delegate contract address - THIS IS WHAT WE ANALYZE
	nonce: string;
}

interface TypedDataMessage {
	types: {
		Authorization?: unknown;
		[key: string]: unknown;
	};
	primaryType: string;
	domain: unknown;
	message: EIP7702Authorization;
}

interface AnalysisResult {
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
	warnings?: Warning[];
	address: string;
	blocked: boolean;
}

// Inject Google Fonts for Material Symbols
function injectFonts(): void {
	if (!document.getElementById('testudo-fonts')) {
		const link = document.createElement('link');
		link.id = 'testudo-fonts';
		link.rel = 'stylesheet';
		link.href =
			'https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&family=Inter:wght@400;500;600;700&family=Roboto+Mono:wght@400;500&display=swap';
		document.head.appendChild(link);
	}
}

// Track if we've already wrapped the provider
let providerWrapped = false;

/**
 * Wrap the ethereum provider's request method
 */
function wrapEthereumProvider(): void {
	if (providerWrapped || typeof window.ethereum === 'undefined') {
		return;
	}

	console.log('[Testudo] 🛡️ Initializing EIP-7702 protection...');
	providerWrapped = true;

	injectFonts();

	const originalRequest = window.ethereum.request.bind(window.ethereum);

	// Wrap the request method
	// Use try/catch to handle frozen provider objects (Object.freeze)
	try {
		window.ethereum.request = async (args: { method: string; params?: unknown[] }) => {
			// Intercept eth_sendTransaction
			if (args.method === 'eth_sendTransaction') {
				try {
					const txParams = (args.params as Record<string, string>[])?.[0];
					const toAddress = txParams?.to;

					if (toAddress && /^0x[a-fA-F0-9]{40}$/.test(toAddress)) {
						const analysis = await requestAddressCheck(toAddress);

						if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
							const userConfirmed = await showWarning(analysis, 'transaction');

							if (!userConfirmed) {
								throw new Error(
									'Testudo: Transaction blocked by user - malicious recipient detected',
								);
							}
						}
					}

					return originalRequest(args);
				} catch (error) {
					if (error instanceof Error && error.message.includes('Testudo')) {
						throw error;
					}
					console.error('[Testudo] Error checking transaction:', error);
					return originalRequest(args);
				}
			}

			// Only intercept eth_signTypedData_v4 for EIP-7702
			if (args.method !== 'eth_signTypedData_v4') {
				return originalRequest(args);
			}

			try {
				// Parse the typed data
				const params = args.params as [string, string];
				const typedDataString = params[1];
				const typedData: TypedDataMessage =
					typeof typedDataString === 'string' ? JSON.parse(typedDataString) : typedDataString;

				// Check if this is an EIP-7702 Authorization
				if (!isEIP7702Authorization(typedData)) {
					return originalRequest(args);
				}

				console.log('[Testudo] 🔍 EIP-7702 authorization detected!');
				console.log('[Testudo] Delegate address:', typedData.message.address);

				// Request analysis from background script
				const analysis = await requestAnalysis(typedData.message.address);

				console.log('[Testudo] Analysis result:', analysis);

				// Handle based on risk level
				if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
					// Show warning and potentially block
					const userConfirmed = await showWarning(analysis);

					if (!userConfirmed) {
						console.log('[Testudo] ❌ User rejected dangerous delegation');
						throw new Error('Testudo: Delegation blocked by user - dangerous contract detected');
					}

					console.log('[Testudo] ⚠️ User proceeded despite warning');
				} else if (analysis.risk === 'MEDIUM') {
					// Show info but don't block
					showInfo(analysis);
				} else if (analysis.risk === 'UNKNOWN') {
					// Show notice for contracts with no bytecode
					showUnknownNotice(analysis);
				}

				// Allow the signature to proceed
				return originalRequest(args);
			} catch (error) {
				// If it's our block, re-throw
				if (error instanceof Error && error.message.includes('Testudo')) {
					throw error;
				}

				// DESIGN DECISION: Fail-open on parse/analysis errors
				// Rationale: For a security tool wrapping third-party functionality,
				// breaking legitimate dApps would cause users to uninstall the extension,
				// leaving them with NO protection. It's better to allow edge cases through
				// (with logging) than to block all functionality on unexpected errors.
				// The core security path (detected threats) still blocks correctly.
				console.error('[Testudo] Error analyzing request:', error);
				return originalRequest(args);
			}
		};
	} catch (wrapError) {
		// Provider object may be frozen (Object.freeze) or have non-configurable properties
		// Fail-open: Allow original requests rather than breaking dApp functionality
		console.error('[Testudo] Failed to wrap provider (frozen object?):', wrapError);
		providerWrapped = false; // Reset so we don't think we're protected
		return;
	}

	console.log('[Testudo] ✅ Protection active');
}

// Store reference to the current wrapped provider to detect replacements
let wrappedProvider: Window['ethereum'];

// Try to wrap immediately if provider exists
if (typeof window.ethereum !== 'undefined') {
	wrappedProvider = window.ethereum;
}
wrapEthereumProvider();

// ALWAYS set up the property trap to catch provider replacements
let ethereumValue: Window['ethereum'] = window.ethereum;

Object.defineProperty(window, 'ethereum', {
	configurable: true,
	enumerable: true,
	get() {
		return ethereumValue;
	},
	set(value) {
		// Check if this is a new provider (not our wrapped version)
		if (value !== ethereumValue && value !== wrappedProvider) {
			ethereumValue = value;
			providerWrapped = false; // Reset so we can wrap the new provider
			wrappedProvider = value;
			wrapEthereumProvider();
		} else {
			ethereumValue = value;
		}
	},
});

/**
 * Check if typed data is an EIP-7702 Authorization
 */
function isEIP7702Authorization(typedData: TypedDataMessage): boolean {
	// Check for Authorization type in types
	if (!typedData.types?.Authorization) {
		return false;
	}

	// Check primaryType
	if (typedData.primaryType !== 'Authorization') {
		return false;
	}

	// Check message has required fields
	if (!typedData.message?.address) {
		return false;
	}

	return true;
}

/**
 * Generic message passing helper for content script communication
 */
function sendTestudoRequest<T>(
	requestType: string,
	responseType: string,
	payload: Record<string, unknown>,
	timeoutMs = 10000,
): Promise<T> {
	return new Promise((resolve, reject) => {
		const requestId = Math.random().toString(36).substring(7);

		const handler = (event: MessageEvent) => {
			if (event.data?.type === responseType && event.data?.requestId === requestId) {
				window.removeEventListener('message', handler);
				resolve(event.data.result);
			}
		};

		window.addEventListener('message', handler);

		window.postMessage({ type: requestType, requestId, ...payload }, '*');

		setTimeout(() => {
			window.removeEventListener('message', handler);
			reject(new Error(`${requestType} timeout`));
		}, timeoutMs);
	});
}

/**
 * Send address check request to content script → background script (for eth_sendTransaction)
 */
function requestAddressCheck(address: string): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>(
		'TESTUDO_CHECK_ADDRESS',
		'TESTUDO_ADDRESS_CHECK_RESULT',
		{ address },
	);
}

/**
 * Send analysis request to content script → background script
 */
function requestAnalysis(delegateAddress: string): Promise<AnalysisResult> {
	return sendTestudoRequest<AnalysisResult>('TESTUDO_ANALYZE_REQUEST', 'TESTUDO_ANALYSIS_RESULT', {
		delegateAddress,
	});
}

/**
 * Notify content script that user blocked a delegation
 */
function recordBlocked(): void {
	window.postMessage({ type: 'TESTUDO_RECORD_BLOCKED' }, '*');
}

/**
 * Request to whitelist an address from the modal
 */
function requestWhitelist(address: string, label?: string): Promise<boolean> {
	return new Promise((resolve) => {
		const requestId = Math.random().toString(36).substring(7);

		const handler = (event: MessageEvent) => {
			if (event.data?.type === 'TESTUDO_WHITELIST_RESULT' && event.data?.requestId === requestId) {
				window.removeEventListener('message', handler);
				resolve(event.data.success);
			}
		};

		window.addEventListener('message', handler);

		window.postMessage(
			{
				type: 'TESTUDO_WHITELIST_REQUEST',
				requestId,
				address,
				label,
			},
			'*',
		);

		// Timeout after 5 seconds
		setTimeout(() => {
			window.removeEventListener('message', handler);
			resolve(false);
		}, 5000);
	});
}

/**
 * Get Material Symbol icon for threat type
 */
function getThreatIcon(threat: string): string {
	const iconMap: Record<string, string> = {
		auto_forwarder: 'currency_exchange',
		delegate_call: 'call_split',
		self_destruct: 'delete_forever',
		unlimited_approval: 'all_inclusive',
		create2: 'add_box',
		metamorphic: 'swap_horiz',
		chainid_branching: 'public',
		chainid_comparison: 'public',
		chainid_read: 'public',
		token_drain_fallback: 'token',
		token_hardcoded_dest: 'token',
		token_no_auth: 'token',
		token_replay_risk: 'replay',
		token_approval_no_auth: 'token',
		token_with_auth: 'token',
		ETH_AUTO_FORWARDER: 'currency_exchange',
		INFERNO_DRAINER: 'local_fire_department',
	};
	return iconMap[threat] || 'warning';
}

/**
 * Show warning modal for dangerous contracts
 */
function showWarning(
	analysis: AnalysisResult,
	context: 'delegation' | 'transaction' = 'delegation',
): Promise<boolean> {
	return new Promise((resolve) => {
		// Create modal overlay
		const overlay = document.createElement('div');
		overlay.id = 'testudo-warning-overlay';

		const truncatedAddress = `${analysis.address.slice(0, 10)}...${analysis.address.slice(-6)}`;

		// Get the primary warning for the critical alert
		// First look for CRITICAL/HIGH, then fall back to first actionable warning
		const primaryWarning =
			analysis.warnings?.find((w) => w.severity === 'CRITICAL' || w.severity === 'HIGH') ||
			analysis.warnings?.find((w) => w.severity === 'MEDIUM');

		// Use risk-appropriate fallback titles when no warning found
		const fallbackTitle =
			analysis.risk === 'CRITICAL' ? 'Fund Drain Detected' : 'Multiple Risk Factors Detected';
		const fallbackDescription =
			analysis.risk === 'CRITICAL'
				? 'This contract contains logic known to drain wallets immediately upon signature.'
				: 'This contract has multiple concerning patterns that warrant caution.';

		const criticalTitle = primaryWarning?.title || fallbackTitle;
		const criticalDescription = primaryWarning?.description || fallbackDescription;

		overlay.innerHTML = `
      <style>
        #testudo-warning-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.8);
          backdrop-filter: blur(4px);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 999999;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          animation: testudo-fade-in 0.3s ease;
        }

        @keyframes testudo-fade-in {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes testudo-zoom-in {
          from { opacity: 0; transform: scale(0.95); }
          to { opacity: 1; transform: scale(1); }
        }

        .testudo-modal {
          background: #1a232e;
          border-radius: 16px;
          border: 1px solid rgba(255, 255, 255, 0.1);
          max-width: 480px;
          width: 90%;
          max-height: 90vh;
          color: white;
          box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
          overflow: hidden;
          animation: testudo-zoom-in 0.3s ease;
          display: flex;
          flex-direction: column;
        }

        .testudo-material-icon {
          font-family: 'Material Symbols Outlined';
          font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
          font-style: normal;
          display: inline-block;
          line-height: 1;
          text-transform: none;
          letter-spacing: normal;
          word-wrap: normal;
          white-space: nowrap;
          direction: ltr;
          -webkit-font-smoothing: antialiased;
        }

        .testudo-header {
          display: flex;
          flex-direction: column;
          align-items: center;
          padding: 32px 24px 16px;
          gap: 16px;
          flex-shrink: 0;
        }

        .testudo-header-icon {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 80px;
          height: 80px;
          border-radius: 50%;
          background: rgba(231, 76, 60, 0.1);
          color: #e74c3c;
        }

        .testudo-header-icon .testudo-material-icon {
          font-size: 48px;
        }

        .testudo-header-text {
          text-align: center;
        }

        .testudo-title {
          font-size: 24px;
          font-weight: bold;
          color: #fff;
          margin: 0 0 8px 0;
          letter-spacing: -0.02em;
        }

        .testudo-subtitle {
          font-size: 14px;
          color: #97adc4;
          margin: 0;
          line-height: 1.5;
        }

        .testudo-subtitle strong {
          color: #fff;
          font-weight: 500;
        }

        /* Critical Alert Box */
        .testudo-alert {
          margin: 0 24px;
          position: relative;
          overflow: hidden;
          border-radius: 8px;
          border: 1px solid rgba(231, 76, 60, 0.4);
          background: rgba(231, 76, 60, 0.1);
          padding: 20px;
        }

        .testudo-alert::before {
          content: '';
          position: absolute;
          inset: 0;
          background: linear-gradient(135deg, rgba(231, 76, 60, 0.1) 0%, transparent 100%);
          pointer-events: none;
        }

        .testudo-alert-header {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #e74c3c;
          position: relative;
          z-index: 1;
        }

        .testudo-alert-header .testudo-material-icon {
          font-size: 20px;
        }

        .testudo-alert-title {
          font-size: 14px;
          font-weight: 700;
          letter-spacing: 0.05em;
          text-transform: uppercase;
        }

        .testudo-alert-description {
          color: rgba(255, 255, 255, 0.9);
          font-size: 14px;
          font-weight: 500;
          line-height: 1.6;
          margin-top: 8px;
          position: relative;
          z-index: 1;
        }

        /* Threats List */
        .testudo-threats {
          padding: 16px 24px;
          margin-top: 16px;
          overflow-y: auto;
          max-height: 280px;
          flex-shrink: 1;
        }

        .testudo-threats-title {
          font-size: 12px;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: rgba(255, 255, 255, 0.7);
          margin-bottom: 12px;
          padding: 0 4px;
        }

        .testudo-threat-item {
          display: flex;
          align-items: center;
          gap: 16px;
          background: rgba(18, 26, 33, 0.5);
          border-radius: 8px;
          padding: 12px;
          border: 1px solid rgba(255, 255, 255, 0.05);
          margin-bottom: 8px;
        }

        .testudo-threat-item:last-child {
          margin-bottom: 0;
        }

        .testudo-threat-icon {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 40px;
          height: 40px;
          border-radius: 8px;
          background: rgba(245, 158, 11, 0.1);
          color: #f59e0b;
          flex-shrink: 0;
        }

        .testudo-threat-icon .testudo-material-icon {
          font-size: 24px;
        }

        .testudo-threat-content {
          display: flex;
          flex-direction: column;
        }

        .testudo-threat-name {
          font-size: 14px;
          font-weight: 500;
          color: #fff;
          line-height: 1.4;
        }

        .testudo-threat-desc {
          font-size: 12px;
          color: #97adc4;
          margin-top: 2px;
        }

        /* Address Section */
        .testudo-address-section {
          margin: 8px 24px;
        }

        .testudo-address-box {
          display: flex;
          align-items: center;
          justify-content: space-between;
          background: #121a21;
          border-radius: 4px;
          padding: 8px 12px;
          border: 1px solid rgba(255, 255, 255, 0.05);
        }

        .testudo-address-label {
          font-size: 12px;
          font-weight: 500;
          color: #97adc4;
        }

        .testudo-address-value {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .testudo-address-text {
          font-family: 'Roboto Mono', ui-monospace, monospace;
          font-size: 14px;
          color: #fff;
          letter-spacing: 0.02em;
        }

        .testudo-copy-btn {
          background: none;
          border: none;
          color: #97adc4;
          cursor: pointer;
          padding: 4px;
          display: flex;
          align-items: center;
          justify-content: center;
          transition: color 0.2s;
        }

        .testudo-copy-btn:hover {
          color: #fff;
        }

        .testudo-copy-btn .testudo-material-icon {
          font-size: 16px;
        }

        /* Buttons */
        .testudo-buttons {
          display: flex;
          flex-direction: column;
          gap: 16px;
          padding: 8px 24px 24px;
          background: #1a232e;
          flex-shrink: 0;
        }

        .testudo-btn-cancel {
          width: 100%;
          background: #27ae60;
          color: white;
          border: none;
          border-radius: 8px;
          padding: 16px 24px;
          font-size: 16px;
          font-weight: 700;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          box-shadow: 0 4px 14px rgba(39, 174, 96, 0.2);
          transition: all 0.2s;
        }

        .testudo-btn-cancel:hover {
          background: #229954;
        }

        .testudo-btn-cancel:active {
          transform: scale(0.98);
        }

        .testudo-btn-cancel .testudo-material-icon {
          font-size: 20px;
        }

        .testudo-secondary-actions {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 24px;
          padding-top: 8px;
        }

        .testudo-btn-link {
          background: none;
          border: none;
          color: #97adc4;
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          padding: 8px;
          transition: color 0.2s;
          border-bottom: 1px solid transparent;
        }

        .testudo-btn-link:hover {
          color: #fff;
          border-bottom-color: rgba(255, 255, 255, 0.2);
        }

        .testudo-btn-danger {
          display: flex;
          align-items: center;
          gap: 4px;
          background: none;
          border: none;
          color: rgba(231, 76, 60, 0.7);
          font-size: 14px;
          font-weight: 500;
          cursor: pointer;
          padding: 8px;
          transition: color 0.2s;
        }

        .testudo-btn-danger:hover {
          color: #e74c3c;
        }

        .testudo-btn-danger .testudo-material-icon {
          font-size: 16px;
          transition: transform 0.2s;
        }

        .testudo-btn-danger:hover .testudo-material-icon {
          transform: translateX(2px);
        }
      </style>

      <div class="testudo-modal">
        <!-- Header -->
        <div class="testudo-header">
          <div class="testudo-header-icon">
            <span class="testudo-material-icon">gpp_maybe</span>
          </div>
          <div class="testudo-header-text">
            <h2 class="testudo-title">${context === 'transaction' ? 'Malicious Recipient Detected' : 'Dangerous Contract Detected'}</h2>
            <p class="testudo-subtitle">
              ${context === 'transaction' ? 'You are about to send funds to a <strong>known scammer</strong> address.' : 'We have intercepted a malicious <strong>EIP-7702</strong> delegation request.'}
            </p>
          </div>
        </div>

        <!-- Critical Alert Box -->
        <div class="testudo-alert">
          <div class="testudo-alert-header">
            <span class="testudo-material-icon">error</span>
            <span class="testudo-alert-title">CRITICAL: ${escapeHtml(criticalTitle)}</span>
          </div>
          <p class="testudo-alert-description">
            ${escapeHtml(criticalDescription)}
          </p>
        </div>

        <!-- Threats List -->
        <div class="testudo-threats">
          <h3 class="testudo-threats-title">Threats Detected</h3>
          ${analysis.threats
						.slice(0, 3)
						.map((threat) => {
							const formatted = formatThreat(threat);
							const shortDesc = getThreatShortDesc(threat);
							return `
              <div class="testudo-threat-item">
                <div class="testudo-threat-icon">
                  <span class="testudo-material-icon">${getThreatIcon(threat)}</span>
                </div>
                <div class="testudo-threat-content">
                  <span class="testudo-threat-name">${escapeHtml(formatted)}</span>
                  <span class="testudo-threat-desc">${escapeHtml(shortDesc)}</span>
                </div>
              </div>
            `;
						})
						.join('')}
        </div>

        <!-- Contract Address -->
        <div class="testudo-address-section">
          <div class="testudo-address-box">
            <span class="testudo-address-label">${context === 'transaction' ? 'Recipient Address' : 'Target Contract'}</span>
            <div class="testudo-address-value">
              <span class="testudo-address-text">${escapeHtml(truncatedAddress)}</span>
              <button class="testudo-copy-btn" id="testudo-copy" title="Copy Address">
                <span class="testudo-material-icon">content_copy</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="testudo-buttons">
          <button class="testudo-btn-cancel" id="testudo-cancel">
            <span class="testudo-material-icon">shield</span>
            Cancel (Safe)
          </button>
          <div class="testudo-secondary-actions">
            <button class="testudo-btn-link" id="testudo-trust">
              Trust contract & Proceed
            </button>
            <button class="testudo-btn-danger" id="testudo-proceed">
              <span>Proceed Anyway</span>
              <span class="testudo-material-icon">arrow_forward</span>
            </button>
          </div>
        </div>
      </div>
    `;

		document.body.appendChild(overlay);

		// Handle Escape key to cancel (safe action)
		const escapeHandler = (event: KeyboardEvent) => {
			if (event.key === 'Escape') {
				document.removeEventListener('keydown', escapeHandler);
				overlay.remove();
				recordBlocked();
				resolve(false);
			}
		};
		document.addEventListener('keydown', escapeHandler);

		// Handle copy button
		document.getElementById('testudo-copy')?.addEventListener('click', async () => {
			try {
				await navigator.clipboard.writeText(analysis.address);
				const copyBtn = document.getElementById('testudo-copy');
				if (copyBtn) {
					const iconEl = copyBtn.querySelector('.testudo-material-icon');
					if (iconEl) {
						iconEl.textContent = 'check';
						setTimeout(() => {
							iconEl.textContent = 'content_copy';
						}, 2000);
					}
				}
			} catch {
				console.error('[Testudo] Failed to copy address');
			}
		});

		// Handle button clicks
		document.getElementById('testudo-cancel')?.addEventListener('click', () => {
			document.removeEventListener('keydown', escapeHandler);
			overlay.remove();
			recordBlocked();
			resolve(false);
		});

		document.getElementById('testudo-trust')?.addEventListener('click', async () => {
			const trustBtn = document.getElementById('testudo-trust');
			if (trustBtn) {
				trustBtn.textContent = 'Adding...';
				trustBtn.setAttribute('disabled', 'true');
			}

			const success = await requestWhitelist(analysis.address, 'Trusted from warning');

			if (success) {
				console.log('[Testudo] ✅ Address added to whitelist');
				document.removeEventListener('keydown', escapeHandler);
				overlay.remove();
				resolve(true);
			} else {
				if (trustBtn) {
					trustBtn.textContent = 'Failed - Try Again';
					trustBtn.removeAttribute('disabled');
				}
			}
		});

		document.getElementById('testudo-proceed')?.addEventListener('click', () => {
			document.removeEventListener('keydown', escapeHandler);
			overlay.remove();
			resolve(true);
		});
	});
}

/**
 * Get short description for threat
 */
function getThreatShortDesc(threat: string): string {
	const descMap: Record<string, string> = {
		auto_forwarder: 'Redirects incoming assets to external address',
		delegate_call: 'Executes code in context of your wallet',
		self_destruct: 'Can destroy itself after draining funds',
		unlimited_approval: 'Requests access to all your tokens',
		create2: 'Can deploy contracts at predictable addresses',
		metamorphic: 'Code can change while keeping same address',
		chainid_branching: 'Behavior changes based on network',
		chainid_comparison: 'May restrict behavior on specific chains',
		chainid_read: 'Reads network ID for conditional logic',
		token_drain_fallback: 'Auto-drains tokens on any interaction',
		token_hardcoded_dest: 'Sends funds to hardcoded attacker address',
		token_no_auth: 'No signature verification for transfers',
		token_replay_risk: 'Same signature can be reused multiple times',
		token_approval_no_auth: 'Unlimited access without verification',
		token_with_auth: 'Has some security controls in place',
		ETH_AUTO_FORWARDER: 'Known malicious ETH drainer contract',
		INFERNO_DRAINER: 'Known Inferno Drainer attack contract',
	};
	return descMap[threat] || 'Suspicious behavior detected';
}

/**
 * Escape HTML entities to prevent XSS
 */
function escapeHtml(text: string): string {
	const div = document.createElement('div');
	div.textContent = text;
	return div.innerHTML;
}

/**
 * Show info toast for medium risk
 */
function showInfo(analysis: AnalysisResult): void {
	const firstWarning = analysis.warnings?.find((w) => w.severity !== 'INFO');
	const warningTitle = firstWarning?.title || 'Review Required';
	const warningText = firstWarning?.description || 'Review this delegation carefully';

	const toast = document.createElement('div');
	toast.innerHTML = `
    <style>
      .testudo-toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #1a232e;
        border: 1px solid rgba(245, 158, 11, 0.4);
        border-radius: 12px;
        padding: 16px 20px;
        color: white;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        z-index: 999998;
        max-width: 400px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        animation: testudo-slide-in 0.3s ease;
        display: flex;
        gap: 12px;
        align-items: flex-start;
      }

      @keyframes testudo-slide-in {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }

      .testudo-toast-icon {
        font-family: 'Material Symbols Outlined';
        font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        font-size: 24px;
        color: #f59e0b;
      }

      .testudo-toast-content {
        flex: 1;
      }

      .testudo-toast-title {
        font-weight: 600;
        color: #f59e0b;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .testudo-toast-title .testudo-toast-icon-inline {
        font-family: 'Material Symbols Outlined';
        font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        font-size: 16px;
      }

      .testudo-toast-text {
        font-size: 13px;
        color: #97adc4;
        margin-top: 4px;
        line-height: 1.5;
      }

      .testudo-toast-dismiss {
        background: none;
        border: none;
        color: #97adc4;
        cursor: pointer;
        font-size: 12px;
        margin-top: 8px;
        padding: 4px 8px;
        border-radius: 4px;
        transition: background 0.2s, color 0.2s;
      }

      .testudo-toast-dismiss:hover {
        background: rgba(255, 255, 255, 0.1);
        color: #fff;
      }
    </style>
    <div class="testudo-toast" id="testudo-info-toast">
      <span class="testudo-toast-icon">info</span>
      <div class="testudo-toast-content">
        <div class="testudo-toast-title">
          <span class="testudo-toast-icon-inline">bolt</span>
          ${escapeHtml(warningTitle)}
        </div>
        <div class="testudo-toast-text">${escapeHtml(warningText)}</div>
        <button class="testudo-toast-dismiss" id="testudo-toast-dismiss">Dismiss</button>
      </div>
    </div>
  `;

	document.body.appendChild(toast);

	document.getElementById('testudo-toast-dismiss')?.addEventListener('click', () => {
		toast.remove();
	});

	setTimeout(() => toast.remove(), 7000);
}

/**
 * Show notice for unknown/unverified contracts
 */
function showUnknownNotice(analysis: AnalysisResult): void {
	const truncatedAddress = `${analysis.address.slice(0, 10)}...${analysis.address.slice(-6)}`;

	const toast = document.createElement('div');
	toast.innerHTML = `
    <style>
      .testudo-toast-unknown {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #1a232e;
        border: 1px solid rgba(148, 163, 184, 0.4);
        border-radius: 12px;
        padding: 16px 20px;
        color: white;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        z-index: 999998;
        max-width: 400px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        animation: testudo-slide-in 0.3s ease;
        display: flex;
        gap: 12px;
        align-items: flex-start;
      }

      @keyframes testudo-slide-in {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }

      .testudo-toast-unknown-icon {
        font-family: 'Material Symbols Outlined';
        font-variation-settings: 'FILL' 1, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        font-size: 24px;
        color: #94a3b8;
      }

      .testudo-toast-unknown-content {
        flex: 1;
      }

      .testudo-toast-unknown-title {
        font-weight: 600;
        color: #94a3b8;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .testudo-toast-unknown-text {
        font-size: 13px;
        color: #97adc4;
        margin-top: 4px;
        line-height: 1.5;
      }

      .testudo-toast-unknown-address {
        font-family: 'Roboto Mono', monospace;
        font-size: 12px;
        color: #64748b;
        margin-top: 6px;
      }

      .testudo-toast-unknown-dismiss {
        background: none;
        border: none;
        color: #97adc4;
        cursor: pointer;
        font-size: 12px;
        margin-top: 8px;
        padding: 4px 8px;
        border-radius: 4px;
        transition: background 0.2s, color 0.2s;
      }

      .testudo-toast-unknown-dismiss:hover {
        background: rgba(255, 255, 255, 0.1);
        color: #fff;
      }
    </style>
    <div class="testudo-toast-unknown" id="testudo-unknown-toast">
      <span class="testudo-toast-unknown-icon">help_outline</span>
      <div class="testudo-toast-unknown-content">
        <div class="testudo-toast-unknown-title">Unverified Contract</div>
        <div class="testudo-toast-unknown-text">
          This contract has no bytecode or doesn't exist on-chain. It may be an EOA (regular wallet) or undeployed contract.
        </div>
        <div class="testudo-toast-unknown-address">${escapeHtml(truncatedAddress)}</div>
        <button class="testudo-toast-unknown-dismiss" id="testudo-unknown-dismiss">Dismiss</button>
      </div>
    </div>
  `;

	document.body.appendChild(toast);

	document.getElementById('testudo-unknown-dismiss')?.addEventListener('click', () => {
		toast.remove();
	});

	setTimeout(() => toast.remove(), 5000);
}

/**
 * Format threat names for display
 */
function formatThreat(threat: string): string {
	const threatMap: Record<string, string> = {
		auto_forwarder: 'Auto-forwards ETH',
		delegate_call: 'Uses DELEGATECALL',
		self_destruct: 'Can self-destruct',
		unlimited_approval: 'Unlimited token approval',
		create2: 'Uses CREATE2',
		metamorphic: 'Metamorphic contract',
		chainid_branching: 'Cross-chain behavior',
		chainid_comparison: 'Network ID comparison',
		chainid_read: 'Reads network ID',
		token_drain_fallback: 'Token drain in fallback',
		token_hardcoded_dest: 'Hardcoded destination',
		token_no_auth: 'No access control',
		token_replay_risk: 'Replay attack risk',
		token_approval_no_auth: 'Unprotected approvals',
		token_with_auth: 'Token transfers enabled',
		ETH_AUTO_FORWARDER: 'Known ETH drainer',
		INFERNO_DRAINER: 'Inferno Drainer',
	};

	return threatMap[threat] || threat.replace(/_/g, ' ');
}

// TypeScript declarations for window.ethereum
declare global {
	interface Window {
		ethereum?: {
			request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
			isMetaMask?: boolean;
		};
	}
}
