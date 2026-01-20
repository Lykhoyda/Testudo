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
	warnings?: string[];
	address: string;
	blocked: boolean;
}

// Check if ethereum provider exists
if (typeof window.ethereum !== 'undefined') {
	console.log('[Testudo] 🛡️ Initializing EIP-7702 protection...');

	const originalRequest = window.ethereum.request.bind(window.ethereum);

	// Wrap the request method
	window.ethereum.request = async (args: { method: string; params?: unknown[] }) => {
		// Only intercept eth_signTypedData_v4
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

	console.log('[Testudo] ✅ Protection active');
}

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
 * Send analysis request to content script → background script
 */
function requestAnalysis(delegateAddress: string): Promise<AnalysisResult> {
	return new Promise((resolve, reject) => {
		const requestId = Math.random().toString(36).substring(7);

		// Listen for response
		const handler = (event: MessageEvent) => {
			if (event.data?.type === 'TESTUDO_ANALYSIS_RESULT' && event.data?.requestId === requestId) {
				window.removeEventListener('message', handler);
				resolve(event.data.result);
			}
		};

		window.addEventListener('message', handler);

		// Send request to content script
		window.postMessage(
			{
				type: 'TESTUDO_ANALYZE_REQUEST',
				requestId,
				delegateAddress,
			},
			'*',
		);

		// Timeout after 10 seconds
		setTimeout(() => {
			window.removeEventListener('message', handler);
			reject(new Error('Analysis timeout'));
		}, 10000);
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
			if (
				event.data?.type === 'TESTUDO_WHITELIST_RESULT' &&
				event.data?.requestId === requestId
			) {
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
 * Show warning modal for dangerous contracts
 */
function showWarning(analysis: AnalysisResult): Promise<boolean> {
	return new Promise((resolve) => {
		// Create modal overlay
		const overlay = document.createElement('div');
		overlay.id = 'testudo-warning-overlay';
		overlay.innerHTML = `
      <style>
        #testudo-warning-overlay {
          position: fixed;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
          background: rgba(0, 0, 0, 0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 999999;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        .testudo-modal {
          background: #1a1a2e;
          border: 2px solid #e74c3c;
          border-radius: 16px;
          padding: 32px;
          max-width: 480px;
          color: white;
          box-shadow: 0 20px 60px rgba(231, 76, 60, 0.3);
        }
        
        .testudo-header {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-bottom: 20px;
        }
        
        .testudo-icon {
          font-size: 48px;
        }
        
        .testudo-title {
          font-size: 24px;
          font-weight: bold;
          color: #e74c3c;
          margin: 0;
        }
        
        .testudo-subtitle {
          font-size: 14px;
          color: #888;
          margin: 4px 0 0 0;
        }
        
        .testudo-threats {
          background: #2d2d44;
          border-radius: 8px;
          padding: 16px;
          margin: 20px 0;
        }
        
        .testudo-threat {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 0;
          border-bottom: 1px solid #3d3d5c;
        }
        
        .testudo-threat:last-child {
          border-bottom: none;
        }
        
        .testudo-threat-icon {
          color: #e74c3c;
        }
        
        .testudo-address {
          font-family: monospace;
          font-size: 12px;
          color: #888;
          word-break: break-all;
          margin: 16px 0;
        }
        
        .testudo-buttons {
          display: flex;
          gap: 12px;
          margin-top: 24px;
        }
        
        .testudo-btn {
          flex: 1;
          padding: 14px 24px;
          border-radius: 8px;
          font-size: 16px;
          font-weight: 600;
          cursor: pointer;
          border: none;
          transition: transform 0.1s, opacity 0.1s;
        }
        
        .testudo-btn:hover {
          transform: scale(1.02);
        }
        
        .testudo-btn:active {
          transform: scale(0.98);
        }
        
        .testudo-btn-cancel {
          background: #27ae60;
          color: white;
        }

        .testudo-btn-trust {
          background: #3498db;
          color: white;
        }

        .testudo-btn-trust:hover {
          background: #2980b9;
        }

        .testudo-btn-proceed {
          background: transparent;
          border: 1px solid #666;
          color: #888;
        }

        .testudo-btn-proceed:hover {
          border-color: #e74c3c;
          color: #e74c3c;
        }
      </style>
      
      <div class="testudo-modal">
        <div class="testudo-header">
          <span class="testudo-icon">🛡️</span>
          <div>
            <h2 class="testudo-title">Dangerous Contract Detected</h2>
            <p class="testudo-subtitle">Testudo blocked a risky EIP-7702 delegation</p>
          </div>
        </div>
        
        <div class="testudo-threats">
          ${analysis.threats
						.map(
							(threat) => `
            <div class="testudo-threat">
              <span class="testudo-threat-icon">⚠️</span>
              <span>${formatThreat(threat)}</span>
            </div>
          `,
						)
						.join('')}
        </div>

        ${
					analysis.warnings && analysis.warnings.length > 0
						? `
        <div style="background: #3d2d2d; border-radius: 8px; padding: 12px 16px; margin: 16px 0; border-left: 3px solid #e74c3c;">
          ${analysis.warnings.map((warning) => `<p style="color: #ffcccc; font-size: 13px; line-height: 1.5; margin: 8px 0;">${warning}</p>`).join('')}
        </div>
        `
						: ''
				}

        <div class="testudo-address">
          Contract: ${analysis.address}
        </div>

        <p style="color: #ccc; font-size: 14px; line-height: 1.5;">
          Signing this authorization could give this contract full control over your wallet,
          including the ability to drain all your ETH, tokens, and NFTs.
        </p>
        
        <div class="testudo-buttons">
          <button class="testudo-btn testudo-btn-cancel" id="testudo-cancel">
            ✓ Cancel (Safe)
          </button>
          <button class="testudo-btn testudo-btn-trust" id="testudo-trust">
            Trust & Proceed
          </button>
          <button class="testudo-btn testudo-btn-proceed" id="testudo-proceed">
            Proceed Anyway
          </button>
        </div>
      </div>
    `;

		document.body.appendChild(overlay);

		// Handle button clicks
		document.getElementById('testudo-cancel')?.addEventListener('click', () => {
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
			overlay.remove();
			resolve(true);
		});
	});
}

/**
 * Show info toast for medium risk
 */
function showInfo(analysis: AnalysisResult): void {
	const warningText =
		analysis.warnings && analysis.warnings.length > 0
			? analysis.warnings[0]
			: 'Review this delegation carefully';

	const toast = document.createElement('div');
	toast.innerHTML = `
    <style>
      .testudo-toast {
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: #2d2d44;
        border: 1px solid #f39c12;
        border-radius: 12px;
        padding: 16px 20px;
        color: white;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        z-index: 999998;
        max-width: 400px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        animation: slideIn 0.3s ease;
      }

      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    </style>
    <div class="testudo-toast">
      <span style="font-size: 24px;">🛡️</span>
      <div>
        <div style="font-weight: 600; color: #f39c12;">Testudo: Medium Risk</div>
        <div style="font-size: 12px; color: #ccc; margin-top: 4px; line-height: 1.4;">${warningText}</div>
      </div>
    </div>
  `;

	document.body.appendChild(toast);

	setTimeout(() => toast.remove(), 7000);
}

/**
 * Format threat names for display
 */
function formatThreat(threat: string): string {
	const threatMap: Record<string, string> = {
		hasAutoForwarder: 'Auto-forwards ETH to attacker',
		isDelegatedCall: 'Uses DELEGATECALL (can execute any code)',
		hasSelfDestruct: 'Can self-destruct after draining',
		hasUnlimitedApprovals: 'Requests unlimited token approvals',
		hasCreate2: 'Uses CREATE2 (can deploy additional contracts)',
		metamorphicPattern: 'Metamorphic contract (can change code at same address)',
		crossChainPolymorphism: 'Cross-chain polymorphism (may behave differently on other chains)',
		unprotectedTokenTransfer: 'Token transfers without authorization checks',
		missingTokenAuth: 'Token operations without proper access control',
		tokenTransferInFallback: 'Token transfer in fallback function (auto-drain)',
		hasHardcodedDestination: 'Funds sent to hardcoded attacker address',
		ETH_AUTO_FORWARDER: 'Known ETH drainer contract',
		INFERNO_DRAINER: 'Known Inferno Drainer exploit',
	};

	return threatMap[threat] || threat;
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

export {};
