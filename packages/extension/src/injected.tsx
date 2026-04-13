import '@preact/signals';
import type { Warning } from '@testudo/core';
import { render } from 'preact';
import { InfoToast } from './components/warning/InfoToast';
import { UnknownToast } from './components/warning/UnknownToast';
import { WarningModal } from './components/warning/WarningModal';
import { injectWarningStyles } from './components/warning/warning-styles';
import { buildIntent } from './decoder';
import { getInstantToken, resolveToken } from './decoder/token-resolver';
import * as warningVM from './hooks/warningVM';
import { isBlindSignature, parseBlindSignature } from './parsers/blind-signature';
import { detectPhishingPatterns } from './parsers/phishing';
import {
	isApprovalTransaction,
	isKnownMarketplace,
	isNftApprovalTransaction,
	isUnlimitedValue,
	isZeroApproval,
	parseApprovalData,
	parseNftApprovalData,
} from './parsers/transaction';
import {
	extractPermitInfo,
	extractTypedDataAddresses,
	isEIP7702Authorization,
	isPermitSignature,
} from './parsers/typed-data';
import { batchCheckAddresses, requestAddressCheck, requestAnalysis } from './services/messaging';
import type {
	AnalysisResult,
	TypedDataMessage,
	TypedDataScanInfo,
	WarningOptions,
} from './utils/types';

(window as unknown as { __TESTUDO_LOADED__: boolean }).__TESTUDO_LOADED__ = true;

// ============================================================================
// PREACT MOUNT
// ============================================================================

let modalRoot: HTMLDivElement | null = null;
let shadowRoot: ShadowRoot | null = null;

function mountModalTree(root: ShadowRoot): void {
	const pageFonts = document.getElementById('testudo-fonts');
	if (pageFonts?.textContent) {
		const fontStyle = document.createElement('style');
		fontStyle.textContent = pageFonts.textContent;
		root.appendChild(fontStyle);
	}

	const container = document.createElement('div');
	root.appendChild(container);
	render(
		<>
			<WarningModal />
			<InfoToast />
			<UnknownToast />
		</>,
		container,
	);
}

function ensureModalRoot(): void {
	if (modalRoot?.isConnected && shadowRoot) return;

	const target = document.body || document.documentElement;

	if (modalRoot && !modalRoot.isConnected) {
		target.appendChild(modalRoot);
		return;
	}

	modalRoot = document.createElement('div');
	modalRoot.id = 'testudo-root';
	modalRoot.style.cssText =
		'display:block!important;position:static!important;visibility:visible!important;';
	target.appendChild(modalRoot);

	shadowRoot = modalRoot.attachShadow({ mode: 'open' });
	injectWarningStyles(shadowRoot);
	mountModalTree(shadowRoot);
}

// ============================================================================
// PUBLIC API — replaces imperative showWarning/showInfo/showUnknownNotice
// ============================================================================

async function showWarningWithIntent(
	opts: WarningOptions,
	tokenAddress?: string,
): Promise<boolean> {
	const instantToken = tokenAddress ? getInstantToken(tokenAddress) : null;
	const intent = buildIntent(opts, instantToken);
	ensureModalRoot();

	if (tokenAddress && !instantToken) {
		const modalPromise = warningVM.show({ ...opts, intent: intent ?? undefined });
		const gen = warningVM.getModalGeneration();
		resolveToken(tokenAddress)
			.then((resolved) => {
				const updatedIntent = buildIntent(opts, resolved);
				if (updatedIntent) warningVM.updateIntent(updatedIntent, gen);
			})
			.catch((err) => {
				console.debug('[Testudo] Background token resolution failed:', err);
			});
		return modalPromise;
	}

	return warningVM.show({ ...opts, intent: intent ?? undefined });
}

function showInfo(analysis: AnalysisResult): void {
	ensureModalRoot();
	warningVM.showInfoToast(analysis);
}

function showUnknownNotice(analysis: AnalysisResult): void {
	ensureModalRoot();
	warningVM.showUnknownToast(analysis);
}

// ============================================================================
// PROVIDER WRAPPING
// ============================================================================

let providerWrapped = false;
let activeWrapper: ((args: { method: string; params?: unknown[] }) => Promise<unknown>) | null =
	null;

function wrapEthereumProvider(): void {
	if (providerWrapped || typeof window.ethereum === 'undefined') {
		return;
	}

	console.log('[Testudo] \u{1F6E1}\uFE0F Initializing EIP-7702 protection...');
	providerWrapped = true;

	const originalRequest = window.ethereum.request.bind(window.ethereum);

	try {
		const wrappedRequest = async (args: { method: string; params?: unknown[] }) => {
			// Intercept eth_sendTransaction
			if (args.method === 'eth_sendTransaction') {
				try {
					const txParams = (args.params as Record<string, string>[])?.[0];
					const toAddress = txParams?.to;
					const data = txParams?.data;

					// Check for NFT approval transactions (setApprovalForAll)
					if (toAddress && data && isNftApprovalTransaction(data)) {
						const nftApprovalInfo = parseNftApprovalData(data, toAddress);
						if (nftApprovalInfo) {
							console.log('[Testudo] NFT setApprovalForAll detected');

							if (!nftApprovalInfo.approved) {
								console.log('[Testudo] NFT approval revocation detected, passing through');
								return originalRequest(args);
							}

							const analysis = await requestAddressCheck(nftApprovalInfo.operator);

							if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
								const userConfirmed = await showWarningWithIntent({
									analysis,
									context: 'nft-approval',
									nftApprovalInfo,
								});
								if (!userConfirmed) {
									throw new Error(
										'Testudo: NFT approval blocked by user - malicious operator detected',
									);
								}
								return originalRequest(args);
							}

							if (analysis.whitelisted) {
								console.log('[Testudo] Operator is whitelisted, passing through');
								return originalRequest(args);
							}

							const marketplaceName = isKnownMarketplace(nftApprovalInfo.operator);
							if (marketplaceName) {
								console.log(`[Testudo] Known marketplace: ${marketplaceName}`);
								return originalRequest(args);
							}

							const syntheticAnalysis: AnalysisResult = {
								...analysis,
								risk: 'HIGH',
								threats: ['nft_full_collection_access', ...analysis.threats],
								blocked: true,
							};
							const userConfirmed = await showWarningWithIntent({
								analysis: syntheticAnalysis,
								context: 'nft-approval',
								nftApprovalInfo,
							});
							if (!userConfirmed) {
								throw new Error('Testudo: NFT approval blocked by user - unknown operator');
							}

							return originalRequest(args);
						}
					}

					// Check for approval transactions
					if (toAddress && data && isApprovalTransaction(data)) {
						const approvalInfo = parseApprovalData(data, toAddress);
						if (approvalInfo) {
							console.log('[Testudo] Token approval detected:', approvalInfo.type);

							if (isZeroApproval(approvalInfo.amount)) {
								console.log('[Testudo] Approval revocation detected, passing through');
								return originalRequest(args);
							}

							const analysis = await requestAddressCheck(approvalInfo.spender);
							const unlimited = isUnlimitedValue(approvalInfo.amount);

							if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
								const userConfirmed = await showWarningWithIntent(
									{
										analysis,
										context: 'approval',
										approvalInfo,
									},
									approvalInfo.tokenAddress,
								);
								if (!userConfirmed) {
									throw new Error('Testudo: Approval blocked by user - malicious spender detected');
								}
							} else if (unlimited) {
								const syntheticAnalysis: AnalysisResult = {
									...analysis,
									risk: 'HIGH',
									threats: ['unlimited_approval', ...analysis.threats],
									blocked: true,
								};
								const userConfirmed = await showWarningWithIntent(
									{
										analysis: syntheticAnalysis,
										context: 'approval',
										approvalInfo,
									},
									approvalInfo.tokenAddress,
								);
								if (!userConfirmed) {
									throw new Error('Testudo: Approval blocked by user - unlimited amount');
								}
							}

							return originalRequest(args);
						}
					}

					// Check recipient address for non-approval transactions
					if (toAddress && /^0x[a-fA-F0-9]{40}$/.test(toAddress)) {
						const analysis = await requestAddressCheck(toAddress);

						if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
							const userConfirmed = await showWarningWithIntent({
								analysis,
								context: 'transaction',
							});

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

			// Hard block eth_sign
			if (args.method === 'eth_sign') {
				const blindSigInfo = parseBlindSignature('eth_sign', args.params as unknown[]);

				if (!blindSigInfo) {
					console.warn('[Testudo] eth_sign blocked \u2014 malformed parameters');
					throw new Error('Testudo: eth_sign blocked \u2014 malformed parameters');
				}

				console.log(
					'[Testudo] eth_sign detected \u2014 CRITICAL: deprecated method signs raw hashes',
				);

				const syntheticAnalysis: AnalysisResult = {
					address: blindSigInfo.signer,
					risk: 'CRITICAL',
					threats: ['eth_sign_deprecated', 'blind_signature'],
					warnings: [
						{
							type: 'ETH_SIGN_DEPRECATED',
							title: 'Deprecated: eth_sign',
							description:
								'eth_sign signs a raw 32-byte hash without any safety prefix. An attacker can craft a valid transaction hash, and signing it gives them full control to execute that transaction from your wallet.',
							severity: 'CRITICAL',
						},
					],
					blocked: true,
					whitelisted: false,
				};

				const userConfirmed = await showWarningWithIntent({
					analysis: syntheticAnalysis,
					context: 'eth-sign-danger',
					blindSignatureInfo: blindSigInfo,
				});

				if (!userConfirmed) {
					throw new Error('Testudo: eth_sign blocked by user \u2014 deprecated method rejected');
				}

				return originalRequest(args);
			}

			// Check for blind signatures (personal_sign)
			if (isBlindSignature(args.method)) {
				const blindSigInfo = parseBlindSignature(args.method, args.params as unknown[]);
				if (blindSigInfo) {
					console.log(`[Testudo] Blind signature detected: ${blindSigInfo.type}`);

					const phishing = detectPhishingPatterns(blindSigInfo.decodedMessage);

					const isPhishing = phishing.risk === 'HIGH';
					const threats: string[] = isPhishing
						? [...phishing.patterns, 'blind_signature']
						: ['blind_signature'];

					const syntheticAnalysis: AnalysisResult = {
						address: blindSigInfo.signer,
						risk: isPhishing ? 'HIGH' : 'MEDIUM',
						threats,
						warnings: [
							{
								type: isPhishing ? 'PHISHING_PATTERN' : 'BLIND_SIGNATURE',
								title: isPhishing ? 'Suspicious Message Detected' : 'Blind Signature Request',
								description: isPhishing
									? 'This message contains patterns commonly used in phishing attacks.'
									: 'You are signing data that cannot be verified. This could authorize actions you cannot see.',
								severity: isPhishing ? 'HIGH' : 'MEDIUM',
							},
						],
						blocked: isPhishing,
						whitelisted: false,
					};

					const userConfirmed = await showWarningWithIntent({
						analysis: syntheticAnalysis,
						context: 'blind-signature',
						blindSignatureInfo: blindSigInfo,
					});

					if (!userConfirmed) {
						throw new Error(
							`Testudo: ${blindSigInfo.type} blocked by user - blind signature rejected`,
						);
					}
				}

				return originalRequest(args);
			}

			// Intercept eth_signTypedData v3/v4
			if (args.method !== 'eth_signTypedData_v4' && args.method !== 'eth_signTypedData_v3') {
				return originalRequest(args);
			}

			try {
				const params = args.params as [string, string];
				const typedDataString = params[1];
				const typedData: TypedDataMessage =
					typeof typedDataString === 'string' ? JSON.parse(typedDataString) : typedDataString;

				// Check for Permit signatures first
				if (isPermitSignature(typedData)) {
					const permitInfo = extractPermitInfo(typedData);
					if (permitInfo) {
						console.log('[Testudo] Permit signature detected:', permitInfo.type);
						const analysis = await requestAddressCheck(permitInfo.spender);

						const unlimited = isUnlimitedValue(permitInfo.value);
						if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
							const userConfirmed = await showWarningWithIntent(
								{ analysis, context: 'permit', permitInfo },
								permitInfo.token,
							);
							if (!userConfirmed) {
								throw new Error('Testudo: Permit blocked by user - malicious spender detected');
							}
						} else if (unlimited) {
							const syntheticAnalysis: AnalysisResult = {
								...analysis,
								risk: 'HIGH',
								threats: ['unlimited_approval', ...analysis.threats],
								blocked: true,
							};
							const userConfirmed = await showWarningWithIntent(
								{ analysis: syntheticAnalysis, context: 'permit', permitInfo },
								permitInfo.token,
							);
							if (!userConfirmed) {
								throw new Error('Testudo: Permit blocked by user - unlimited approval');
							}
						}

						return originalRequest(args);
					}
				}

				// Check if this is an EIP-7702 Authorization
				if (!isEIP7702Authorization(typedData)) {
					try {
						const addresses = extractTypedDataAddresses(typedData);
						if (addresses.length > 0) {
							const { malicious, results } = await batchCheckAddresses(addresses);
							if (malicious.length > 0) {
								const worstAddr = malicious[0].address.toLowerCase();
								const worstResult = results.get(worstAddr);
								const syntheticAnalysis: AnalysisResult = {
									address: worstAddr,
									risk: 'CRITICAL',
									threats: ['typed_data_malicious_address', ...(worstResult?.threats || [])],
									warnings: [
										{
											type: 'TYPED_DATA_MALICIOUS_ADDRESS',
											title: 'Malicious Address in Signed Data',
											description:
												'A known malicious address was found in the data you are about to sign.',
											severity: 'CRITICAL',
										},
									],
									blocked: true,
									whitelisted: false,
								};

								const scanInfo: TypedDataScanInfo = {
									maliciousAddresses: malicious,
									primaryType: typedData.primaryType,
									domainName: typedData.domain?.name,
								};

								const userConfirmed = await showWarningWithIntent({
									analysis: syntheticAnalysis,
									context: 'typed-data-scan',
									typedDataScanInfo: scanInfo,
								});

								if (!userConfirmed) {
									throw new Error(
										'Testudo: Typed data blocked by user - malicious address in signed data',
									);
								}
							}
						}
					} catch (error) {
						if (error instanceof Error && error.message.includes('Testudo')) throw error;
						console.error('[Testudo] Error scanning typed data:', error);
					}
					return originalRequest(args);
				}

				console.log('[Testudo] EIP-7702 authorization detected!');
				const delegateAddress = typedData.message.address as string;
				const rawChainId = typedData.message.chainId as number | string | undefined;
				const isReplayRisk =
					rawChainId === 0 || rawChainId === '0' || rawChainId === '0x0' || rawChainId === '0x00';

				ensureModalRoot();
				const loadingPromise = warningVM.showLoading({
					context: 'delegation',
					address: delegateAddress,
				});

				let analysis: AnalysisResult;
				try {
					analysis = await requestAnalysis(delegateAddress);
				} catch (err) {
					console.error('[Testudo] Analysis failed, failing open:', err);
					warningVM.dismissLoading();
					return originalRequest(args);
				}

				if (isReplayRisk) {
					const replayWarning: Warning = {
						type: 'EIP7702_REPLAY_RISK',
						severity: 'CRITICAL',
						title: 'Cross-Chain Replay Risk',
						description:
							'This authorization uses chainId=0, making it valid on every EVM network. An attacker can replay your signature on any chain to drain funds across all networks.',
					};
					analysis = {
						...analysis,
						risk: 'CRITICAL',
						blocked: true,
						threats: ['eip7702_replay_risk', ...(analysis.threats ?? [])],
						warnings: [replayWarning, ...(analysis.warnings ?? [])],
					};
				}

				if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
					const intent = buildIntent({ analysis, chainId: rawChainId }, null);
					warningVM.updateAnalysis(analysis, intent ?? undefined);
					const userConfirmed = await loadingPromise;

					if (!userConfirmed) {
						throw new Error('Testudo: Delegation blocked by user - dangerous contract detected');
					}
				} else if (analysis.risk === 'MEDIUM') {
					warningVM.dismissLoading();
					showInfo(analysis);
				} else {
					warningVM.dismissLoading();
					if (analysis.risk === 'UNKNOWN') {
						showUnknownNotice(analysis);
					}
				}

				return originalRequest(args);
			} catch (error) {
				if (error instanceof Error && error.message.includes('Testudo')) {
					throw error;
				}
				console.error('[Testudo] Error analyzing request:', error);
				return originalRequest(args);
			}
		};

		// Harden: use Object.defineProperty to make .request non-writable and non-configurable.
		// This prevents drainer kits from replacing or shadowing the wrapper via:
		//   - Direct assignment: window.ethereum.request = malicious
		//   - Object.defineProperty with different descriptor
		// Check if .request is already locked (e.g. from a previous wrap on this object)
		const existingDesc = Object.getOwnPropertyDescriptor(window.ethereum, 'request');
		if (existingDesc && existingDesc.configurable === false) {
			// Already locked by a prior wrap — cannot redefine, but check if it's ours
			if (existingDesc.value === wrappedRequest) {
				activeWrapper = wrappedRequest;
			} else {
				console.warn('[Testudo] .request already locked by another party');
				activeWrapper = null;
				providerWrapped = false;
			}
		} else {
			Object.defineProperty(window.ethereum, 'request', {
				value: wrappedRequest,
				writable: false,
				configurable: false,
				enumerable: true,
			});
			activeWrapper = wrappedRequest;
		}
	} catch (wrapError) {
		console.error('[Testudo] Failed to wrap provider (frozen object?):', wrapError);
		providerWrapped = false;
		activeWrapper = null;
		return;
	}

	console.log('[Testudo] \u2705 Protection active');
}

// Store reference to the current wrapped provider to detect replacements
let wrappedProvider: Window['ethereum'];

if (typeof window.ethereum !== 'undefined') {
	wrappedProvider = window.ethereum;
}
wrapEthereumProvider();

let ethereumValue: Window['ethereum'] = window.ethereum;

Object.defineProperty(window, 'ethereum', {
	configurable: true,
	enumerable: true,
	get() {
		return ethereumValue;
	},
	set(value) {
		if (value !== ethereumValue && value !== wrappedProvider) {
			ethereumValue = value;
			providerWrapped = false;
			activeWrapper = null;
			wrappedProvider = value;
			wrapEthereumProvider();
		} else {
			ethereumValue = value;
		}
	},
});

// Periodic integrity check: detect if a drainer removed or replaced our wrapper.
// Runs every 2s as a backup — primary check happens on each intercepted request.
setInterval(() => {
	if (typeof window.ethereum !== 'undefined' && activeWrapper) {
		const currentRequest = window.ethereum.request;
		if (currentRequest !== activeWrapper) {
			console.warn('[Testudo] Provider wrapper tampered — re-wrapping');
			providerWrapped = false;
			wrapEthereumProvider();
		}
	}
}, 2000);

declare global {
	interface Window {
		ethereum?: {
			request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
			isMetaMask?: boolean;
		};
	}
}
