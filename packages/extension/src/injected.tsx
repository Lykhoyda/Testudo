import '@preact/signals';
import { render } from 'preact';
import { InfoToast } from './components/warning/InfoToast';
import { UnknownToast } from './components/warning/UnknownToast';
import { WarningModal } from './components/warning/WarningModal';
import { injectWarningStyles } from './components/warning/warning-styles';
import { buildIntent } from './decoder';
import { getCachedToken, resolveToken } from './decoder/token-resolver';
import * as warningVM from './hooks/warningVM';
import { isBlindSignature, parseBlindSignature } from './parsers/blind-signature';
import { detectPhishingPatterns } from './parsers/phishing';
import {
	formatApprovalAmount,
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
import {
	batchCheckAddresses,
	recordBlocked,
	requestAddressCheck,
	requestAnalysis,
} from './services/messaging';
import type {
	AnalysisResult,
	TokenInfo,
	TypedDataMessage,
	TypedDataScanInfo,
	WarningOptions,
} from './utils/types';

// ============================================================================
// PREACT MOUNT
// ============================================================================

let modalRoot: HTMLDivElement | null = null;

function mountModalTree(root: HTMLDivElement): void {
	render(
		<>
			<WarningModal />
			<InfoToast />
			<UnknownToast />
		</>,
		root,
	);
}

function ensureModalRoot(): void {
	if (modalRoot?.isConnected) return;

	injectWarningStyles();

	if (modalRoot && !modalRoot.isConnected) {
		document.body.appendChild(modalRoot);
		return;
	}

	modalRoot = document.createElement('div');
	modalRoot.id = 'testudo-root';
	document.body.appendChild(modalRoot);
	mountModalTree(modalRoot);
}

// ============================================================================
// PUBLIC API — replaces imperative showWarning/showInfo/showUnknownNotice
// ============================================================================

async function resolveTokenWithTimeout(
	address: string,
	timeoutMs = 2000,
): Promise<TokenInfo | null> {
	const cached = getCachedToken(address);
	if (cached) return cached;
	try {
		return await Promise.race([
			resolveToken(address),
			new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
		]);
	} catch {
		return null;
	}
}

async function showWarningWithIntent(
	opts: WarningOptions,
	tokenAddress?: string,
): Promise<boolean> {
	let tokenInfo: TokenInfo | null = null;
	if (tokenAddress) {
		tokenInfo = await resolveTokenWithTimeout(tokenAddress);
	}
	const intent = buildIntent(opts, tokenInfo);
	ensureModalRoot();
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

function wrapEthereumProvider(): void {
	if (providerWrapped || typeof window.ethereum === 'undefined') {
		return;
	}

	console.log('[Testudo] \u{1F6E1}\uFE0F Initializing EIP-7702 protection...');
	providerWrapped = true;

	const originalRequest = window.ethereum.request.bind(window.ethereum);

	try {
		window.ethereum.request = async (args: { method: string; params?: unknown[] }) => {
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

				console.log('[Testudo] \u{1F50D} EIP-7702 authorization detected!');
				const delegateAddress = typedData.message.address as string;
				console.log('[Testudo] Delegate address:', delegateAddress);

				const analysis = await requestAnalysis(delegateAddress);

				console.log('[Testudo] Analysis result:', analysis);

				if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
					const userConfirmed = await showWarningWithIntent({ analysis });

					if (!userConfirmed) {
						console.log('[Testudo] \u274C User rejected dangerous delegation');
						throw new Error('Testudo: Delegation blocked by user - dangerous contract detected');
					}

					console.log('[Testudo] \u26A0\uFE0F User proceeded despite warning');
				} else if (analysis.risk === 'MEDIUM') {
					showInfo(analysis);
				} else if (analysis.risk === 'UNKNOWN') {
					showUnknownNotice(analysis);
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
	} catch (wrapError) {
		console.error('[Testudo] Failed to wrap provider (frozen object?):', wrapError);
		providerWrapped = false;
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
			wrappedProvider = value;
			wrapEthereumProvider();
		} else {
			ethereumValue = value;
		}
	},
});

// Suppress unused variable warnings for functions used via provider interception
void recordBlocked;
void formatApprovalAmount;

declare global {
	interface Window {
		ethereum?: {
			request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
			isMetaMask?: boolean;
		};
	}
}
