/**
 * INJECTED SCRIPT
 *
 * This script runs in the PAGE context (not extension context).
 * It intercepts window.ethereum.request calls to detect EIP-7702 authorization requests.
 *
 * Flow:
 * 1. Wrap window.ethereum.request
 * 2. Detect eth_signTypedData_v3/v4 with Authorization type
 * 3. Send delegate address to content script for analysis
 * 4. Wait for risk assessment
 * 5. Block or allow based on result
 */

import type { Warning } from '@testudo/core';

interface TypedDataDomain {
	name?: string;
	version?: string;
	chainId?: number;
	verifyingContract?: string;
}

interface TypedDataMessage {
	types: {
		Authorization?: unknown;
		[key: string]: unknown;
	};
	primaryType: string;
	domain: TypedDataDomain;
	message: Record<string, unknown>;
}

interface PermitInfo {
	type:
		| 'permit'
		| 'permit2-single'
		| 'permit2-batch'
		| 'permit2-transfer'
		| 'permit2-witness-transfer'
		| 'dai-permit';
	spender: string;
	value?: string;
	deadline?: string;
	token?: string;
	tokenName?: string;
}

interface ApprovalInfo {
	type: 'approve' | 'increaseAllowance' | 'decreaseAllowance';
	spender: string;
	amount: string;
	tokenAddress: string;
}

interface NftApprovalInfo {
	type: 'setApprovalForAll';
	operator: string;
	approved: boolean;
	collectionAddress: string;
	collectionName?: string;
}

interface BlindSignatureInfo {
	type: 'personal_sign' | 'eth_sign';
	message: string;
	decodedMessage: string;
	messagePreview: string;
	signer: string;
	isHex: boolean;
}

const APPROVAL_SELECTORS = {
	approve: '0x095ea7b3',
	increaseAllowance: '0x39509351',
	decreaseAllowance: '0xa457c2d7',
} as const;

const NFT_APPROVAL_SELECTORS = {
	setApprovalForAll: '0xa22cb465',
} as const;

const KNOWN_MARKETPLACES: Record<string, string> = {
	'0x1e0049783f008a0085193e00003d00cd54003c71': 'OpenSea Seaport 1.1',
	'0x00000000000001ad428e4906ae43d8f9852d0dd6': 'OpenSea Seaport 1.4',
	'0x00000000000000adc04c56bf30ac9d3c0aaf14dc': 'OpenSea Seaport 1.5',
	'0x00000000000000adc04c56bf30ac9d3c0aaf14dd': 'OpenSea Seaport 1.6',
	'0x000000000000ad05ccc4f10045630fb830b95127': 'Blur',
	'0x59728544b08ab483533076417fbbb2fd0b17ce3a': 'LooksRare Exchange',
	'0x74312363e45dcaba76c59ec49a7aa8a65a67eed3': 'X2Y2 Exchange',
	'0x2b2e8cda09bba9660dca5cb6233787738ad68329': 'Sudoswap',
};

function isApprovalTransaction(data: string | undefined): boolean {
	if (!data || data.length < 10) return false;
	const selector = data.slice(0, 10).toLowerCase();
	return Object.values(APPROVAL_SELECTORS).includes(
		selector as (typeof APPROVAL_SELECTORS)[keyof typeof APPROVAL_SELECTORS],
	);
}

function parseApprovalData(data: string, tokenAddress: string): ApprovalInfo | null {
	const selector = data.slice(0, 10).toLowerCase();
	if (data.length < 138) return null;

	const spenderPadded = data.slice(10, 74);
	const amountHex = data.slice(74, 138);

	const spender = `0x${spenderPadded.slice(24).toLowerCase()}`;
	if (!/^0x[a-fA-F0-9]{40}$/.test(spender)) return null;

	const type =
		selector === APPROVAL_SELECTORS.approve
			? 'approve'
			: selector === APPROVAL_SELECTORS.increaseAllowance
				? 'increaseAllowance'
				: 'decreaseAllowance';

	return { type, spender, amount: `0x${amountHex}`, tokenAddress: tokenAddress.toLowerCase() };
}

function formatApprovalAmount(hexAmount: string): string {
	if (isUnlimitedValue(hexAmount)) {
		return 'UNLIMITED';
	}
	try {
		const amount = BigInt(hexAmount);
		return amount.toLocaleString();
	} catch {
		return 'Invalid Amount Data';
	}
}

function isZeroApproval(hexAmount: string): boolean {
	try {
		return BigInt(hexAmount) === BigInt(0);
	} catch {
		return false;
	}
}

function isNftApprovalTransaction(data: string | undefined): boolean {
	if (!data || data.length < 10) return false;
	const selector = data.slice(0, 10).toLowerCase();
	return selector === NFT_APPROVAL_SELECTORS.setApprovalForAll;
}

function parseNftApprovalData(data: string, collectionAddress: string): NftApprovalInfo | null {
	if (data.length < 138) return null;

	const operatorPadded = data.slice(10, 74);
	const approvedHex = data.slice(74, 138);

	const operator = `0x${operatorPadded.slice(24).toLowerCase()}`;
	if (!/^0x[a-fA-F0-9]{40}$/.test(operator)) return null;

	const approved = BigInt(`0x${approvedHex}`) !== BigInt(0);

	return {
		type: 'setApprovalForAll',
		operator,
		approved,
		collectionAddress: collectionAddress.toLowerCase(),
	};
}

function isKnownMarketplace(address: string): string | null {
	return KNOWN_MARKETPLACES[address.toLowerCase()] || null;
}

function isBlindSignature(method: string): boolean {
	return method === 'personal_sign';
}

function parseBlindSignature(method: string, params: unknown[]): BlindSignatureInfo | null {
	if (!Array.isArray(params) || params.length < 2) return null;

	const [first, second] = params;
	const message = method === 'personal_sign' ? String(first) : String(second);
	const signer = method === 'personal_sign' ? String(second) : String(first);

	if (!/^0x[a-fA-F0-9]{40}$/.test(signer)) return null;

	const isHex = /^0x[a-fA-F0-9]+$/.test(message);

	let decodedMessage = message;
	if (isHex && message.length > 2) {
		try {
			// Decode up to 4000 hex chars (2000 bytes) for phishing detection
			const hexToDecode = message.slice(2, 4002);
			const bytes = hexToDecode.match(/.{1,2}/g);
			if (bytes) {
				const decoded = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join('');
				if (/^[\x20-\x7E\s]+$/.test(decoded)) {
					decodedMessage = decoded;
				}
			}
		} catch {
			// Keep original hex
		}
	}

	let messagePreview = decodedMessage;
	if (messagePreview.length > 100) {
		messagePreview = `${messagePreview.slice(0, 97)}...`;
	}

	return {
		type: method as 'personal_sign' | 'eth_sign',
		message,
		decodedMessage,
		messagePreview,
		signer: signer.toLowerCase(),
		isHex,
	};
}

interface PhishingPattern {
	category: string;
	regex: RegExp;
	score: number;
}

const PHISHING_PATTERNS: PhishingPattern[] = [
	{ category: 'airdrop_scam', regex: /claim\s+(your\s+)?airdrop/i, score: 3 },
	{ category: 'airdrop_scam', regex: /free\s+tokens?/i, score: 3 },
	{ category: 'airdrop_scam', regex: /claim\s+(your\s+)?reward/i, score: 3 },
	{ category: 'verification_scam', regex: /verify\s+(your\s+)?wallet/i, score: 3 },
	{ category: 'verification_scam', regex: /confirm\s+(your\s+)?ownership/i, score: 3 },
	{ category: 'verification_scam', regex: /security\s+(check|verification)/i, score: 3 },
	{ category: 'urgency', regex: /expires?\s+in/i, score: 2 },
	{ category: 'urgency', regex: /act\s+now/i, score: 2 },
	{ category: 'urgency', regex: /limited\s+time/i, score: 2 },
	{ category: 'urgency', regex: /within\s+\d+\s+(hour|minute)/i, score: 2 },
	{ category: 'impersonation', regex: /opensea/i, score: 2 },
	{ category: 'impersonation', regex: /metamask/i, score: 2 },
	{ category: 'impersonation', regex: /uniswap/i, score: 2 },
	{ category: 'impersonation', regex: /coinbase/i, score: 2 },
	{ category: 'financial_lure', regex: /you\s+(have\s+)?won/i, score: 2 },
	{ category: 'financial_lure', regex: /prize/i, score: 2 },
	{ category: 'financial_lure', regex: /bonus\s+token/i, score: 2 },
];

interface PhishingResult {
	score: number;
	patterns: string[];
	risk: 'INFO' | 'MEDIUM' | 'HIGH';
}

function detectPhishingPatterns(messageText: string): PhishingResult {
	let score = 0;
	const matchedCategories = new Set<string>();

	for (const pattern of PHISHING_PATTERNS) {
		if (pattern.regex.test(messageText)) {
			score += pattern.score;
			matchedCategories.add(pattern.category);
		}
	}

	const patterns = Array.from(matchedCategories);
	const risk: PhishingResult['risk'] = score >= 3 ? 'HIGH' : score >= 1 ? 'MEDIUM' : 'INFO';

	return { score, patterns, risk };
}

interface AnalysisResult {
	risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
	threats: string[];
	warnings?: Warning[];
	address: string;
	blocked: boolean;
	whitelisted?: boolean;
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
					const data = txParams?.data;

					// Check for NFT approval transactions (setApprovalForAll)
					if (toAddress && data && isNftApprovalTransaction(data)) {
						const nftApprovalInfo = parseNftApprovalData(data, toAddress);
						if (nftApprovalInfo) {
							console.log('[Testudo] NFT setApprovalForAll detected');

							// Silent pass for revocations (approved = false) - user is removing access
							if (!nftApprovalInfo.approved) {
								console.log('[Testudo] NFT approval revocation detected, passing through');
								return originalRequest(args);
							}

							// Check operator against threat database FIRST (defense-in-depth)
							const analysis = await requestAddressCheck(nftApprovalInfo.operator);

							// If malicious, always show warning (even for known marketplaces)
							if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
								const userConfirmed = await showWarning(
									analysis,
									'nft-approval',
									undefined,
									undefined,
									nftApprovalInfo,
								);
								if (!userConfirmed) {
									throw new Error(
										'Testudo: NFT approval blocked by user - malicious operator detected',
									);
								}
								return originalRequest(args);
							}

							// If user has whitelisted this operator, pass through
							if (analysis.whitelisted) {
								console.log('[Testudo] Operator is whitelisted, passing through');
								return originalRequest(args);
							}

							// If operator is a known marketplace (trusted), pass through
							const marketplaceName = isKnownMarketplace(nftApprovalInfo.operator);
							if (marketplaceName) {
								console.log(`[Testudo] Known marketplace: ${marketplaceName}`);
								return originalRequest(args);
							}

							// Unknown operator - show HIGH warning (granting full collection access)
							const syntheticAnalysis: AnalysisResult = {
								...analysis,
								risk: 'HIGH',
								threats: ['nft_full_collection_access', ...analysis.threats],
								blocked: true,
							};
							const userConfirmed = await showWarning(
								syntheticAnalysis,
								'nft-approval',
								undefined,
								undefined,
								nftApprovalInfo,
							);
							if (!userConfirmed) {
								throw new Error('Testudo: NFT approval blocked by user - unknown operator');
							}

							return originalRequest(args);
						}
					}

					// Check for approval transactions (approve, increaseAllowance, decreaseAllowance)
					if (toAddress && data && isApprovalTransaction(data)) {
						const approvalInfo = parseApprovalData(data, toAddress);
						if (approvalInfo) {
							console.log('[Testudo] Token approval detected:', approvalInfo.type);

							// Silent pass for revocations (amount = 0) - no security risk
							if (isZeroApproval(approvalInfo.amount)) {
								console.log('[Testudo] Approval revocation detected, passing through');
								return originalRequest(args);
							}

							const analysis = await requestAddressCheck(approvalInfo.spender);
							const unlimited = isUnlimitedValue(approvalInfo.amount);

							if (analysis.risk === 'CRITICAL' || analysis.risk === 'HIGH') {
								const userConfirmed = await showWarning(
									analysis,
									'approval',
									undefined,
									approvalInfo,
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
								const userConfirmed = await showWarning(
									syntheticAnalysis,
									'approval',
									undefined,
									approvalInfo,
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

			// Hard block eth_sign — always CRITICAL, requires typed confirmation
			if (args.method === 'eth_sign') {
				const blindSigInfo = parseBlindSignature('eth_sign', args.params as unknown[]);

				if (!blindSigInfo) {
					// Fail-closed: block malformed eth_sign requests entirely
					console.warn('[Testudo] eth_sign blocked — malformed parameters');
					throw new Error('Testudo: eth_sign blocked — malformed parameters');
				}

				console.log('[Testudo] eth_sign detected — CRITICAL: deprecated method signs raw hashes');

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

				const userConfirmed = await showWarning(
					syntheticAnalysis,
					'eth-sign-danger',
					undefined,
					undefined,
					undefined,
					blindSigInfo,
				);

				if (!userConfirmed) {
					throw new Error('Testudo: eth_sign blocked by user — deprecated method rejected');
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

					const userConfirmed = await showWarning(
						syntheticAnalysis,
						'blind-signature',
						undefined,
						undefined,
						undefined,
						blindSigInfo,
					);

					if (!userConfirmed) {
						throw new Error(
							`Testudo: ${blindSigInfo.type} blocked by user - blind signature rejected`,
						);
					}
				}

				return originalRequest(args);
			}

			// Intercept eth_signTypedData v3/v4 for EIP-7702, Permit, and address scanning
			if (args.method !== 'eth_signTypedData_v4' && args.method !== 'eth_signTypedData_v3') {
				return originalRequest(args);
			}

			try {
				// Parse the typed data
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
							const userConfirmed = await showWarning(analysis, 'permit', permitInfo);
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
							const userConfirmed = await showWarning(syntheticAnalysis, 'permit', permitInfo);
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

								const userConfirmed = await showWarning(
									syntheticAnalysis,
									'typed-data-scan',
									undefined,
									undefined,
									undefined,
									undefined,
									scanInfo,
								);

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

				console.log('[Testudo] 🔍 EIP-7702 authorization detected!');
				const delegateAddress = typedData.message.address as string;
				console.log('[Testudo] Delegate address:', delegateAddress);

				// Request analysis from background script
				const analysis = await requestAnalysis(delegateAddress);

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

function isPermitSignature(typedData: TypedDataMessage): boolean {
	const pt = typedData.primaryType;
	return (
		pt === 'Permit' ||
		pt === 'PermitSingle' ||
		pt === 'PermitBatch' ||
		pt === 'PermitTransferFrom' ||
		pt === 'PermitWitnessTransferFrom'
	);
}

function validateAddress(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	if (!/^0x[a-fA-F0-9]{40}$/.test(value)) return null;
	return value.toLowerCase();
}

interface ExtractedAddress {
	address: string;
	fieldPath: string;
}

function extractTypedDataAddresses(typedData: TypedDataMessage): ExtractedAddress[] {
	const results: ExtractedAddress[] = [];
	const seen = new Set<string>();
	const MAX_DEPTH = 10;
	const MAX_ADDRESSES = 100;

	const verifyingContract = validateAddress(typedData.domain?.verifyingContract);
	if (verifyingContract) {
		seen.add(verifyingContract);
		results.push({ address: verifyingContract, fieldPath: 'domain.verifyingContract' });
	}

	const typeMap = typedData.types as Record<string, Array<{ name: string; type: string }>>;

	function walk(value: unknown, typeName: string, path: string, depth: number): void {
		if (depth > MAX_DEPTH || results.length >= MAX_ADDRESSES) return;
		if (typeName === 'EIP712Domain') return;

		const fields = typeMap[typeName];
		if (!Array.isArray(fields) || typeof value !== 'object' || value === null) return;

		for (const field of fields) {
			const fieldValue = (value as Record<string, unknown>)[field.name];
			const fieldPath = path ? `${path}.${field.name}` : field.name;

			if (field.type === 'address') {
				const addr = validateAddress(fieldValue);
				if (addr && !seen.has(addr)) {
					seen.add(addr);
					results.push({ address: addr, fieldPath });
				}
			} else if (field.type === 'address[]' && Array.isArray(fieldValue)) {
				for (let i = 0; i < fieldValue.length && results.length < MAX_ADDRESSES; i++) {
					const addr = validateAddress(fieldValue[i]);
					if (addr && !seen.has(addr)) {
						seen.add(addr);
						results.push({ address: addr, fieldPath: `${fieldPath}[${i}]` });
					}
				}
			} else if (field.type.endsWith('[]')) {
				const baseType = field.type.slice(0, -2);
				if (typeMap[baseType] && Array.isArray(fieldValue)) {
					for (let i = 0; i < fieldValue.length && results.length < MAX_ADDRESSES; i++) {
						walk(fieldValue[i], baseType, `${fieldPath}[${i}]`, depth + 1);
					}
				}
			} else if (typeMap[field.type]) {
				walk(fieldValue, field.type, fieldPath, depth + 1);
			}
		}
	}

	walk(typedData.message, typedData.primaryType, 'message', 0);

	return results;
}

function isDaiPermit(typedData: TypedDataMessage): boolean {
	const fields = typedData.types[typedData.primaryType] as Array<{ name: string }> | undefined;
	if (!Array.isArray(fields)) return false;
	return fields.some((f) => f.name === 'holder') && fields.some((f) => f.name === 'allowed');
}

function extractPermitInfo(typedData: TypedDataMessage): PermitInfo | null {
	const { primaryType, message, domain } = typedData;

	if (primaryType === 'Permit') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const dai = isDaiPermit(typedData);
		return {
			type: dai ? 'dai-permit' : 'permit',
			spender,
			value: dai ? (message.allowed === true ? 'unlimited' : '0') : String(message.value ?? ''),
			deadline:
				message.deadline != null
					? String(message.deadline)
					: message.expiry != null
						? String(message.expiry)
						: undefined,
			token: domain?.verifyingContract,
			tokenName: domain?.name,
		};
	}

	if (primaryType === 'PermitSingle') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const details = message.details as Record<string, unknown> | undefined;
		return {
			type: 'permit2-single',
			spender,
			value: details?.amount != null ? String(details.amount) : undefined,
			deadline: message.sigDeadline != null ? String(message.sigDeadline) : undefined,
			token: typeof details?.token === 'string' ? details.token : undefined,
		};
	}

	if (primaryType === 'PermitBatch') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const details = message.details as Array<Record<string, unknown>> | undefined;
		if (!Array.isArray(details) || details.length === 0) return null;
		const hasUnlimited = details.some((d) =>
			isUnlimitedValue(d.amount != null ? String(d.amount) : undefined),
		);
		return {
			type: 'permit2-batch',
			spender,
			deadline: message.sigDeadline != null ? String(message.sigDeadline) : undefined,
			token: typeof details[0]?.token === 'string' ? details[0].token : undefined,
			value: hasUnlimited ? 'unlimited' : 'batch',
		};
	}

	if (primaryType === 'PermitTransferFrom' || primaryType === 'PermitWitnessTransferFrom') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const permitted = message.permitted as Record<string, unknown> | undefined;
		return {
			type: primaryType === 'PermitTransferFrom' ? 'permit2-transfer' : 'permit2-witness-transfer',
			spender,
			value: permitted?.amount != null ? String(permitted.amount) : undefined,
			deadline: message.deadline != null ? String(message.deadline) : undefined,
			token: typeof permitted?.token === 'string' ? permitted.token : undefined,
		};
	}

	return null;
}

const MAX_UINT256 = '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
const MAX_UINT160 = '0xffffffffffffffffffffffffffffffffffffffff';

function isUnlimitedValue(value?: string): boolean {
	if (!value) return false;
	const normalized = value.toLowerCase();
	if (normalized === MAX_UINT256 || normalized === MAX_UINT160 || normalized === 'unlimited')
		return true;
	if (/[eE]/.test(value)) {
		const num = Number(value);
		if (!Number.isNaN(num) && num > 1e30) return true;
	}
	try {
		return BigInt(value) > BigInt(10) ** BigInt(30);
	} catch {
		return false;
	}
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

interface BatchCheckResult {
	malicious: ExtractedAddress[];
	results: Map<string, AnalysisResult>;
}

async function batchCheckAddresses(addresses: ExtractedAddress[]): Promise<BatchCheckResult> {
	const uniqueMap = new Map<string, ExtractedAddress[]>();
	for (const entry of addresses) {
		const key = entry.address.toLowerCase();
		if (!uniqueMap.has(key)) uniqueMap.set(key, []);
		uniqueMap.get(key)?.push(entry);
	}

	const results = new Map<string, AnalysisResult>();
	const malicious: ExtractedAddress[] = [];

	const checks = Array.from(uniqueMap.entries()).map(async ([addr, entries]) => {
		try {
			const result = await requestAddressCheck(addr);
			results.set(addr, result);
			if (result.risk === 'CRITICAL' || result.risk === 'HIGH') {
				malicious.push(...entries);
			}
		} catch {
			// fail-open: treat check failure as UNKNOWN
		}
	});

	await Promise.all(checks);

	return { malicious, results };
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
		nft_full_collection_access: 'collections',
		eth_sign_deprecated: 'dangerous',
		blind_signature: 'visibility_off',
		airdrop_scam: 'card_giftcard',
		verification_scam: 'verified_user',
		urgency: 'timer',
		impersonation: 'person_alert',
		financial_lure: 'payments',
		typed_data_malicious_address: 'gpp_bad',
		ETH_AUTO_FORWARDER: 'currency_exchange',
		INFERNO_DRAINER: 'local_fire_department',
	};
	return iconMap[threat] || 'warning';
}

/**
 * Show warning modal for dangerous contracts
 */
interface TypedDataScanInfo {
	maliciousAddresses: ExtractedAddress[];
	primaryType: string;
	domainName?: string;
}

function showWarning(
	analysis: AnalysisResult,
	context:
		| 'delegation'
		| 'transaction'
		| 'permit'
		| 'approval'
		| 'nft-approval'
		| 'blind-signature'
		| 'typed-data-scan'
		| 'eth-sign-danger' = 'delegation',
	permitInfo?: PermitInfo,
	approvalInfo?: ApprovalInfo,
	nftApprovalInfo?: NftApprovalInfo,
	blindSignatureInfo?: BlindSignatureInfo,
	typedDataScanInfo?: TypedDataScanInfo,
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

        /* Medium severity alert (amber instead of red) */
        .testudo-alert-medium {
          border-color: rgba(245, 158, 11, 0.4);
          background: rgba(245, 158, 11, 0.1);
        }

        .testudo-alert-medium::before {
          background: linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, transparent 100%);
        }

        .testudo-alert-medium .testudo-alert-header {
          color: #f59e0b;
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

        .testudo-confirm-section {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .testudo-confirm-label {
          font-size: 13px;
          color: #97adc4;
          font-weight: 500;
        }

        .testudo-confirm-input {
          width: 100%;
          background: #121a21;
          border: 1px solid rgba(231, 76, 60, 0.3);
          border-radius: 6px;
          padding: 12px;
          font-size: 14px;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          color: #fff;
          outline: none;
          transition: border-color 0.2s;
          box-sizing: border-box;
        }

        .testudo-confirm-input:focus {
          border-color: rgba(231, 76, 60, 0.6);
        }

        .testudo-confirm-input::placeholder {
          color: rgba(151, 173, 196, 0.5);
        }

        .testudo-btn-danger-confirm {
          width: 100%;
          background: rgba(231, 76, 60, 0.15);
          color: rgba(231, 76, 60, 0.4);
          border: 1px solid rgba(231, 76, 60, 0.2);
          border-radius: 8px;
          padding: 14px 24px;
          font-size: 15px;
          font-weight: 600;
          cursor: not-allowed;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: all 0.2s;
        }

        .testudo-btn-danger-confirm.enabled {
          background: rgba(231, 76, 60, 0.9);
          color: #fff;
          border-color: #e74c3c;
          cursor: pointer;
        }

        .testudo-btn-danger-confirm.enabled:hover {
          background: #e74c3c;
        }
      </style>

      <div class="testudo-modal">
        <!-- Header -->
        <div class="testudo-header">
          <div class="testudo-header-icon">
            <span class="testudo-material-icon">gpp_maybe</span>
          </div>
          <div class="testudo-header-text">
            <h2 class="testudo-title">${context === 'eth-sign-danger' ? 'Dangerous: eth_sign Detected' : context === 'blind-signature' ? (analysis.risk === 'HIGH' ? 'Suspicious Message Detected' : 'Blind Signature Request') : context === 'typed-data-scan' ? 'Malicious Address in Signed Data' : context === 'nft-approval' ? 'NFT Collection Approval Detected' : context === 'approval' ? 'Token Approval Detected' : context === 'permit' ? 'Permit Signature Detected' : context === 'transaction' ? 'Malicious Recipient Detected' : 'Dangerous Contract Detected'}</h2>
            <p class="testudo-subtitle">
              ${context === 'eth-sign-danger' ? '<strong>eth_sign</strong> is deprecated and signs raw hashes. An attacker can craft a valid <strong>transaction hash</strong> — signing it gives them full control of your wallet.' : context === 'blind-signature' ? (analysis.risk === 'HIGH' ? 'This message contains <strong>phishing patterns</strong> commonly used in scams.' : 'You are signing <strong>arbitrary data</strong> that cannot be verified.') : context === 'typed-data-scan' ? 'A <strong>known malicious address</strong> was found in the data you are about to sign.' : context === 'nft-approval' ? 'You are granting <strong>full collection access</strong> to another address.' : context === 'approval' ? 'You are granting <strong>token spending rights</strong> to another address.' : context === 'permit' ? 'This signature grants <strong>token spending rights</strong>!' : context === 'transaction' ? 'You are about to send funds to a <strong>known scammer</strong> address.' : 'We have intercepted a malicious <strong>EIP-7702</strong> delegation request.'}
            </p>
          </div>
        </div>

        <!-- Alert Box -->
        <div class="testudo-alert${analysis.risk === 'MEDIUM' ? ' testudo-alert-medium' : ''}">
          <div class="testudo-alert-header">
            <span class="testudo-material-icon">${analysis.risk === 'MEDIUM' ? 'info' : 'error'}</span>
            <span class="testudo-alert-title">${analysis.risk}: ${escapeHtml(criticalTitle)}</span>
          </div>
          <p class="testudo-alert-description">
            ${escapeHtml(criticalDescription)}
          </p>
        </div>

        ${
					permitInfo
						? `
        <!-- Permit Details -->
        <div class="testudo-address-section">
          ${permitInfo.tokenName ? `<div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Token</span><span class="testudo-address-text">${escapeHtml(permitInfo.tokenName)}${permitInfo.token ? ` (${permitInfo.token.slice(0, 8)}...)` : ''}</span></div>` : ''}
          <div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Amount</span><span class="testudo-address-text" style="${isUnlimitedValue(permitInfo.value) ? 'color:#e74c3c;font-weight:700' : ''}">${isUnlimitedValue(permitInfo.value) ? 'UNLIMITED' : permitInfo.value === 'batch' ? 'Batch (multiple tokens)' : (permitInfo.value || 'Unknown')}</span></div>
          ${permitInfo.deadline ? `<div class="testudo-address-box"><span class="testudo-address-label">Deadline</span><span class="testudo-address-text">${escapeHtml(String(permitInfo.deadline))}</span></div>` : ''}
        </div>
        `
						: ''
				}

        ${
					approvalInfo
						? `
        <!-- Approval Details -->
        <div class="testudo-address-section">
          <div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Token Contract</span><span class="testudo-address-text">${approvalInfo.tokenAddress.slice(0, 10)}...${approvalInfo.tokenAddress.slice(-6)}</span></div>
          <div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Amount</span><span class="testudo-address-text" style="${isUnlimitedValue(approvalInfo.amount) ? 'color:#e74c3c;font-weight:700' : ''}">${formatApprovalAmount(approvalInfo.amount)}</span></div>
          <div class="testudo-address-box"><span class="testudo-address-label">Operation</span><span class="testudo-address-text">${approvalInfo.type === 'approve' ? 'approve()' : approvalInfo.type === 'increaseAllowance' ? 'increaseAllowance()' : 'decreaseAllowance()'}</span></div>
        </div>
        `
						: ''
				}

        ${
					nftApprovalInfo
						? `
        <!-- NFT Approval Details -->
        <div class="testudo-address-section">
          <div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Collection</span><span class="testudo-address-text">${nftApprovalInfo.collectionAddress.slice(0, 10)}...${nftApprovalInfo.collectionAddress.slice(-6)}</span></div>
          <div class="testudo-address-box"><span class="testudo-address-label">Access Level</span><span class="testudo-address-text" style="color:#e74c3c;font-weight:700">FULL COLLECTION</span></div>
        </div>
        `
						: ''
				}

        ${
					blindSignatureInfo
						? `
        <!-- Blind Signature Details -->
        <div class="testudo-address-section">
          <div class="testudo-address-box" style="margin-bottom:6px">
            <span class="testudo-address-label">Method</span>
            <span class="testudo-address-text">${blindSignatureInfo.type}</span>
          </div>
          <div class="testudo-address-box" style="margin-bottom:6px">
            <span class="testudo-address-label">Message${blindSignatureInfo.isHex ? ' (hex)' : ''}</span>
            <span class="testudo-address-text" style="font-family:monospace;font-size:12px;word-break:break-all">${escapeHtml(blindSignatureInfo.messagePreview)}</span>
          </div>
        </div>
        `
						: ''
				}

        ${
					typedDataScanInfo
						? `
        <!-- Typed Data Scan Details -->
        <div class="testudo-address-section">
          <div class="testudo-address-box" style="margin-bottom:6px">
            <span class="testudo-address-label">Primary Type</span>
            <span class="testudo-address-text">${escapeHtml(typedDataScanInfo.primaryType)}</span>
          </div>
          ${typedDataScanInfo.domainName ? `<div class="testudo-address-box" style="margin-bottom:6px"><span class="testudo-address-label">Domain</span><span class="testudo-address-text">${escapeHtml(typedDataScanInfo.domainName)}</span></div>` : ''}
          ${typedDataScanInfo.maliciousAddresses
						.slice(0, 3)
						.map(
							(a) => `
            <div class="testudo-address-box" style="margin-bottom:6px">
              <span class="testudo-address-label">Found in: ${escapeHtml(a.fieldPath)}</span>
              <span class="testudo-address-text" style="color:#e74c3c">${a.address.slice(0, 10)}...${a.address.slice(-6)}</span>
            </div>`,
						)
						.join('')}
        </div>
        `
						: ''
				}

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
            <span class="testudo-address-label">${context === 'eth-sign-danger' ? 'Signer Address' : context === 'blind-signature' ? 'Signer Address' : context === 'typed-data-scan' ? 'Malicious Address' : context === 'nft-approval' ? 'Operator Address' : context === 'approval' ? 'Spender Address' : context === 'permit' ? 'Spender Address' : context === 'transaction' ? 'Recipient Address' : 'Target Contract'}</span>
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
          ${
						context === 'eth-sign-danger'
							? `
          <div class="testudo-confirm-section">
            <label class="testudo-confirm-label" for="testudo-confirm-input">Type <strong style="color:#e74c3c">I ACCEPT THE RISK</strong> to proceed</label>
            <input type="text" class="testudo-confirm-input" id="testudo-confirm-input" placeholder="I ACCEPT THE RISK" autocomplete="off" spellcheck="false" />
            <button class="testudo-btn-danger-confirm" id="testudo-eth-sign-proceed" disabled>
              <span class="testudo-material-icon">warning</span>
              Proceed with eth_sign
            </button>
          </div>
          `
							: `
          <div class="testudo-secondary-actions">
            <button class="testudo-btn-link" id="testudo-trust">
              Trust contract & Proceed
            </button>
            <button class="testudo-btn-danger" id="testudo-proceed">
              <span>Proceed Anyway</span>
              <span class="testudo-material-icon">arrow_forward</span>
            </button>
          </div>
          `
					}
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

		// eth_sign typed confirmation handler
		const confirmInput = document.getElementById(
			'testudo-confirm-input',
		) as HTMLInputElement | null;
		const ethSignProceed = document.getElementById('testudo-eth-sign-proceed');
		if (confirmInput && ethSignProceed) {
			confirmInput.addEventListener('input', () => {
				const matches = confirmInput.value.trim().toUpperCase() === 'I ACCEPT THE RISK';
				if (matches) {
					ethSignProceed.classList.add('enabled');
					ethSignProceed.removeAttribute('disabled');
				} else {
					ethSignProceed.classList.remove('enabled');
					ethSignProceed.setAttribute('disabled', 'true');
				}
			});

			ethSignProceed.addEventListener('click', () => {
				if (confirmInput.value.trim().toUpperCase() !== 'I ACCEPT THE RISK') return;
				document.removeEventListener('keydown', escapeHandler);
				overlay.remove();
				resolve(true);
			});

			confirmInput.focus();
		}
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
		nft_full_collection_access: 'Grants control over ALL NFTs in this collection',
		eth_sign_deprecated: 'eth_sign is deprecated and signs raw hashes without safety prefix',
		blind_signature: 'Signing arbitrary data without visibility into its purpose',
		airdrop_scam: 'Message contains airdrop/reward scam language',
		verification_scam: 'Message impersonates wallet verification request',
		urgency: 'Message uses urgency pressure tactics',
		impersonation: 'Message impersonates a known brand or protocol',
		financial_lure: 'Message contains financial lure language',
		typed_data_malicious_address: 'A known malicious address is embedded in the signed data',
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
		nft_full_collection_access: 'Full NFT collection access',
		eth_sign_deprecated: 'Deprecated: eth_sign',
		blind_signature: 'Blind signature',
		airdrop_scam: 'Airdrop scam pattern',
		verification_scam: 'Verification scam pattern',
		urgency: 'Urgency pressure tactic',
		impersonation: 'Brand impersonation',
		financial_lure: 'Financial lure',
		typed_data_malicious_address: 'Malicious address in signed data',
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
