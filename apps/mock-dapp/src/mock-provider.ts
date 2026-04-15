/**
 * Mock Ethereum Provider for Testing
 *
 * Provides a minimal window.ethereum that triggers EIP-7702 delegation requests.
 * The injected script from the Testudo extension will intercept these.
 */

// Known addresses from @testudo/core
export const MALICIOUS_ADDRESS = '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b';
export const SAFE_ADDRESS = '0x63c0c19a282a1b52b07dd5a65b58948a07dae32b';
export const CDN_SAFE_ADDRESS = '0x1111111111111111111111111111111111111111';
export const API_ONLY_MALICIOUS_ADDRESS = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

// EIP-7702 Authorization typed data structure
export interface EIP7702TypedData {
	types: {
		EIP712Domain: Array<{ name: string; type: string }>;
		Authorization: Array<{ name: string; type: string }>;
	};
	primaryType: string;
	domain: {
		name: string;
		version: string;
		chainId: number;
	};
	message: {
		chainId: string;
		address: string;
		nonce: string;
	};
}

// Create EIP-7702 Authorization typed data
export function createAuthorizationTypedData(delegateAddress: string): EIP7702TypedData {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
			],
			Authorization: [
				{ name: 'chainId', type: 'uint256' },
				{ name: 'address', type: 'address' },
				{ name: 'nonce', type: 'uint256' },
			],
		},
		primaryType: 'Authorization',
		domain: {
			name: 'EIP-7702 Authorization',
			version: '1',
			chainId: 1,
		},
		message: {
			chainId: '1',
			address: delegateAddress,
			nonce: '0',
		},
	};
}

// Request arguments type
interface RequestArgs {
	method: string;
	params?: unknown[];
}

// Mock provider type
interface MockProvider {
	isMetaMask: boolean;
	request: (args: RequestArgs) => Promise<unknown>;
}

// Initialize mock ethereum provider
export function initMockProvider(): void {
	const mockProvider: MockProvider = {
		isMetaMask: true,

		request: async (args: RequestArgs): Promise<unknown> => {
			console.log('[Mock Provider] Request:', args.method, args.params);

			if (args.method === 'eth_requestAccounts' || args.method === 'eth_accounts') {
				return ['0x1234567890123456789012345678901234567890'];
			}

			if (args.method === 'eth_chainId') {
				return '0x1';
			}

			if (args.method === 'eth_signTypedData_v4') {
				const params = args.params as [string, string];
				const typedDataString = params[1];
				const typedData =
					typeof typedDataString === 'string' ? JSON.parse(typedDataString) : typedDataString;

				console.log('[Mock Provider] Typed data:', typedData);

				return `0x${'00'.repeat(65)}`;
			}

			if (args.method === 'eth_sendTransaction') {
				const txParams = (args.params as Record<string, string>[])?.[0];
				console.log('[Mock Provider] Transaction:', txParams);
				return `0x${'ab'.repeat(32)}`;
			}

			if (args.method === 'personal_sign') {
				const params = args.params as [string, string];
				console.log('[Mock Provider] personal_sign:', { message: params[0], address: params[1] });
				return `0x${'cd'.repeat(65)}`;
			}

			if (args.method === 'eth_sign') {
				const params = args.params as [string, string];
				console.log('[Mock Provider] eth_sign:', { address: params[0], message: params[1] });
				return `0x${'ef'.repeat(65)}`;
			}

			throw new Error(`Unsupported method: ${args.method}`);
		},
	};

	// Simple assignment triggers Testudo's setter trap on window.ethereum.
	// Using Object.defineProperty would bypass the setter (installs a data
	// descriptor over an accessor descriptor), breaking extension integration.
	// If another wallet extension's proxy overrides us (e.g. Polkadot.js),
	// we re-apply via simple assignment so Testudo's setter fires again.
	function applyProvider(): void {
		(window as unknown as { ethereum: MockProvider }).ethereum = mockProvider;
	}

	applyProvider();

	queueMicrotask(() => {
		if ((window as unknown as { ethereum: MockProvider }).ethereum !== mockProvider) {
			console.log('[Mock Provider] Re-applying after proxy override');
			applyProvider();
		}
	});

	setTimeout(() => {
		if ((window as unknown as { ethereum: MockProvider }).ethereum !== mockProvider) {
			console.log('[Mock Provider] Re-applying after async proxy override');
			applyProvider();
		}
	}, 50);

	console.log('[Mock Provider] Initialized with EIP-7702 support');
}

export async function sendTransaction(toAddress: string): Promise<string> {
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_sendTransaction',
		params: [
			{
				from: '0x1234567890123456789012345678901234567890',
				to: toAddress,
				value: '0xde0b6b3a7640000',
			},
		],
	});

	return result as string;
}

export function createPermitTypedData(spenderAddress: string): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			Permit: [
				{ name: 'owner', type: 'address' },
				{ name: 'spender', type: 'address' },
				{ name: 'value', type: 'uint256' },
				{ name: 'nonce', type: 'uint256' },
				{ name: 'deadline', type: 'uint256' },
			],
		},
		primaryType: 'Permit',
		domain: {
			name: 'USD Coin',
			version: '2',
			chainId: 1,
			verifyingContract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
		},
		message: {
			owner: '0x1234567890123456789012345678901234567890',
			spender: spenderAddress,
			value: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
			nonce: '0',
			deadline: '1735689600',
		},
	};
}

export function createPermit2TypedData(spenderAddress: string): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			PermitSingle: [
				{ name: 'details', type: 'PermitDetails' },
				{ name: 'spender', type: 'address' },
				{ name: 'sigDeadline', type: 'uint256' },
			],
			PermitDetails: [
				{ name: 'token', type: 'address' },
				{ name: 'amount', type: 'uint160' },
				{ name: 'expiration', type: 'uint48' },
				{ name: 'nonce', type: 'uint48' },
			],
		},
		primaryType: 'PermitSingle',
		domain: {
			name: 'Permit2',
			chainId: 1,
			verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3',
		},
		message: {
			details: {
				token: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
				amount: '1000000',
				expiration: '1735689600',
				nonce: '0',
			},
			spender: spenderAddress,
			sigDeadline: '1735689600',
		},
	};
}

export function createPermitTransferFromTypedData(spenderAddress: string): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			PermitTransferFrom: [
				{ name: 'permitted', type: 'TokenPermissions' },
				{ name: 'spender', type: 'address' },
				{ name: 'nonce', type: 'uint256' },
				{ name: 'deadline', type: 'uint256' },
			],
			TokenPermissions: [
				{ name: 'token', type: 'address' },
				{ name: 'amount', type: 'uint256' },
			],
		},
		primaryType: 'PermitTransferFrom',
		domain: {
			name: 'Permit2',
			chainId: 1,
			verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3',
		},
		message: {
			permitted: {
				token: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
				amount: '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
			},
			spender: spenderAddress,
			nonce: '0',
			deadline: '1735689600',
		},
	};
}

export async function signPermitTransferFrom(spenderAddress: string): Promise<string> {
	const typedData = createPermitTransferFromTypedData(spenderAddress);
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}

export async function signPermit(spenderAddress: string): Promise<string> {
	const typedData = createPermitTypedData(spenderAddress);
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}

export async function signPermit2(spenderAddress: string): Promise<string> {
	const typedData = createPermit2TypedData(spenderAddress);
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}

export async function signDelegation(delegateAddress: string): Promise<string> {
	const typedData = createAuthorizationTypedData(delegateAddress);
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}

export async function sendApproval(
	tokenAddress: string,
	spenderAddress: string,
	unlimited = true,
): Promise<string> {
	const amount = unlimited
		? 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
		: '0000000000000000000000000000000000000000000000000de0b6b3a7640000';

	const data = `0x095ea7b3${spenderAddress.slice(2).toLowerCase().padStart(64, '0')}${amount}`;

	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_sendTransaction',
		params: [
			{
				from: '0x1234567890123456789012345678901234567890',
				to: tokenAddress,
				data,
			},
		],
	});

	return result as string;
}

export async function sendIncreaseAllowance(
	tokenAddress: string,
	spenderAddress: string,
	unlimited = true,
): Promise<string> {
	const amount = unlimited
		? 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
		: '0000000000000000000000000000000000000000000000000de0b6b3a7640000';

	const data = `0x39509351${spenderAddress.slice(2).toLowerCase().padStart(64, '0')}${amount}`;

	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_sendTransaction',
		params: [
			{
				from: '0x1234567890123456789012345678901234567890',
				to: tokenAddress,
				data,
			},
		],
	});

	return result as string;
}

export async function sendApprovalRevocation(
	tokenAddress: string,
	spenderAddress: string,
): Promise<string> {
	const zeroAmount = '0000000000000000000000000000000000000000000000000000000000000000';

	const data = `0x095ea7b3${spenderAddress.slice(2).toLowerCase().padStart(64, '0')}${zeroAmount}`;

	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_sendTransaction',
		params: [
			{
				from: '0x1234567890123456789012345678901234567890',
				to: tokenAddress,
				data,
			},
		],
	});

	return result as string;
}

export async function sendSetApprovalForAll(
	collectionAddress: string,
	operatorAddress: string,
	approved = true,
): Promise<string> {
	const approvedValue = approved
		? '0000000000000000000000000000000000000000000000000000000000000001'
		: '0000000000000000000000000000000000000000000000000000000000000000';

	const data = `0xa22cb465${operatorAddress.slice(2).toLowerCase().padStart(64, '0')}${approvedValue}`;

	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_sendTransaction',
		params: [
			{
				from: '0x1234567890123456789012345678901234567890',
				to: collectionAddress,
				data,
			},
		],
	});

	return result as string;
}

export async function signPersonalMessage(message: string): Promise<string> {
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;
	const account = '0x1234567890123456789012345678901234567890';

	const result = await ethereum.request({
		method: 'personal_sign',
		params: [message, account],
	});

	return result as string;
}

export async function signEthMessage(message: string): Promise<string> {
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;
	const account = '0x1234567890123456789012345678901234567890';

	const result = await ethereum.request({
		method: 'eth_sign',
		params: [account, message],
	});

	return result as string;
}

export function createTypedDataWithMaliciousAddress(): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			Transfer: [
				{ name: 'from', type: 'address' },
				{ name: 'to', type: 'address' },
				{ name: 'amount', type: 'uint256' },
				{ name: 'nonce', type: 'uint256' },
			],
		},
		primaryType: 'Transfer',
		domain: {
			name: 'Test Token',
			version: '1',
			chainId: 1,
			verifyingContract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
		},
		message: {
			from: '0x1234567890123456789012345678901234567890',
			to: MALICIOUS_ADDRESS,
			amount: '1000000000000000000',
			nonce: '0',
		},
	};
}

export function createTypedDataCleanAddresses(): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			Transfer: [
				{ name: 'from', type: 'address' },
				{ name: 'to', type: 'address' },
				{ name: 'amount', type: 'uint256' },
				{ name: 'nonce', type: 'uint256' },
			],
		},
		primaryType: 'Transfer',
		domain: {
			name: 'Test Token',
			version: '1',
			chainId: 1,
			verifyingContract: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
		},
		message: {
			from: '0x1234567890123456789012345678901234567890',
			to: SAFE_ADDRESS,
			amount: '1000000000000000000',
			nonce: '0',
		},
	};
}

export function createSeaportOrderTypedData(): Record<string, unknown> {
	return {
		types: {
			EIP712Domain: [
				{ name: 'name', type: 'string' },
				{ name: 'version', type: 'string' },
				{ name: 'chainId', type: 'uint256' },
				{ name: 'verifyingContract', type: 'address' },
			],
			OrderComponents: [
				{ name: 'offerer', type: 'address' },
				{ name: 'zone', type: 'address' },
				{ name: 'orderType', type: 'uint8' },
				{ name: 'startTime', type: 'uint256' },
				{ name: 'endTime', type: 'uint256' },
				{ name: 'salt', type: 'uint256' },
				{ name: 'conduitKey', type: 'bytes32' },
				{ name: 'counter', type: 'uint256' },
			],
		},
		primaryType: 'OrderComponents',
		domain: {
			name: 'Seaport',
			version: '1.5',
			chainId: 1,
			verifyingContract: '0x00000000000000adc04c56bf30ac9d3c0aaf14dc',
		},
		message: {
			offerer: '0x1234567890123456789012345678901234567890',
			zone: '0x0000000000000000000000000000000000000000',
			orderType: 0,
			startTime: '1700000000',
			endTime: '1800000000',
			salt: '12345',
			conduitKey: '0x0000000000000000000000000000000000000000000000000000000000000000',
			counter: '0',
		},
	};
}

export async function signGenericTypedData(typedData: Record<string, unknown>): Promise<string> {
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}
