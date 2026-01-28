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

			if (args.method === 'eth_requestAccounts') {
				return ['0x1234567890123456789012345678901234567890'];
			}

			if (args.method === 'eth_signTypedData_v4') {
				// The extension's injected script will intercept this
				// and potentially show a warning modal
				const params = args.params as [string, string];
				const typedDataString = params[1];
				const typedData =
					typeof typedDataString === 'string' ? JSON.parse(typedDataString) : typedDataString;

				console.log('[Mock Provider] Typed data:', typedData);

				// Simulate successful signature if extension allows it
				return `0x${'00'.repeat(65)}`;
			}

			if (args.method === 'eth_sendTransaction') {
				const txParams = (args.params as Record<string, string>[])?.[0];
				console.log('[Mock Provider] Transaction:', txParams);
				return `0x${'ab'.repeat(32)}`;
			}

			throw new Error(`Unsupported method: ${args.method}`);
		},
	};

	// Assign to window
	(window as unknown as { ethereum: MockProvider }).ethereum = mockProvider;

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

export async function signDelegation(delegateAddress: string): Promise<string> {
	const typedData = createAuthorizationTypedData(delegateAddress);
	const ethereum = (window as unknown as { ethereum: MockProvider }).ethereum;

	const result = await ethereum.request({
		method: 'eth_signTypedData_v4',
		params: ['0x1234567890123456789012345678901234567890', JSON.stringify(typedData)],
	});

	return result as string;
}
