import type { Address } from 'viem';
import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';
import { EIP1967_SLOTS } from './opcode';

const DEFAULT_RPC = 'https://eth.llamarpc.com';

let cachedClient: ReturnType<typeof createPublicClient> | null = null;
let cachedRpcUrl: string | null = null;

export class BytecodeFetchError extends Error {
	constructor(
		message: string,
		public readonly cause: unknown,
	) {
		super(message);
		this.name = 'BytecodeFetchError';
	}
}

function getClient(rpcUrl?: string): ReturnType<typeof createPublicClient> {
	const url = rpcUrl || DEFAULT_RPC;

	// Reuse cached client if RPC URL hasn't changed
	if (cachedClient && cachedRpcUrl === url) {
		return cachedClient;
	}

	cachedClient = createPublicClient({
		chain: mainnet,
		transport: http(url),
	});
	cachedRpcUrl = url;

	return cachedClient;
}

export async function fetchBytecode(address: string, rpcUrl?: string): Promise<string | null> {
	const client = getClient(rpcUrl);

	let bytecode: `0x${string}` | undefined;
	try {
		bytecode = await client.getCode({
			address: address as `0x${string}`,
		});
	} catch (err) {
		throw new BytecodeFetchError(
			`Failed to fetch bytecode for ${address}: ${err instanceof Error ? err.message : String(err)}`,
			err,
		);
	}

	return !bytecode || bytecode === '0x' ? null : (bytecode as `0x${string}`);
}

export async function resolveProxyImplementation(
	proxyAddress: Address,
	rpcUrl?: string,
): Promise<Address | null> {
	const client = getClient(rpcUrl);

	try {
		const slotValue = await client.getStorageAt({
			address: proxyAddress,
			slot: `0x${EIP1967_SLOTS.implementation}`,
		});

		if (!slotValue || slotValue === `0x${'0'.repeat(64)}`) {
			return null;
		}

		// Extract rightmost 20 bytes (address) from the 32-byte slot value
		const implAddress = `0x${slotValue.slice(-40)}` as Address;

		// Validate it's not the zero address
		if (implAddress === '0x0000000000000000000000000000000000000000') {
			return null;
		}

		return implAddress;
	} catch {
		return null;
	}
}
