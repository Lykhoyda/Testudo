import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const DEFAULT_RPC = 'https://eth.llamarpc.com';

let cachedClient: ReturnType<typeof createPublicClient> | null = null;
let cachedRpcUrl: string | null = null;

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

	const bytecode = await client.getCode({
		address: address as `0x${string}`,
	});

	return bytecode === '0x' ? null : (bytecode as `0x${string}`);
}
