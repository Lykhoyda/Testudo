import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const client = createPublicClient({
	chain: mainnet,
	transport: http('https://eth.llamarpc.com'),
});

export async function fetchBytecode(address: string): Promise<string | null> {
	const bytecode = await client.getCode({
		address: address as `0x${string}`,
	});

	return bytecode === '0x' ? null : (bytecode as `0x${string}`);
}
