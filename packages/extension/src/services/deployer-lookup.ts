import type { Address, PublicClient } from 'viem';

export interface DeployerStaticInfo {
	deployerAddress: string;
	deployerNonce: number;
	contractCreationTimestamp: number;
}

interface BlockscoutAddressResponse {
	creator_address_hash?: string;
	creation_transaction_hash?: string;
}

const BLOCKSCOUT_BASE = 'https://eth.blockscout.com';
const FETCH_TIMEOUT = 3_000;

export async function fetchDeployerStaticInfo(
	contractAddress: Address,
	client: PublicClient,
): Promise<DeployerStaticInfo | null> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT);
	try {
		const res = await fetch(`${BLOCKSCOUT_BASE}/api/v2/addresses/${contractAddress}`, {
			signal: controller.signal,
		});

		if (!res.ok) return null;

		const data: BlockscoutAddressResponse = await res.json();
		if (
			typeof data.creator_address_hash !== 'string' ||
			typeof data.creation_transaction_hash !== 'string'
		)
			return null;

		const creationTxHash = data.creation_transaction_hash as `0x${string}`;

		const [tx, receipt] = await Promise.all([
			client.getTransaction({ hash: creationTxHash }),
			client.getTransactionReceipt({ hash: creationTxHash }),
		]);

		const creationBlock = await client.getBlock({ blockNumber: receipt.blockNumber });

		return {
			deployerAddress: data.creator_address_hash,
			deployerNonce: tx.nonce,
			contractCreationTimestamp: Number(creationBlock.timestamp),
		};
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}
