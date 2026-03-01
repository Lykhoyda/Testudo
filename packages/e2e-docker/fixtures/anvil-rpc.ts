export const ANVIL_RPC = 'http://localhost:8545';
export const ANVIL_ACCOUNT_0 = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

async function rpcCall(method: string, params: unknown[]): Promise<string> {
	const res = await fetch(ANVIL_RPC, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
	});
	const json = (await res.json()) as {
		result?: string;
		error?: { code: number; message: string };
	};
	if (json.error) {
		throw new Error(`RPC error calling ${method}: ${json.error.message}`);
	}
	if (json.result === undefined || json.result === null) {
		throw new Error(`RPC returned no result for ${method}`);
	}
	return json.result;
}

export async function getEthBalance(address: string): Promise<bigint> {
	const hex = await rpcCall('eth_getBalance', [address, 'latest']);
	return BigInt(hex);
}

function encodeAddressArgs(selector: string, ...addresses: string[]): string {
	return selector + addresses.map((a) => a.slice(2).toLowerCase().padStart(64, '0')).join('');
}

export async function getTokenBalance(token: string, account: string): Promise<bigint> {
	const data = encodeAddressArgs('0x70a08231', account);
	const hex = await rpcCall('eth_call', [{ to: token, data }, 'latest']);
	if (hex === '0x' || hex === '') {
		throw new Error(`balanceOf returned empty data — is mock-erc20 deployed at ${token}?`);
	}
	return BigInt(hex);
}

export async function getTokenAllowance(token: string, owner: string, spender: string): Promise<bigint> {
	const data = encodeAddressArgs('0xdd62ed3e', owner, spender);
	const hex = await rpcCall('eth_call', [{ to: token, data }, 'latest']);
	if (hex === '0x' || hex === '') {
		throw new Error(`allowance returned empty data — is mock-erc20 deployed at ${token}?`);
	}
	return BigInt(hex);
}
