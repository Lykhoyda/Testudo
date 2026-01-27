export interface RawSafeAddressEntry {
	address: string;
	chainId?: number;
	name?: string;
	category: string;
	isDelegationSafe?: boolean;
}

export interface AdapterResult<T> {
	source: string;
	entries: T[];
	fetchedAt: Date;
}
