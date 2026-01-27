export interface RawAddressEntry {
	address: string;
	chainId?: number;
	threatType?: string;
	threatLevel?: string;
}

export interface RawDomainEntry {
	domain: string;
	threatType?: string;
	isFuzzyMatch?: boolean;
	matchedLegitimate?: string | null;
}

export interface AdapterResult<T> {
	source: string;
	entries: T[];
	fetchedAt: Date;
}
