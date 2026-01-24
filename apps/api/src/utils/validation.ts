const ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

export function isValidAddress(address: string): boolean {
	return ADDRESS_REGEX.test(address);
}

export function normalizeAddress(address: string): string {
	return address.toLowerCase();
}

export function normalizeDomain(input: string): string {
	try {
		const urlStr = input.startsWith('http') ? input : `http://${input}`;
		const url = new URL(urlStr);
		return url.hostname.replace(/^www\./, '').toLowerCase();
	} catch {
		return input
			.replace(/^www\./, '')
			.replace(/\/.*$/, '')
			.toLowerCase()
			.trim();
	}
}

export function isValidDomain(domain: string): boolean {
	const normalized = normalizeDomain(domain);
	return normalized.length > 2 && normalized.includes('.') && !normalized.startsWith('.');
}
