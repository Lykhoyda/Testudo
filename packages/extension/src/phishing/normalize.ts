import { getDomain } from 'tldts';

export interface NormalizedDomain {
	hostname: string;
	registrable: string;
	isIP: boolean;
}

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function isIPLiteral(hostname: string): boolean {
	if (hostname.startsWith('[') && hostname.endsWith(']')) {
		return true;
	}
	return IPV4_RE.test(hostname);
}

export function normalizeDomain(urlString: string): NormalizedDomain | null {
	let parsed: URL;
	try {
		parsed = new URL(urlString);
	} catch {
		return null;
	}

	if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
		return null;
	}

	let hostname = parsed.hostname.toLowerCase();

	hostname = hostname.replace(/\.$/, '');

	if (hostname.startsWith('www.')) {
		hostname = hostname.slice(4);
	}

	const isIP = isIPLiteral(hostname);

	if (isIP) {
		return { hostname, registrable: hostname, isIP: true };
	}

	const registrable =
		getDomain(hostname, { validHosts: [], allowPrivateDomains: true }) ?? hostname;

	return { hostname, registrable, isIP: false };
}
