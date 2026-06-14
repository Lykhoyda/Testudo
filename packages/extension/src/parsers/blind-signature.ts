import type { BlindSignatureInfo } from '../utils/types';

const MAX_DECODE_HEX = 4000; // bound decode work to 2000 bytes

export function isBlindSignature(method: string): boolean {
	return method === 'personal_sign';
}

// Control chars (excluding tab/newline/CR) and the UTF-8 replacement char (0xFFFD)
// mark binary content rather than a human-readable message.
function isBinaryNoise(code: number): boolean {
	return (
		code <= 0x08 ||
		code === 0x0b ||
		code === 0x0c ||
		(code >= 0x0e && code <= 0x1f) ||
		code === 0x7f ||
		code === 0xfffd
	);
}

function hexToBytes(message: string): Uint8Array | null {
	const clean = (message.startsWith('0x') ? message.slice(2) : message).slice(0, MAX_DECODE_HEX);
	if (clean.length === 0 || clean.length % 2 !== 0) return null;
	const bytes = new Uint8Array(clean.length / 2);
	for (let i = 0; i < bytes.length; i++) {
		const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
		if (Number.isNaN(byte)) return null;
		bytes[i] = byte;
	}
	return bytes;
}

// AUDIT-17: decode a hex personal_sign payload as UTF-8 and surface human-readable
// text. Clean text (no binary noise) is kept whole — including multi-byte chars —
// so it isn't mangled. Mixed binary/text payloads, which drainers use to smuggle
// phishing copy past naive scanners, have their printable substring extracted so
// downstream phishing detection still sees it.
function decodeHexMessage(message: string): string | null {
	const bytes = hexToBytes(message);
	if (!bytes) return null;
	const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

	let hasNoise = false;
	let printable = '';
	for (const ch of decoded) {
		if (isBinaryNoise(ch.codePointAt(0) ?? 0)) {
			hasNoise = true;
			if (!printable.endsWith(' ')) printable += ' ';
		} else {
			printable += ch;
		}
	}

	if (!hasNoise) return decoded;
	const collapsed = printable.replace(/\s+/g, ' ').trim();
	return collapsed.length >= 4 ? collapsed : null;
}

export function parseBlindSignature(method: string, params: unknown[]): BlindSignatureInfo | null {
	if (!Array.isArray(params) || params.length < 2) return null;

	const [first, second] = params;
	const message = method === 'personal_sign' ? String(first) : String(second);
	const signer = method === 'personal_sign' ? String(second) : String(first);

	if (!/^0x[a-fA-F0-9]{40}$/.test(signer)) return null;

	const isHex = /^0x[a-fA-F0-9]+$/.test(message);

	let decodedMessage = message;
	if (isHex && message.length > 2) {
		const decoded = decodeHexMessage(message);
		if (decoded !== null) decodedMessage = decoded;
	}

	let messagePreview = decodedMessage;
	if (messagePreview.length > 100) {
		messagePreview = `${messagePreview.slice(0, 97)}...`;
	}

	return {
		type: method as 'personal_sign' | 'eth_sign',
		message,
		decodedMessage,
		messagePreview,
		signer: signer.toLowerCase(),
		isHex,
	};
}
