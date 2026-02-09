import type { BlindSignatureInfo } from '../utils/types';

export function isBlindSignature(method: string): boolean {
	return method === 'personal_sign';
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
		try {
			const hexToDecode = message.slice(2, 4002);
			const bytes = hexToDecode.match(/.{1,2}/g);
			if (bytes) {
				const decoded = bytes.map((b) => String.fromCharCode(parseInt(b, 16))).join('');
				if (/^[\x20-\x7E\s]+$/.test(decoded)) {
					decodedMessage = decoded;
				}
			}
		} catch {
			// Keep original hex
		}
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
