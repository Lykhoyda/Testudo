import type { ExtractedAddress, PermitInfo, TypedDataMessage } from '../utils/types';
import { isUnlimitedValue } from './transaction';

export function isEIP7702Authorization(typedData: TypedDataMessage): boolean {
	if (!typedData.types?.Authorization) return false;
	if (typedData.primaryType !== 'Authorization') return false;
	if (!typedData.message?.address) return false;
	return true;
}

export function isPermitSignature(typedData: TypedDataMessage): boolean {
	const pt = typedData.primaryType;
	return (
		pt === 'Permit' ||
		pt === 'PermitSingle' ||
		pt === 'PermitBatch' ||
		pt === 'PermitTransferFrom' ||
		pt === 'PermitWitnessTransferFrom'
	);
}

export function validateAddress(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	if (!/^0x[a-fA-F0-9]{40}$/.test(value)) return null;
	return value.toLowerCase();
}

export function extractTypedDataAddresses(typedData: TypedDataMessage): ExtractedAddress[] {
	const results: ExtractedAddress[] = [];
	const seen = new Set<string>();
	const MAX_DEPTH = 10;
	const MAX_ADDRESSES = 100;

	const verifyingContract = validateAddress(typedData.domain?.verifyingContract);
	if (verifyingContract) {
		seen.add(verifyingContract);
		results.push({ address: verifyingContract, fieldPath: 'domain.verifyingContract' });
	}

	const typeMap = typedData.types as Record<string, Array<{ name: string; type: string }>>;

	function walk(value: unknown, typeName: string, path: string, depth: number): void {
		if (depth > MAX_DEPTH || results.length >= MAX_ADDRESSES) return;
		if (typeName === 'EIP712Domain') return;

		const fields = typeMap[typeName];
		if (!Array.isArray(fields) || typeof value !== 'object' || value === null) return;

		for (const field of fields) {
			const fieldValue = (value as Record<string, unknown>)[field.name];
			const fieldPath = path ? `${path}.${field.name}` : field.name;

			if (field.type === 'address') {
				const addr = validateAddress(fieldValue);
				if (addr && !seen.has(addr)) {
					seen.add(addr);
					results.push({ address: addr, fieldPath });
				}
			} else if (field.type === 'address[]' && Array.isArray(fieldValue)) {
				for (let i = 0; i < fieldValue.length && results.length < MAX_ADDRESSES; i++) {
					const addr = validateAddress(fieldValue[i]);
					if (addr && !seen.has(addr)) {
						seen.add(addr);
						results.push({ address: addr, fieldPath: `${fieldPath}[${i}]` });
					}
				}
			} else if (field.type.endsWith('[]')) {
				const baseType = field.type.slice(0, -2);
				if (typeMap[baseType] && Array.isArray(fieldValue)) {
					for (let i = 0; i < fieldValue.length && results.length < MAX_ADDRESSES; i++) {
						walk(fieldValue[i], baseType, `${fieldPath}[${i}]`, depth + 1);
					}
				}
			} else if (typeMap[field.type]) {
				walk(fieldValue, field.type, fieldPath, depth + 1);
			}
		}
	}

	walk(typedData.message, typedData.primaryType, 'message', 0);

	return results;
}

function isDaiPermit(typedData: TypedDataMessage): boolean {
	const fields = typedData.types[typedData.primaryType] as Array<{ name: string }> | undefined;
	if (!Array.isArray(fields)) return false;
	return fields.some((f) => f.name === 'holder') && fields.some((f) => f.name === 'allowed');
}

export function extractPermitInfo(typedData: TypedDataMessage): PermitInfo | null {
	const { primaryType, message, domain } = typedData;

	if (primaryType === 'Permit') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const dai = isDaiPermit(typedData);
		return {
			type: dai ? 'dai-permit' : 'permit',
			spender,
			value: dai ? (message.allowed === true ? 'unlimited' : '0') : String(message.value ?? ''),
			deadline:
				message.deadline != null
					? String(message.deadline)
					: message.expiry != null
						? String(message.expiry)
						: undefined,
			token: domain?.verifyingContract,
			tokenName: domain?.name,
		};
	}

	if (primaryType === 'PermitSingle') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const details = message.details as Record<string, unknown> | undefined;
		return {
			type: 'permit2-single',
			spender,
			value: details?.amount != null ? String(details.amount) : undefined,
			deadline: message.sigDeadline != null ? String(message.sigDeadline) : undefined,
			token: typeof details?.token === 'string' ? details.token : undefined,
		};
	}

	if (primaryType === 'PermitBatch') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const details = message.details as Array<Record<string, unknown>> | undefined;
		if (!Array.isArray(details) || details.length === 0) return null;
		const hasUnlimited = details.some((d) =>
			isUnlimitedValue(d.amount != null ? String(d.amount) : undefined),
		);
		return {
			type: 'permit2-batch',
			spender,
			deadline: message.sigDeadline != null ? String(message.sigDeadline) : undefined,
			token: typeof details[0]?.token === 'string' ? details[0].token : undefined,
			value: hasUnlimited ? 'unlimited' : 'batch',
		};
	}

	if (primaryType === 'PermitTransferFrom' || primaryType === 'PermitWitnessTransferFrom') {
		const spender = validateAddress(message.spender);
		if (!spender) return null;
		const permitted = message.permitted as Record<string, unknown> | undefined;
		return {
			type: primaryType === 'PermitTransferFrom' ? 'permit2-transfer' : 'permit2-witness-transfer',
			spender,
			value: permitted?.amount != null ? String(permitted.amount) : undefined,
			deadline: message.deadline != null ? String(message.deadline) : undefined,
			token: typeof permitted?.token === 'string' ? permitted.token : undefined,
		};
	}

	return null;
}
