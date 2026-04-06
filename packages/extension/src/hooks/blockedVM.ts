import { computed, signal } from '@preact/signals';
import type { DomainThreatResponse } from '../api-client';
import type { BlockAction } from '../phishing/checker';

export type BlockScreenState = 'loading' | 'hard-block' | 'soft-block' | 'soft-allow';

export const domain = signal('');
export const originalUrl = signal('');
export const blockAction = signal<BlockAction>('hard-block');
export const metadata = signal<DomainThreatResponse | null>(null);
export const screenState = signal<BlockScreenState>('loading');
export const overrideInput = signal('');

export const isOverrideValid = computed(
	() => overrideInput.value.toLowerCase() === domain.value.toLowerCase(),
);

export function initFromUrlParams(): void {
	const params = new URLSearchParams(window.location.search);
	const d = params.get('domain') ?? '';
	const url = params.get('url') ?? '';
	const action = (params.get('action') ?? 'hard-block') as BlockAction;

	domain.value = d;
	originalUrl.value = url;
	blockAction.value = action;
}

export async function fetchMetadata(): Promise<void> {
	const d = domain.value;
	if (!d) {
		screenState.value = (blockAction.value as BlockScreenState) ?? 'hard-block';
		return;
	}

	try {
		const response = await chrome.runtime.sendMessage({
			type: 'TESTUDO_CHECK_DOMAIN_METADATA',
			domain: d,
		});

		if (response?.data) {
			metadata.value = response.data as DomainThreatResponse;
		}
	} catch {
		// Background unavailable — proceed with URL param action
	}

	screenState.value = (blockAction.value as BlockScreenState) ?? 'hard-block';
}

export async function override(): Promise<void> {
	if (!isOverrideValid.value) return;

	try {
		await chrome.runtime.sendMessage({
			type: 'TESTUDO_PHISHING_OVERRIDE',
			domain: domain.value,
		});
	} catch {
		// Best-effort — navigate anyway
	}

	const target = originalUrl.value || 'about:newtab';
	window.location.href = target;
}

export function goBack(): void {
	if (window.history.length > 1) {
		window.history.back();
	} else {
		window.location.href = 'about:newtab';
	}
}
