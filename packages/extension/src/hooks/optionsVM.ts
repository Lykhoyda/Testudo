import { computed, signal } from '@preact/signals';
import {
	addToWhitelist,
	clearScanHistory,
	exportWhitelist,
	getScanHistory,
	getSettings,
	getStorageUsage,
	getWhitelist,
	importWhitelist,
	isValidAddress,
	removeFromWhitelist,
	updateSettings,
} from '../storage';
import type { ScanRecord, Settings, WhitelistEntry } from '../utils/types';

export const activeTab = signal('general');
export const settings = signal<Settings>({
	apiUrl: null,
	showMediumRiskToast: true,
	autoRecordScans: true,
});
export const whitelist = signal<WhitelistEntry[]>([]);
export const scanHistory = signal<ScanRecord[]>([]);
export const storageUsage = signal({ bytesUsed: 0, quota: 5242880 });
export const toast = signal<{ message: string; isError: boolean; visible: boolean }>({
	message: '',
	isError: false,
	visible: false,
});

export const storagePercentage = computed(
	() => (storageUsage.value.bytesUsed / storageUsage.value.quota) * 100,
);

let toastTimer: ReturnType<typeof setTimeout> | undefined;

function showToast(message: string, isError = false): void {
	if (toastTimer) clearTimeout(toastTimer);
	toast.value = { message, isError, visible: true };
	toastTimer = setTimeout(() => {
		toast.value = { ...toast.value, visible: false };
	}, 3000);
}

export async function init(): Promise<void> {
	const hash = window.location.hash.slice(1);
	if (hash && ['general', 'whitelist', 'history', 'advanced'].includes(hash)) {
		activeTab.value = hash;
	}
	await loadSettings();
	await loadWhitelist();
	await loadStorageInfo();
	if (activeTab.value === 'history') await loadHistory();
}

export function switchTab(tabId: string): void {
	activeTab.value = tabId;
	history.replaceState(null, '', `#${tabId}`);
	if (tabId === 'whitelist') loadWhitelist();
	if (tabId === 'history') loadHistory();
	if (tabId === 'advanced') loadStorageInfo();
}

export async function loadSettings(): Promise<void> {
	settings.value = await getSettings();
}

export async function toggleMediumToast(): Promise<void> {
	const newVal = !settings.value.showMediumRiskToast;
	await updateSettings({ showMediumRiskToast: newVal });
	settings.value = { ...settings.value, showMediumRiskToast: newVal };
}

export async function toggleAutoRecord(): Promise<void> {
	const newVal = !settings.value.autoRecordScans;
	await updateSettings({ autoRecordScans: newVal });
	settings.value = { ...settings.value, autoRecordScans: newVal };
}

export async function loadWhitelist(): Promise<void> {
	whitelist.value = await getWhitelist();
}

export async function addWhitelistEntry(address: string, label: string): Promise<boolean> {
	if (!address) {
		showToast('Please enter an address', true);
		return false;
	}
	if (!isValidAddress(address)) {
		showToast('Invalid address format', true);
		return false;
	}
	const success = await addToWhitelist(address, label);
	if (success) {
		await loadWhitelist();
		showToast('Address added to whitelist');
		return true;
	}
	showToast('Failed to add address', true);
	return false;
}

export async function removeWhitelistEntry(address: string): Promise<void> {
	await removeFromWhitelist(address);
	await loadWhitelist();
	showToast('Address removed from whitelist');
}

export async function handleExport(): Promise<void> {
	const json = await exportWhitelist();
	const blob = new Blob([json], { type: 'application/json' });
	const url = URL.createObjectURL(blob);

	const a = document.createElement('a');
	a.href = url;
	a.download = `testudo-whitelist-${Date.now()}.json`;
	a.click();

	URL.revokeObjectURL(url);
	showToast('Whitelist exported');
}

export async function handleImport(file: File): Promise<void> {
	try {
		const text = await file.text();
		const entries: WhitelistEntry[] = JSON.parse(text);

		if (!Array.isArray(entries)) {
			throw new Error('Invalid format');
		}

		const count = await importWhitelist(entries);
		await loadWhitelist();
		showToast(`Imported ${count} address${count !== 1 ? 'es' : ''}`);
	} catch {
		showToast('Failed to import - invalid file', true);
	}
}

export async function loadHistory(): Promise<void> {
	scanHistory.value = await getScanHistory();
}

export async function clearHistory(): Promise<void> {
	if (!confirm('Clear all scan history? This cannot be undone.')) return;
	await clearScanHistory();
	await loadHistory();
	showToast('History cleared');
}

export async function clearAllData(): Promise<void> {
	if (!confirm('Delete ALL settings, whitelist, and scan history? This cannot be undone.')) return;
	await chrome.storage.local.clear();
	showToast('All data cleared');
	await loadSettings();
	await loadWhitelist();
	await loadHistory();
	await loadStorageInfo();
}

export async function loadStorageInfo(): Promise<void> {
	storageUsage.value = await getStorageUsage();
}
