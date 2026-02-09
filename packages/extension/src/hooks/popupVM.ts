import { signal } from '@preact/signals';
import type { RecentScan } from '../utils/types';

interface Stats {
	cacheSize: number;
	knownMalicious: number;
	knownSafe: number;
	blocked?: number;
	scanned?: number;
}

export const blocked = signal(0);
export const scanned = signal(0);
export const recentScans = signal<RecentScan[]>([]);

export async function init(): Promise<void> {
	try {
		const stats: Stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' });
		const storageData = await chrome.storage.local.get(['blocked', 'scanned']);
		blocked.value = storageData.blocked || 0;
		scanned.value = storageData.scanned || stats.cacheSize;
	} catch (error) {
		console.error('[Testudo Popup] Error fetching stats:', error);
	}

	try {
		const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
		recentScans.value = (scanHistory as RecentScan[]).slice(0, 5);
	} catch (error) {
		console.error('[Testudo Popup] Error loading recent scans:', error);
	}
}

export function openSettings(): void {
	chrome.runtime.openOptionsPage();
}

export function openHistory(): void {
	chrome.tabs.create({ url: chrome.runtime.getURL('options.html#history') });
}
