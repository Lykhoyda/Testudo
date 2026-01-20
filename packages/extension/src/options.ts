/**
 * OPTIONS PAGE SCRIPT
 *
 * Manages settings, whitelist, and scan history.
 */

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
	type Settings,
	updateSettings,
	type WhitelistEntry,
} from './storage';

// ============================================================================
// UI HELPERS
// ============================================================================

function showToast(message: string, isError = false): void {
	const toast = document.getElementById('toast');
	if (!toast) return;

	toast.textContent = message;
	toast.className = isError ? 'toast error show' : 'toast show';

	setTimeout(() => {
		toast.className = 'toast';
	}, 3000);
}

function formatDate(timestamp: number): string {
	return new Date(timestamp).toLocaleDateString(undefined, {
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
	});
}

function truncateAddress(address: string): string {
	return `${address.slice(0, 10)}...${address.slice(-8)}`;
}

function getRiskIcon(risk: string): string {
	const icons: Record<string, string> = {
		CRITICAL: '🚨',
		HIGH: '⚠️',
		MEDIUM: '⚡',
		LOW: '✓',
		UNKNOWN: '❓',
	};
	return icons[risk] || '❓';
}

// ============================================================================
// TAB NAVIGATION
// ============================================================================

function switchToTab(tabId: string): void {
	const tabs = document.querySelectorAll('.tab');
	const contents = document.querySelectorAll('.tab-content');

	for (const t of tabs) {
		t.classList.remove('active');
	}
	for (const c of contents) {
		c.classList.remove('active');
	}

	const targetTab = document.querySelector(`.tab[data-tab="${tabId}"]`);
	targetTab?.classList.add('active');
	document.getElementById(`tab-${tabId}`)?.classList.add('active');

	// Refresh content when switching tabs
	if (tabId === 'whitelist') loadWhitelist();
	if (tabId === 'history') loadHistory();
	if (tabId === 'advanced') loadStorageInfo();
}

function initTabs(): void {
	const tabs = document.querySelectorAll('.tab');

	tabs.forEach((tab) => {
		tab.addEventListener('click', () => {
			const targetId = tab.getAttribute('data-tab');
			if (targetId) {
				switchToTab(targetId);
				// Update URL hash without triggering navigation
				history.replaceState(null, '', `#${targetId}`);
			}
		});
	});

	// Check for URL hash to open specific tab (e.g., #history)
	const hash = window.location.hash.slice(1);
	if (hash && ['general', 'whitelist', 'history', 'advanced'].includes(hash)) {
		switchToTab(hash);
	}
}

// ============================================================================
// SETTINGS
// ============================================================================

async function loadSettings(): Promise<void> {
	const settings = await getSettings();

	// Protection level
	const protectionSelect = document.getElementById('protection-level') as HTMLSelectElement;
	if (protectionSelect) {
		protectionSelect.value = settings.protectionLevel;
	}

	// Toggles
	const mediumToastToggle = document.getElementById('toggle-medium-toast');
	const autoRecordToggle = document.getElementById('toggle-auto-record');

	if (mediumToastToggle) {
		mediumToastToggle.classList.toggle('active', settings.showMediumRiskToast);
	}
	if (autoRecordToggle) {
		autoRecordToggle.classList.toggle('active', settings.autoRecordScans);
	}

	// Custom RPC
	const rpcInput = document.getElementById('custom-rpc') as HTMLInputElement;
	if (rpcInput && settings.customRpcUrl) {
		rpcInput.value = settings.customRpcUrl;
	}
}

function initSettingsListeners(): void {
	// Protection level
	const protectionSelect = document.getElementById('protection-level');
	protectionSelect?.addEventListener('change', async (e) => {
		const value = (e.target as HTMLSelectElement).value as Settings['protectionLevel'];
		const success = await updateSettings({ protectionLevel: value });
		showToast(success ? 'Protection level updated' : 'Failed to update', !success);
	});

	// Medium toast toggle
	const mediumToastToggle = document.getElementById('toggle-medium-toast');
	mediumToastToggle?.addEventListener('click', async () => {
		const isActive = mediumToastToggle.classList.toggle('active');
		await updateSettings({ showMediumRiskToast: isActive });
	});

	// Auto record toggle
	const autoRecordToggle = document.getElementById('toggle-auto-record');
	autoRecordToggle?.addEventListener('click', async () => {
		const isActive = autoRecordToggle.classList.toggle('active');
		await updateSettings({ autoRecordScans: isActive });
	});

	// Custom RPC
	document.getElementById('btn-save-rpc')?.addEventListener('click', async () => {
		const input = document.getElementById('custom-rpc') as HTMLInputElement;
		const url = input?.value.trim() || null;

		if (url) {
			try {
				new URL(url);
			} catch {
				showToast('Invalid URL format', true);
				return;
			}
		}

		const success = await updateSettings({ customRpcUrl: url });
		showToast(success ? 'RPC endpoint saved' : 'Failed to save', !success);
	});

	document.getElementById('btn-clear-rpc')?.addEventListener('click', async () => {
		const input = document.getElementById('custom-rpc') as HTMLInputElement;
		if (input) input.value = '';
		await updateSettings({ customRpcUrl: null });
		showToast('RPC endpoint cleared');
	});
}

// ============================================================================
// WHITELIST
// ============================================================================

async function loadWhitelist(): Promise<void> {
	const whitelist = await getWhitelist();
	const tbody = document.getElementById('whitelist-body');
	const count = document.getElementById('whitelist-count');

	if (count) {
		count.textContent = `${whitelist.length} address${whitelist.length !== 1 ? 'es' : ''}`;
	}

	if (!tbody) return;

	if (whitelist.length === 0) {
		tbody.innerHTML =
			'<tr><td colspan="4" class="whitelist-empty">No whitelisted addresses</td></tr>';
		return;
	}

	tbody.innerHTML = whitelist
		.map(
			(entry) => `
      <tr data-address="${entry.address}">
        <td class="whitelist-address">${truncateAddress(entry.address)}</td>
        <td>${entry.label || '-'}</td>
        <td>${formatDate(entry.addedAt)}</td>
        <td><button class="btn-remove" data-address="${entry.address}">Remove</button></td>
      </tr>
    `,
		)
		.join('');

	// Add remove listeners
	tbody.querySelectorAll('.btn-remove').forEach((btn) => {
		btn.addEventListener('click', async (e) => {
			const address = (e.target as HTMLElement).getAttribute('data-address');
			if (address) {
				await removeFromWhitelist(address);
				await loadWhitelist();
				showToast('Address removed from whitelist');
			}
		});
	});
}

function initWhitelistListeners(): void {
	// Add to whitelist
	document.getElementById('btn-add-whitelist')?.addEventListener('click', async () => {
		const addressInput = document.getElementById('whitelist-address') as HTMLInputElement;
		const labelInput = document.getElementById('whitelist-label') as HTMLInputElement;

		const address = addressInput?.value.trim();
		const label = labelInput?.value.trim() || '';

		if (!address) {
			showToast('Please enter an address', true);
			return;
		}

		if (!isValidAddress(address)) {
			showToast('Invalid address format', true);
			return;
		}

		const success = await addToWhitelist(address, label);
		if (success) {
			addressInput.value = '';
			labelInput.value = '';
			await loadWhitelist();
			showToast('Address added to whitelist');
		} else {
			showToast('Failed to add address', true);
		}
	});

	// Export
	document.getElementById('btn-export')?.addEventListener('click', async () => {
		const json = await exportWhitelist();
		const blob = new Blob([json], { type: 'application/json' });
		const url = URL.createObjectURL(blob);

		const a = document.createElement('a');
		a.href = url;
		a.download = `testudo-whitelist-${Date.now()}.json`;
		a.click();

		URL.revokeObjectURL(url);
		showToast('Whitelist exported');
	});

	// Import
	const importFile = document.getElementById('import-file') as HTMLInputElement;

	document.getElementById('btn-import')?.addEventListener('click', () => {
		importFile?.click();
	});

	importFile?.addEventListener('change', async (e) => {
		const file = (e.target as HTMLInputElement).files?.[0];
		if (!file) return;

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

		importFile.value = '';
	});
}

// ============================================================================
// HISTORY
// ============================================================================

async function loadHistory(): Promise<void> {
	const history = await getScanHistory();
	const container = document.getElementById('history-list');

	if (!container) return;

	if (history.length === 0) {
		container.innerHTML = '<div class="whitelist-empty">No scan history</div>';
		return;
	}

	container.innerHTML = history
		.map(
			(scan) => `
      <div class="history-item">
        <span class="history-icon">${getRiskIcon(scan.risk)}</span>
        <div class="history-details">
          <div class="history-address">${truncateAddress(scan.address)}</div>
          <div class="history-meta">
            ${formatDate(scan.timestamp)}
            ${scan.blocked ? ' • Blocked' : ''}
            ${scan.url ? ` • ${new URL(scan.url).hostname}` : ''}
          </div>
        </div>
        <span class="history-risk ${scan.risk.toLowerCase()}">${scan.risk}</span>
      </div>
    `,
		)
		.join('');
}

function initHistoryListeners(): void {
	document.getElementById('btn-clear-history')?.addEventListener('click', async () => {
		if (confirm('Are you sure you want to clear all scan history?')) {
			await clearScanHistory();
			await loadHistory();
			showToast('History cleared');
		}
	});
}

// ============================================================================
// STORAGE
// ============================================================================

async function loadStorageInfo(): Promise<void> {
	const { bytesUsed, quota } = await getStorageUsage();
	const percentage = (bytesUsed / quota) * 100;

	const fill = document.getElementById('storage-fill');
	const text = document.getElementById('storage-text');

	if (fill) {
		fill.style.width = `${percentage}%`;
		fill.className = 'storage-bar-fill';
		if (percentage > 80) fill.classList.add('danger');
		else if (percentage > 50) fill.classList.add('warning');
	}

	if (text) {
		const usedMB = (bytesUsed / 1024 / 1024).toFixed(2);
		const quotaMB = (quota / 1024 / 1024).toFixed(0);
		text.textContent = `${usedMB} MB of ${quotaMB} MB used (${percentage.toFixed(1)}%)`;
	}
}

function initAdvancedListeners(): void {
	document.getElementById('btn-clear-all')?.addEventListener('click', async () => {
		if (confirm('Are you sure you want to clear ALL Testudo data? This cannot be undone.')) {
			await chrome.storage.local.clear();
			showToast('All data cleared');
			await loadSettings();
			await loadWhitelist();
			await loadHistory();
			await loadStorageInfo();
		}
	});
}

// ============================================================================
// INIT
// ============================================================================

async function init(): Promise<void> {
	initTabs();
	initSettingsListeners();
	initWhitelistListeners();
	initHistoryListeners();
	initAdvancedListeners();

	await loadSettings();
	await loadWhitelist();
	await loadStorageInfo();
}

document.addEventListener('DOMContentLoaded', init);
