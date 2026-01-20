interface Stats {
	cacheSize: number;
	knownMalicious: number;
	knownSafe: number;
	blocked?: number;
	scanned?: number;
}

interface RecentScan {
	address: string;
	risk: string;
	timestamp: number;
}

async function init() {
	await updateStats();
	await loadRecentScans();
	setupEventListeners();
}

async function updateStats() {
	try {
		const stats: Stats = await chrome.runtime.sendMessage({ type: 'GET_STATS' });

		const storageData = await chrome.storage.local.get(['blocked', 'scanned']);
		const blocked = storageData.blocked || 0;
		const scanned = storageData.scanned || stats.cacheSize;

		const blockedEl = document.getElementById('stat-blocked');
		const scannedEl = document.getElementById('stat-scanned');

		if (blockedEl) blockedEl.textContent = String(blocked);
		if (scannedEl) scannedEl.textContent = String(scanned);
	} catch (error) {
		console.error('[Testudo Popup] Error fetching stats:', error);
	}
}

async function loadRecentScans() {
	try {
		const { scanHistory: recentScans = [] } = await chrome.storage.local.get('scanHistory');
		const listEl = document.getElementById('recent-list');

		if (!listEl) return;

		if (recentScans.length === 0) {
			listEl.innerHTML = '<div class="empty-state">No recent scans</div>';
			return;
		}

		listEl.innerHTML = recentScans
			.slice(0, 5)
			.map(
				(scan: RecentScan) => `
        <div class="activity-item">
          <div class="activity-icon-wrapper ${scan.risk.toLowerCase()}">
            <span class="material-symbols-outlined activity-icon">${getRiskIcon(scan.risk)}</span>
          </div>
          <div class="activity-content">
            <div class="activity-row">
              <span class="activity-badge ${scan.risk.toLowerCase()}">${getRiskLabel(scan.risk)}</span>
              <span class="activity-time">${formatRelativeTime(scan.timestamp)}</span>
            </div>
            <span class="activity-address">${truncateAddress(scan.address)}</span>
          </div>
        </div>
      `,
			)
			.join('');
	} catch (error) {
		console.error('[Testudo Popup] Error loading recent scans:', error);
	}
}

function getRiskIcon(risk: string): string {
	const icons: Record<string, string> = {
		CRITICAL: 'warning',
		HIGH: 'error',
		MEDIUM: 'info',
		LOW: 'check_circle',
		UNKNOWN: 'help',
	};
	return icons[risk] || 'help';
}

function getRiskLabel(risk: string): string {
	const labels: Record<string, string> = {
		CRITICAL: 'Critical',
		HIGH: 'High',
		MEDIUM: 'Medium',
		LOW: 'Safe',
		UNKNOWN: 'Unknown',
	};
	return labels[risk] || risk;
}

function formatRelativeTime(timestamp: number): string {
	const now = Date.now();
	const diff = now - timestamp;

	const minutes = Math.floor(diff / 60000);
	const hours = Math.floor(diff / 3600000);
	const days = Math.floor(diff / 86400000);

	if (minutes < 1) return 'just now';
	if (minutes < 60) return `${minutes}m ago`;
	if (hours < 24) return `${hours}h ago`;
	if (days < 7) return `${days}d ago`;

	return new Date(timestamp).toLocaleDateString();
}

function truncateAddress(address: string): string {
	if (address.length <= 16) return address;
	return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function setupEventListeners() {
	const settingsBtn = document.getElementById('settings-btn');
	if (settingsBtn) {
		settingsBtn.addEventListener('click', () => {
			chrome.runtime.openOptionsPage();
		});
	}

	const viewAllBtn = document.getElementById('view-all-btn');
	if (viewAllBtn) {
		viewAllBtn.addEventListener('click', () => {
			// Open options page directly to History tab
			chrome.tabs.create({ url: chrome.runtime.getURL('options.html#history') });
		});
	}

	const notificationsBtn = document.getElementById('notifications-btn');
	if (notificationsBtn) {
		notificationsBtn.addEventListener('click', () => {
			chrome.runtime.openOptionsPage();
		});
	}
}

document.addEventListener('DOMContentLoaded', init);

export {};
