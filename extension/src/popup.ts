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
    const { recentScans = [] } = await chrome.storage.local.get('recentScans');
    const listEl = document.getElementById('recent-list');

    if (!listEl) return;

    if (recentScans.length === 0) {
      listEl.innerHTML = '<div class="empty-state">No recent scans</div>';
      return;
    }

    listEl.innerHTML = recentScans
      .slice(0, 5)
      .map((scan: RecentScan) => `
        <div class="recent-item">
          <span class="recent-icon">${getRiskIcon(scan.risk)}</span>
          <span class="recent-address">${truncateAddress(scan.address)}</span>
          <span class="recent-risk ${scan.risk.toLowerCase()}">${scan.risk}</span>
        </div>
      `)
      .join('');
  } catch (error) {
    console.error('[Testudo Popup] Error loading recent scans:', error);
  }
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

function truncateAddress(address: string): string {
  if (address.length <= 16) return address;
  return `${address.slice(0, 8)}...${address.slice(-6)}`;
}

function setupEventListeners() {
  const clearCacheLink = document.getElementById('clear-cache');
  if (clearCacheLink) {
    clearCacheLink.addEventListener('click', async (e) => {
      e.preventDefault();
      await chrome.storage.local.clear();
      await updateStats();
      await loadRecentScans();
    });
  }
}

document.addEventListener('DOMContentLoaded', init);

export {};
