export function formatRelativeTime(timestamp: number): string {
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

export function truncateAddress(address: string, start = 10, end = 6): string {
	if (address.length <= start + end) return address;
	return `${address.slice(0, start)}...${address.slice(-end)}`;
}

export function formatDate(timestamp: number): string {
	return new Date(timestamp).toLocaleDateString(undefined, {
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
	});
}

export function getRiskIcon(risk: string): string {
	const icons: Record<string, string> = {
		CRITICAL: 'warning',
		HIGH: 'error',
		MEDIUM: 'info',
		LOW: 'check_circle',
		UNKNOWN: 'help',
	};
	return icons[risk] || 'help';
}

export function getRiskLabel(risk: string): string {
	const labels: Record<string, string> = {
		CRITICAL: 'Critical',
		HIGH: 'High',
		MEDIUM: 'Medium',
		LOW: 'Safe',
		UNKNOWN: 'Unknown',
	};
	return labels[risk] || risk;
}

export function getRiskEmoji(risk: string): string {
	const icons: Record<string, string> = {
		CRITICAL: '\u{1F6A8}',
		HIGH: '\u26A0\uFE0F',
		MEDIUM: '\u26A1',
		LOW: '\u2713',
		UNKNOWN: '\u2753',
	};
	return icons[risk] || '\u2753';
}
