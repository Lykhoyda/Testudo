import { useEffect } from 'preact/hooks';
import * as vm from '../../hooks/popupVM';
import { MaterialIcon } from '../shared/MaterialIcon';
import { RecentActivity } from './RecentActivity';
import { StatsGrid } from './StatsGrid';

export function PopupApp() {
	useEffect(() => {
		vm.init();
	}, []);

	return (
		<>
			<header class="header">
				<div class="header-left">
					<img src="icon-128.png" alt="Testudo" class="header-icon" />
					<h1 class="header-title">Testudo</h1>
				</div>
				<div class="header-actions">
					<button
						type="button"
						class="header-btn"
						title="Notifications"
						id="notifications-btn"
						onClick={vm.openSettings}
					>
						<MaterialIcon name="notifications" style="font-size: 20px;" />
					</button>
				</div>
			</header>

			<main class="main">
				<div class="hero-card">
					<div class="hero-icon-wrapper">
						<MaterialIcon name="verified_user" class="hero-icon" />
					</div>
					<div class="hero-content">
						<h2 class="hero-title" id="status-title">
							Protection Active
						</h2>
						<p class="hero-subtitle" id="status-description">
							System Operational
						</p>
					</div>
				</div>

				<StatsGrid blocked={vm.blocked} scanned={vm.scanned} />
				<RecentActivity scans={vm.recentScans} onViewAll={vm.openHistory} />
			</main>

			<footer class="footer">
				<div class="footer-content">
					<button type="button" class="footer-link" id="settings-btn" onClick={vm.openSettings}>
						<MaterialIcon name="settings" class="footer-icon" />
						<span>Settings</span>
					</button>
					<a
						class="footer-link"
						href="https://github.com/Lykhoyda/Testudo"
						target="_blank"
						rel="noopener noreferrer"
					>
						<span>GitHub</span>
						<MaterialIcon name="code" class="footer-icon" />
					</a>
				</div>
			</footer>
		</>
	);
}
