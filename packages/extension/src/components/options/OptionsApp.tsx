import { useEffect } from 'preact/hooks';
import * as vm from '../../hooks/optionsVM';
import { AdvancedTab } from './AdvancedTab';
import { GeneralTab } from './GeneralTab';
import { HistoryTab } from './HistoryTab';
import { TabNav } from './TabNav';
import { Toast } from './Toast';
import { WhitelistTab } from './WhitelistTab';

const PAGE_META: Record<string, { title: string; subtitle: string }> = {
	general: {
		title: 'General',
		subtitle: 'Tune how Testudo analyzes transactions and presents warnings.',
	},
	whitelist: {
		title: 'Whitelist',
		subtitle: 'Trusted addresses that skip all Testudo checks.',
	},
	history: {
		title: 'History',
		subtitle: 'Recently scanned contracts and detected threats.',
	},
	advanced: {
		title: 'Advanced',
		subtitle: 'Storage, diagnostics, and extension internals.',
	},
};

export function OptionsApp() {
	useEffect(() => {
		vm.init();
	}, []);

	const meta = PAGE_META[vm.activeTab.value] ?? PAGE_META.general;

	return (
		<div class="opt-layout">
			<aside class="opt-side">
				<div class="opt-brand">
					<img src="icon-128.png" alt="Testudo" class="opt-brand-mark" />
					<div class="opt-brand-text">Testudo</div>
				</div>
				<div class="opt-nav-label">Preferences</div>
				<TabNav activeTab={vm.activeTab} onSwitch={vm.switchTab} />
			</aside>

			<main class="opt-main">
				<header class="opt-header">
					<h1 class="opt-title">{meta.title}</h1>
					<p class="opt-sub">{meta.subtitle}</p>
				</header>

				<div
					id="tab-general"
					class={`tab-content${vm.activeTab.value === 'general' ? ' active' : ''}`}
				>
					<GeneralTab
						settings={vm.settings}
						onToggleMediumToast={vm.toggleMediumToast}
						onToggleAutoRecord={vm.toggleAutoRecord}
					/>
				</div>

				<div
					id="tab-whitelist"
					class={`tab-content${vm.activeTab.value === 'whitelist' ? ' active' : ''}`}
				>
					<WhitelistTab
						whitelist={vm.whitelist}
						onAdd={vm.addWhitelistEntry}
						onRemove={vm.removeWhitelistEntry}
						onExport={vm.handleExport}
						onImport={vm.handleImport}
					/>
				</div>

				<div
					id="tab-history"
					class={`tab-content${vm.activeTab.value === 'history' ? ' active' : ''}`}
				>
					<HistoryTab history={vm.scanHistory} onClear={vm.clearHistory} />
				</div>

				<div
					id="tab-advanced"
					class={`tab-content${vm.activeTab.value === 'advanced' ? ' active' : ''}`}
				>
					<AdvancedTab
						storagePercentage={vm.storagePercentage}
						storageUsage={vm.storageUsage}
						onClearAll={vm.clearAllData}
					/>
				</div>
			</main>

			<Toast toast={vm.toast} />
		</div>
	);
}
