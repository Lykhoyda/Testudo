import { useEffect } from 'preact/hooks';
import * as vm from '../../hooks/optionsVM';
import { AdvancedTab } from './AdvancedTab';
import { GeneralTab } from './GeneralTab';
import { HistoryTab } from './HistoryTab';
import { TabNav } from './TabNav';
import { Toast } from './Toast';
import { WhitelistTab } from './WhitelistTab';

export function OptionsApp() {
	useEffect(() => {
		vm.init();
	}, []);

	return (
		<div class="container">
			<div class="header">
				<div class="header-icon">
					<img src="icon-128.png" alt="Testudo" />
				</div>
				<div class="header-text">
					<h1>Testudo Settings</h1>
					<p>Configure your EIP-7702 protection</p>
				</div>
			</div>

			<TabNav activeTab={vm.activeTab} onSwitch={vm.switchTab} />

			<div
				id="tab-general"
				class={`tab-content${vm.activeTab.value === 'general' ? ' active' : ''}`}
			>
				<GeneralTab
					settings={vm.settings}
					onChangeProtection={vm.changeProtectionLevel}
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
					settings={vm.settings}
					storagePercentage={vm.storagePercentage}
					storageUsage={vm.storageUsage}
					onSaveRpc={vm.saveRpc}
					onClearRpc={vm.clearRpc}
					onClearAll={vm.clearAllData}
				/>
			</div>

			<Toast toast={vm.toast} />
		</div>
	);
}
