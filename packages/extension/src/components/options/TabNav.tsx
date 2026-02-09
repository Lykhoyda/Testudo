import type { ReadonlySignal } from '@preact/signals';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	activeTab: ReadonlySignal<string>;
	onSwitch: (tab: string) => void;
}

const TABS = [
	{ id: 'general', icon: 'tune', label: 'General' },
	{ id: 'whitelist', icon: 'verified', label: 'Whitelist' },
	{ id: 'history', icon: 'history', label: 'History' },
	{ id: 'advanced', icon: 'settings', label: 'Advanced' },
] as const;

export function TabNav({ activeTab, onSwitch }: Props) {
	return (
		<div class="tabs">
			{TABS.map((tab) => (
				<button
					type="button"
					key={tab.id}
					class={`tab${activeTab.value === tab.id ? ' active' : ''}`}
					data-tab={tab.id}
					onClick={() => onSwitch(tab.id)}
				>
					<MaterialIcon name={tab.icon} />
					{tab.label}
				</button>
			))}
		</div>
	);
}
