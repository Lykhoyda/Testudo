import type { ReadonlySignal } from '@preact/signals';
import { useRef } from 'preact/hooks';
import type { Settings } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	settings: ReadonlySignal<Settings>;
	storagePercentage: ReadonlySignal<number>;
	storageUsage: ReadonlySignal<{ bytesUsed: number; quota: number }>;
	onSaveRpc: (url: string | null) => void;
	onClearRpc: () => void;
	onClearAll: () => void;
}

export function AdvancedTab({
	settings: s,
	storagePercentage,
	storageUsage: su,
	onSaveRpc,
	onClearRpc,
	onClearAll,
}: Props) {
	const rpcRef = useRef<HTMLInputElement>(null);

	const pct = storagePercentage.value;
	const fillClass = pct > 80 ? ' danger' : pct > 50 ? ' warning' : '';
	const usedMB = (su.value.bytesUsed / 1024 / 1024).toFixed(2);
	const quotaMB = (su.value.quota / 1024 / 1024).toFixed(0);

	return (
		<>
			<div class="section">
				<h2 class="section-title">
					<MaterialIcon name="link" />
					Custom RPC
				</h2>
				<div class="form-group">
					<label class="form-label" htmlFor="custom-rpc">
						RPC Endpoint URL
					</label>
					<input
						type="url"
						id="custom-rpc"
						placeholder="https://eth.llamarpc.com"
						ref={rpcRef}
						defaultValue={s.value.customRpcUrl || ''}
					/>
					<p class="form-description">
						Use a custom RPC endpoint for bytecode fetching. Leave empty for default.
					</p>
				</div>
				<div class="btn-group">
					<button
						type="button"
						class="btn btn-primary"
						id="btn-save-rpc"
						onClick={() => onSaveRpc(rpcRef.current?.value.trim() || null)}
					>
						<MaterialIcon name="save" />
						Save RPC
					</button>
					<button
						type="button"
						class="btn btn-secondary"
						id="btn-clear-rpc"
						onClick={() => {
							if (rpcRef.current) rpcRef.current.value = '';
							onClearRpc();
						}}
					>
						<MaterialIcon name="clear" />
						Clear
					</button>
				</div>
			</div>

			<div class="section">
				<h2 class="section-title">
					<MaterialIcon name="storage" />
					Storage
				</h2>
				<p class="form-label">Storage Usage</p>
				<div class="storage-bar">
					<div class={`storage-bar-fill${fillClass}`} id="storage-fill" style={`width: ${pct}%`} />
				</div>
				<p class="storage-text" id="storage-text">
					{usedMB} MB of {quotaMB} MB used ({pct.toFixed(1)}%)
				</p>
			</div>

			<div class="section danger-zone">
				<h2 class="section-title">
					<MaterialIcon name="warning" />
					Danger Zone
				</h2>
				<p class="form-description" style="margin-bottom: 16px;">
					This will permanently delete all your settings, whitelist, and scan history.
				</p>
				<button type="button" class="btn btn-danger" id="btn-clear-all" onClick={onClearAll}>
					<MaterialIcon name="delete_forever" />
					Clear All Data
				</button>
			</div>

			<div
				class="footer-links"
				style="margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border-subtle); display: flex; gap: 16px; justify-content: center;"
			>
				<a
					href="https://github.com/Lykhoyda/testudo"
					target="_blank"
					rel="noopener noreferrer"
					style="color: var(--text-muted); text-decoration: none; display: flex; align-items: center; gap: 4px; font-size: 12px;"
				>
					<MaterialIcon name="code" style="font-size: 16px;" />
					GitHub
				</a>
				<a
					href="https://github.com/Lykhoyda/testudo/blob/main/PRIVACY_POLICY.md"
					target="_blank"
					rel="noopener noreferrer"
					style="color: var(--text-muted); text-decoration: none; display: flex; align-items: center; gap: 4px; font-size: 12px;"
				>
					<MaterialIcon name="privacy_tip" style="font-size: 16px;" />
					Privacy Policy
				</a>
			</div>
		</>
	);
}
