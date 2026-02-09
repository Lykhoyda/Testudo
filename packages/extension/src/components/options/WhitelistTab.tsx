import type { ReadonlySignal } from '@preact/signals';
import { useRef } from 'preact/hooks';
import { formatDate, truncateAddress } from '../../utils/formatters';
import type { WhitelistEntry } from '../../utils/types';
import { MaterialIcon } from '../shared/MaterialIcon';

interface Props {
	whitelist: ReadonlySignal<WhitelistEntry[]>;
	onAdd: (address: string, label: string) => Promise<boolean>;
	onRemove: (address: string) => void;
	onExport: () => void;
	onImport: (file: File) => void;
}

export function WhitelistTab({ whitelist: wl, onAdd, onRemove, onExport, onImport }: Props) {
	const addressRef = useRef<HTMLInputElement>(null);
	const labelRef = useRef<HTMLInputElement>(null);
	const fileRef = useRef<HTMLInputElement>(null);

	const handleAdd = async () => {
		const address = addressRef.current?.value.trim() || '';
		const label = labelRef.current?.value.trim() || '';
		const success = await onAdd(address, label);
		if (success && addressRef.current && labelRef.current) {
			addressRef.current.value = '';
			labelRef.current.value = '';
		}
	};

	const handleFileChange = (e: Event) => {
		const file = (e.target as HTMLInputElement).files?.[0];
		if (file) {
			onImport(file);
			if (fileRef.current) fileRef.current.value = '';
		}
	};

	return (
		<div class="section">
			<div class="whitelist-header">
				<h2 class="section-title">
					<MaterialIcon name="verified" />
					Whitelisted Addresses
				</h2>
				<span class="whitelist-count" id="whitelist-count">
					{wl.value.length} address{wl.value.length !== 1 ? 'es' : ''}
				</span>
			</div>

			<div class="whitelist-add">
				<input type="text" id="whitelist-address" placeholder="0x..." ref={addressRef} />
				<input
					type="text"
					id="whitelist-label"
					placeholder="Label (optional)"
					style="max-width: 200px;"
					ref={labelRef}
				/>
				<button type="button" class="btn btn-success" id="btn-add-whitelist" onClick={handleAdd}>
					<MaterialIcon name="add" />
					Add
				</button>
			</div>

			<table class="whitelist-table">
				<thead>
					<tr>
						<th>Address</th>
						<th>Label</th>
						<th>Added</th>
						<th />
					</tr>
				</thead>
				<tbody id="whitelist-body">
					{wl.value.length === 0 ? (
						<tr>
							<td colspan={4} class="whitelist-empty">
								No whitelisted addresses
							</td>
						</tr>
					) : (
						wl.value.map((entry) => (
							<tr key={entry.address} data-address={entry.address}>
								<td class="whitelist-address">{truncateAddress(entry.address, 10, 8)}</td>
								<td>{entry.label || '-'}</td>
								<td>{formatDate(entry.addedAt)}</td>
								<td>
									<button
										type="button"
										class="btn-remove"
										data-address={entry.address}
										onClick={() => onRemove(entry.address)}
									>
										Remove
									</button>
								</td>
							</tr>
						))
					)}
				</tbody>
			</table>

			<div class="whitelist-actions">
				<button
					type="button"
					class="btn btn-secondary"
					id="btn-import"
					onClick={() => fileRef.current?.click()}
				>
					<MaterialIcon name="upload" />
					Import
				</button>
				<button type="button" class="btn btn-secondary" id="btn-export" onClick={onExport}>
					<MaterialIcon name="download" />
					Export
				</button>
			</div>

			<input
				type="file"
				id="import-file"
				accept=".json"
				style="display: none;"
				ref={fileRef}
				onChange={handleFileChange}
			/>
		</div>
	);
}
