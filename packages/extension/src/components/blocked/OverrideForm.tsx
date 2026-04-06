import * as vm from '../../hooks/blockedVM';

const styles = {
	wrapper: {
		display: 'flex',
		flexDirection: 'column' as const,
		gap: '8px',
	},
	label: {
		fontFamily: 'var(--font-mono)',
		fontSize: '11px',
		color: 'var(--text-muted)',
		letterSpacing: '0.06em',
	},
	row: {
		display: 'flex',
		gap: '8px',
	},
	input: {
		flex: 1,
		background: 'var(--bg-void)',
		border: '1px solid var(--border-hard)',
		borderRadius: '8px',
		padding: '10px 12px',
		color: 'var(--text-bright)',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		outline: 'none',
	},
	btn: {
		padding: '10px 16px',
		background: 'var(--danger-glow)',
		border: '1px solid rgba(255, 59, 92, 0.3)',
		borderRadius: '8px',
		color: 'var(--danger)',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		fontWeight: 700,
		letterSpacing: '0.08em',
		textTransform: 'uppercase' as const,
		cursor: 'pointer',
		whiteSpace: 'nowrap' as const,
	},
	btnDisabled: {
		opacity: 0.4,
		cursor: 'not-allowed',
	},
} as const;

export function OverrideForm() {
	const domain = vm.domain.value;
	const isValid = vm.isOverrideValid.value;

	const btnStyle = isValid ? styles.btn : { ...styles.btn, ...styles.btnDisabled };

	return (
		<div style={styles.wrapper}>
			<span style={styles.label}>
				Type <strong style={{ color: 'var(--text-primary)' }}>{domain}</strong> to override
				protection
			</span>
			<div style={styles.row}>
				<input
					type="text"
					style={styles.input}
					placeholder={domain}
					value={vm.overrideInput.value}
					onInput={(e) => {
						vm.overrideInput.value = (e.target as HTMLInputElement).value;
					}}
				/>
				<button
					type="button"
					style={btnStyle}
					disabled={!isValid}
					onClick={() => void vm.override()}
				>
					OVERRIDE
				</button>
			</div>
		</div>
	);
}
