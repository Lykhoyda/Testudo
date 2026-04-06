import { useEffect } from 'preact/hooks';
import * as vm from '../../hooks/blockedVM';
import { OverrideForm } from './OverrideForm';

const styles = {
	container: {
		display: 'flex',
		flexDirection: 'column' as const,
		gap: '16px',
	},
	header: {
		display: 'flex',
		alignItems: 'center',
		gap: '12px',
		padding: '14px 18px',
		background: 'var(--bg-void)',
		border: '1px solid rgba(255, 59, 92, 0.2)',
		borderRadius: '10px',
	},
	dot: {
		width: '10px',
		height: '10px',
		borderRadius: '50%',
		background: 'var(--danger)',
		flexShrink: 0,
		boxShadow: '0 0 8px var(--danger)',
		animation: 'pulse-dot 2s ease-in-out infinite',
	},
	headerTitle: {
		fontFamily: 'var(--font-mono)',
		fontSize: '13px',
		fontWeight: 700,
		letterSpacing: '0.12em',
		textTransform: 'uppercase' as const,
		color: 'var(--danger)',
	},
	card: {
		background: 'var(--bg-surface)',
		border: '1px solid rgba(255, 59, 92, 0.15)',
		borderRadius: '10px',
		padding: '20px',
		display: 'flex',
		flexDirection: 'column' as const,
		gap: '8px',
	},
	terminalLine: {
		display: 'flex',
		alignItems: 'flex-start',
		gap: '8px',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		lineHeight: '1.6',
	},
	terminalTag: {
		color: 'var(--text-muted)',
		flexShrink: 0,
		minWidth: '56px',
	},
	terminalValue: {
		color: 'var(--text-primary)',
		wordBreak: 'break-all' as const,
	},
	terminalDanger: {
		color: 'var(--danger)',
		fontWeight: 700,
	},
	terminalWarning: {
		color: 'var(--warning)',
	},
	infoBox: {
		background: 'var(--warning-glow)',
		border: '1px solid rgba(255, 170, 44, 0.2)',
		borderRadius: '8px',
		padding: '12px 16px',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		color: 'var(--warning)',
		lineHeight: '1.5',
	},
	actions: {
		display: 'flex',
		gap: '10px',
		marginTop: '4px',
	},
	btnPrimary: {
		flex: 1,
		padding: '11px 16px',
		background: 'var(--bg-void)',
		border: '1px solid var(--border-hard)',
		borderRadius: '8px',
		color: 'var(--text-bright)',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		fontWeight: 700,
		letterSpacing: '0.08em',
		textTransform: 'uppercase' as const,
		cursor: 'pointer',
	},
	btnDanger: {
		flex: 1,
		padding: '11px 16px',
		background: 'transparent',
		border: '1px solid rgba(255, 59, 92, 0.3)',
		borderRadius: '8px',
		color: 'var(--danger)',
		fontFamily: 'var(--font-mono)',
		fontSize: '12px',
		fontWeight: 700,
		letterSpacing: '0.08em',
		textTransform: 'uppercase' as const,
		cursor: 'pointer',
	},
} as const;

export function BlockScreen() {
	useEffect(() => {
		vm.initFromUrlParams();
		void vm.fetchMetadata();
	}, []);

	const state = vm.screenState.value;
	const domainVal = vm.domain.value;
	const meta = vm.metadata.value;

	const isHardBlock = state === 'hard-block';
	const headerLabel = state === 'soft-allow' ? 'UNCONFIRMED THREAT' : 'THREAT INTERCEPTED';

	if (state === 'loading') {
		return (
			<div style={styles.container}>
				<div style={styles.header}>
					<div style={styles.dot} />
					<span style={styles.headerTitle}>Analyzing...</span>
				</div>
			</div>
		);
	}

	return (
		<div style={styles.container}>
			<div style={styles.header}>
				<div style={styles.dot} />
				<span style={styles.headerTitle}>{headerLabel}</span>
			</div>

			<div style={styles.card}>
				<div style={styles.terminalLine}>
					<span style={styles.terminalTag}>[SCAN]</span>
					<span style={styles.terminalValue}>{domainVal || '—'}</span>
				</div>

				{meta?.sources && meta.sources.length > 0 && (
					<div style={styles.terminalLine}>
						<span style={styles.terminalTag}>[MATCH]</span>
						<span style={styles.terminalValue}>{meta.sources.join(', ')}</span>
					</div>
				)}

				{meta?.threatType && (
					<div style={styles.terminalLine}>
						<span style={styles.terminalTag}>[TYPE]</span>
						<span style={{ ...styles.terminalValue, ...styles.terminalWarning }}>
							{meta.threatType}
						</span>
					</div>
				)}

				{(meta?.matchedLegitimate || meta?.firstSeen) && (
					<div style={styles.terminalLine}>
						<span style={styles.terminalTag}>[INFO]</span>
						<span style={styles.terminalValue}>
							{meta.matchedLegitimate && <>Mimics: {meta.matchedLegitimate}</>}
							{meta.matchedLegitimate && meta.firstSeen && ' · '}
							{meta.firstSeen && <>First seen: {meta.firstSeen}</>}
						</span>
					</div>
				)}

				<div style={styles.terminalLine}>
					<span style={styles.terminalTag}>[RISK]</span>
					<span style={{ ...styles.terminalValue, ...styles.terminalDanger }}>CRITICAL</span>
				</div>
			</div>

			{state === 'soft-block' && (
				<div style={styles.infoBox}>
					API unavailable — domain matched local threat database but could not be confirmed in
					real-time.
				</div>
			)}

			{state === 'soft-allow' && (
				<div
					style={{
						...styles.infoBox,
						background: 'var(--phosphor-faint)',
						border: '1px solid rgba(0, 229, 153, 0.15)',
						color: 'var(--text-muted)',
					}}
				>
					Could not confirm threat — domain was flagged but real-time check shows clean.
				</div>
			)}

			{isHardBlock && <OverrideForm />}

			<div style={styles.actions}>
				<button type="button" style={styles.btnPrimary} onClick={vm.goBack}>
					SAFE EXIT
				</button>

				{!isHardBlock && (
					<button
						type="button"
						style={styles.btnDanger}
						onClick={() => vm.safeNavigate(vm.originalUrl.value)}
					>
						PROCEED ANYWAY
					</button>
				)}
			</div>
		</div>
	);
}
