import type { AnalysisResult } from '../../utils/types';

interface Props {
	analysis: AnalysisResult;
}

export function AlertBox({ analysis }: Props) {
	const primaryWarning =
		analysis.warnings?.find((w) => w.severity === 'CRITICAL' || w.severity === 'HIGH') ||
		analysis.warnings?.find((w) => w.severity === 'MEDIUM');

	const fallbackTitle =
		analysis.risk === 'CRITICAL' ? 'Fund Drain Detected' : 'Multiple Risk Factors Detected';
	const fallbackDescription =
		analysis.risk === 'CRITICAL'
			? 'This contract contains logic known to drain wallets immediately upon signature.'
			: 'This contract has multiple concerning patterns that warrant caution.';

	const title = primaryWarning?.title || fallbackTitle;
	const description = primaryWarning?.description || fallbackDescription;
	const isMedium = analysis.risk === 'MEDIUM';

	return (
		<div class={`testudo-alert${isMedium ? ' testudo-alert-medium' : ''}`}>
			<div class="testudo-alert-header">
				<span class="testudo-material-icon">{isMedium ? 'info' : 'error'}</span>
				<span class="testudo-alert-title">
					{analysis.risk}: {title}
				</span>
			</div>
			<p class="testudo-alert-description">{description}</p>
		</div>
	);
}
