import { formatThreat, getThreatIcon, getThreatShortDesc } from '../../utils/threat-data';

interface Props {
	threats: string[];
}

export function ThreatList({ threats }: Props) {
	return (
		<div class="testudo-threats">
			<h3 class="testudo-threats-title">Threats Detected</h3>
			{threats.slice(0, 3).map((threat) => (
				<div class="testudo-threat-item" key={threat}>
					<div class="testudo-threat-icon">
						<span class="testudo-material-icon">{getThreatIcon(threat)}</span>
					</div>
					<div class="testudo-threat-content">
						<span class="testudo-threat-name">{formatThreat(threat)}</span>
						<span class="testudo-threat-desc">{getThreatShortDesc(threat)}</span>
					</div>
				</div>
			))}
		</div>
	);
}
