import { useEffect } from 'preact/hooks';
import * as vm from '../../hooks/warningVM';
import { AddressBox } from './AddressBox';
import { AlertBox } from './AlertBox';
import { ContextDetails } from './ContextDetails';
import { ModalButtons } from './ModalButtons';
import { ModalHeader } from './ModalHeader';
import { ThreatList } from './ThreatList';

export function WarningModal() {
	const {
		visible,
		analysis,
		context,
		permitInfo,
		approvalInfo,
		nftApprovalInfo,
		blindSignatureInfo,
		typedDataScanInfo,
		intent,
	} = vm.state.value;

	useEffect(() => {
		if (!visible) return;
		const handler = (e: KeyboardEvent) => {
			if (e.key === 'Escape') vm.cancel();
		};
		document.addEventListener('keydown', handler);
		return () => document.removeEventListener('keydown', handler);
	}, [visible]);

	if (!visible || !analysis) return null;

	return (
		<div id="testudo-warning-overlay">
			<div class="testudo-modal">
				<ModalHeader context={context} analysis={analysis} intent={intent} />
				<AlertBox analysis={analysis} />
				<ContextDetails
					permitInfo={permitInfo}
					approvalInfo={approvalInfo}
					nftApprovalInfo={nftApprovalInfo}
					blindSignatureInfo={blindSignatureInfo}
					typedDataScanInfo={typedDataScanInfo}
					intent={intent}
				/>
				<ThreatList threats={analysis.threats} />
				<AddressBox
					address={analysis.address}
					context={context}
					copyIcon={vm.copyIcon}
					onCopy={vm.copyAddress}
				/>
				<ModalButtons
					context={context}
					confirmInput={vm.confirmInput}
					isConfirmValid={vm.isConfirmValid}
					onCancel={vm.cancel}
					onProceed={vm.proceed}
					onEthSignProceed={vm.ethSignProceed}
					onConfirmInput={(val) => {
						vm.confirmInput.value = val;
					}}
				/>
			</div>
		</div>
	);
}
