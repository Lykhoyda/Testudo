import { formatApprovalAmount, isUnlimitedValue } from '../../parsers/transaction';
import { truncateAddress } from '../../utils/formatters';
import type {
	ApprovalInfo,
	BlindSignatureInfo,
	NftApprovalInfo,
	PermitInfo,
	TypedDataScanInfo,
} from '../../utils/types';

interface Props {
	permitInfo?: PermitInfo;
	approvalInfo?: ApprovalInfo;
	nftApprovalInfo?: NftApprovalInfo;
	blindSignatureInfo?: BlindSignatureInfo;
	typedDataScanInfo?: TypedDataScanInfo;
}

function AddressRow({
	label,
	value,
	style,
	mb = true,
}: {
	label: string;
	value: string;
	style?: string;
	mb?: boolean;
}) {
	return (
		<div class="testudo-address-box" style={mb ? 'margin-bottom:6px' : undefined}>
			<span class="testudo-address-label">{label}</span>
			<span class="testudo-address-text" style={style}>
				{value}
			</span>
		</div>
	);
}

export function ContextDetails({
	permitInfo,
	approvalInfo,
	nftApprovalInfo,
	blindSignatureInfo,
	typedDataScanInfo,
}: Props) {
	return (
		<>
			{permitInfo && (
				<div class="testudo-address-section">
					{permitInfo.tokenName && (
						<AddressRow
							label="Token"
							value={`${permitInfo.tokenName}${permitInfo.token ? ` (${permitInfo.token.slice(0, 8)}...)` : ''}`}
						/>
					)}
					<AddressRow
						label="Amount"
						value={
							isUnlimitedValue(permitInfo.value)
								? 'UNLIMITED'
								: permitInfo.value === 'batch'
									? 'Batch (multiple tokens)'
									: permitInfo.value || 'Unknown'
						}
						style={isUnlimitedValue(permitInfo.value) ? 'color:#e74c3c;font-weight:700' : undefined}
					/>
					{permitInfo.deadline && (
						<AddressRow label="Deadline" value={String(permitInfo.deadline)} mb={false} />
					)}
				</div>
			)}

			{approvalInfo && (
				<div class="testudo-address-section">
					<AddressRow label="Token Contract" value={truncateAddress(approvalInfo.tokenAddress)} />
					<AddressRow
						label="Amount"
						value={formatApprovalAmount(approvalInfo.amount)}
						style={
							isUnlimitedValue(approvalInfo.amount) ? 'color:#e74c3c;font-weight:700' : undefined
						}
					/>
					<AddressRow
						label="Operation"
						value={
							approvalInfo.type === 'approve'
								? 'approve()'
								: approvalInfo.type === 'increaseAllowance'
									? 'increaseAllowance()'
									: 'decreaseAllowance()'
						}
						mb={false}
					/>
				</div>
			)}

			{nftApprovalInfo && (
				<div class="testudo-address-section">
					<AddressRow
						label="Collection"
						value={truncateAddress(nftApprovalInfo.collectionAddress)}
					/>
					<AddressRow
						label="Access Level"
						value="FULL COLLECTION"
						style="color:#e74c3c;font-weight:700"
						mb={false}
					/>
				</div>
			)}

			{blindSignatureInfo && (
				<div class="testudo-address-section">
					<AddressRow label="Method" value={blindSignatureInfo.type} />
					<AddressRow
						label={`Message${blindSignatureInfo.isHex ? ' (hex)' : ''}`}
						value={blindSignatureInfo.messagePreview}
						style="font-family:monospace;font-size:12px;word-break:break-all"
						mb={false}
					/>
				</div>
			)}

			{typedDataScanInfo && (
				<div class="testudo-address-section">
					<AddressRow label="Primary Type" value={typedDataScanInfo.primaryType} />
					{typedDataScanInfo.domainName && (
						<AddressRow label="Domain" value={typedDataScanInfo.domainName} />
					)}
					{typedDataScanInfo.maliciousAddresses.slice(0, 3).map((a) => (
						<AddressRow
							key={a.address}
							label={`Found in: ${a.fieldPath}`}
							value={truncateAddress(a.address)}
							style="color:#e74c3c"
						/>
					))}
				</div>
			)}
		</>
	);
}
