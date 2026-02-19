import { computed, signal } from '@preact/signals';
import type {
	AnalysisResult,
	ApprovalInfo,
	BlindSignatureInfo,
	HumanReadableIntent,
	NftApprovalInfo,
	PermitInfo,
	TypedDataScanInfo,
	WarningContext,
	WarningOptions,
} from '../utils/types';

interface WarningState {
	visible: boolean;
	loading: boolean;
	analysis: AnalysisResult | null;
	context: WarningContext;
	permitInfo?: PermitInfo;
	approvalInfo?: ApprovalInfo;
	nftApprovalInfo?: NftApprovalInfo;
	blindSignatureInfo?: BlindSignatureInfo;
	typedDataScanInfo?: TypedDataScanInfo;
	intent?: HumanReadableIntent;
	resolver: ((value: boolean) => void) | null;
}

const INITIAL_STATE: WarningState = {
	visible: false,
	loading: false,
	analysis: null,
	context: 'delegation',
	resolver: null,
};

export const state = signal<WarningState>(INITIAL_STATE);
export const confirmInput = signal('');
export const isConfirmValid = computed(
	() => confirmInput.value.trim().toUpperCase() === 'I ACCEPT THE RISK',
);
export const copyIcon = signal('content_copy');

export function show(opts: WarningOptions): Promise<boolean> {
	const previousResolver = state.value.resolver;
	if (previousResolver) {
		previousResolver(false);
	}

	return new Promise((resolve) => {
		confirmInput.value = '';
		copyIcon.value = 'content_copy';
		state.value = {
			visible: true,
			loading: false,
			analysis: opts.analysis,
			context: opts.context ?? 'delegation',
			permitInfo: opts.permitInfo,
			approvalInfo: opts.approvalInfo,
			nftApprovalInfo: opts.nftApprovalInfo,
			blindSignatureInfo: opts.blindSignatureInfo,
			typedDataScanInfo: opts.typedDataScanInfo,
			intent: opts.intent,
			resolver: resolve,
		};
	});
}

export interface LoadingOptions {
	context: WarningContext;
	address: string;
}

export function showLoading(opts: LoadingOptions): Promise<boolean> {
	const previousResolver = state.value.resolver;
	if (previousResolver) {
		previousResolver(false);
	}

	return new Promise((resolve) => {
		confirmInput.value = '';
		copyIcon.value = 'content_copy';
		state.value = {
			visible: true,
			loading: true,
			analysis: {
				address: opts.address as `0x${string}`,
				risk: 'UNKNOWN',
				threats: [],
				blocked: false,
			},
			context: opts.context,
			resolver: resolve,
		};
	});
}

export function updateAnalysis(analysis: AnalysisResult, intent?: HumanReadableIntent): void {
	const current = state.value;
	if (!current.visible || !current.resolver) return;
	state.value = {
		...current,
		loading: false,
		analysis,
		intent,
	};
}

// Resolves true = allow transaction to proceed (no user decision needed)
export function dismissLoading(): void {
	const { resolver } = state.value;
	if (!resolver) return;
	state.value = INITIAL_STATE;
	confirmInput.value = '';
	resolver(true);
}

function resolve(value: boolean): void {
	const { resolver } = state.value;
	state.value = INITIAL_STATE;
	confirmInput.value = '';
	if (resolver) resolver(value);
}

export function cancel(): void {
	if (!state.value.loading) {
		window.postMessage({ type: 'TESTUDO_RECORD_BLOCKED' }, '*');
	}
	resolve(false);
}

export function proceed(): void {
	resolve(true);
}

export function ethSignProceed(): void {
	if (!isConfirmValid.value) return;
	resolve(true);
}

export async function copyAddress(): Promise<void> {
	const address = state.value.analysis?.address;
	if (!address) return;
	try {
		await navigator.clipboard.writeText(address);
		copyIcon.value = 'check';
		setTimeout(() => {
			copyIcon.value = 'content_copy';
		}, 2000);
	} catch {
		console.error('[Testudo] Failed to copy address');
	}
}

// --- Info Toast ---

interface InfoToastState {
	visible: boolean;
	title: string;
	text: string;
}

export const infoToast = signal<InfoToastState>({ visible: false, title: '', text: '' });

let infoTimer: ReturnType<typeof setTimeout> | undefined;

export function showInfoToast(analysis: AnalysisResult): void {
	const firstWarning = analysis.warnings?.find((w) => w.severity !== 'INFO');
	infoToast.value = {
		visible: true,
		title: firstWarning?.title || 'Review Required',
		text: firstWarning?.description || 'Review this delegation carefully',
	};
	if (infoTimer) clearTimeout(infoTimer);
	infoTimer = setTimeout(() => {
		infoToast.value = { ...infoToast.value, visible: false };
	}, 7000);
}

export function dismissInfoToast(): void {
	if (infoTimer) clearTimeout(infoTimer);
	infoToast.value = { ...infoToast.value, visible: false };
}

// --- Unknown Toast ---

interface UnknownToastState {
	visible: boolean;
	address: string;
}

export const unknownToast = signal<UnknownToastState>({ visible: false, address: '' });

let unknownTimer: ReturnType<typeof setTimeout> | undefined;

export function showUnknownToast(analysis: AnalysisResult): void {
	unknownToast.value = { visible: true, address: analysis.address };
	if (unknownTimer) clearTimeout(unknownTimer);
	unknownTimer = setTimeout(() => {
		unknownToast.value = { ...unknownToast.value, visible: false };
	}, 5000);
}

export function dismissUnknownToast(): void {
	if (unknownTimer) clearTimeout(unknownTimer);
	unknownToast.value = { ...unknownToast.value, visible: false };
}
