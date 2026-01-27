import type { ScheduledTask } from 'node-cron';
import cron from 'node-cron';
import { buildFilter, buildRevocations } from '../modules/safe/filter-service.js';
import { runSafeSyncSafe } from '../modules/safe/orchestrator.js';
import { runSyncSafe } from '../modules/threats/orchestrator.js';

let threatSyncTask: ScheduledTask | null = null;
let safeSyncTask: ScheduledTask | null = null;
let revocationTask: ScheduledTask | null = null;
let initialThreatTimeout: ReturnType<typeof setTimeout> | null = null;
let initialSafeTimeout: ReturnType<typeof setTimeout> | null = null;

export function startScheduler(): void {
	initialThreatTimeout = setTimeout(() => {
		console.log('[Scheduler] Running initial threat sync...');
		runSyncSafe();
	}, 5000);

	initialSafeTimeout = setTimeout(async () => {
		console.log('[Scheduler] Running initial safe sync + filter build...');
		await runSafeSyncSafe();
		try {
			await buildFilter();
			await buildRevocations();
		} catch (error) {
			console.error('[Scheduler] Initial filter build failed:', error);
		}
	}, 10000);

	threatSyncTask = cron.schedule('*/30 * * * *', () => {
		console.log('[Scheduler] Running scheduled threat sync...');
		runSyncSafe();
	});

	safeSyncTask = cron.schedule('0 3 * * *', async () => {
		console.log('[Scheduler] Running daily safe sync + filter build...');
		await runSafeSyncSafe();
		try {
			await buildFilter();
			await buildRevocations();
		} catch (error) {
			console.error('[Scheduler] Filter build failed:', error);
		}
	});

	revocationTask = cron.schedule('0 * * * *', async () => {
		console.log('[Scheduler] Running hourly revocations rebuild...');
		try {
			await buildRevocations();
		} catch (error) {
			console.error('[Scheduler] Revocations rebuild failed:', error);
		}
	});

	console.log('[Scheduler] Started - threats: every 30min, safe: daily 3am, revocations: hourly');
}

export function stopScheduler(): void {
	if (threatSyncTask) {
		threatSyncTask.stop();
		threatSyncTask = null;
	}
	if (safeSyncTask) {
		safeSyncTask.stop();
		safeSyncTask = null;
	}
	if (revocationTask) {
		revocationTask.stop();
		revocationTask = null;
	}
	if (initialThreatTimeout) {
		clearTimeout(initialThreatTimeout);
		initialThreatTimeout = null;
	}
	if (initialSafeTimeout) {
		clearTimeout(initialSafeTimeout);
		initialSafeTimeout = null;
	}
	console.log('[Scheduler] Stopped');
}
