import type { ScheduledTask } from 'node-cron';
import cron from 'node-cron';
import { runSyncSafe } from './orchestrator.js';

let task: ScheduledTask | null = null;
let initialTimeout: ReturnType<typeof setTimeout> | null = null;

export function startScheduler(): void {
	// Run initial sync after 5s delay (let DB connection stabilize)
	initialTimeout = setTimeout(() => {
		console.log('[Scheduler] Running initial sync...');
		runSyncSafe();
	}, 5000);

	// Schedule every 30 minutes
	task = cron.schedule('*/30 * * * *', () => {
		console.log('[Scheduler] Running scheduled sync...');
		runSyncSafe();
	});

	console.log('[Scheduler] Started - syncing every 30 minutes');
}

export function stopScheduler(): void {
	if (task) {
		task.stop();
		task = null;
	}
	if (initialTimeout) {
		clearTimeout(initialTimeout);
		initialTimeout = null;
	}
	console.log('[Scheduler] Stopped');
}
