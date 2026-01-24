import { db } from '../src/db';
import { threats } from '../src/db/schema.js';

const SEED_THREATS = [
	{
		address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
		chainId: 1,
		threatType: 'ETH_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo'],
	},
	{
		address: '0xa85d90b8febc092e11e75bf8f93a7090e2ed04de',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo', 'slowmist'],
	},
	{
		address: '0x0000db5c8b030ae20308ac975898e09741e70000',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo', 'slowmist'],
	},
	{
		address: '0x00008c22f9f6f3101533f520e229bbb54be90000',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo', 'slowmist'],
	},
];

async function seed() {
	console.log('Seeding threat data...');

	for (const entry of SEED_THREATS) {
		await db
			.insert(threats)
			.values(entry)
			.onConflictDoNothing({ target: threats.address });
	}

	console.log(`Seeded ${SEED_THREATS.length} threat entries (conflicts skipped).`);
	process.exit(0);
}

seed().catch((error) => {
	console.error('Seed failed:', error);
	process.exit(1);
});
