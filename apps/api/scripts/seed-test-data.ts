/**
 * LOCAL DEVELOPMENT ONLY - Test Data Seeder
 *
 * This script seeds the database with sample threat data for local testing.
 * DO NOT run in production - the sync service automatically populates
 * real threat data from ScamSniffer, eth-phishing-detect, and GoPlus.
 *
 * Usage: yarn db:seed-test-data
 */

import { db } from '../src/db';
import { threats, safeAddresses, revocations } from '../src/db/schema.js';

const TEST_THREATS = [
	{
		address: '0x930fcc37d6042c79211ee18a02857cb1fd7f0d0b',
		chainId: 1,
		threatType: 'ETH_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo-test-data'],
	},
	{
		address: '0xa85d90b8febc092e11e75bf8f93a7090e2ed04de',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo-test-data'],
	},
	{
		address: '0x0000db5c8b030ae20308ac975898e09741e70000',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo-test-data'],
	},
	{
		address: '0x00008c22f9f6f3101533f520e229bbb54be90000',
		chainId: 1,
		threatType: 'INFERNO_DRAINER',
		threatLevel: 'CRITICAL',
		confidence: '1.00',
		sources: ['testudo-test-data'],
	},
];

const TEST_SAFE_ADDRESSES = [
	{
		address: '0x1111111111111111111111111111111111111111',
		chainId: 1,
		name: 'Test Safe 1',
		category: 'DEFI_PROTOCOL',
		sources: ['test-seed'],
		confidence: '0.95',
		isDelegationSafe: true,
	},
	{
		address: '0x2222222222222222222222222222222222222222',
		chainId: 1,
		name: 'Test Safe 2',
		category: 'STABLECOIN',
		sources: ['test-seed'],
		confidence: '0.90',
		isDelegationSafe: true,
	},
	{
		address: '0x3333333333333333333333333333333333333333',
		chainId: 1,
		name: 'Test Revoked',
		category: 'DEFI_PROTOCOL',
		sources: ['test-seed'],
		confidence: '0.85',
		isDelegationSafe: true,
	},
];

const TEST_REVOCATIONS = [
	{
		address: '0x3333333333333333333333333333333333333333',
		chainId: 1,
		reason: 'test_revocation',
		revokedBy: 'test-seed',
		isActive: true,
	},
];

async function seedTestData() {
	console.log('⚠️  LOCAL DEVELOPMENT ONLY - Seeding test threat data...');
	console.log('   (Production uses automated sync service)\n');

	for (const entry of TEST_THREATS) {
		await db
			.insert(threats)
			.values(entry)
			.onConflictDoNothing({ target: threats.address });
	}
	console.log(`✓ Seeded ${TEST_THREATS.length} test threat entries (conflicts skipped).`);

	for (const entry of TEST_SAFE_ADDRESSES) {
		await db
			.insert(safeAddresses)
			.values(entry)
			.onConflictDoNothing();
	}
	console.log(`✓ Seeded ${TEST_SAFE_ADDRESSES.length} safe address entries (conflicts skipped).`);

	for (const entry of TEST_REVOCATIONS) {
		await db
			.insert(revocations)
			.values(entry);
	}
	console.log(`✓ Seeded ${TEST_REVOCATIONS.length} revocation entries.`);

	process.exit(0);
}

seedTestData().catch((error) => {
	console.error('Seed failed:', error);
	process.exit(1);
});
