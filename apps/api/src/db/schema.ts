import { sql } from 'drizzle-orm';
import {
	boolean,
	check,
	decimal,
	index,
	integer,
	jsonb,
	pgTable,
	serial,
	text,
	timestamp,
	unique,
	varchar,
} from 'drizzle-orm/pg-core';

export const threats = pgTable(
	'threats',
	{
		id: serial('id').primaryKey(),
		address: varchar('address', { length: 42 }).notNull().unique(),
		chainId: integer('chain_id').notNull().default(1),
		threatType: varchar('threat_type', { length: 50 }).notNull(),
		threatLevel: varchar('threat_level', { length: 20 }).notNull(),
		confidence: decimal('confidence', { precision: 3, scale: 2 }).notNull(),
		sources: text('sources').array().notNull(),
		metadata: jsonb('metadata'),
		firstSeen: timestamp('first_seen').notNull().defaultNow(),
		lastUpdated: timestamp('last_updated').notNull().defaultNow(),
		createdAt: timestamp('created_at').notNull().defaultNow(),
	},
	(table) => [
		index('idx_threats_address').on(table.address),
		check('address_lowercase_check', sql`${table.address} = LOWER(${table.address})`),
	],
);

export const domains = pgTable(
	'domains',
	{
		id: serial('id').primaryKey(),
		domain: varchar('domain', { length: 255 }).notNull().unique(),
		threatType: varchar('threat_type', { length: 50 }).notNull(),
		confidence: decimal('confidence', { precision: 3, scale: 2 }).notNull(),
		sources: text('sources').array().notNull(),
		isFuzzyMatch: boolean('is_fuzzy_match').notNull().default(false),
		matchedLegitimate: varchar('matched_legitimate', { length: 255 }),
		metadata: jsonb('metadata'),
		firstSeen: timestamp('first_seen').notNull().defaultNow(),
		lastUpdated: timestamp('last_updated').notNull().defaultNow(),
		createdAt: timestamp('created_at').notNull().defaultNow(),
	},
	(table) => [index('idx_domains_domain').on(table.domain)],
);

export const encounters = pgTable(
	'encounters',
	{
		id: serial('id').primaryKey(),
		address: varchar('address', { length: 42 }),
		domain: varchar('domain', { length: 255 }),
		chainId: integer('chain_id').notNull().default(1),
		action: varchar('action', { length: 20 }).notNull(),
		extensionVersion: varchar('extension_version', { length: 20 }),
		createdAt: timestamp('created_at').notNull().defaultNow(),
	},
	(table) => [
		index('idx_encounters_address').on(table.address),
		index('idx_encounters_created_at').on(table.createdAt),
	],
);

export const safeAddresses = pgTable(
	'safe_addresses',
	{
		id: serial('id').primaryKey(),
		address: varchar('address', { length: 42 }).notNull(),
		chainId: integer('chain_id').notNull().default(1),
		name: varchar('name', { length: 255 }),
		category: varchar('category', { length: 50 }).notNull(),
		isDelegationSafe: boolean('is_delegation_safe').notNull().default(false),
		sources: text('sources').array().notNull(),
		confidence: decimal('confidence', { precision: 3, scale: 2 }).notNull(),
		metadata: jsonb('metadata'),
		firstSeen: timestamp('first_seen').notNull().defaultNow(),
		lastUpdated: timestamp('last_updated').notNull().defaultNow(),
		createdAt: timestamp('created_at').notNull().defaultNow(),
	},
	(table) => [
		unique('uq_safe_address_chain').on(table.address, table.chainId),
		index('idx_safe_address').on(table.address),
		index('idx_safe_chain_address').on(table.chainId, table.address),
		check('safe_address_lowercase_check', sql`${table.address} = LOWER(${table.address})`),
	],
);

export const revocations = pgTable(
	'revocations',
	{
		id: serial('id').primaryKey(),
		address: varchar('address', { length: 42 }).notNull(),
		chainId: integer('chain_id').notNull().default(1),
		reason: text('reason').notNull(),
		revokedBy: varchar('revoked_by', { length: 100 }).notNull(),
		isActive: boolean('is_active').notNull().default(true),
		createdAt: timestamp('created_at').notNull().defaultNow(),
	},
	(table) => [
		index('idx_revocations_address').on(table.address),
		index('idx_revocations_active').on(table.isActive),
	],
);

export const safeFilterBuilds = pgTable('safe_filter_builds', {
	id: serial('id').primaryKey(),
	version: varchar('version', { length: 50 }).notNull(),
	format: varchar('format', { length: 20 }).notNull().default('json'),
	entryCount: integer('entry_count').notNull(),
	fileSizeBytes: integer('file_size_bytes').notNull(),
	sha256: varchar('sha256', { length: 64 }).notNull(),
	r2Key: varchar('r2_key', { length: 255 }).notNull(),
	r2Url: varchar('r2_url', { length: 512 }).notNull(),
	revocationCount: integer('revocation_count').notNull().default(0),
	buildDurationMs: integer('build_duration_ms'),
	createdAt: timestamp('created_at').notNull().defaultNow(),
});

export const syncLogs = pgTable('sync_logs', {
	id: serial('id').primaryKey(),
	source: varchar('source', { length: 50 }).notNull(),
	status: varchar('status', { length: 20 }).notNull(),
	recordsAdded: integer('records_added').notNull().default(0),
	recordsUpdated: integer('records_updated').notNull().default(0),
	errorMessage: text('error_message'),
	durationMs: integer('duration_ms'),
	syncedAt: timestamp('synced_at').notNull().defaultNow(),
});
