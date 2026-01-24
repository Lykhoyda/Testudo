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
