CREATE TABLE "revocations" (
	"id" serial PRIMARY KEY NOT NULL,
	"address" varchar(42) NOT NULL,
	"chain_id" integer DEFAULT 1 NOT NULL,
	"reason" text NOT NULL,
	"revoked_by" varchar(100) NOT NULL,
	"is_active" boolean DEFAULT true NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "safe_addresses" (
	"id" serial PRIMARY KEY NOT NULL,
	"address" varchar(42) NOT NULL,
	"chain_id" integer DEFAULT 1 NOT NULL,
	"name" varchar(255),
	"category" varchar(50) NOT NULL,
	"is_delegation_safe" boolean DEFAULT false NOT NULL,
	"sources" text[] NOT NULL,
	"confidence" numeric(3, 2) NOT NULL,
	"metadata" jsonb,
	"first_seen" timestamp DEFAULT now() NOT NULL,
	"last_updated" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "uq_safe_address_chain" UNIQUE("address","chain_id"),
	CONSTRAINT "safe_address_lowercase_check" CHECK ("safe_addresses"."address" = LOWER("safe_addresses"."address"))
);
--> statement-breakpoint
CREATE TABLE "safe_filter_builds" (
	"id" serial PRIMARY KEY NOT NULL,
	"version" varchar(50) NOT NULL,
	"format" varchar(20) DEFAULT 'json' NOT NULL,
	"entry_count" integer NOT NULL,
	"file_size_bytes" integer NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"r2_key" varchar(255) NOT NULL,
	"r2_url" varchar(512) NOT NULL,
	"revocation_count" integer DEFAULT 0 NOT NULL,
	"build_duration_ms" integer,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "idx_revocations_address" ON "revocations" USING btree ("address");--> statement-breakpoint
CREATE INDEX "idx_revocations_active" ON "revocations" USING btree ("is_active");--> statement-breakpoint
CREATE INDEX "idx_safe_address" ON "safe_addresses" USING btree ("address");--> statement-breakpoint
CREATE INDEX "idx_safe_chain_address" ON "safe_addresses" USING btree ("chain_id","address");