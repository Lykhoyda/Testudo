CREATE TABLE "domains" (
	"id" serial PRIMARY KEY NOT NULL,
	"domain" varchar(255) NOT NULL,
	"threat_type" varchar(50) NOT NULL,
	"confidence" numeric(3, 2) NOT NULL,
	"sources" text[] NOT NULL,
	"is_fuzzy_match" boolean DEFAULT false NOT NULL,
	"matched_legitimate" varchar(255),
	"metadata" jsonb,
	"first_seen" timestamp DEFAULT now() NOT NULL,
	"last_updated" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "domains_domain_unique" UNIQUE("domain")
);
--> statement-breakpoint
CREATE TABLE "encounters" (
	"id" serial PRIMARY KEY NOT NULL,
	"address" varchar(42),
	"domain" varchar(255),
	"chain_id" integer DEFAULT 1 NOT NULL,
	"action" varchar(20) NOT NULL,
	"extension_version" varchar(20),
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sync_logs" (
	"id" serial PRIMARY KEY NOT NULL,
	"source" varchar(50) NOT NULL,
	"status" varchar(20) NOT NULL,
	"records_added" integer DEFAULT 0 NOT NULL,
	"records_updated" integer DEFAULT 0 NOT NULL,
	"error_message" text,
	"duration_ms" integer,
	"synced_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "threats" (
	"id" serial PRIMARY KEY NOT NULL,
	"address" varchar(42) NOT NULL,
	"chain_id" integer DEFAULT 1 NOT NULL,
	"threat_type" varchar(50) NOT NULL,
	"threat_level" varchar(20) NOT NULL,
	"confidence" numeric(3, 2) NOT NULL,
	"sources" text[] NOT NULL,
	"metadata" jsonb,
	"first_seen" timestamp DEFAULT now() NOT NULL,
	"last_updated" timestamp DEFAULT now() NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "threats_address_unique" UNIQUE("address"),
	CONSTRAINT "address_lowercase_check" CHECK ("threats"."address" = LOWER("threats"."address"))
);
--> statement-breakpoint
CREATE INDEX "idx_domains_domain" ON "domains" USING btree ("domain");--> statement-breakpoint
CREATE INDEX "idx_encounters_address" ON "encounters" USING btree ("address");--> statement-breakpoint
CREATE INDEX "idx_encounters_created_at" ON "encounters" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "idx_threats_address" ON "threats" USING btree ("address");