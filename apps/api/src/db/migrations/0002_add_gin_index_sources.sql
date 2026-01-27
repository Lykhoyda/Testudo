CREATE INDEX idx_safe_addresses_sources ON safe_addresses USING GIN (sources);
