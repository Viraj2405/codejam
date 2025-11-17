-- Drop tables in reverse order
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS user_profiles;
DROP TABLE IF EXISTS remediation_logs;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS events;

-- Drop extensions
DROP EXTENSION IF EXISTS "pg_trgm";
DROP EXTENSION IF EXISTS "uuid-ossp";

