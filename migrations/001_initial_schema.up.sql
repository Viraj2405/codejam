-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Events table
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    raw JSONB NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255),
    resource VARCHAR(255),
    ip VARCHAR(45),
    region VARCHAR(100),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ingest_failed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_events_event_type ON events(event_type);
CREATE INDEX idx_events_actor ON events(actor);
CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_ip ON events(ip);

-- Alerts table
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_refs UUID[] NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    user_id VARCHAR(255),
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    evidence JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);

-- Remediation logs table
CREATE TABLE remediation_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id),
    actor_user VARCHAR(255) NOT NULL,
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('lock_user', 'unlock_user', 'revoke_key')),
    payload JSONB,
    result TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_remediation_logs_alert_id ON remediation_logs(alert_id);
CREATE INDEX idx_remediation_logs_actor ON remediation_logs(actor_user);
CREATE INDEX idx_remediation_logs_timestamp ON remediation_logs(timestamp);

-- User profiles table
CREATE TABLE user_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scaleway_user_id VARCHAR(255) UNIQUE NOT NULL,
    last_seen_ip VARCHAR(45),
    last_seen_region VARCHAR(100),
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    locked BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_user_profiles_scaleway_user_id ON user_profiles(scaleway_user_id);
CREATE INDEX idx_user_profiles_risk_score ON user_profiles(risk_score);

-- Rules table
CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    params JSONB,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_rules_active ON rules(active);

