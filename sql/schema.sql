-- XDR Event Storage Schema
-- SQLite database schema for storing normalized events

-- Main events table
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    source INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    process_id INTEGER NOT NULL,
    thread_id INTEGER NOT NULL,
    session_id INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    prev_sequence_number INTEGER NOT NULL,
    key_hash INTEGER NOT NULL,
    flags TEXT NOT NULL,
    data TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Performance indices
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_severity ON events(source, severity);
CREATE INDEX IF NOT EXISTS idx_events_process_id ON events(process_id);
CREATE INDEX IF NOT EXISTS idx_events_key_hash ON events(key_hash);
CREATE INDEX IF NOT EXISTS idx_events_sequence ON events(sequence_number);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- Event correlation table
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correlation_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    key_hash INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    correlation_type TEXT NOT NULL, -- 'process_chain', 'file_lineage', etc.
    confidence_score REAL DEFAULT 1.0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_correlations_id ON correlations(correlation_id);
CREATE INDEX IF NOT EXISTS idx_correlations_key_hash ON correlations(key_hash);
CREATE INDEX IF NOT EXISTS idx_correlations_type ON correlations(correlation_type);

-- Rule execution results
CREATE TABLE IF NOT EXISTS rule_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    event_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    message TEXT NOT NULL,
    details TEXT, -- JSON
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_rule_results_rule_id ON rule_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_rule_results_event_id ON rule_results(event_id);
CREATE INDEX IF NOT EXISTS idx_rule_results_severity ON rule_results(severity);
CREATE INDEX IF NOT EXISTS idx_rule_results_created_at ON rule_results(created_at);

-- Alerts table (aggregated rule results)
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open', -- open, investigating, resolved, false_positive
    event_count INTEGER NOT NULL DEFAULT 1,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    primary_event_id TEXT NOT NULL,
    details TEXT, -- JSON
    analyst_notes TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (primary_event_id) REFERENCES events (id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_updated_at ON alerts(updated_at);

-- Statistics table for dashboards
CREATE TABLE IF NOT EXISTS statistics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL, -- YYYY-MM-DD format
    source INTEGER NOT NULL,
    severity INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(date, source, severity)
);

CREATE INDEX IF NOT EXISTS idx_statistics_date ON statistics(date);
CREATE INDEX IF NOT EXISTS idx_statistics_source ON statistics(source);

-- Process lineage tracking
CREATE TABLE IF NOT EXISTS process_lineage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_pid INTEGER NOT NULL,
    child_pid INTEGER NOT NULL,
    parent_image_hash INTEGER,
    child_image_hash INTEGER,
    creation_time INTEGER NOT NULL,
    session_id INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_lineage_parent ON process_lineage(parent_pid);
CREATE INDEX IF NOT EXISTS idx_lineage_child ON process_lineage(child_pid);
CREATE INDEX IF NOT EXISTS idx_lineage_creation ON process_lineage(creation_time);

-- File reputation cache
CREATE TABLE IF NOT EXISTS file_reputation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash TEXT NOT NULL UNIQUE,
    file_path TEXT,
    reputation_score REAL NOT NULL DEFAULT 0.0, -- 0.0 = unknown, 1.0 = trusted
    is_signed BOOLEAN DEFAULT 0,
    signer TEXT,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_reputation_hash ON file_reputation(file_hash);
CREATE INDEX IF NOT EXISTS idx_reputation_score ON file_reputation(reputation_score);
CREATE INDEX IF NOT EXISTS idx_reputation_updated ON file_reputation(updated_at);

-- Network connections tracking
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    process_id INTEGER NOT NULL,
    process_image_hash INTEGER,
    local_addr TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_addr TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    direction INTEGER NOT NULL, -- 0=outbound, 1=inbound
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_connections_process ON network_connections(process_id);
CREATE INDEX IF NOT EXISTS idx_connections_remote ON network_connections(remote_addr, remote_port);
CREATE INDEX IF NOT EXISTS idx_connections_first_seen ON network_connections(first_seen);

-- Live response audit log
CREATE TABLE IF NOT EXISTS live_response_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters TEXT, -- JSON
    result TEXT NOT NULL, -- success, failure, partial
    message TEXT,
    user_name TEXT,
    machine_name TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_action_id ON live_response_audit(action_id);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON live_response_audit(action_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON live_response_audit(created_at);

-- Configuration change log
CREATE TABLE IF NOT EXISTS config_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT NOT NULL,
    changed_by TEXT,
    reason TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_config_changes_key ON config_changes(config_key);
CREATE INDEX IF NOT EXISTS idx_config_changes_created_at ON config_changes(created_at);

-- Views for common queries

-- Recent high severity events
CREATE VIEW IF NOT EXISTS recent_high_severity AS
SELECT 
    e.id,
    e.source,
    e.severity,
    datetime(e.timestamp, 'unixepoch') as event_time,
    e.process_id,
    json_extract(e.data, '$.process.image_path') as process_image,
    json_extract(e.data, '$.file.file_path') as file_path,
    json_extract(e.data, '$.network.remote_address.ip') as remote_ip
FROM events e
WHERE e.severity >= 2 -- High or Critical
  AND e.timestamp > strftime('%s', 'now', '-7 days')
ORDER BY e.timestamp DESC;

-- Process creation timeline
CREATE VIEW IF NOT EXISTS process_timeline AS
SELECT 
    e.id,
    datetime(e.timestamp, 'unixepoch') as event_time,
    e.process_id,
    json_extract(e.data, '$.process.parent_process_id') as parent_pid,
    json_extract(e.data, '$.process.image_path') as image_path,
    json_extract(e.data, '$.process.operation') as operation
FROM events e
WHERE e.source = 0 -- Process events
ORDER BY e.timestamp;

-- Network activity summary
CREATE VIEW IF NOT EXISTS network_summary AS
SELECT 
    json_extract(e.data, '$.network.remote_address.ip') as remote_ip,
    json_extract(e.data, '$.network.remote_address.port') as remote_port,
    COUNT(*) as connection_count,
    MIN(datetime(e.timestamp, 'unixepoch')) as first_seen,
    MAX(datetime(e.timestamp, 'unixepoch')) as last_seen,
    GROUP_CONCAT(DISTINCT e.process_id) as process_ids
FROM events e
WHERE e.source = 5 -- Network events
  AND json_extract(e.data, '$.network.remote_address.ip') IS NOT NULL
GROUP BY 
    json_extract(e.data, '$.network.remote_address.ip'),
    json_extract(e.data, '$.network.remote_address.port')
ORDER BY connection_count DESC;

-- File modification timeline
CREATE VIEW IF NOT EXISTS file_modifications AS
SELECT 
    e.id,
    datetime(e.timestamp, 'unixepoch') as event_time,
    e.process_id,
    json_extract(e.data, '$.file.operation') as operation,
    json_extract(e.data, '$.file.file_path') as file_path,
    json_extract(e.data, '$.file.file_extension') as extension
FROM events e
WHERE e.source = 4 -- File events
  AND json_extract(e.data, '$.file.operation') IN ('Create', 'Write', 'Delete')
ORDER BY e.timestamp DESC;

-- Alert summary view
CREATE VIEW IF NOT EXISTS alert_summary AS
SELECT 
    a.id,
    a.rule_name,
    a.severity,
    a.status,
    a.event_count,
    datetime(a.first_seen, 'unixepoch') as first_seen,
    datetime(a.last_seen, 'unixepoch') as last_seen,
    datetime(a.created_at, 'unixepoch') as created_at
FROM alerts a
ORDER BY a.created_at DESC;

-- System health view
CREATE VIEW IF NOT EXISTS system_health AS
SELECT 
    'Total Events' as metric,
    COUNT(*) as value,
    'count' as unit
FROM events
UNION ALL
SELECT 
    'Events Last Hour' as metric,
    COUNT(*) as value,
    'count' as unit
FROM events 
WHERE timestamp > strftime('%s', 'now', '-1 hour')
UNION ALL
SELECT 
    'Open Alerts' as metric,
    COUNT(*) as value,
    'count' as unit
FROM alerts 
WHERE status = 'open'
UNION ALL
SELECT 
    'Database Size' as metric,
    page_count * page_size as value,
    'bytes' as unit
FROM pragma_page_count(), pragma_page_size();

-- Triggers for maintaining statistics

-- Update daily statistics when events are inserted
CREATE TRIGGER IF NOT EXISTS update_daily_stats
AFTER INSERT ON events
BEGIN
    INSERT OR REPLACE INTO statistics (date, source, severity, count)
    VALUES (
        date(NEW.timestamp, 'unixepoch'),
        NEW.source,
        NEW.severity,
        COALESCE((
            SELECT count + 1 
            FROM statistics 
            WHERE date = date(NEW.timestamp, 'unixepoch') 
              AND source = NEW.source 
              AND severity = NEW.severity
        ), 1)
    );
END;

-- Update alert last_seen and event_count
CREATE TRIGGER IF NOT EXISTS update_alert_stats
AFTER INSERT ON rule_results
BEGIN
    UPDATE alerts 
    SET 
        last_seen = strftime('%s', 'now'),
        event_count = event_count + 1,
        updated_at = strftime('%s', 'now')
    WHERE rule_id = NEW.rule_id;
END;