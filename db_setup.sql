
-- Create tables for RansomEye

-- Table for detected events
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT,
    severity INTEGER,
    source TEXT,
    description TEXT,
    mitigated BOOLEAN DEFAULT 0
);

-- Table for file events
CREATE TABLE IF NOT EXISTS file_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    file_path TEXT,
    file_hash TEXT,
    entropy REAL,
    action_taken TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

-- Table for process events
CREATE TABLE IF NOT EXISTS process_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    pid INTEGER,
    process_name TEXT,
    command_line TEXT,
    parent_pid INTEGER,
    process_tree TEXT,
    action_taken TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

-- Table for network events
CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER,
    source_ip TEXT,
    destination_ip TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT,
    packet_count INTEGER,
    action_taken TEXT,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

-- Table for configurations
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Insert default configurations
INSERT OR IGNORE INTO config (key, value) VALUES
    ('scan_interval', '60'),
    ('entropy_threshold', '7.8'),
    ('file_rename_threshold', '10'),
    ('process_cpu_threshold', '80'),
    ('network_conn_threshold', '50'),
    ('ai_confidence_threshold', '0.7'),
    ('auto_mitigation', 'False');
