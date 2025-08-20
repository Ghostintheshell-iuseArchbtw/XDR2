//! Storage Layer Module
//! 
//! Provides persistent storage for events using SQLite with WAL mode
//! and NDJSON export capabilities for analysis and debugging.

use crate::events::{EventEnvelope, EventSource, Severity};
use crate::{LibResult, XdrError};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde_json;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Storage-specific error types
#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Storage not initialized")]
    NotInitialized,
    
    #[error("Invalid query parameters: {0}")]
    InvalidQuery(String),
    
    #[error("Event not found: {0}")]
    NotFound(String),
    
    #[error("Schema migration failed: {0}")]
    Migration(String),
    
    #[error("Storage limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Database file path
    pub database_path: PathBuf,
    
    /// NDJSON export directory
    pub export_directory: PathBuf,
    
    /// Maximum database size in bytes
    pub max_database_size: u64,
    
    /// Event retention period in days
    pub retention_days: u32,
    
    /// Enable WAL mode
    pub enable_wal: bool,
    
    /// Connection pool size
    pub pool_size: u32,
    
    /// Batch size for bulk operations
    pub batch_size: usize,
    
    /// Auto-vacuum mode
    pub auto_vacuum: bool,
    
    /// Enable NDJSON export
    pub enable_ndjson_export: bool,
    
    /// Compression for old data
    pub enable_compression: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("C:\\ProgramData\\XDR\\events.db"),
            export_directory: PathBuf::from("C:\\ProgramData\\XDR\\exports"),
            max_database_size: 10 * 1024 * 1024 * 1024, // 10 GB
            retention_days: 90,
            enable_wal: true,
            pool_size: 10,
            batch_size: 1000,
            auto_vacuum: true,
            enable_ndjson_export: true,
            enable_compression: true,
        }
    }
}

/// Event query parameters
#[derive(Debug, Clone)]
pub struct EventQuery {
    /// Filter by event source
    pub source: Option<EventSource>,
    
    /// Filter by minimum severity
    pub min_severity: Option<Severity>,
    
    /// Time range start
    pub start_time: Option<DateTime<Utc>>,
    
    /// Time range end
    pub end_time: Option<DateTime<Utc>>,
    
    /// Filter by process ID
    pub process_id: Option<u32>,
    
    /// Filter by key hash (for correlation)
    pub key_hash: Option<u64>,
    
    /// Text search in event data
    pub search_text: Option<String>,
    
    /// Maximum results to return
    pub limit: Option<u32>,
    
    /// Result offset for pagination
    pub offset: Option<u32>,
    
    /// Sort order (newest first by default)
    pub ascending: bool,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            source: None,
            min_severity: None,
            start_time: None,
            end_time: None,
            process_id: None,
            key_hash: None,
            search_text: None,
            limit: Some(1000),
            offset: None,
            ascending: false,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_events: u64,
    pub events_by_source: HashMap<EventSource, u64>,
    pub events_by_severity: HashMap<Severity, u64>,
    pub database_size_bytes: u64,
    pub oldest_event: Option<DateTime<Utc>>,
    pub newest_event: Option<DateTime<Utc>>,
    pub export_files_count: u32,
    pub last_cleanup: Option<DateTime<Utc>>,
}

/// NDJSON export writer
pub struct NdjsonWriter {
    file: BufWriter<File>,
    current_date: String,
    export_dir: PathBuf,
    events_written: u64,
}

impl NdjsonWriter {
    /// Create a new NDJSON writer
    pub fn new(export_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&export_dir)?;
        
        let current_date = Utc::now().format("%Y-%m-%d").to_string();
        let file_path = export_dir.join(format!("events_{}.ndjson", current_date));
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        
        Ok(Self {
            file: BufWriter::new(file),
            current_date,
            export_dir,
            events_written: 0,
        })
    }
    
    /// Write an event to NDJSON
    pub fn write_event(&mut self, event: &EventEnvelope) -> Result<()> {
        // Check if we need to rotate the file
        let today = Utc::now().format("%Y-%m-%d").to_string();
        if today != self.current_date {
            self.rotate_file()?;
            self.current_date = today;
        }
        
        // Serialize and write the event
        let json_line = serde_json::to_string(event)?;
        writeln!(self.file, "{}", json_line)?;
        self.file.flush()?;
        
        self.events_written += 1;
        
        if self.events_written % 1000 == 0 {
            debug!("NDJSON writer: {} events written", self.events_written);
        }
        
        Ok(())
    }
    
    /// Rotate to a new file
    fn rotate_file(&mut self) -> Result<()> {
        self.file.flush()?;
        
        let file_path = self.export_dir.join(format!("events_{}.ndjson", self.current_date));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        
        self.file = BufWriter::new(file);
        
        info!("NDJSON writer rotated to new file: {:?}", file_path);
        Ok(())
    }
}

/// Main storage interface
pub struct EventStorage {
    config: StorageConfig,
    connection: Arc<Mutex<Connection>>,
    ndjson_writer: Option<Arc<Mutex<NdjsonWriter>>>,
}

impl EventStorage {
    /// Create a new event storage instance
    pub fn new(config: StorageConfig) -> Result<Self> {
        // Ensure directories exist
        if let Some(parent) = config.database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        if config.enable_ndjson_export {
            std::fs::create_dir_all(&config.export_directory)?;
        }
        
        // Open database connection
        let connection = Self::open_database(&config)?;
        
        // Initialize schema
        Self::initialize_schema(&connection)?;
        
        // Create NDJSON writer if enabled
        let ndjson_writer = if config.enable_ndjson_export {
            Some(Arc::new(Mutex::new(NdjsonWriter::new(config.export_directory.clone())?)))
        } else {
            None
        };
        
        let storage = Self {
            config,
            connection: Arc::new(Mutex::new(connection)),
            ndjson_writer,
        };
        
        info!("Event storage initialized: {:?}", storage.config.database_path);
        Ok(storage)
    }
    
    /// Open database connection with optimizations
    fn open_database(config: &StorageConfig) -> Result<Connection> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE 
            | OpenFlags::SQLITE_OPEN_CREATE 
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        
        let conn = Connection::open_with_flags(&config.database_path, flags)?;
        
        // Configure SQLite pragmas for performance
        if config.enable_wal {
            conn.execute("PRAGMA journal_mode = WAL", [])?;
            conn.execute("PRAGMA wal_autocheckpoint = 1000", [])?;
        }
        
        conn.execute("PRAGMA synchronous = NORMAL", [])?;
        conn.execute("PRAGMA cache_size = -64000", [])?; // 64MB cache
        conn.execute("PRAGMA temp_store = MEMORY", [])?;
        conn.execute("PRAGMA mmap_size = 268435456", [])?; // 256MB mmap
        
        if config.auto_vacuum {
            conn.execute("PRAGMA auto_vacuum = INCREMENTAL", [])?;
        }
        
        Ok(conn)
    }
    
    /// Initialize database schema
    fn initialize_schema(conn: &Connection) -> Result<()> {
        // Create events table
        conn.execute(
            r#"
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
            )
            "#,
            [],
        )?;
        
        // Create indices for performance
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source_severity ON events(source, severity)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_process_id ON events(process_id)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_key_hash ON events(key_hash)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_sequence ON events(sequence_number)",
            [],
        )?;
        
        // Create correlation table for event chains
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                key_hash INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (event_id) REFERENCES events (id)
            )
            "#,
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlations_id ON correlations(correlation_id)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_correlations_key_hash ON correlations(key_hash)",
            [],
        )?;
        
        // Create statistics table
        conn.execute(
            r#"
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                source INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                UNIQUE(date, source, severity)
            )
            "#,
            [],
        )?;
        
        info!("Database schema initialized");
        Ok(())
    }
    
    /// Store an event
    pub fn store_event(&self, event: &EventEnvelope) -> Result<()> {
        // Serialize event data
        let flags_json = serde_json::to_string(&event.flags)?;
        let data_json = serde_json::to_string(&event.data)?;
        let metadata_json = serde_json::to_string(&event.metadata)?;
        
        // Store in database
        {
            let conn = self.connection.lock().unwrap();
            conn.execute(
                r#"
                INSERT INTO events (
                    id, source, severity, timestamp, process_id, thread_id, session_id,
                    sequence_number, prev_sequence_number, key_hash, flags, data, metadata
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
                params![
                    event.id.to_string(),
                    event.source as u32,
                    event.severity as u32,
                    event.timestamp.timestamp(),
                    event.process_id,
                    event.thread_id,
                    event.session_id,
                    event.sequence_number as i64,
                    event.prev_sequence_number as i64,
                    event.key_hash as i64,
                    flags_json,
                    data_json,
                    metadata_json,
                ],
            )?;
        }
        
        // Export to NDJSON if enabled
        if let Some(ref writer) = self.ndjson_writer {
            writer.lock().unwrap().write_event(event)?;
        }
        
        debug!("Event stored: {} ({})", event.id, event.source);
        Ok(())
    }
    
    /// Store multiple events in a transaction
    pub fn store_events_batch(&self, events: &[EventEnvelope]) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        let transaction = conn.unchecked_transaction()?;
        
        {
            let mut stmt = transaction.prepare(
                r#"
                INSERT INTO events (
                    id, source, severity, timestamp, process_id, thread_id, session_id,
                    sequence_number, prev_sequence_number, key_hash, flags, data, metadata
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                "#,
            )?;
            
            for event in events {
                let flags_json = serde_json::to_string(&event.flags)?;
                let data_json = serde_json::to_string(&event.data)?;
                let metadata_json = serde_json::to_string(&event.metadata)?;
                
                stmt.execute(params![
                    event.id.to_string(),
                    event.source as u32,
                    event.severity as u32,
                    event.timestamp.timestamp(),
                    event.process_id,
                    event.thread_id,
                    event.session_id,
                    event.sequence_number as i64,
                    event.prev_sequence_number as i64,
                    event.key_hash as i64,
                    flags_json,
                    data_json,
                    metadata_json,
                ])?;
                
                // Export to NDJSON if enabled
                if let Some(ref writer) = self.ndjson_writer {
                    writer.lock().unwrap().write_event(event)?;
                }
            }
        }
        
        transaction.commit()?;
        
        info!("Batch stored: {} events", events.len());
        Ok(())
    }
    
    /// Query events
    pub fn query_events(&self, query: &EventQuery) -> Result<Vec<EventEnvelope>> {
        let conn = self.connection.lock().unwrap();
        
        // Build SQL query
        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        
        if let Some(source) = query.source {
            sql.push_str(" AND source = ?");
            params.push(Box::new(source as u32));
        }
        
        if let Some(min_severity) = query.min_severity {
            sql.push_str(" AND severity >= ?");
            params.push(Box::new(min_severity as u32));
        }
        
        if let Some(start_time) = query.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(Box::new(start_time.timestamp()));
        }
        
        if let Some(end_time) = query.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(Box::new(end_time.timestamp()));
        }
        
        if let Some(process_id) = query.process_id {
            sql.push_str(" AND process_id = ?");
            params.push(Box::new(process_id));
        }
        
        if let Some(key_hash) = query.key_hash {
            sql.push_str(" AND key_hash = ?");
            params.push(Box::new(key_hash as i64));
        }
        
        if let Some(ref search_text) = query.search_text {
            sql.push_str(" AND (data LIKE ? OR metadata LIKE ?)");
            let search_pattern = format!("%{}%", search_text);
            params.push(Box::new(search_pattern.clone()));
            params.push(Box::new(search_pattern));
        }
        
        // Add ordering
        if query.ascending {
            sql.push_str(" ORDER BY timestamp ASC");
        } else {
            sql.push_str(" ORDER BY timestamp DESC");
        }
        
        // Add limit and offset
        if let Some(limit) = query.limit {
            sql.push_str(" LIMIT ?");
            params.push(Box::new(limit));
            
            if let Some(offset) = query.offset {
                sql.push_str(" OFFSET ?");
                params.push(Box::new(offset));
            }
        }
        
        // Execute query
        let mut stmt = conn.prepare(&sql)?;
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        
        let event_iter = stmt.query_map(&param_refs[..], |row| {
            Ok(Self::row_to_event(row)?)
        })?;
        
        let mut events = Vec::new();
        for event_result in event_iter {
            match event_result {
                Ok(Ok(event)) => events.push(event),
                Ok(Err(e)) => warn!("Failed to parse event from database: {}", e),
                Err(e) => return Err(e.into()),
            }
        }
        
        debug!("Query returned {} events", events.len());
        Ok(events)
    }
    
    /// Convert database row to event envelope
    fn row_to_event(row: &rusqlite::Row) -> Result<EventEnvelope> {
        let id_str: String = row.get("id")?;
        let id = Uuid::parse_str(&id_str)?;
        
        let source_num: u32 = row.get("source")?;
        let source = EventSource::from(source_num as u16);
        
        let severity_num: u32 = row.get("severity")?;
        let severity = Severity::from(severity_num as u16);
        
        let timestamp_unix: i64 = row.get("timestamp")?;
        let timestamp = DateTime::from_timestamp(timestamp_unix, 0)
            .unwrap_or_else(|| Utc::now());
        
        let flags_json: String = row.get("flags")?;
        let flags: Vec<String> = serde_json::from_str(&flags_json)?;
        
        let data_json: String = row.get("data")?;
        let data = serde_json::from_str(&data_json)?;
        
        let metadata_json: String = row.get("metadata")?;
        let metadata = serde_json::from_str(&metadata_json)?;
        
        Ok(EventEnvelope {
            id,
            source,
            severity,
            timestamp,
            process_id: row.get("process_id")?,
            thread_id: row.get("thread_id")?,
            session_id: row.get("session_id")?,
            sequence_number: row.get::<_, i64>("sequence_number")? as u64,
            prev_sequence_number: row.get::<_, i64>("prev_sequence_number")? as u64,
            key_hash: row.get::<_, i64>("key_hash")? as u64,
            flags,
            data,
            metadata,
        })
    }
    
    /// Get storage statistics
    pub fn get_statistics(&self) -> Result<StorageStats> {
        let conn = self.connection.lock().unwrap();
        
        // Get total events
        let total_events: u64 = conn.query_row(
            "SELECT COUNT(*) FROM events",
            [],
            |row| Ok(row.get::<_, i64>(0)? as u64),
        )?;
        
        // Get events by source
        let mut events_by_source = HashMap::new();
        let mut stmt = conn.prepare("SELECT source, COUNT(*) FROM events GROUP BY source")?;
        let source_iter = stmt.query_map([], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        
        for result in source_iter {
            let (source_num, count) = result?;
            let source = EventSource::from(source_num as u16);
            events_by_source.insert(source, count);
        }
        
        // Get events by severity
        let mut events_by_severity = HashMap::new();
        let mut stmt = conn.prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity")?;
        let severity_iter = stmt.query_map([], |row| {
            Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        
        for result in severity_iter {
            let (severity_num, count) = result?;
            let severity = Severity::from(severity_num as u16);
            events_by_severity.insert(severity, count);
        }
        
        // Get database size
        let database_size_bytes = std::fs::metadata(&self.config.database_path)
            .map(|m| m.len())
            .unwrap_or(0);
        
        // Get oldest and newest events
        let oldest_event: Option<DateTime<Utc>> = conn.query_row(
            "SELECT MIN(timestamp) FROM events",
            [],
            |row| Ok(row.get::<_, Option<i64>>(0)?),
        ).optional()?
          .flatten()
          .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_else(|| Utc::now()));
        
        let newest_event: Option<DateTime<Utc>> = conn.query_row(
            "SELECT MAX(timestamp) FROM events",
            [],
            |row| Ok(row.get::<_, Option<i64>>(0)?),
        ).optional()?
          .flatten()
          .map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or_else(|| Utc::now()));
        
        // Count export files
        let export_files_count = if self.config.export_directory.exists() {
            std::fs::read_dir(&self.config.export_directory)?
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry.path().extension()
                        .map_or(false, |ext| ext == "ndjson")
                })
                .count() as u32
        } else {
            0
        };
        
        Ok(StorageStats {
            total_events,
            events_by_source,
            events_by_severity,
            database_size_bytes,
            oldest_event,
            newest_event,
            export_files_count,
            last_cleanup: None, // TODO: Track cleanup operations
        })
    }
    
    /// Cleanup old events based on retention policy
    pub fn cleanup_old_events(&self) -> Result<u64> {
        let cutoff_time = Utc::now() - chrono::Duration::days(self.config.retention_days as i64);
        let cutoff_timestamp = cutoff_time.timestamp();
        
        let conn = self.connection.lock().unwrap();
        let deleted_count = conn.execute(
            "DELETE FROM events WHERE timestamp < ?",
            params![cutoff_timestamp],
        )?;
        
        // Also cleanup correlations for deleted events
        conn.execute(
            "DELETE FROM correlations WHERE event_id NOT IN (SELECT id FROM events)",
            [],
        )?;
        
        // Run incremental vacuum if auto-vacuum is enabled
        if self.config.auto_vacuum {
            conn.execute("PRAGMA incremental_vacuum", [])?;
        }
        
        info!("Cleaned up {} old events", deleted_count);
        Ok(deleted_count as u64)
    }
    
    /// Get event by ID
    pub fn get_event(&self, event_id: &Uuid) -> Result<Option<EventEnvelope>> {
        let conn = self.connection.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM events WHERE id = ?")?;
        
        match stmt.query_row([event_id.to_string()], |row| {
            Ok(Self::row_to_event(row)?)
        }).optional()? {
            Some(Ok(event)) => Ok(Some(event)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
    
    /// Get correlated events for a given key hash
    pub fn get_correlated_events(&self, key_hash: u64, limit: Option<u32>) -> Result<Vec<EventEnvelope>> {
        let mut query = EventQuery::default();
        query.key_hash = Some(key_hash);
        query.limit = limit;
        query.ascending = true; // Show chronological order for correlation
        
        self.query_events(&query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventData, ProcessEvent, ProcessOperation};
    use tempfile::TempDir;

    fn create_test_storage() -> (EventStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            database_path: temp_dir.path().join("test.db"),
            export_directory: temp_dir.path().join("exports"),
            enable_ndjson_export: false,
            ..Default::default()
        };
        
        let storage = EventStorage::new(config).unwrap();
        (storage, temp_dir)
    }

    fn create_test_event() -> EventEnvelope {
        EventEnvelope {
            id: Uuid::new_v4(),
            source: EventSource::Process,
            severity: Severity::Medium,
            timestamp: Utc::now(),
            process_id: 1234,
            thread_id: 5678,
            session_id: 1,
            sequence_number: 1,
            prev_sequence_number: 0,
            key_hash: 0x123456789abcdef0,
            flags: vec!["test".to_string()],
            data: EventData::Process(ProcessEvent {
                operation: ProcessOperation::Start,
                parent_process_id: Some(999),
                image_path: "C:\\Windows\\System32\\notepad.exe".to_string(),
                command_line_hash: Some(0xdeadbeef),
                integrity_level: Some(0x2000),
                token_flags: None,
                sid_hash: Some(0xcafebabe),
                exit_code: None,
            }),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_storage_creation() {
        let (_storage, _temp_dir) = create_test_storage();
    }

    #[test]
    fn test_store_and_retrieve_event() {
        let (storage, _temp_dir) = create_test_storage();
        let event = create_test_event();
        let event_id = event.id;

        // Store event
        storage.store_event(&event).unwrap();

        // Retrieve event
        let retrieved = storage.get_event(&event_id).unwrap();
        assert!(retrieved.is_some());
        
        let retrieved_event = retrieved.unwrap();
        assert_eq!(retrieved_event.id, event_id);
        assert_eq!(retrieved_event.source, EventSource::Process);
        assert_eq!(retrieved_event.process_id, 1234);
    }

    #[test]
    fn test_query_events() {
        let (storage, _temp_dir) = create_test_storage();
        
        // Store multiple events
        for i in 0..5 {
            let mut event = create_test_event();
            event.process_id = 1000 + i;
            storage.store_event(&event).unwrap();
        }

        // Query all events
        let query = EventQuery::default();
        let events = storage.query_events(&query).unwrap();
        assert_eq!(events.len(), 5);

        // Query with process ID filter
        let mut query = EventQuery::default();
        query.process_id = Some(1002);
        let events = storage.query_events(&query).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process_id, 1002);
    }

    #[test]
    fn test_storage_statistics() {
        let (storage, _temp_dir) = create_test_storage();
        
        // Store some events
        for _ in 0..3 {
            storage.store_event(&create_test_event()).unwrap();
        }

        let stats = storage.get_statistics().unwrap();
        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.events_by_source.get(&EventSource::Process), Some(&3));
    }
}