//! Event Correlation Module
//! 
//! Handles correlation of events across time windows for complex detection scenarios.

use crate::events::EventEnvelope;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use uuid::Uuid;

/// Event correlator for tracking related events
pub struct EventCorrelator {
    /// Active correlation windows indexed by correlation key
    correlations: HashMap<String, CorrelationWindow>,
    
    /// Maximum number of correlation windows to maintain
    max_correlations: usize,
    
    /// Default correlation window duration
    default_window: Duration,
}

/// Correlation window containing related events
#[derive(Debug, Clone)]
pub struct CorrelationWindow {
    /// Unique correlation ID
    pub id: String,
    
    /// Correlation type (e.g., "process_chain", "network_flow")
    pub correlation_type: String,
    
    /// Correlation key used for grouping
    pub key: String,
    
    /// Events in this correlation window
    pub events: VecDeque<CorrelatedEvent>,
    
    /// Window start time
    pub start_time: DateTime<Utc>,
    
    /// Window end time (start + duration)
    pub end_time: DateTime<Utc>,
    
    /// Maximum number of events in window
    pub max_events: Option<usize>,
    
    /// Whether this correlation has been finalized
    pub finalized: bool,
}

/// Event with correlation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedEvent {
    /// Original event ID
    pub event_id: String,
    
    /// Timestamp when event was added to correlation
    pub correlation_timestamp: DateTime<Utc>,
    
    /// Sequence number within correlation
    pub sequence: u32,
    
    /// Key hash for fast lookups
    pub key_hash: u64,
    
    /// Additional correlation metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Correlation configuration
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    pub correlation_type: String,
    pub key_fields: Vec<String>,
    pub window_duration: Duration,
    pub min_events: usize,
    pub max_events: Option<usize>,
    pub allow_partial: bool,
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub correlation_id: String,
    pub correlation_type: String,
    pub event_count: usize,
    pub confidence_score: f32,
    pub timespan: Duration,
    pub events: Vec<String>, // Event IDs
}

impl EventCorrelator {
    /// Create a new event correlator
    pub fn new() -> Self {
        Self {
            correlations: HashMap::new(),
            max_correlations: 10000, // Reasonable default
            default_window: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Add an event to correlation tracking
    pub fn add_event(
        &mut self,
        event: &EventEnvelope,
        config: &CorrelationConfig,
    ) -> Option<CorrelationResult> {
        // Generate correlation key from specified fields
        let correlation_key = self.generate_correlation_key(event, &config.key_fields);
        
        // Check if we have an existing correlation for this key
        let now = Utc::now();
        
        if let Some(window) = self.correlations.get_mut(&correlation_key) {
            // Check if window is still active
            if now <= window.end_time && !window.finalized {
                // Add event to existing window
                let correlated_event = CorrelatedEvent {
                    event_id: event.id.clone(),
                    correlation_timestamp: now,
                    sequence: window.events.len() as u32,
                    key_hash: self.hash_string(&correlation_key),
                    metadata: HashMap::new(),
                };
                
                window.events.push_back(correlated_event);
                
                // Check if we've reached max events
                if let Some(max_events) = window.max_events {
                    if window.events.len() >= max_events {
                        window.finalized = true;
                    }
                }
                
                // Check if we should generate a correlation result
                if window.events.len() >= config.min_events {
                    if window.finalized || (!config.allow_partial && window.events.len() >= config.min_events) {
                        return Some(self.create_correlation_result(window));
                    }
                }
            } else {
                // Window expired, remove it and start new one
                self.correlations.remove(&correlation_key);
            }
        }
        
        // Create new correlation window if needed
        if !self.correlations.contains_key(&correlation_key) {
            let correlation_id = Uuid::new_v4().to_string();
            
            let mut window = CorrelationWindow {
                id: correlation_id,
                correlation_type: config.correlation_type.clone(),
                key: correlation_key.clone(),
                events: VecDeque::new(),
                start_time: now,
                end_time: now + config.window_duration,
                max_events: config.max_events,
                finalized: false,
            };
            
            // Add the current event
            let correlated_event = CorrelatedEvent {
                event_id: event.id.clone(),
                correlation_timestamp: now,
                sequence: 0,
                key_hash: self.hash_string(&correlation_key),
                metadata: HashMap::new(),
            };
            
            window.events.push_back(correlated_event);
            
            // Ensure we don't exceed max correlations
            if self.correlations.len() >= self.max_correlations {
                self.cleanup_oldest_correlations(self.max_correlations / 10); // Remove 10%
            }
            
            self.correlations.insert(correlation_key, window);
        }
        
        None
    }

    /// Generate correlation key from event fields
    fn generate_correlation_key(&self, event: &EventEnvelope, key_fields: &[String]) -> String {
        let mut key_parts = Vec::new();
        
        for field in key_fields {
            if let Some(value) = self.extract_field_value(event, field) {
                key_parts.push(format!("{}={}", field, value));
            }
        }
        
        key_parts.join("&")
    }

    /// Extract field value from event
    fn extract_field_value(&self, event: &EventEnvelope, field: &str) -> Option<String> {
        // Handle common field patterns
        match field {
            "process.process_id" => Some(event.process_id.to_string()),
            "process.session_id" => Some(event.session_id.to_string()),
            "source" => Some(format!("{:?}", event.source)),
            "severity" => Some(format!("{:?}", event.severity)),
            _ => {
                // Try to extract from JSON data
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&event.data) {
                    self.extract_json_field(&data, field).map(|v| v.to_string())
                } else {
                    None
                }
            }
        }
    }

    /// Extract field from JSON data using dot notation
    fn extract_json_field(&self, data: &serde_json::Value, field: &str) -> Option<&serde_json::Value> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = data;
        
        for part in parts {
            match current {
                serde_json::Value::Object(obj) => {
                    current = obj.get(part)?;
                }
                _ => return None,
            }
        }
        
        Some(current)
    }

    /// Create correlation result from window
    fn create_correlation_result(&self, window: &CorrelationWindow) -> CorrelationResult {
        let event_ids: Vec<String> = window.events.iter()
            .map(|e| e.event_id.clone())
            .collect();
        
        let timespan = window.end_time - window.start_time;
        
        // Calculate confidence based on event count and timespan
        let confidence_score = self.calculate_correlation_confidence(window);
        
        CorrelationResult {
            correlation_id: window.id.clone(),
            correlation_type: window.correlation_type.clone(),
            event_count: window.events.len(),
            confidence_score,
            timespan: timespan.to_std().unwrap_or(Duration::from_secs(0)),
            events: event_ids,
        }
    }

    /// Calculate correlation confidence score
    fn calculate_correlation_confidence(&self, window: &CorrelationWindow) -> f32 {
        let event_count = window.events.len() as f32;
        let timespan_seconds = (window.end_time - window.start_time).num_seconds() as f32;
        
        // Base confidence from event count (more events = higher confidence)
        let count_confidence = (event_count.ln() / 10.0).min(1.0);
        
        // Time density factor (events closer in time = higher confidence)
        let time_density = if timespan_seconds > 0.0 {
            (event_count / timespan_seconds).min(1.0)
        } else {
            1.0
        };
        
        // Combine factors
        (count_confidence * 0.7 + time_density * 0.3).min(1.0)
    }

    /// Get events for a specific correlation
    pub fn get_correlation_events(&self, correlation_id: &str) -> Vec<String> {
        self.correlations.values()
            .find(|w| w.id == correlation_id)
            .map(|w| w.events.iter().map(|e| e.event_id.clone()).collect())
            .unwrap_or_default()
    }

    /// Clean up old correlations
    pub fn cleanup_old_correlations(&mut self, max_age: Duration) {
        let cutoff_time = Utc::now() - chrono::Duration::from_std(max_age).unwrap_or_default();
        
        self.correlations.retain(|_, window| {
            window.end_time > cutoff_time
        });
    }

    /// Remove oldest correlations when at capacity
    fn cleanup_oldest_correlations(&mut self, remove_count: usize) {
        let mut windows: Vec<_> = self.correlations.drain().collect();
        
        // Sort by start time and remove oldest
        windows.sort_by_key(|(_, window)| window.start_time);
        
        // Keep only the newest correlations
        let keep_count = windows.len().saturating_sub(remove_count);
        windows.truncate(keep_count);
        
        // Re-insert remaining correlations
        for (key, window) in windows {
            self.correlations.insert(key, window);
        }
    }

    /// Hash string for consistent key generation
    fn hash_string(&self, s: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }

    /// Get correlation statistics
    pub fn get_stats(&self) -> CorrelationStats {
        let active_correlations = self.correlations.len();
        let total_events: usize = self.correlations.values()
            .map(|w| w.events.len())
            .sum();
        
        let finalized_correlations = self.correlations.values()
            .filter(|w| w.finalized)
            .count();
        
        CorrelationStats {
            active_correlations,
            finalized_correlations,
            total_events,
            oldest_correlation: self.correlations.values()
                .map(|w| w.start_time)
                .min(),
        }
    }
}

/// Correlation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationStats {
    pub active_correlations: usize,
    pub finalized_correlations: usize,
    pub total_events: usize,
    pub oldest_correlation: Option<DateTime<Utc>>,
}

impl Default for EventCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventSource, Severity};

    fn create_test_event(id: &str, process_id: u32) -> EventEnvelope {
        EventEnvelope {
            id: id.to_string(),
            source: EventSource::Process,
            severity: Severity::Medium,
            timestamp: Utc::now(),
            process_id,
            thread_id: 1234,
            session_id: 1,
            sequence_number: 1,
            prev_sequence_number: 0,
            key_hash: 12345,
            flags: "0x00000001".to_string(),
            data: r#"{"process":{"operation":"Create","image_path":"test.exe"}}"#.to_string(),
            metadata: r#"{}"#.to_string(),
        }
    }

    #[test]
    fn test_correlation_basic() {
        let mut correlator = EventCorrelator::new();
        
        let config = CorrelationConfig {
            correlation_type: "test".to_string(),
            key_fields: vec!["process.process_id".to_string()],
            window_duration: Duration::from_secs(300),
            min_events: 2,
            max_events: Some(5),
            allow_partial: false,
        };
        
        let event1 = create_test_event("event1", 1234);
        let event2 = create_test_event("event2", 1234);
        let event3 = create_test_event("event3", 5678);
        
        // First event - no correlation yet
        assert!(correlator.add_event(&event1, &config).is_none());
        
        // Second event with same PID - should create correlation
        let result = correlator.add_event(&event2, &config);
        assert!(result.is_some());
        
        let correlation = result.unwrap();
        assert_eq!(correlation.event_count, 2);
        assert_eq!(correlation.events.len(), 2);
        
        // Third event with different PID - new correlation window
        assert!(correlator.add_event(&event3, &config).is_none());
    }

    #[test]
    fn test_correlation_window_expiry() {
        let mut correlator = EventCorrelator::new();
        
        let config = CorrelationConfig {
            correlation_type: "test".to_string(),
            key_fields: vec!["process.process_id".to_string()],
            window_duration: Duration::from_millis(100), // Very short window
            min_events: 2,
            max_events: None,
            allow_partial: false,
        };
        
        let event1 = create_test_event("event1", 1234);
        correlator.add_event(&event1, &config);
        
        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));
        
        let event2 = create_test_event("event2", 1234);
        // Should not correlate due to expired window
        assert!(correlator.add_event(&event2, &config).is_none());
    }

    #[test]
    fn test_correlation_max_events() {
        let mut correlator = EventCorrelator::new();
        
        let config = CorrelationConfig {
            correlation_type: "test".to_string(),
            key_fields: vec!["process.process_id".to_string()],
            window_duration: Duration::from_secs(300),
            min_events: 2,
            max_events: Some(3),
            allow_partial: false,
        };
        
        let events: Vec<_> = (0..5).map(|i| create_test_event(&format!("event{}", i), 1234)).collect();
        
        // Add events one by one
        for (i, event) in events.iter().enumerate() {
            let result = correlator.add_event(event, &config);
            
            if i == 1 {
                // Second event should trigger correlation (min_events = 2)
                assert!(result.is_some());
            } else if i >= 2 {
                // After max_events reached, window is finalized
                if i == 2 {
                    // Third event finalizes the window
                    assert!(result.is_some());
                } else {
                    // Subsequent events should start new correlations
                    assert!(result.is_none());
                }
            }
        }
    }
}