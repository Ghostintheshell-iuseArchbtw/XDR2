//! Rules Engine Module
//!
//! Implements YAML-based rule definition and evaluation engine with event correlation.
//! Supports real-time rule execution, correlation windows, and alert generation.

#[cfg(all(feature = "rules-engine", windows))]
mod correlation;
#[cfg(all(feature = "rules-engine", windows))]
mod engine;
mod parser;
mod schema;

#[cfg(all(feature = "rules-engine", windows))]
pub use correlation::*;
#[cfg(all(feature = "rules-engine", windows))]
pub use engine::*;
pub use parser::*;
pub use schema::*;

#[cfg(all(feature = "rules-engine", windows))]
use crate::events::EventEnvelope;
use crate::types::Severity;
#[cfg(all(feature = "rules-engine", windows))]
use crate::LibResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
#[cfg(all(feature = "rules-engine", windows))]
use std::collections::HashMap;
#[cfg(all(feature = "rules-engine", windows))]
use std::path::PathBuf;
#[cfg(all(feature = "rules-engine", windows))]
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RulesError {
    #[error("Rule parsing failed: {0}")]
    ParseError(String),
    #[error("Rule validation failed: {0}")]
    ValidationError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("YAML error: {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("Regex error: {0}")]
    RegexError(#[from] regex::Error),
    #[error("Rule not found: {0}")]
    RuleNotFound(String),
    #[error("Correlation error: {0}")]
    CorrelationError(String),
}

/// Rule evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub event_id: String,
    pub severity: Severity,
    pub confidence: f32,
    pub message: String,
    pub details: serde_json::Value,
    pub correlation_id: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(all(feature = "rules-engine", windows))]
/// Rule execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStats {
    pub rule_id: String,
    pub rule_name: String,
    pub total_evaluations: u64,
    pub total_matches: u64,
    pub last_match: Option<DateTime<Utc>>,
    pub avg_execution_time_ms: f64,
    pub enabled: bool,
}

#[cfg(all(feature = "rules-engine", windows))]
/// Alert aggregation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub status: AlertStatus,
    pub event_count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub primary_event_id: String,
    pub details: serde_json::Value,
    pub analyst_notes: Option<String>,
}

#[cfg(all(feature = "rules-engine", windows))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertStatus {
    Open,
    Investigating,
    Resolved,
    FalsePositive,
}

#[cfg(all(feature = "rules-engine", windows))]
/// Main rules engine
pub struct RulesEngine {
    rules_directory: PathBuf,
    rules: HashMap<String, Rule>,
    correlator: EventCorrelator,
    stats: HashMap<String, RuleStats>,
    enabled: bool,
}

#[cfg(all(feature = "rules-engine", windows))]
impl RulesEngine {
    /// Create a new rules engine
    pub fn new(rules_directory: PathBuf) -> Self {
        Self {
            rules_directory,
            rules: HashMap::new(),
            correlator: EventCorrelator::new(),
            stats: HashMap::new(),
            enabled: true,
        }
    }

    /// Load all rules from the rules directory
    pub fn load_rules(&mut self) -> LibResult<()> {
        if !self.rules_directory.exists() {
            std::fs::create_dir_all(&self.rules_directory)?;
            return Ok(());
        }

        self.rules.clear();
        self.stats.clear();

        let parser = RuleParser::new();

        for entry in std::fs::read_dir(&self.rules_directory)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().and_then(|s| s.to_str()) == Some("yaml")
                || path.extension().and_then(|s| s.to_str()) == Some("yml")
            {
                match parser.parse_file(&path) {
                    Ok(rule) => {
                        tracing::info!("Loaded rule: {} ({})", rule.name, rule.id);

                        // Initialize stats
                        let stats = RuleStats {
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            total_evaluations: 0,
                            total_matches: 0,
                            last_match: None,
                            avg_execution_time_ms: 0.0,
                            enabled: rule.enabled,
                        };

                        self.stats.insert(rule.id.clone(), stats);
                        self.rules.insert(rule.id.clone(), rule);
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse rule file {:?}: {}", path, e);
                    }
                }
            }
        }

        tracing::info!(
            "Loaded {} rules from {:?}",
            self.rules.len(),
            self.rules_directory
        );
        Ok(())
    }

    /// Evaluate an event against all loaded rules
    pub fn evaluate_event(&mut self, event: &EventEnvelope) -> LibResult<Vec<RuleMatch>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let mut matches = Vec::new();
        let engine = RuleExecutionEngine::new();

        for (rule_id, rule) in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Update stats
            if let Some(stats) = self.stats.get_mut(rule_id) {
                stats.total_evaluations += 1;
            }

            let start_time = std::time::Instant::now();

            match engine.evaluate_rule(rule, event, &mut self.correlator) {
                Ok(Some(rule_match)) => {
                    let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;

                    // Update stats
                    if let Some(stats) = self.stats.get_mut(rule_id) {
                        stats.total_matches += 1;
                        stats.last_match = Some(Utc::now());

                        // Update moving average
                        let count = stats.total_evaluations as f64;
                        stats.avg_execution_time_ms =
                            (stats.avg_execution_time_ms * (count - 1.0) + elapsed) / count;
                    }

                    tracing::info!(
                        "Rule match: {} -> {} (confidence: {:.2})",
                        rule.name,
                        rule_match.message,
                        rule_match.confidence
                    );

                    matches.push(rule_match);
                }
                Ok(None) => {
                    // No match, update execution time stats
                    let elapsed = start_time.elapsed().as_secs_f64() * 1000.0;
                    if let Some(stats) = self.stats.get_mut(rule_id) {
                        let count = stats.total_evaluations as f64;
                        stats.avg_execution_time_ms =
                            (stats.avg_execution_time_ms * (count - 1.0) + elapsed) / count;
                    }
                }
                Err(e) => {
                    tracing::error!("Rule evaluation error for {}: {}", rule.name, e);
                }
            }
        }

        Ok(matches)
    }

    /// Hot reload rules from disk
    pub fn reload_rules(&mut self) -> LibResult<()> {
        tracing::info!("Reloading rules from {:?}", self.rules_directory);
        self.load_rules()
    }

    /// Get rule statistics
    pub fn get_stats(&self) -> Vec<RuleStats> {
        self.stats.values().cloned().collect()
    }

    /// Get specific rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&Rule> {
        self.rules.get(rule_id)
    }

    /// Get all loaded rules
    pub fn get_rules(&self) -> Vec<&Rule> {
        self.rules.values().collect()
    }

    /// Enable/disable the rules engine
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        tracing::info!(
            "Rules engine {}",
            if enabled { "enabled" } else { "disabled" }
        );
    }

    /// Enable/disable a specific rule
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) -> LibResult<()> {
        if let Some(rule) = self.rules.get_mut(rule_id) {
            rule.enabled = enabled;
            if let Some(stats) = self.stats.get_mut(rule_id) {
                stats.enabled = enabled;
            }
            tracing::info!(
                "Rule {} {}",
                rule_id,
                if enabled { "enabled" } else { "disabled" }
            );
            Ok(())
        } else {
            Err(RulesError::RuleNotFound(rule_id.to_string()).into())
        }
    }

    /// Get correlation events
    pub fn get_correlations(&self, correlation_id: &str) -> Vec<String> {
        self.correlator.get_correlation_events(correlation_id)
    }

    /// Cleanup old correlation data
    pub fn cleanup_correlations(&mut self, max_age: Duration) {
        self.correlator.cleanup_old_correlations(max_age);
    }
}
