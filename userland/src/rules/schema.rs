//! Rule Schema Definitions
//!
//! Defines the YAML schema structure for XDR detection rules.

use crate::types::{EventSource, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Complete rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub version: String,
    pub enabled: bool,
    pub severity: Severity,
    pub confidence: f32,

    /// Rule metadata
    pub metadata: RuleMetadata,

    /// Event sources this rule applies to
    pub sources: Vec<EventSource>,

    /// Rule conditions
    pub conditions: RuleConditions,

    /// Correlation settings
    pub correlation: Option<CorrelationConfig>,

    /// False positive filters
    pub false_positives: Vec<FalsePositiveFilter>,

    /// Rule output configuration
    pub output: RuleOutput,
}

/// Rule metadata for classification and management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// ATT&CK framework references
    pub attack: Option<AttackMapping>,

    /// Rule category (e.g., "malware", "persistence", "lateral_movement")
    pub category: String,

    /// Sub-category for more specific classification
    pub subcategory: Option<String>,

    /// Associated CVE numbers
    pub cve: Vec<String>,

    /// Reference URLs for additional context
    pub references: Vec<String>,

    /// Tags for flexible classification
    pub tags: Vec<String>,

    /// Rule creation date
    pub created: String,

    /// Last modification date
    pub modified: String,
}

/// MITRE ATT&CK framework mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackMapping {
    /// ATT&CK technique IDs (e.g., "T1055")
    pub techniques: Vec<String>,

    /// ATT&CK tactic names (e.g., "Defense Evasion")
    pub tactics: Vec<String>,

    /// ATT&CK matrix (e.g., "enterprise", "mobile", "ics")
    pub matrix: String,
}

/// Rule conditions and logic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Primary condition that must be satisfied
    pub condition: Condition,

    /// Time window for evaluating conditions
    #[serde(default, with = "duration_serde::option")]
    pub timeframe: Option<Duration>,

    /// Minimum event count threshold
    pub threshold: Option<u32>,

    /// Group by fields for aggregation
    pub group_by: Vec<String>,
}

/// Individual condition definition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Condition {
    /// Simple field matching
    Match {
        field: String,
        value: ConditionValue,
        operator: MatchOperator,
    },

    /// Regular expression matching
    Regex {
        field: String,
        pattern: String,
        flags: Option<String>,
    },

    /// Logical combination of conditions
    And { conditions: Vec<Condition> },

    /// Logical OR of conditions
    Or { conditions: Vec<Condition> },

    /// Negation of a condition
    Not { condition: Box<Condition> },

    /// Time-based condition
    Temporal {
        condition: Box<Condition>,
        #[serde(with = "duration_serde")]
        within: Duration,
    },

    /// Count-based condition
    Count {
        condition: Box<Condition>,
        threshold: u32,
        #[serde(with = "duration_serde")]
        timeframe: Duration,
    },

    /// Sequence detection
    Sequence {
        conditions: Vec<Condition>,
        #[serde(with = "duration_serde")]
        max_timespan: Duration,
    },

    /// Statistical anomaly detection
    Anomaly {
        field: String,
        #[serde(with = "duration_serde")]
        baseline_window: Duration,
        #[serde(with = "duration_serde")]
        detection_window: Duration,
        threshold_sigma: f64,
    },
}

/// Condition value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
    Range { min: f64, max: f64 },
}

/// Match operators for conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchOperator {
    #[serde(rename = "equals")]
    Equals,
    #[serde(rename = "not_equals")]
    NotEquals,
    #[serde(rename = "contains")]
    Contains,
    #[serde(rename = "not_contains")]
    NotContains,
    #[serde(rename = "starts_with")]
    StartsWith,
    #[serde(rename = "ends_with")]
    EndsWith,
    #[serde(rename = "in")]
    In,
    #[serde(rename = "not_in")]
    NotIn,
    #[serde(rename = "greater_than")]
    GreaterThan,
    #[serde(rename = "less_than")]
    LessThan,
    #[serde(rename = "greater_equal")]
    GreaterEqual,
    #[serde(rename = "less_equal")]
    LessEqual,
    #[serde(rename = "exists")]
    Exists,
    #[serde(rename = "not_exists")]
    NotExists,
}

/// Event correlation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Correlation key fields for grouping related events
    pub key_fields: Vec<String>,

    /// Maximum time window for correlation
    #[serde(with = "duration_serde")]
    pub max_timespan: Duration,

    /// Minimum number of events required for correlation
    pub min_events: u32,

    /// Maximum number of events in correlation window
    pub max_events: Option<u32>,

    /// Correlation type identifier
    pub correlation_type: String,

    /// Whether to create alerts for partial correlations
    pub allow_partial: bool,
}

/// False positive filter definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveFilter {
    /// Filter name for documentation
    pub name: String,

    /// Condition that identifies false positives
    pub condition: Condition,

    /// Confidence reduction factor (0.0 to 1.0)
    pub confidence_reduction: f32,
}

/// Rule output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOutput {
    /// Alert message template
    pub message: String,

    /// Additional details to include in alert
    pub details: HashMap<String, String>,

    /// Whether to include raw event data
    pub include_raw_event: bool,

    /// Custom fields to extract from events
    pub extract_fields: Vec<String>,

    /// Alert title template
    pub title: Option<String>,

    /// Alert description template
    pub description: Option<String>,
}

/// Serde helper for duration parsing
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let seconds = duration.as_secs();
        serializer.serialize_str(&format!("{}s", seconds))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }

    pub fn parse_duration(s: &str) -> Result<Duration, String> {
        if let Some(num_str) = s.strip_suffix("ms") {
            let millis: u64 = num_str.parse().map_err(|_| "Invalid duration format")?;
            Ok(Duration::from_millis(millis))
        } else if let Some(num_str) = s.strip_suffix('s') {
            let seconds: u64 = num_str.parse().map_err(|_| "Invalid duration format")?;
            Ok(Duration::from_secs(seconds))
        } else if let Some(num_str) = s.strip_suffix('m') {
            let minutes: u64 = num_str.parse().map_err(|_| "Invalid duration format")?;
            Ok(Duration::from_secs(minutes * 60))
        } else if let Some(num_str) = s.strip_suffix('h') {
            let hours: u64 = num_str.parse().map_err(|_| "Invalid duration format")?;
            Ok(Duration::from_secs(hours * 3600))
        } else {
            Err("Duration must end with 's', 'm', 'h', or 'ms'".to_string())
        }
    }

    pub mod option {
        use super::*;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match duration {
                Some(d) => super::serialize(d, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) => super::parse_duration(&s)
                    .map(Some)
                    .map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duration_parsing() {
        assert_eq!(
            duration_serde::parse_duration("30s").unwrap(),
            Duration::from_secs(30)
        );
        assert_eq!(
            duration_serde::parse_duration("5m").unwrap(),
            Duration::from_secs(300)
        );
        assert_eq!(
            duration_serde::parse_duration("2h").unwrap(),
            Duration::from_secs(7200)
        );
        assert_eq!(
            duration_serde::parse_duration("500ms").unwrap(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn test_rule_serialization() {
        let rule = Rule {
            id: "test-001".to_string(),
            name: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            author: "XDR Team".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            severity: Severity::High,
            confidence: 0.9,
            metadata: RuleMetadata {
                attack: None,
                category: "test".to_string(),
                subcategory: None,
                cve: vec![],
                references: vec![],
                tags: vec!["test".to_string()],
                created: "2024-01-01".to_string(),
                modified: "2024-01-01".to_string(),
            },
            sources: vec![EventSource::Process],
            conditions: RuleConditions {
                condition: Condition::Match {
                    field: "process.image_path".to_string(),
                    value: ConditionValue::String("malware.exe".to_string()),
                    operator: MatchOperator::Contains,
                },
                timeframe: None,
                threshold: None,
                group_by: vec![],
            },
            correlation: None,
            false_positives: vec![],
            output: RuleOutput {
                message: "Suspicious process detected".to_string(),
                details: HashMap::new(),
                include_raw_event: false,
                extract_fields: vec![],
                title: None,
                description: None,
            },
        };

        let yaml = serde_yaml::to_string(&rule).expect("Failed to serialize rule");
        let _deserialized: Rule = serde_yaml::from_str(&yaml).expect("Failed to deserialize rule");
    }
}
