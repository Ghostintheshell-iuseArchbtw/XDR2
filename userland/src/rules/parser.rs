//! Rule Parser Module
//! 
//! Handles parsing and validation of YAML rule files.

use super::schema::*;
use super::RulesError;
use crate::LibResult;
use std::fs;
use std::path::Path;

/// Rule parser for YAML files
pub struct RuleParser {
    // Future: Could add schema validation, custom deserializers, etc.
}

impl RuleParser {
    /// Create a new rule parser
    pub fn new() -> Self {
        Self {}
    }

    /// Parse a rule from a YAML file
    pub fn parse_file<P: AsRef<Path>>(&self, path: P) -> Result<Rule, RulesError> {
        let path = path.as_ref();
        
        tracing::debug!("Parsing rule file: {:?}", path);
        
        let content = fs::read_to_string(path)
            .map_err(|e| RulesError::IoError(e))?;
            
        self.parse_yaml(&content)
            .map_err(|e| {
                tracing::error!("Failed to parse rule file {:?}: {}", path, e);
                e
            })
    }

    /// Parse a rule from YAML content
    pub fn parse_yaml(&self, content: &str) -> Result<Rule, RulesError> {
        let mut rule: Rule = serde_yaml::from_str(content)
            .map_err(|e| RulesError::YamlError(e))?;
        
        // Validate the rule after parsing
        self.validate_rule(&mut rule)?;
        
        Ok(rule)
    }

    /// Validate a parsed rule
    fn validate_rule(&self, rule: &mut Rule) -> Result<(), RulesError> {
        // Basic field validation
        if rule.id.is_empty() {
            return Err(RulesError::ValidationError("Rule ID cannot be empty".to_string()));
        }
        
        if rule.name.is_empty() {
            return Err(RulesError::ValidationError("Rule name cannot be empty".to_string()));
        }
        
        if rule.sources.is_empty() {
            return Err(RulesError::ValidationError("Rule must specify at least one event source".to_string()));
        }
        
        // Validate confidence is between 0.0 and 1.0
        if rule.confidence < 0.0 || rule.confidence > 1.0 {
            return Err(RulesError::ValidationError("Rule confidence must be between 0.0 and 1.0".to_string()));
        }
        
        // Validate conditions
        self.validate_condition(&rule.conditions.condition)?;
        
        // Validate correlation config if present
        if let Some(ref correlation) = rule.correlation {
            self.validate_correlation_config(correlation)?;
        }
        
        // Validate false positive filters
        for fp_filter in &rule.false_positives {
            self.validate_condition(&fp_filter.condition)?;
            
            if fp_filter.confidence_reduction < 0.0 || fp_filter.confidence_reduction > 1.0 {
                return Err(RulesError::ValidationError(
                    "False positive confidence reduction must be between 0.0 and 1.0".to_string()
                ));
            }
        }
        
        // Validate output configuration
        if rule.output.message.is_empty() {
            return Err(RulesError::ValidationError("Rule output message cannot be empty".to_string()));
        }
        
        tracing::debug!("Rule validation passed for: {}", rule.id);
        Ok(())
    }

    /// Validate a condition recursively
    fn validate_condition(&self, condition: &Condition) -> Result<(), RulesError> {
        match condition {
            Condition::Match { field, value, .. } => {
                if field.is_empty() {
                    return Err(RulesError::ValidationError("Match condition field cannot be empty".to_string()));
                }
                
                // Validate value based on type
                match value {
                    ConditionValue::String(s) if s.is_empty() => {
                        return Err(RulesError::ValidationError("Match condition string value cannot be empty".to_string()));
                    }
                    ConditionValue::Array(arr) if arr.is_empty() => {
                        return Err(RulesError::ValidationError("Match condition array cannot be empty".to_string()));
                    }
                    ConditionValue::Range { min, max } if min >= max => {
                        return Err(RulesError::ValidationError("Match condition range min must be less than max".to_string()));
                    }
                    _ => {}
                }
            }
            
            Condition::Regex { field, pattern, .. } => {
                if field.is_empty() {
                    return Err(RulesError::ValidationError("Regex condition field cannot be empty".to_string()));
                }
                
                if pattern.is_empty() {
                    return Err(RulesError::ValidationError("Regex condition pattern cannot be empty".to_string()));
                }
                
                // Validate regex pattern
                regex::Regex::new(pattern)
                    .map_err(|e| RulesError::ValidationError(format!("Invalid regex pattern: {}", e)))?;
            }
            
            Condition::And { conditions } | Condition::Or { conditions } => {
                if conditions.is_empty() {
                    return Err(RulesError::ValidationError("Logical condition must have at least one sub-condition".to_string()));
                }
                
                for sub_condition in conditions {
                    self.validate_condition(sub_condition)?;
                }
            }
            
            Condition::Not { condition } => {
                self.validate_condition(condition)?;
            }
            
            Condition::Temporal { condition, within } => {
                self.validate_condition(condition)?;
                
                if within.as_secs() == 0 {
                    return Err(RulesError::ValidationError("Temporal condition timeframe must be greater than 0".to_string()));
                }
            }
            
            Condition::Count { condition, threshold, timeframe } => {
                self.validate_condition(condition)?;
                
                if *threshold == 0 {
                    return Err(RulesError::ValidationError("Count condition threshold must be greater than 0".to_string()));
                }
                
                if timeframe.as_secs() == 0 {
                    return Err(RulesError::ValidationError("Count condition timeframe must be greater than 0".to_string()));
                }
            }
            
            Condition::Sequence { conditions, max_timespan } => {
                if conditions.len() < 2 {
                    return Err(RulesError::ValidationError("Sequence condition must have at least 2 sub-conditions".to_string()));
                }
                
                for sub_condition in conditions {
                    self.validate_condition(sub_condition)?;
                }
                
                if max_timespan.as_secs() == 0 {
                    return Err(RulesError::ValidationError("Sequence condition max timespan must be greater than 0".to_string()));
                }
            }
            
            Condition::Anomaly { field, baseline_window, detection_window, threshold_sigma } => {
                if field.is_empty() {
                    return Err(RulesError::ValidationError("Anomaly condition field cannot be empty".to_string()));
                }
                
                if baseline_window.as_secs() == 0 {
                    return Err(RulesError::ValidationError("Anomaly baseline window must be greater than 0".to_string()));
                }
                
                if detection_window.as_secs() == 0 {
                    return Err(RulesError::ValidationError("Anomaly detection window must be greater than 0".to_string()));
                }
                
                if *threshold_sigma <= 0.0 {
                    return Err(RulesError::ValidationError("Anomaly threshold sigma must be greater than 0".to_string()));
                }
            }
        }
        
        Ok(())
    }

    /// Validate correlation configuration
    fn validate_correlation_config(&self, config: &CorrelationConfig) -> Result<(), RulesError> {
        if config.key_fields.is_empty() {
            return Err(RulesError::ValidationError("Correlation key fields cannot be empty".to_string()));
        }
        
        if config.max_timespan.as_secs() == 0 {
            return Err(RulesError::ValidationError("Correlation max timespan must be greater than 0".to_string()));
        }
        
        if config.min_events == 0 {
            return Err(RulesError::ValidationError("Correlation min events must be greater than 0".to_string()));
        }
        
        if let Some(max_events) = config.max_events {
            if max_events < config.min_events {
                return Err(RulesError::ValidationError("Correlation max events must be greater than or equal to min events".to_string()));
            }
        }
        
        if config.correlation_type.is_empty() {
            return Err(RulesError::ValidationError("Correlation type cannot be empty".to_string()));
        }
        
        Ok(())
    }
}

impl Default for RuleParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventSource, Severity};
    use std::collections::HashMap;

    #[test]
    fn test_parse_simple_rule() {
        let yaml = r#"
id: "test-001"
name: "Test Rule"
description: "A simple test rule"
author: "XDR Team"
version: "1.0"
enabled: true
severity: "High"
confidence: 0.9

metadata:
  category: "test"
  tags: ["test"]
  created: "2024-01-01"
  modified: "2024-01-01"

sources:
  - "Process"

conditions:
  condition:
    type: "Match"
    field: "process.image_path"
    value: "test.exe"
    operator: "contains"

output:
  message: "Test process detected"
"#;

        let parser = RuleParser::new();
        let rule = parser.parse_yaml(yaml).expect("Failed to parse rule");
        
        assert_eq!(rule.id, "test-001");
        assert_eq!(rule.name, "Test Rule");
        assert_eq!(rule.confidence, 0.9);
        assert!(rule.enabled);
    }

    #[test]
    fn test_parse_complex_rule() {
        let yaml = r#"
id: "complex-001"
name: "Complex Rule"
description: "A complex rule with correlation"
author: "XDR Team"
version: "1.0"
enabled: true
severity: "Critical"
confidence: 0.95

metadata:
  attack:
    techniques: ["T1055"]
    tactics: ["Defense Evasion"]
    matrix: "enterprise"
  category: "process_injection"
  subcategory: "dll_injection"
  cve: ["CVE-2021-1234"]
  references: ["https://example.com"]
  tags: ["injection", "evasion"]
  created: "2024-01-01"
  modified: "2024-01-02"

sources:
  - "Process"
  - "Image"

conditions:
  condition:
    type: "And"
    conditions:
      - type: "Match"
        field: "process.operation"
        value: "Create"
        operator: "equals"
      - type: "Regex"
        field: "process.image_path"
        pattern: ".*\\.(exe|dll)$"
  timeframe: "5m"
  threshold: 3
  group_by: ["process.parent_process_id"]

correlation:
  key_fields: ["process.parent_process_id"]
  max_timespan: "10m"
  min_events: 2
  max_events: 10
  correlation_type: "process_injection"
  allow_partial: false

false_positives:
  - name: "System processes"
    condition:
      type: "Match"
      field: "process.image_path"
      value: "C:\\Windows\\System32"
      operator: "starts_with"
    confidence_reduction: 0.8

output:
  message: "Potential process injection detected"
  title: "Process Injection Alert"
  description: "Multiple suspicious process operations detected"
  include_raw_event: true
  extract_fields: ["process.image_path", "process.parent_process_id"]
  details:
    technique: "Process Injection"
    severity: "Critical"
"#;

        let parser = RuleParser::new();
        let rule = parser.parse_yaml(yaml).expect("Failed to parse complex rule");
        
        assert_eq!(rule.id, "complex-001");
        assert!(rule.correlation.is_some());
        assert_eq!(rule.false_positives.len(), 1);
        assert!(rule.metadata.attack.is_some());
    }

    #[test]
    fn test_validation_errors() {
        let parser = RuleParser::new();
        
        // Test empty ID
        let yaml = r#"
id: ""
name: "Test"
"#;
        assert!(parser.parse_yaml(yaml).is_err());
        
        // Test invalid confidence
        let yaml = r#"
id: "test"
name: "Test"
confidence: 1.5
"#;
        assert!(parser.parse_yaml(yaml).is_err());
        
        // Test invalid regex
        let yaml = r#"
id: "test"
name: "Test"
sources: ["Process"]
conditions:
  condition:
    type: "Regex"
    field: "test"
    pattern: "["
output:
  message: "test"
metadata:
  category: "test"
  tags: []
  created: "2024-01-01"
  modified: "2024-01-01"
"#;
        assert!(parser.parse_yaml(yaml).is_err());
    }
}