//! Rule Execution Engine
//! 
//! Core engine for evaluating rules against events and generating matches.

use super::correlation::{CorrelationConfig, EventCorrelator};
use super::schema::*;
use super::{RuleMatch, RulesError};
use crate::events::{EventEnvelope, Severity};
use crate::LibResult;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use uuid::Uuid;

/// Rule execution engine
pub struct RuleExecutionEngine {
    /// Compiled regex cache for performance
    regex_cache: HashMap<String, Regex>,
}

impl RuleExecutionEngine {
    /// Create a new rule execution engine
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
        }
    }

    /// Evaluate a rule against an event
    pub fn evaluate_rule(
        &self,
        rule: &Rule,
        event: &EventEnvelope,
        correlator: &mut EventCorrelator,
    ) -> Result<Option<RuleMatch>, RulesError> {
        // Check if event source matches rule sources
        if !rule.sources.contains(&event.source) {
            return Ok(None);
        }

        // Parse event data as JSON for field access
        let event_data: serde_json::Value = serde_json::from_str(&event.data)
            .map_err(|e| RulesError::ParseError(format!("Failed to parse event data: {}", e)))?;

        // Evaluate main condition
        let condition_result = self.evaluate_condition(&rule.conditions.condition, event, &event_data)?;
        
        if !condition_result {
            return Ok(None);
        }

        // Apply time-based and threshold constraints if specified
        if let Some(_timeframe) = &rule.conditions.timeframe {
            // TODO: Implement timeframe evaluation with event history
        }

        if let Some(_threshold) = rule.conditions.threshold {
            // TODO: Implement threshold evaluation with event counting
        }

        // Check false positive filters
        let mut confidence = rule.confidence;
        for fp_filter in &rule.false_positives {
            if self.evaluate_condition(&fp_filter.condition, event, &event_data)? {
                confidence *= (1.0 - fp_filter.confidence_reduction);
                tracing::debug!(
                    "False positive filter '{}' applied, confidence reduced to {:.2}",
                    fp_filter.name,
                    confidence
                );
            }
        }

        // Handle correlation if configured
        let correlation_id = if let Some(ref correlation_config) = rule.correlation {
            let config = CorrelationConfig {
                correlation_type: correlation_config.correlation_type.clone(),
                key_fields: correlation_config.key_fields.clone(),
                window_duration: correlation_config.max_timespan,
                min_events: correlation_config.min_events as usize,
                max_events: correlation_config.max_events.map(|n| n as usize),
                allow_partial: correlation_config.allow_partial,
            };

            if let Some(correlation_result) = correlator.add_event(event, &config) {
                Some(correlation_result.correlation_id)
            } else {
                // Event added to correlation but no result yet
                return Ok(None);
            }
        } else {
            None
        };

        // Generate rule match
        let rule_match = RuleMatch {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            event_id: event.id.clone(),
            severity: rule.severity,
            confidence,
            message: self.format_message(&rule.output.message, event, &event_data),
            details: self.create_match_details(rule, event, &event_data)?,
            correlation_id,
            timestamp: Utc::now(),
        };

        Ok(Some(rule_match))
    }

    /// Evaluate a condition against an event
    fn evaluate_condition(
        &self,
        condition: &Condition,
        event: &EventEnvelope,
        event_data: &serde_json::Value,
    ) -> Result<bool, RulesError> {
        match condition {
            Condition::Match { field, value, operator } => {
                let field_value = self.get_field_value(field, event, event_data);
                self.evaluate_match_condition(&field_value, value, operator)
            }

            Condition::Regex { field, pattern, flags: _ } => {
                let field_value = self.get_field_value(field, event, event_data);
                self.evaluate_regex_condition(&field_value, pattern)
            }

            Condition::And { conditions } => {
                for sub_condition in conditions {
                    if !self.evaluate_condition(sub_condition, event, event_data)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }

            Condition::Or { conditions } => {
                for sub_condition in conditions {
                    if self.evaluate_condition(sub_condition, event, event_data)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }

            Condition::Not { condition } => {
                let result = self.evaluate_condition(condition, event, event_data)?;
                Ok(!result)
            }

            Condition::Temporal { condition, within: _ } => {
                // For now, just evaluate the inner condition
                // TODO: Implement temporal evaluation with event history
                self.evaluate_condition(condition, event, event_data)
            }

            Condition::Count { condition, threshold: _, timeframe: _ } => {
                // For now, just evaluate the inner condition
                // TODO: Implement count evaluation with event history
                self.evaluate_condition(condition, event, event_data)
            }

            Condition::Sequence { conditions, max_timespan: _ } => {
                // For now, just check if any condition matches
                // TODO: Implement proper sequence detection
                for sub_condition in conditions {
                    if self.evaluate_condition(sub_condition, event, event_data)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }

            Condition::Anomaly { field: _, baseline_window: _, detection_window: _, threshold_sigma: _ } => {
                // TODO: Implement statistical anomaly detection
                Ok(false)
            }
        }
    }

    /// Get field value from event
    fn get_field_value(
        &self,
        field: &str,
        event: &EventEnvelope,
        event_data: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        match field {
            "id" => Some(serde_json::Value::String(event.id.clone())),
            "source" => Some(serde_json::Value::String(format!("{:?}", event.source))),
            "severity" => Some(serde_json::Value::String(format!("{:?}", event.severity))),
            "timestamp" => Some(serde_json::Value::String(event.timestamp.to_rfc3339())),
            "process_id" => Some(serde_json::Value::Number(event.process_id.into())),
            "thread_id" => Some(serde_json::Value::Number(event.thread_id.into())),
            "session_id" => Some(serde_json::Value::Number(event.session_id.into())),
            "sequence_number" => Some(serde_json::Value::Number(event.sequence_number.into())),
            "key_hash" => Some(serde_json::Value::Number(event.key_hash.into())),
            "flags" => Some(serde_json::Value::String(event.flags.clone())),
            _ => {
                // Try to extract from event data using dot notation
                self.extract_nested_field(event_data, field)
            }
        }
    }

    /// Extract nested field using dot notation
    fn extract_nested_field(&self, data: &serde_json::Value, field: &str) -> Option<serde_json::Value> {
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = data;

        for part in parts {
            match current {
                serde_json::Value::Object(obj) => {
                    current = obj.get(part)?;
                }
                serde_json::Value::Array(arr) => {
                    // Handle array indexing
                    if let Ok(index) = part.parse::<usize>() {
                        current = arr.get(index)?;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        Some(current.clone())
    }

    /// Evaluate match condition
    fn evaluate_match_condition(
        &self,
        field_value: &Option<serde_json::Value>,
        condition_value: &ConditionValue,
        operator: &MatchOperator,
    ) -> Result<bool, RulesError> {
        match operator {
            MatchOperator::Exists => Ok(field_value.is_some()),
            MatchOperator::NotExists => Ok(field_value.is_none()),
            _ => {
                let field_val = field_value.as_ref().ok_or_else(|| {
                    RulesError::ValidationError("Field value is None".to_string())
                })?;

                match operator {
                    MatchOperator::Equals => self.compare_values_equal(field_val, condition_value),
                    MatchOperator::NotEquals => self.compare_values_equal(field_val, condition_value).map(|r| !r),
                    MatchOperator::Contains => self.compare_values_contains(field_val, condition_value),
                    MatchOperator::NotContains => self.compare_values_contains(field_val, condition_value).map(|r| !r),
                    MatchOperator::StartsWith => self.compare_values_starts_with(field_val, condition_value),
                    MatchOperator::EndsWith => self.compare_values_ends_with(field_val, condition_value),
                    MatchOperator::In => self.compare_values_in(field_val, condition_value),
                    MatchOperator::NotIn => self.compare_values_in(field_val, condition_value).map(|r| !r),
                    MatchOperator::GreaterThan => self.compare_values_numeric(field_val, condition_value, |a, b| a > b),
                    MatchOperator::LessThan => self.compare_values_numeric(field_val, condition_value, |a, b| a < b),
                    MatchOperator::GreaterEqual => self.compare_values_numeric(field_val, condition_value, |a, b| a >= b),
                    MatchOperator::LessEqual => self.compare_values_numeric(field_val, condition_value, |a, b| a <= b),
                    MatchOperator::Exists | MatchOperator::NotExists => unreachable!(),
                }
            }
        }
    }

    /// Compare values for equality
    fn compare_values_equal(&self, field_val: &serde_json::Value, condition_val: &ConditionValue) -> Result<bool, RulesError> {
        match condition_val {
            ConditionValue::String(s) => {
                Ok(field_val.as_str().map_or(false, |fv| fv == s))
            }
            ConditionValue::Number(n) => {
                Ok(field_val.as_f64().map_or(false, |fv| (fv - n).abs() < f64::EPSILON))
            }
            ConditionValue::Boolean(b) => {
                Ok(field_val.as_bool().map_or(false, |fv| fv == *b))
            }
            ConditionValue::Array(_) => {
                Err(RulesError::ValidationError("Cannot use array value for equality comparison".to_string()))
            }
            ConditionValue::Range { min, max } => {
                if let Some(fv) = field_val.as_f64() {
                    Ok(fv >= *min && fv <= *max)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Compare values for contains
    fn compare_values_contains(&self, field_val: &serde_json::Value, condition_val: &ConditionValue) -> Result<bool, RulesError> {
        if let ConditionValue::String(s) = condition_val {
            Ok(field_val.as_str().map_or(false, |fv| fv.contains(s)))
        } else {
            Err(RulesError::ValidationError("Contains operator only supports string values".to_string()))
        }
    }

    /// Compare values for starts_with
    fn compare_values_starts_with(&self, field_val: &serde_json::Value, condition_val: &ConditionValue) -> Result<bool, RulesError> {
        if let ConditionValue::String(s) = condition_val {
            Ok(field_val.as_str().map_or(false, |fv| fv.starts_with(s)))
        } else {
            Err(RulesError::ValidationError("StartsWith operator only supports string values".to_string()))
        }
    }

    /// Compare values for ends_with
    fn compare_values_ends_with(&self, field_val: &serde_json::Value, condition_val: &ConditionValue) -> Result<bool, RulesError> {
        if let ConditionValue::String(s) = condition_val {
            Ok(field_val.as_str().map_or(false, |fv| fv.ends_with(s)))
        } else {
            Err(RulesError::ValidationError("EndsWith operator only supports string values".to_string()))
        }
    }

    /// Compare values for in array
    fn compare_values_in(&self, field_val: &serde_json::Value, condition_val: &ConditionValue) -> Result<bool, RulesError> {
        if let ConditionValue::Array(arr) = condition_val {
            if let Some(fv_str) = field_val.as_str() {
                Ok(arr.contains(&fv_str.to_string()))
            } else {
                Ok(false)
            }
        } else {
            Err(RulesError::ValidationError("In operator requires array value".to_string()))
        }
    }

    /// Compare values numerically
    fn compare_values_numeric<F>(&self, field_val: &serde_json::Value, condition_val: &ConditionValue, op: F) -> Result<bool, RulesError>
    where
        F: Fn(f64, f64) -> bool,
    {
        if let ConditionValue::Number(n) = condition_val {
            if let Some(fv) = field_val.as_f64() {
                Ok(op(fv, *n))
            } else {
                Ok(false)
            }
        } else {
            Err(RulesError::ValidationError("Numeric comparison requires number value".to_string()))
        }
    }

    /// Evaluate regex condition
    fn evaluate_regex_condition(&self, field_value: &Option<serde_json::Value>, pattern: &str) -> Result<bool, RulesError> {
        if let Some(field_val) = field_value {
            if let Some(field_str) = field_val.as_str() {
                let regex = Regex::new(pattern)?;
                Ok(regex.is_match(field_str))
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Format message template with event data
    fn format_message(&self, template: &str, event: &EventEnvelope, event_data: &serde_json::Value) -> String {
        let mut message = template.to_string();

        // Replace common placeholders
        message = message.replace("{event.id}", &event.id);
        message = message.replace("{event.source}", &format!("{:?}", event.source));
        message = message.replace("{event.severity}", &format!("{:?}", event.severity));
        message = message.replace("{event.process_id}", &event.process_id.to_string());
        message = message.replace("{event.timestamp}", &event.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string());

        // Replace field placeholders from event data
        // Simple implementation - could be enhanced with more sophisticated templating
        if let Some(process_path) = self.extract_nested_field(event_data, "process.image_path") {
            if let Some(path_str) = process_path.as_str() {
                message = message.replace("{process.image_path}", path_str);
            }
        }

        message
    }

    /// Create match details JSON
    fn create_match_details(&self, rule: &Rule, event: &EventEnvelope, event_data: &serde_json::Value) -> Result<serde_json::Value, RulesError> {
        let mut details = serde_json::Map::new();

        // Add rule metadata
        details.insert("rule_id".to_string(), serde_json::Value::String(rule.id.clone()));
        details.insert("rule_version".to_string(), serde_json::Value::String(rule.version.clone()));
        details.insert("rule_category".to_string(), serde_json::Value::String(rule.metadata.category.clone()));

        // Add ATT&CK information if available
        if let Some(ref attack) = rule.metadata.attack {
            let mut attack_data = serde_json::Map::new();
            attack_data.insert("techniques".to_string(), serde_json::Value::Array(
                attack.techniques.iter().map(|t| serde_json::Value::String(t.clone())).collect()
            ));
            attack_data.insert("tactics".to_string(), serde_json::Value::Array(
                attack.tactics.iter().map(|t| serde_json::Value::String(t.clone())).collect()
            ));
            attack_data.insert("matrix".to_string(), serde_json::Value::String(attack.matrix.clone()));
            details.insert("attack".to_string(), serde_json::Value::Object(attack_data));
        }

        // Add extracted fields if specified
        for field in &rule.output.extract_fields {
            if let Some(value) = self.get_field_value(field, event, event_data) {
                details.insert(field.clone(), value);
            }
        }

        // Add custom details from rule output
        for (key, value_template) in &rule.output.details {
            let formatted_value = self.format_message(value_template, event, event_data);
            details.insert(key.clone(), serde_json::Value::String(formatted_value));
        }

        // Include raw event if requested
        if rule.output.include_raw_event {
            details.insert("raw_event".to_string(), serde_json::Value::String(event.data.clone()));
        }

        Ok(serde_json::Value::Object(details))
    }
}

impl Default for RuleExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{EventData, EventEnvelope, EventSource, ProcessEvent, ProcessOperation, Severity};
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_test_event() -> EventEnvelope {
        EventEnvelope {
            id: Uuid::new_v4(),
            source: EventSource::Process,
            severity: Severity::Medium,
            timestamp: Utc::now(),
            process_id: 1234,
            thread_id: 5678,
            session_id: 1,
            sequence_number: 42,
            prev_sequence_number: 41,
            key_hash: 0x12345678,
            flags: vec!["0x00000001".to_string()],
            data: EventData::Process(ProcessEvent {
                operation: ProcessOperation::Create,
                parent_process_id: None,
                image_path: "C:\\Windows\\System32\\notepad.exe".to_string(),
                command_line_hash: None,
                integrity_level: None,
                token_flags: None,
                sid_hash: None,
                exit_code: None,
            }),
            metadata: HashMap::new(),
        }
    }

    fn create_test_rule() -> Rule {
        Rule {
            id: "test-rule-001".to_string(),
            name: "Test Process Creation".to_string(),
            description: "Detects process creation".to_string(),
            author: "Test".to_string(),
            version: "1.0".to_string(),
            enabled: true,
            severity: Severity::High,
            confidence: 0.8,
            metadata: RuleMetadata {
                attack: None,
                category: "process".to_string(),
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
                    field: "process.operation".to_string(),
                    value: ConditionValue::String("Create".to_string()),
                    operator: MatchOperator::Equals,
                },
                timeframe: None,
                threshold: None,
                group_by: vec![],
            },
            correlation: None,
            false_positives: vec![],
            output: RuleOutput {
                message: "Process creation detected: {process.image_path}".to_string(),
                details: HashMap::new(),
                include_raw_event: false,
                extract_fields: vec!["process.image_path".to_string()],
                title: None,
                description: None,
            },
        }
    }

    #[test]
    fn test_rule_evaluation_match() {
        let engine = RuleExecutionEngine::new();
        let mut correlator = EventCorrelator::new();
        let rule = create_test_rule();
        let event = create_test_event();

        let result = engine.evaluate_rule(&rule, &event, &mut correlator).unwrap();
        assert!(result.is_some());

        let rule_match = result.unwrap();
        assert_eq!(rule_match.rule_id, "test-rule-001");
        assert_eq!(rule_match.event_id, "test-event-001");
        assert_eq!(rule_match.confidence, 0.8);
    }

    #[test]
    fn test_rule_evaluation_no_match() {
        let engine = RuleExecutionEngine::new();
        let mut correlator = EventCorrelator::new();
        let mut rule = create_test_rule();
        
        // Change condition to not match
        rule.conditions.condition = Condition::Match {
            field: "process.operation".to_string(),
            value: ConditionValue::String("Delete".to_string()),
            operator: MatchOperator::Equals,
        };
        
        let event = create_test_event();

        let result = engine.evaluate_rule(&rule, &event, &mut correlator).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_false_positive_filter() {
        let engine = RuleExecutionEngine::new();
        let mut correlator = EventCorrelator::new();
        let mut rule = create_test_rule();
        
        // Add false positive filter
        rule.false_positives.push(FalsePositiveFilter {
            name: "System processes".to_string(),
            condition: Condition::Match {
                field: "process.image_path".to_string(),
                value: ConditionValue::String("C:\\Windows\\System32".to_string()),
                operator: MatchOperator::StartsWith,
            },
            confidence_reduction: 0.5,
        });
        
        let event = create_test_event();

        let result = engine.evaluate_rule(&rule, &event, &mut correlator).unwrap();
        assert!(result.is_some());

        let rule_match = result.unwrap();
        assert_eq!(rule_match.confidence, 0.4); // 0.8 * (1.0 - 0.5)
    }

    #[test]
    fn test_regex_condition() {
        let engine = RuleExecutionEngine::new();
        let mut correlator = EventCorrelator::new();
        let mut rule = create_test_rule();
        
        // Use regex condition
        rule.conditions.condition = Condition::Regex {
            field: "process.image_path".to_string(),
            pattern: r".*\\notepad\.exe$".to_string(),
            flags: None,
        };
        
        let event = create_test_event();

        let result = engine.evaluate_rule(&rule, &event, &mut correlator).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_complex_condition() {
        let engine = RuleExecutionEngine::new();
        let mut correlator = EventCorrelator::new();
        let mut rule = create_test_rule();
        
        // Use complex AND condition
        rule.conditions.condition = Condition::And {
            conditions: vec![
                Condition::Match {
                    field: "process.operation".to_string(),
                    value: ConditionValue::String("Create".to_string()),
                    operator: MatchOperator::Equals,
                },
                Condition::Match {
                    field: "process.image_path".to_string(),
                    value: ConditionValue::String("notepad.exe".to_string()),
                    operator: MatchOperator::Contains,
                },
            ],
        };
        
        let event = create_test_event();

        let result = engine.evaluate_rule(&rule, &event, &mut correlator).unwrap();
        assert!(result.is_some());
    }
}