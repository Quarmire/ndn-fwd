//! Logs, event streams, security audit, and operation history models.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "trace" => Some(Self::Trace),
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "warn" | "warning" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRow {
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    pub trace_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAuditRow {
    pub action: String,
    pub actor: String,
    pub outcome: String,
    pub trace_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationHistoryRow {
    pub operation: String,
    pub target: String,
    pub status: String,
    pub result: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventStreamState {
    pub source: &'static str,
    pub enabled: bool,
    pub fallback: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditViewModel {
    pub logs: Vec<LogRow>,
    pub security: Vec<SecurityAuditRow>,
    pub events: EventStreamState,
}

impl AuditViewModel {
    pub fn demo() -> Self {
        Self {
            logs: vec![
                LogRow {
                    level: LogLevel::Info,
                    target: "ndn_fwd::mgmt".into(),
                    message: "faces/list satisfied".into(),
                    trace_id: Some("trace-a1".into()),
                },
                LogRow {
                    level: LogLevel::Warn,
                    target: "ndn_security::validator".into(),
                    message: "schema fallback used".into(),
                    trace_id: Some("trace-b7".into()),
                },
            ],
            security: vec![SecurityAuditRow {
                action: "approve device".into(),
                actor: "/local/operator".into(),
                outcome: "pending signature".into(),
                trace_id: Some("trace-b7".into()),
            }],
            events: EventStreamState {
                source: "/localhost/nfd/events",
                enabled: true,
                fallback: "polling",
            },
        }
    }

    pub fn filter_logs(&self, min_level: LogLevel, target_prefix: &str) -> Vec<LogRow> {
        self.logs
            .iter()
            .filter(|row| row.level >= min_level)
            .filter(|row| target_prefix.is_empty() || row.target.starts_with(target_prefix))
            .cloned()
            .collect()
    }

    pub fn logs_for_trace(&self, trace_id: &str) -> Vec<LogRow> {
        self.logs
            .iter()
            .filter(|row| row.trace_id.as_deref() == Some(trace_id))
            .cloned()
            .collect()
    }

    pub fn export_logs_json(rows: &[LogRow]) -> Result<String, String> {
        serde_json::to_string_pretty(rows).map_err(|err| err.to_string())
    }
}

pub fn parse_log_line(line: &str) -> Option<LogRow> {
    let mut parts = line.splitn(4, ' ');
    let level = LogLevel::parse(parts.next()?)?;
    let target = parts.next()?.trim().to_string();
    let trace_part = parts.next()?.trim();
    let message = parts.next().unwrap_or_default().trim().to_string();
    let trace_id = trace_part
        .strip_prefix("trace=")
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    Some(LogRow {
        level,
        target,
        message,
        trace_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_log_line_with_trace() {
        let row = parse_log_line("INFO ndn_fwd::mgmt trace=abc faces/list").expect("row");

        assert_eq!(row.level, LogLevel::Info);
        assert_eq!(row.trace_id.as_deref(), Some("abc"));
        assert_eq!(row.message, "faces/list");
    }

    #[test]
    fn filters_logs_by_level_and_target() {
        let model = AuditViewModel::demo();
        let rows = model.filter_logs(LogLevel::Warn, "ndn_security");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].level, LogLevel::Warn);
    }

    #[test]
    fn correlates_logs_under_trace() {
        let model = AuditViewModel::demo();
        let rows = model.logs_for_trace("trace-b7");

        assert_eq!(rows.len(), 1);
        assert!(rows[0].target.contains("validator"));
    }
}
