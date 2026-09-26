//! Detection of password-spraying activity in authentication logs.
//!
//! Log lines use the format `timestamp|ip|user|status`, where `timestamp`
//! is RFC 3339 and `status` is `success` or `fail`. Three patterns are
//! detected:
//!
//! * **Spray** — one source fails against many distinct accounts in a short
//!   window. This is the classic "one password, many users" attack.
//! * **Distributed** — one account fails from many distinct sources in a
//!   short window, typical of botnets rotating IPs to dodge rate limits.
//! * **Compromise** — a source flagged for spraying later logs in
//!   successfully. This is the finding that most needs a human.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

/// Outcome of a single authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
}

/// A parsed authentication event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub line: usize,
    pub timestamp: DateTime<Utc>,
    pub ip: String,
    pub user: String,
    pub outcome: Outcome,
}

/// Why a log line could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub reason: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.reason)
    }
}

impl std::error::Error for ParseError {}

/// Parses one log line. Blank lines and `#` comments yield `Ok(None)`.
pub fn parse_line(line_no: usize, line: &str) -> Result<Option<Event>, ParseError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    let err = |reason: String| ParseError {
        line: line_no,
        reason,
    };
    let fields: Vec<&str> = line.split('|').map(str::trim).collect();
    let [ts, ip, user, status] = fields[..] else {
        return Err(err(format!(
            "expected 4 fields separated by '|', found {}",
            fields.len()
        )));
    };

    let timestamp = DateTime::parse_from_rfc3339(ts)
        .map_err(|e| err(format!("invalid timestamp {ts:?}: {e}")))?
        .with_timezone(&Utc);

    if ip.is_empty() || user.is_empty() {
        return Err(err("ip and user must not be empty".into()));
    }

    let outcome = match status.to_ascii_lowercase().as_str() {
        "success" | "ok" | "accepted" => Outcome::Success,
        "fail" | "failed" | "failure" | "denied" => Outcome::Failure,
        other => {
            return Err(err(format!(
                "unknown status {other:?} (expected success or fail)"
            )))
        }
    };

    Ok(Some(Event {
        line: line_no,
        timestamp,
        ip: ip.to_string(),
        user: user.to_string(),
        outcome,
    }))
}

/// Parses a whole log, returning the events and any lines that were rejected.
pub fn parse_log(text: &str) -> (Vec<Event>, Vec<ParseError>) {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        match parse_line(idx + 1, line) {
            Ok(Some(event)) => events.push(event),
            Ok(None) => {}
            Err(e) => errors.push(e),
        }
    }
    events.sort_by_key(|e| e.timestamp);
    (events, errors)
}

/// Detection thresholds.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Length of the sliding window.
    pub window: Duration,
    /// Distinct accounts a single source must fail against to count as a spray.
    pub users_per_ip: usize,
    /// Distinct sources a single account must fail from to count as distributed.
    pub ips_per_user: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            window: Duration::minutes(15),
            users_per_ip: 3,
            ips_per_user: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertKind {
    Spray,
    Distributed,
    Compromise,
}

/// A detected suspicious pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    pub severity: Severity,
    /// The IP (for spray/compromise) or user (for distributed) at the center of the alert.
    pub subject: String,
    /// The accounts or sources involved.
    pub related: Vec<String>,
    pub failures: usize,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Runs every detector and returns alerts ordered by severity, then time.
pub fn detect(events: &[Event], config: &Config) -> Vec<Alert> {
    let mut alerts = Vec::new();

    let sprays = sliding_window(events, config.window, config.users_per_ip, |e| {
        (&e.ip, &e.user)
    });
    for (ip, hit) in &sprays {
        alerts.push(Alert {
            kind: AlertKind::Spray,
            severity: Severity::High,
            subject: ip.clone(),
            related: hit.related.iter().cloned().collect(),
            failures: hit.failures,
            first_seen: hit.first_seen,
            last_seen: hit.last_seen,
        });
    }

    let distributed = sliding_window(events, config.window, config.ips_per_user, |e| {
        (&e.user, &e.ip)
    });
    for (user, hit) in distributed {
        alerts.push(Alert {
            kind: AlertKind::Distributed,
            severity: Severity::Medium,
            subject: user,
            related: hit.related.into_iter().collect(),
            failures: hit.failures,
            first_seen: hit.first_seen,
            last_seen: hit.last_seen,
        });
    }

    alerts.extend(detect_compromise(events, &sprays, config.window));

    alerts.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.first_seen.cmp(&b.first_seen))
            .then(a.subject.cmp(&b.subject))
    });
    alerts
}

/// The busiest window found for one key.
#[derive(Debug, Clone)]
struct WindowHit {
    related: BTreeSet<String>,
    failures: usize,
    first_seen: DateTime<Utc>,
    last_seen: DateTime<Utc>,
}

/// For each key, finds the window with the most distinct related values
/// among failed attempts, keeping only keys that reach `threshold`.
///
/// Runs in O(n) per key using a two-pointer window with per-value counts.
fn sliding_window<'a, F>(
    events: &'a [Event],
    window: Duration,
    threshold: usize,
    key_of: F,
) -> BTreeMap<String, WindowHit>
where
    F: Fn(&'a Event) -> (&'a String, &'a String),
{
    let mut by_key: HashMap<&String, Vec<&Event>> = HashMap::new();
    for event in events.iter().filter(|e| e.outcome == Outcome::Failure) {
        by_key.entry(key_of(event).0).or_default().push(event);
    }

    let mut hits = BTreeMap::new();
    for (key, failures) in by_key {
        let mut queue: VecDeque<&Event> = VecDeque::new();
        let mut counts: HashMap<&String, usize> = HashMap::new();
        let mut best: Option<WindowHit> = None;

        for &event in &failures {
            queue.push_back(event);
            *counts.entry(key_of(event).1).or_insert(0) += 1;

            while let Some(&front) = queue.front() {
                if event.timestamp - front.timestamp <= window {
                    break;
                }
                let related = key_of(front).1;
                if let Some(n) = counts.get_mut(related) {
                    *n -= 1;
                    if *n == 0 {
                        counts.remove(related);
                    }
                }
                queue.pop_front();
            }

            let improves = best.as_ref().is_none_or(|b| counts.len() > b.related.len());
            if counts.len() >= threshold && improves {
                best = Some(WindowHit {
                    related: counts.keys().map(|s| (*s).clone()).collect(),
                    failures: queue.len(),
                    first_seen: queue
                        .front()
                        .map(|e| e.timestamp)
                        .unwrap_or(event.timestamp),
                    last_seen: event.timestamp,
                });
            }
        }

        if let Some(hit) = best {
            hits.insert(key.clone(), hit);
        }
    }
    hits
}

/// Flags successful logins from a spraying source during or shortly after the spray.
fn detect_compromise(
    events: &[Event],
    sprays: &BTreeMap<String, WindowHit>,
    window: Duration,
) -> Vec<Alert> {
    let mut accounts: BTreeMap<&String, BTreeSet<String>> = BTreeMap::new();
    let mut last: BTreeMap<&String, DateTime<Utc>> = BTreeMap::new();

    for event in events.iter().filter(|e| e.outcome == Outcome::Success) {
        let Some(hit) = sprays.get(&event.ip) else {
            continue;
        };
        if event.timestamp >= hit.first_seen && event.timestamp <= hit.last_seen + window {
            accounts
                .entry(&event.ip)
                .or_default()
                .insert(event.user.clone());
            last.insert(&event.ip, event.timestamp);
        }
    }

    accounts
        .into_iter()
        .map(|(ip, users)| {
            let hit = &sprays[ip];
            Alert {
                kind: AlertKind::Compromise,
                severity: Severity::Critical,
                subject: ip.clone(),
                related: users.into_iter().collect(),
                failures: hit.failures,
                first_seen: hit.first_seen,
                last_seen: last[ip],
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(log: &str) -> Vec<Event> {
        let (events, errors) = parse_log(log);
        assert!(errors.is_empty(), "unexpected parse errors: {errors:?}");
        events
    }

    fn kinds(alerts: &[Alert]) -> Vec<(AlertKind, &str)> {
        alerts
            .iter()
            .map(|a| (a.kind, a.subject.as_str()))
            .collect()
    }

    #[test]
    fn parses_valid_line() {
        let event = parse_line(1, "2026-01-14T12:00:01Z|10.0.0.5|alex|FAIL")
            .unwrap()
            .unwrap();
        assert_eq!(event.ip, "10.0.0.5");
        assert_eq!(event.outcome, Outcome::Failure);
    }

    #[test]
    fn skips_blank_lines_and_comments() {
        assert_eq!(parse_line(1, "   "), Ok(None));
        assert_eq!(parse_line(2, "# header"), Ok(None));
    }

    #[test]
    fn reports_malformed_lines() {
        let (events, errors) = parse_log("bad line\n2026-01-14T12:00:01Z|1.2.3.4|bob|maybe\n");
        assert!(events.is_empty());
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].line, 1);
        assert!(errors[1].reason.contains("unknown status"));
    }

    #[test]
    fn detects_spray_within_window() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.5|alex|fail
2026-01-14T12:05:00Z|10.0.0.5|maria|fail
2026-01-14T12:10:00Z|10.0.0.5|jules|fail";
        let alerts = detect(&events(log), &Config::default());
        assert_eq!(kinds(&alerts), vec![(AlertKind::Spray, "10.0.0.5")]);
        assert_eq!(alerts[0].related, vec!["alex", "jules", "maria"]);
    }

    #[test]
    fn ignores_attempts_spread_beyond_window() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.5|alex|fail
2026-01-14T12:20:00Z|10.0.0.5|maria|fail
2026-01-14T12:40:00Z|10.0.0.5|jules|fail";
        assert!(detect(&events(log), &Config::default()).is_empty());
    }

    #[test]
    fn repeated_failures_on_one_account_are_not_a_spray() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.8|alex|fail
2026-01-14T12:00:10Z|10.0.0.8|alex|fail
2026-01-14T12:00:20Z|10.0.0.8|alex|fail
2026-01-14T12:00:30Z|10.0.0.8|alex|fail";
        assert!(detect(&events(log), &Config::default()).is_empty());
    }

    #[test]
    fn detects_distributed_attack_on_one_account() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.1|sara|fail
2026-01-14T12:01:00Z|10.0.0.2|sara|fail
2026-01-14T12:02:00Z|10.0.0.3|sara|fail";
        let alerts = detect(&events(log), &Config::default());
        assert_eq!(kinds(&alerts), vec![(AlertKind::Distributed, "sara")]);
    }

    #[test]
    fn flags_success_after_spray_as_compromise() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.5|alex|fail
2026-01-14T12:01:00Z|10.0.0.5|maria|fail
2026-01-14T12:02:00Z|10.0.0.5|jules|fail
2026-01-14T12:03:00Z|10.0.0.5|maria|success";
        let alerts = detect(&events(log), &Config::default());
        assert_eq!(alerts[0].kind, AlertKind::Compromise);
        assert_eq!(alerts[0].severity, Severity::Critical);
        assert_eq!(alerts[0].related, vec!["maria"]);
    }

    #[test]
    fn handles_unsorted_input_and_timezones() {
        let log = "\
2026-01-14T09:10:00-03:00|10.0.0.5|jules|fail
2026-01-14T12:00:00Z|10.0.0.5|alex|fail
2026-01-14T12:05:00Z|10.0.0.5|maria|fail";
        let alerts = detect(&events(log), &Config::default());
        assert_eq!(kinds(&alerts), vec![(AlertKind::Spray, "10.0.0.5")]);
    }

    #[test]
    fn respects_custom_thresholds() {
        let log = "\
2026-01-14T12:00:00Z|10.0.0.5|alex|fail
2026-01-14T12:01:00Z|10.0.0.5|maria|fail";
        let config = Config {
            users_per_ip: 2,
            ..Config::default()
        };
        assert_eq!(detect(&events(log), &config).len(), 1);
    }
}
