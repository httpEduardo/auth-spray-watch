use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;

#[derive(Clone)]
struct Event {
    timestamp: DateTime<Utc>,
    ip: String,
    user: String,
    status: String,
}

fn parse_line(line: &str) -> Option<Event> {
    let parts: Vec<&str> = line.split('|').collect();
    if parts.len() != 4 {
        return None;
    }
    let timestamp = parts[0].parse::<DateTime<Utc>>().ok()?;
    Some(Event {
        timestamp,
        ip: parts[1].to_string(),
        user: parts[2].to_string(),
        status: parts[3].to_string(),
    })
}

fn parse_args() -> (String, i64, usize) {
    let args: Vec<String> = env::args().collect();
    let input = args
        .iter()
        .position(|arg| arg == "--input")
        .and_then(|idx| args.get(idx + 1))
        .cloned()
        .unwrap_or_else(|| "auth.log".to_string());
    let window = args
        .iter()
        .position(|arg| arg == "--window")
        .and_then(|idx| args.get(idx + 1))
        .and_then(|val| val.parse::<i64>().ok())
        .unwrap_or(15);
    let threshold = args
        .iter()
        .position(|arg| arg == "--threshold")
        .and_then(|idx| args.get(idx + 1))
        .and_then(|val| val.parse::<usize>().ok())
        .unwrap_or(3);
    (input, window, threshold)
}

fn main() {
    let (input, window_minutes, threshold) = parse_args();
    let raw = fs::read_to_string(&input).expect("Failed to read log file");

    let mut events: Vec<Event> = raw.lines().filter_map(parse_line).collect();
    events.sort_by_key(|event| event.timestamp);

    let mut ip_windows: HashMap<String, Vec<Event>> = HashMap::new();
    let mut user_ips: HashMap<String, HashSet<String>> = HashMap::new();

    for event in &events {
        if event.status != "fail" {
            continue;
        }
        ip_windows
            .entry(event.ip.clone())
            .or_default()
            .push(event.clone());
        user_ips
            .entry(event.user.clone())
            .or_default()
            .insert(event.ip.clone());
    }

    println!("Spray window: {window_minutes} minutes, threshold: {threshold}");

    println!("\nIP spray suspects:");
    for (ip, mut failures) in ip_windows {
        failures.sort_by_key(|event| event.timestamp);
        let mut flagged = false;
        for idx in 0..failures.len() {
            let start = failures[idx].timestamp;
            let end = start + Duration::minutes(window_minutes);
            let mut users = HashSet::new();
            for event in failures.iter().skip(idx) {
                if event.timestamp > end {
                    break;
                }
                users.insert(event.user.clone());
            }
            if users.len() >= threshold {
                println!("- {ip}: {users} users within {window_minutes}m", users = users.len());
                flagged = true;
                break;
            }
        }
        if !flagged && failures.len() >= threshold {
            println!("- {ip}: {count} failures total", count = failures.len());
        }
    }

    println!("\nUsers targeted by multiple IPs:");
    for (user, ips) in user_ips {
        if ips.len() >= threshold {
            println!("- {user}: {count} IPs", count = ips.len());
        }
    }
}
