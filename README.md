# auth-spray-watch

Detects password-spraying and distributed brute-force activity in authentication logs, and — most importantly — tells you when one of those attempts actually worked.

Password spraying flips the usual brute-force pattern around: instead of hammering one account with thousands of passwords, the attacker tries one or two common passwords against many accounts. Each account only sees a failure or two, so per-account lockouts never trigger and the attack slips under most alerting. The signal only shows up when you look across accounts, which is what this tool does.

## What it detects

| Alert | Severity | Pattern |
|-------|----------|---------|
| **Compromise** | Critical | A source that was spraying later logs in successfully. Treat this as an incident. |
| **Spray** | High | One IP fails against many distinct accounts within the window. |
| **Distributed** | Medium | One account fails from many distinct IPs within the window — typical of botnets rotating addresses to dodge rate limits. |

Repeated failures on a *single* account from a *single* IP are deliberately not reported. That's usually someone who forgot their password, and lockout policies already handle it.

## Installation

Requires Rust 1.82 or newer.

```bash
cargo install --git https://github.com/httpEduardo/auth-spray-watch
```

Or build from a clone:

```bash
git clone https://github.com/httpEduardo/auth-spray-watch.git
cd auth-spray-watch
cargo build --release   # binary at target/release/auth-spray-watch
```

## Usage

```bash
auth-spray-watch --input examples/auth.log
```

```text
Analyzed 12 events with a 15-minute window.

[CRITICAL] possible compromise: 10.0.0.5 logged in as lee after spraying
         2026-01-14 12:00:01 → 12:08:30
[HIGH] password spray from 10.0.0.5: 4 failures across 4 accounts (alex, jules, maria, sara)
         2026-01-14 12:00:01 → 12:05:21
[MEDIUM] distributed attack on 'sara': 4 failures from 3 IPs (10.0.0.11, 10.0.0.5, 10.0.0.9)
         2026-01-14 12:05:21 → 12:07:02
```

It also reads from standard input, which makes it easy to plug into an existing pipeline:

```bash
./export-auth-events.sh | auth-spray-watch --input - --format json
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-i, --input <FILE>` | `auth.log` | Log file, or `-` for stdin |
| `-w, --window <MINUTES>` | `15` | Length of the sliding window |
| `-t, --threshold <N>` | `3` | Distinct accounts one IP must fail against to be flagged |
| `--ip-threshold <N>` | same as `--threshold` | Distinct IPs one account must fail from to be flagged |
| `-f, --format <text\|json>` | `text` | Output format |
| `--strict` | off | Fail instead of skipping malformed lines |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No suspicious activity |
| `1` | At least one alert |
| `2` | Input could not be read, or malformed lines in `--strict` mode |

## Log format

One event per line, fields separated by `|`:

```
timestamp|ip|user|status
2026-01-14T12:00:01Z|10.0.0.5|alex|fail
```

- **timestamp** — RFC 3339. Offsets such as `-03:00` are supported and normalized to UTC, and lines don't need to be in order.
- **status** — `success`/`ok`/`accepted` or `fail`/`failed`/`failure`/`denied` (case-insensitive).
- Blank lines and lines starting with `#` are ignored. Malformed lines are reported on stderr with their line number and skipped.

Most identity providers and web servers can export to this shape with a one-line `jq` or `awk` command.

## JSON output

```json
{
  "events": 12,
  "skipped_lines": 0,
  "window_minutes": 15,
  "alerts": [
    {
      "kind": "compromise",
      "severity": "critical",
      "subject": "10.0.0.5",
      "related": ["lee"],
      "failures": 4,
      "first_seen": "2026-01-14T12:00:01Z",
      "last_seen": "2026-01-14T12:08:30Z"
    }
  ]
}
```

`subject` is the IP for spray and compromise alerts and the account for distributed alerts; `related` holds the other side of the relationship.

## How it works

Events are sorted by time and grouped by source (for sprays) or account (for distributed attacks). For each group, a two-pointer sliding window tracks how many *distinct* counterparts appear in failed attempts, and the busiest window is kept. This is linear in the number of events per group, so large logs are fine.

A compromise alert is raised when a flagged source has a successful login between the start of its spray and one window after it ended.

The detection logic lives in `src/lib.rs` and can be used as a library; `src/main.rs` is only the CLI.

## Tuning

The defaults (3 accounts in 15 minutes) are intentionally sensitive for small logs and demos. On a real environment:

- **Shared egress IPs** (corporate NAT, VPNs, mobile carriers) can trigger spray alerts from legitimate users. Raise `--threshold` or allowlist those ranges before analysis.
- **Slow sprays** spread attempts over hours to stay under the radar. Widen `--window` (e.g. `--window 240`) for a second pass.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt
```

## License

[MIT](LICENSE)
