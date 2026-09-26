# Auth Spray Watch

![Rust](https://img.shields.io/badge/Rust-1.82%2B-orange?logo=rust&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**Find password-spraying patterns in authentication logs.**

Auth Spray Watch looks across accounts and source IPs to surface suspicious login failures, including cases where a later successful login may indicate a compromised account.

## Quick start

Requires Rust 1.82 or newer.

```bash
cargo install --git https://github.com/httpEduardo/auth-spray-watch
auth-spray-watch --input auth.log
```

The tool can also read from standard input:

```bash
cat auth.log | auth-spray-watch --input -
```

## Log format

Provide one event per line, with fields separated by `|`:

```text
timestamp|ip|user|status
2026-01-14T12:00:01Z|10.0.0.5|alex|fail
```

Timestamps use RFC 3339. Status can be `success` or `fail`; blank lines and lines beginning with `#` are ignored.

## Alerts

- **Spray:** one IP fails against several accounts in a short period.
- **Distributed:** one account receives failures from several IPs.
- **Possible compromise:** a source associated with a spray later records a successful login.

Use `--window` and `--threshold` to adjust detection, or `--format json` for structured output. These alerts are indicators for investigation, not proof of compromise.

## License

[MIT](LICENSE)
