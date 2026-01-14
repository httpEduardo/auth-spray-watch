# Auth Spray Watch

Auth Spray Watch detects password-spray behavior in auth logs.

## Quick start

```bash
cargo run -- --input auth.log --window 15 --threshold 3
```

## Log format

Each line: `timestamp|ip|user|status` (status = success|fail).

## Output

- IPs with many distinct user failures in a short window.
- Users targeted by multiple IPs.
