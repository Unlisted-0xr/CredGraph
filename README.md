# CredGraph 1.0

**Credential exposure investigation and correlation engine.**

CredGraph is built for authorized security research and incident response. It goes beyond "grep found a token" by correlating repeated credential fingerprints across files, repositories, authors, and Git history, then producing an exposure timeline and risk score.

## What it does

- scans local files/directories
- scans current contents of Git repositories
- inspects changed Git lines across history, including deleted lines
- recognizes several high-signal credential formats
- filters obvious placeholders
- fingerprints secrets with a database-local HMAC key
- never stores discovered plaintext credentials
- correlates the same credential across observations
- produces timelines and risk scores
- exports JSON and HTML investigation reports
- remains offline; it never tests credentials against external services

## Install

```powershell
python -m pip install -e .
```

Verify:

```powershell
credgraph --help
```

## Scan your own repository

```powershell
credgraph scan "C:\path\to\repo" --db case.db
```

For a faster current-tree-only scan:

```powershell
credgraph scan "C:\path\to\repo" --no-history --db case.db
```

Limit Git history:

```powershell
credgraph scan "C:\path\to\repo" --max-commits 1000 --db case.db
```

## Investigate

```powershell
credgraph findings --db case.db
credgraph clusters --db case.db
credgraph stats --db case.db
```

Use a fingerprint from `clusters`:

```powershell
credgraph timeline --db case.db --fingerprint YOUR_FINGERPRINT
```

## Reports

HTML:

```powershell
credgraph report --db case.db --format html --output report.html
```

JSON:

```powershell
credgraph report --db case.db --format json --output report.json
```

## Safe demonstration

The repository contains a synthetic dataset with non-functional values:

```powershell
credgraph scan .\examples\synthetic_case --db demo.db
credgraph findings --db demo.db
credgraph clusters --db demo.db
credgraph report --db demo.db --output demo.html
```

## Why the architecture matters

A normal secret scanner answers:

> "Does this file contain a suspicious string?"

CredGraph is designed to answer:

> "What evidence shows that the same credential appeared repeatedly, when did the exposure happen, and how broad is the observed exposure?"

## Security boundary

Only analyze repositories, files, and datasets you are authorized to access. CredGraph deliberately does **not** authenticate with discovered credentials, validate them against live providers, or perform account actions.

## Project structure

```text
credgraph/
├── credgraph/
│   ├── collectors.py
│   ├── detect.py
│   ├── fingerprint.py
│   ├── models.py
│   ├── report.py
│   ├── risk.py
│   ├── store.py
│   └── cli.py
├── examples/
├── tests/
└── docs/
```
##Educational Use
```text
CredGraph is intended for educational purposes, security research, and authorized testing only. Use it only on systems, repositories, and data you have permission to analyze.

The code is also thoroughly commented to make the implementation and underlying concepts easy to understand.
```
## License

MIT
