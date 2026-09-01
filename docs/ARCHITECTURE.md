# CredGraph 1.0 architecture

CredGraph is an offline evidence engine. It intentionally does not validate credentials against live services or attempt authentication.

## Pipeline

1. **Collectors** — local files and Git repositories.
2. **Historical evidence** — current files plus changed Git lines across history.
3. **Detectors** — high-signal formats and conservative assignment patterns.
4. **Fingerprinting** — database-local HMAC fingerprints; plaintext secret values are not persisted.
5. **Correlation** — identical fingerprints form exposure clusters.
6. **Risk scoring** — confidence, recurrence, repositories, authors, and secret class.
7. **Reporting** — CLI, JSON, and self-contained HTML.

## Design goals

- Evidence before conclusions.
- Repeatable scans and deduplication.
- Historical exposure detection, including removed lines.
- Privacy-safe storage by default.
- Useful output for authorized research and incident response.
