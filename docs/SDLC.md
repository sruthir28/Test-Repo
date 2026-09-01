# PII Detector — SDLC Walkthrough

This document records each phase of the software development lifecycle for the
PII Detector web application.

## 1. Requirements

**Problem.** Users need a quick way to check whether a block of free text
contains personally identifiable information (PII) before sharing it (logs,
support tickets, prompts sent to third-party services).

**Functional requirements**

| ID | Requirement |
| --- | --- |
| FR-1 | User can paste arbitrary text into a web page and submit it for scanning. |
| FR-2 | System detects email addresses, US phone numbers, US SSNs, credit card numbers, IPv4/IPv6 addresses, dates of birth, US passport numbers, and IBANs. |
| FR-3 | Each finding reports its type, matched value, character offsets, and a confidence level. |
| FR-4 | System returns a redacted copy of the input with every finding masked. |
| FR-5 | A JSON HTTP API (`POST /api/scan`) exposes the same capability for programmatic use. |
| FR-6 | Credit card candidates are validated with the Luhn checksum to suppress false positives. |

**Non-functional requirements**

- NFR-1 Privacy: input text is never persisted or logged; scanning happens in-process.
- NFR-2 No third-party PII/ML service — pure local regex + checksum logic, no network egress.
- NFR-3 Simplicity: single Flask process, no database, no build step for the frontend.
- NFR-4 Scans of documents up to 100 KB complete in well under a second.

**Out of scope.** Authentication, persistence, non-US identifier formats beyond
IBAN, named-entity recognition for person/address names.

## 2. Design

```
browser (static/index.html + app.js)
        │  POST /api/scan  {"text": "..."}
        ▼
Flask app (app/server.py)   ── thin HTTP layer, no business logic
        │  scan_text(text)
        ▼
Detection engine (app/detectors.py)
        │  DETECTORS: list[Detector(name, pattern, confidence, validator)]
        ▼
   ScanResult(findings=[Finding...], redacted_text=str)
```

Key decisions:

- **Layering.** All detection logic lives in `app/detectors.py` with zero Flask
  imports, so it is unit-testable and reusable as a library/CLI.
- **Detector as data.** Each PII type is a `Detector` dataclass entry in a single
  list; adding a type is one entry, not new branching code.
- **Validators.** A detector may attach a predicate (e.g. Luhn for credit cards,
  SSN structural rules) that rejects regex matches which are not really PII.
- **Overlap resolution.** Matches are sorted by start offset and, on overlap, the
  longer/earlier match wins — this prevents an SSN also being reported as a phone
  number fragment.
- **Redaction.** Applied right-to-left over resolved findings so offsets stay valid.

## 3. Implementation

- `app/detectors.py` — detection engine (`Finding`, `Detector`, `scan_text`).
- `app/server.py` — Flask app, `POST /api/scan`, `GET /healthz`, static hosting.
- `static/index.html`, `static/app.js`, `static/styles.css` — single-page UI.
- `requirements.txt` — Flask, pytest.

## 4. Testing

`tests/test_detectors.py` and `tests/test_server.py` cover: one positive case per
PII type, Luhn rejection of invalid card numbers, clean text producing no
findings, overlap resolution, redaction correctness, and API contract/validation
errors (missing body, non-string `text`, oversized input).

Run: `pytest -q`

## 5. Deployment

`python -m app.server` serves on `http://localhost:5000` (development server).
For production, front it with a WSGI server: `gunicorn 'app.server:create_app()'`.

## 6. Maintenance

To add a PII type: append a `Detector(...)` to `DETECTORS` in `app/detectors.py`
and add a positive and a negative test. Regex patterns are the only place that
needs to change for format drift.
