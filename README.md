# PII Detector

A small web app that checks whether pasted text contains personally
identifiable information (PII). Detection is local regex + checksum logic — no
external service is called and no input is stored.

Full SDLC walkthrough (requirements, design, testing, deployment): [docs/SDLC.md](docs/SDLC.md).

## Detected types

`EMAIL`, `SSN`, `CREDIT_CARD` (Luhn-validated), `IBAN`, `PHONE` (US), `IPV4`,
`IPV6`, `US_PASSPORT`, `DATE_OF_BIRTH`.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.server        # http://localhost:5000
```

## API

```bash
curl -s localhost:5000/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"text": "call 415-555-0199 or mail jane@example.com"}'
```

```json
{
  "has_pii": true,
  "count": 2,
  "findings": [
    {"type": "PHONE", "value": "415-555-0199", "start": 5, "end": 17, "confidence": "medium"},
    {"type": "EMAIL", "value": "jane@example.com", "start": 26, "end": 42, "confidence": "high"}
  ],
  "redacted_text": "call [PHONE] or mail [EMAIL]"
}
```

`GET /api/detectors` lists supported types; `GET /healthz` is a liveness probe.

## Tests

```bash
pytest -q
```

## Project layout

```
app/detectors.py   detection engine (no web dependencies)
app/server.py      Flask API + static hosting
static/            single-page UI
tests/             unit + API tests
docs/SDLC.md       requirements, design, testing, deployment notes
```

Limitations: heuristics only — it will not catch names, street addresses, or
free-form identifiers, and low-confidence types (passport, date of birth) can
produce false positives. Treat it as a first-pass screen, not a guarantee.
