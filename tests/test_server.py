import pytest

from app.detectors import MAX_TEXT_LENGTH
from app.server import create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def test_healthz(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_index_serves_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PII Detector" in response.data


def test_scan_returns_findings(client):
    response = client.post("/api/scan", json={"text": "reach me at jane@example.com"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["has_pii"] is True
    assert body["count"] == 1
    assert body["findings"][0]["type"] == "EMAIL"
    assert body["redacted_text"] == "reach me at [EMAIL]"


def test_scan_clean_text(client):
    body = client.post("/api/scan", json={"text": "nothing sensitive here"}).get_json()
    assert body["has_pii"] is False
    assert body["findings"] == []


def test_scan_requires_text_field(client):
    assert client.post("/api/scan", json={}).status_code == 400


def test_scan_rejects_non_string_text(client):
    assert client.post("/api/scan", json={"text": 42}).status_code == 400


def test_scan_rejects_oversized_text(client):
    response = client.post("/api/scan", json={"text": "x" * (MAX_TEXT_LENGTH + 1)})
    assert response.status_code == 413


def test_detectors_endpoint_lists_types(client):
    body = client.get("/api/detectors").get_json()
    assert {"EMAIL", "SSN", "CREDIT_CARD"} <= {d["type"] for d in body}
