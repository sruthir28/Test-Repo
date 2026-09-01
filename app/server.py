"""Flask HTTP layer for the PII detector."""

from __future__ import annotations

from flask import Flask, jsonify, request, send_from_directory

from app.detectors import DETECTORS, MAX_TEXT_LENGTH, scan_text

STATIC_DIR = "../static"


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)

    @app.get("/")
    def index():
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:filename>")
    def static_files(filename: str):
        return send_from_directory(STATIC_DIR, filename)

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok"})

    @app.get("/api/detectors")
    def detectors():
        return jsonify(
            [
                {
                    "type": d.name,
                    "description": d.description,
                    "confidence": d.confidence,
                }
                for d in DETECTORS
            ]
        )

    @app.post("/api/scan")
    def scan():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or "text" not in payload:
            return jsonify({"error": "request body must be JSON with a 'text' field"}), 400

        text = payload["text"]
        if not isinstance(text, str):
            return jsonify({"error": "'text' must be a string"}), 400
        if len(text) > MAX_TEXT_LENGTH:
            return jsonify({"error": f"'text' exceeds {MAX_TEXT_LENGTH} characters"}), 413

        return jsonify(scan_text(text).as_dict())

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000)
