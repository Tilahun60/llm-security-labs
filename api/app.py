"""
api/app.py — LLM Security Labs: Flask API Gateway
===================================================
Thin proxy layer between the static frontend and the FastAPI llm-service.

Responsibilities:
  - Add CORS headers so the browser can call this API cross-origin.
  - Forward every request to the appropriate llm-service endpoint.
  - Validate route parameters before forwarding to avoid meaningless errors.

All business logic lives in llm-service/. This file contains no lab logic.
"""

import json
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Address of the llm-service inside the Docker Compose network.
LLM_SERVICE = "http://llm-service:8000"

# ---------------------------------------------------------------------------
# CORS — allow the static frontend (served by nginx) to call this API.
# ---------------------------------------------------------------------------

@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp


# ---------------------------------------------------------------------------
# Generic proxy helper
# ---------------------------------------------------------------------------

def _proxy(path: str, body: dict = None, timeout: int = 15):
    """
    Forward a POST to llm-service at `path`, passing `body` as JSON.
    The llm-service expects every request body to have a `text` field
    containing either a plain string or a JSON-encoded dict.
    """
    payload = body or {}
    text_payload = json.dumps(payload) if payload else ""
    resp = requests.post(
        f"{LLM_SERVICE}{path}",
        json={"text": text_payload},
        timeout=timeout,
    )
    return jsonify(resp.json())


def _options_or_proxy(path: str, body_key: str = "query", timeout: int = 15):
    """
    Handle OPTIONS pre-flight or forward the request body to llm-service.
    Most labs send a JSON body; body_key selects the primary field name
    used when the client sends a flat {key: value} payload.
    """
    if request.method == "OPTIONS":
        return ("", 204)
    body = request.json or {}
    return _proxy(path, body, timeout)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return jsonify({"message": "Welcome to LLM Security Labs API"})


# ---------------------------------------------------------------------------
# LLM01 — Prompt Injection
# ---------------------------------------------------------------------------

@app.route("/vulnerable/llm01", methods=["POST", "OPTIONS"])
def llm01_vulnerable():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm01/vulnerable", {"query": (request.json or {}).get("prompt", "")})

@app.route("/secure/llm01", methods=["POST", "OPTIONS"])
def llm01_secure():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm01/secure", {"query": (request.json or {}).get("prompt", "")})


# ---------------------------------------------------------------------------
# LLM02 — Insecure Output Handling
# ---------------------------------------------------------------------------

@app.route("/vulnerable/llm02", methods=["POST", "OPTIONS"])
def llm02_vulnerable():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm02/vulnerable", {"query": (request.json or {}).get("topic", "")})

@app.route("/secure/llm02", methods=["POST", "OPTIONS"])
def llm02_secure():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm02/secure", {"query": (request.json or {}).get("topic", "")})


# ---------------------------------------------------------------------------
# LLM03 — Training Data Poisoning
# ---------------------------------------------------------------------------

@app.route("/clean/llm03", methods=["POST", "OPTIONS"])
def llm03_clean():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm03/clean", {"query": (request.json or {}).get("query", "")})

@app.route("/poisoned/llm03", methods=["POST", "OPTIONS"])
def llm03_poisoned():
    if request.method == "OPTIONS": return ("", 204)
    return _proxy("/llm03/poisoned", {"query": (request.json or {}).get("query", "")})


# ---------------------------------------------------------------------------
# LLM04 — Vector DB Vulnerabilities
# ---------------------------------------------------------------------------

_LLM04_ATTACKS = {
    "data-leakage", "embedding-inversion", "poisoning",
    "acl-bypass", "dos", "membership-inference",
}
_LLM04_MITIGATIONS = {
    "1-access-control", "2-data-classification", "3-query-monitoring",
    "4-differential-privacy", "5-secure-kb-update", "6-robust-search", "7-security-audit",
}

@app.route("/llm04/<attack>/<mode>", methods=["POST", "OPTIONS"])
def llm04_proxy(attack, mode):
    if request.method == "OPTIONS": return ("", 204)
    if attack not in _LLM04_ATTACKS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown attack '{attack}' or mode '{mode}'"}), 400
    return _proxy(f"/llm04/{attack}/{mode}", request.json or {})

@app.route("/llm04/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm04_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM04_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm04/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM05 — Supply Chain Vulnerabilities
# ---------------------------------------------------------------------------

_LLM05_ATTACKS     = {"dependency", "model-backdoor", "plugin", "data-provenance", "api-compromise"}
_LLM05_MITIGATIONS = {
    "1-inventory", "2-dep-scan", "3-model-verify",
    "4-plugin-sandbox", "5-vendor-assessment", "6-secure-pipeline", "7-monitoring",
}

@app.route("/llm05/<attack>/<mode>", methods=["POST", "OPTIONS"])
def llm05_proxy(attack, mode):
    if request.method == "OPTIONS": return ("", 204)
    if attack not in _LLM05_ATTACKS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown attack '{attack}' or mode '{mode}'"}), 400
    return _proxy(f"/llm05/{attack}/{mode}", request.json or {})

@app.route("/llm05/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm05_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM05_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm05/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM06 — Sensitive Information Disclosure
# ---------------------------------------------------------------------------

_LLM06_ATTACKS     = {"training-extraction", "prompt-leakage", "connected-systems"}
_LLM06_MITIGATIONS = {
    "1-data-sanitization", "2-output-filter", "3-prompt-engineering",
    "4-access-control", "5-differential-privacy", "6-monitoring", "7-red-team",
}

@app.route("/llm06/<attack>/<mode>", methods=["POST", "OPTIONS"])
def llm06_proxy(attack, mode):
    if request.method == "OPTIONS": return ("", 204)
    if attack not in _LLM06_ATTACKS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown attack '{attack}' or mode '{mode}'"}), 400
    return _proxy(f"/llm06/{attack}/{mode}", request.json or {})

@app.route("/llm06/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm06_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM06_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm06/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM07 — Insecure Plugin Design
# ---------------------------------------------------------------------------

_LLM07_ATTACKS     = {"excessive-permissions", "sql-injection", "ssrf"}
_LLM07_MITIGATIONS = {
    "1-least-privilege", "2-auth", "3-input-validation",
    "4-data-handling", "5-sandboxing", "6-security-testing", "7-monitoring",
}

@app.route("/llm07/<attack>/<mode>", methods=["POST", "OPTIONS"])
def llm07_proxy(attack, mode):
    if request.method == "OPTIONS": return ("", 204)
    if attack not in _LLM07_ATTACKS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown attack '{attack}' or mode '{mode}'"}), 400
    return _proxy(f"/llm07/{attack}/{mode}", request.json or {})

@app.route("/llm07/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm07_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM07_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm07/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM08 — Excessive Agency
# ---------------------------------------------------------------------------

_LLM08_SCENARIOS   = {"email", "financial", "sysadmin"}
_LLM08_MITIGATIONS = {
    "1-least-agency", "2-confirmation", "3-logging",
    "4-tiered-agency", "5-guardrails", "6-human-in-loop", "7-user-education",
}

@app.route("/llm08/<scenario>/<mode>", methods=["POST", "OPTIONS"])
def llm08_proxy(scenario, mode):
    if request.method == "OPTIONS": return ("", 204)
    if scenario not in _LLM08_SCENARIOS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown scenario '{scenario}' or mode '{mode}'"}), 400
    return _proxy(f"/llm08/{scenario}/{mode}", request.json or {})

@app.route("/llm08/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm08_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM08_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm08/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM09 — Overreliance
# ---------------------------------------------------------------------------

_LLM09_SCENARIOS   = {"medical", "legal", "code-security"}
_LLM09_MITIGATIONS = {
    "1-disclaimers", "2-citations", "3-confidence-indicators",
    "4-verification-prompts", "5-alternative-viewpoints", "6-human-review", "7-user-agency",
}

@app.route("/llm09/<scenario>/<mode>", methods=["POST", "OPTIONS"])
def llm09_proxy(scenario, mode):
    if request.method == "OPTIONS": return ("", 204)
    if scenario not in _LLM09_SCENARIOS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown scenario '{scenario}' or mode '{mode}'"}), 400
    return _proxy(f"/llm09/{scenario}/{mode}", request.json or {})

@app.route("/llm09/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm09_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM09_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm09/mitigations/{mid}", request.json or {})


# ---------------------------------------------------------------------------
# LLM10 — Model Denial of Service
# ---------------------------------------------------------------------------

_LLM10_ATTACKS     = {"token-stuffing", "recursive-expansion", "infinite-loop", "context-flooding"}
_LLM10_MITIGATIONS = {
    "1-rate-limiting", "2-input-validation", "3-output-controls",
    "4-monitoring", "5-cost-control", "6-tiered-service", "7-circuit-breakers",
}

@app.route("/llm10/<attack>/<mode>", methods=["POST", "OPTIONS"])
def llm10_proxy(attack, mode):
    if request.method == "OPTIONS": return ("", 204)
    if attack not in _LLM10_ATTACKS or mode not in ("vulnerable", "secure"):
        return jsonify({"error": f"Unknown attack '{attack}' or mode '{mode}'"}), 400
    return _proxy(f"/llm10/{attack}/{mode}", request.json or {}, timeout=20)

@app.route("/llm10/mitigations/<mid>", methods=["POST", "OPTIONS"])
def llm10_mitigation(mid):
    if request.method == "OPTIONS": return ("", 204)
    if mid not in _LLM10_MITIGATIONS:
        return jsonify({"error": f"Unknown mitigation '{mid}'"}), 400
    return _proxy(f"/llm10/mitigations/{mid}", request.json or {}, timeout=20)


# ---------------------------------------------------------------------------
# Entry point (dev only — production uses gunicorn via Docker)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
