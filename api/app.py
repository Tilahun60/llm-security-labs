from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Within the docker-compose network, the LLM service is reachable by name.
LLM_SERVICE = "http://llm-service:8000"


@app.after_request
def add_cors_headers(resp):
    # The static frontend (http://localhost:8080) calls this API cross-origin.
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp


@app.route('/')
def index():
    return jsonify({"message": "Welcome to LLM Security Labs API"})


# ---- LLM01: Prompt Injection ---------------------------------------------
@app.route('/vulnerable/llm01', methods=['POST', 'OPTIONS'])
def llm01_vulnerable():
    if request.method == 'OPTIONS':
        return ('', 204)
    user_input = (request.json or {}).get('prompt', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm01/vulnerable",
        json={"text": user_input},
        timeout=10,
    )
    return jsonify(r.json())


@app.route('/secure/llm01', methods=['POST', 'OPTIONS'])
def llm01_secure():
    if request.method == 'OPTIONS':
        return ('', 204)
    user_input = (request.json or {}).get('prompt', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm01/secure",
        json={"text": user_input},
        timeout=10,
    )
    return jsonify(r.json())


# ---- LLM02: INSECURE OUTPUT HANDLING ----------------------------------
@app.route('/vulnerable/llm02', methods=['POST', 'OPTIONS'])
def llm02_vulnerable():
    if request.method == 'OPTIONS':
        return ('', 204)
    topic = (request.json or {}).get('topic', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm02/vulnerable",
        json={"text": topic},
        timeout=10,
    )
    return jsonify(r.json())


@app.route('/secure/llm02', methods=['POST', 'OPTIONS'])
def llm02_secure():
    if request.method == 'OPTIONS':
        return ('', 204)
    topic = (request.json or {}).get('topic', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm02/secure",
        json={"text": topic},
        timeout=10,
    )
    return jsonify(r.json())


# ---- LLM03: TRAINING DATA POISONING ----------------------------------
@app.route('/clean/llm03', methods=['POST', 'OPTIONS'])
def llm03_clean():
    if request.method == 'OPTIONS':
        return ('', 204)
    query = (request.json or {}).get('query', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm03/clean",
        json={"text": query},
        timeout=10,
    )
    return jsonify(r.json())


@app.route('/poisoned/llm03', methods=['POST', 'OPTIONS'])
def llm03_poisoned():
    if request.method == 'OPTIONS':
        return ('', 204)
    query = (request.json or {}).get('query', '')
    r = requests.post(
        f"{LLM_SERVICE}/llm03/poisoned",
        json={"text": query},
        timeout=10,
    )
    return jsonify(r.json())

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
