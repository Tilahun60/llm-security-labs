# Technical Learning Guide
## What You Need to Know to Understand This Project

This guide is for AI security engineers who want to read, modify, or extend this codebase. It covers every Python module, library, and security concept actually used in the project — nothing extra, nothing missing.

---

## The Big Picture First

Before diving into code, understand what each layer does:

```
Browser (index.html)
    ↓  HTTP on port 8080
nginx (serves the frontend)
    ↓
Flask API — api/app.py — port 5000
    ↓  forwards every request
FastAPI LLM Service — llm-service/ — port 8000
    ↓  (LLM04 only)
Qdrant Vector DB — port 6333
```

The browser never calls the LLM service directly. Flask sits in the middle as a gateway that validates routes and forwards requests. All the actual vulnerability logic lives in the FastAPI service, split into one Python module per lab.

---

## 1. Python Fundamentals

### Decorators

Decorators are how FastAPI and Flask register URL endpoints. You see them on every single function in the project.

```python
# This registers the function as the handler for POST /llm01/vulnerable
@router.post("/llm01/vulnerable")
def llm01_vulnerable(prompt: Prompt):
    return {"response": "..."}
```

If you don't understand that `@router.post(...)` is wrapping the function below it, you won't be able to read any lab code.

### Type Annotations

```python
def cosine_sim(a: list, b: list) -> float:
    ...

class Prompt(BaseModel):
    text: str   # FastAPI uses this to validate the incoming request body
```

Annotations tell FastAPI what types to expect and auto-generate validation errors if the wrong type arrives.

### Data Structures — dict, list, set

```python
# Sets — used in api/app.py to validate route parameters before forwarding
_LLM04_ATTACKS = {"data-leakage", "embedding-inversion", "poisoning", "acl-bypass", "dos"}

# Dicts — used everywhere for knowledge bases, registries, state
CLEAN_KNOWLEDGE = {
    "capital of france": "The capital of France is Paris.",
    "inventor of telephone": "Alexander Graham Bell invented the telephone in 1876.",
}

# List comprehension — filtering retrieved documents by sensitivity
leaked = [doc for doc in retrieved if doc["sensitivity"] != "public"]
```

### Exception Handling

Used in every lab endpoint because user input may be JSON or plain text.

```python
try:
    body = json.loads(prompt.text)   # try to parse as JSON
except Exception:
    body = {"query": prompt.text}    # fall back to treating it as a plain string
```

### F-strings and String Methods

```python
full_prompt = f"{SYSTEM_PROMPT}\n\nUser: {user_input}"
query_lower = query.lower()
text[:MAX_INPUT_CHARS]   # slicing to enforce length limits
```

---

## 2. The `re` Module — Regular Expressions

This is the most used module across the entire project. Nearly every security check is built on regex.

```python
import re
```

### Key Methods

| Method | What it does | Example in project |
|--------|-------------|-------------------|
| `re.search(pattern, text)` | Find pattern anywhere — returns match object or None | Injection detection |
| `re.sub(pattern, replacement, text)` | Replace all matches with replacement string | PII redaction |
| `re.match(pattern, text)` | Match only at the start of the string | Input allowlist validation |
| `re.IGNORECASE` | Make the pattern case-insensitive | All security checks |
| `re.DOTALL` | Make `.` match newlines too | Stripping multiline HTML tags |

### How It's Used in Each Lab

**LLM01 — Prompt Injection Detection**
```python
INJECTION_PATTERNS = [
    r"ignore\s+(all|your|the)?\s*(previous|prior)?\s*instructions",
    r"system\s+prompt",
    r"reveal",
    r"you\s+are\s+now",
]

def _is_injection(text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in INJECTION_PATTERNS)
```

**LLM02 — Stripping Dangerous HTML**
```python
# Remove onclick, onerror, onload event attributes
html = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)

# Remove script tags entirely
html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
```

**LLM06 — PII Redaction**
```python
text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[SSN REDACTED]', text)          # Social Security Number
text = re.sub(r'\b\d{4}-\d{4}-\d{4}-\d{4}\b', '[CARD REDACTED]', text)   # Credit card number
text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',  # Email address
              '[EMAIL REDACTED]', text)
```

**LLM07 — SQL Injection Detection**
```python
SQL_PATTERNS = [
    (r"OR\s+1\s*=\s*1",               "OR 1=1 tautology"),
    (r";\s*(DROP|DELETE|UPDATE)",      "destructive statement chaining"),
    (r"UNION\s+SELECT",               "UNION-based extraction"),
]

def detect_sql_injection(text: str) -> tuple:
    for pattern, label in SQL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, label
    return False, None
```

**LLM10 — DoS Pattern Detection**
```python
DOS_PATTERNS = [
    (r"for each .+ expand it into",           "recursive_expansion"),
    (r"continue this pattern indefinitely",   "infinite_loop"),
    (r"(.)\1{49,}",                           "character_stuffing"),  # 50+ repeated chars
]
```

### Regex Syntax You Need to Know

| Syntax | Meaning |
|--------|---------|
| `\s+` | One or more whitespace characters |
| `\b` | Word boundary (so `\bssn\b` matches "ssn" but not "assign") |
| `\d{3}` | Exactly 3 digits |
| `[A-Za-z0-9]` | Any alphanumeric character |
| `(a\|b)` | Match either a or b |
| `.*?` | Any characters, non-greedy (stops at first match) |
| `(?i)` or `re.IGNORECASE` | Case-insensitive |
| `^` | Start of string/line |
| `$` | End of string/line |

---

## 3. The `json` Module

Every request from the browser arrives as JSON. Every response goes back as JSON.

```python
import json

# Parsing — convert JSON string to Python dict
body = json.loads(prompt.text)

# Serialising — convert Python dict to JSON string
payload = json.dumps(body)

# In api/app.py — the gateway serialises the whole body before forwarding
text_payload = json.dumps(request.json or {})
```

The reason `prompt.text` needs to be parsed rather than arriving as a dict directly is that FastAPI receives the entire payload as `{"text": "<json string here>"}` — the inner content is a JSON string, not a nested object.

---

## 4. The `hashlib` Module — Integrity Verification

Used in LLM05 (supply chain) to demonstrate model file integrity checking.

```python
import hashlib

def verify_model_integrity(model_path: str, expected_hash: str) -> bool:
    sha256 = hashlib.sha256()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    actual_hash = sha256.hexdigest()
    return actual_hash == expected_hash
```

**Why this matters for security:** SHA-256 is a one-way cryptographic hash. If even one byte of the model file changes (tampering, corruption, supply chain attack), the hash changes completely. This lets you verify that what you downloaded is exactly what the provider signed.

The `hexdigest()` method returns the hash as a 64-character hex string like `abc123def456...`.

---

## 5. The `math` and `random` Modules — Embeddings and Privacy

### `math` — Cosine Similarity (LLM04)

Vector databases find relevant documents by measuring how similar two vectors are. The cosine similarity formula is used in `shared.py`.

```python
import math

def cosine_sim(a: list, b: list) -> float:
    dot       = sum(x * y for x, y in zip(a, b))
    magnitude = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(x * x for x in b))
    return dot / magnitude
```

Result is always between -1 and 1. Values close to 1 mean the vectors are pointing in the same direction — the documents are semantically similar.

### `random` — Differential Privacy (LLM04, LLM06)

Differential privacy works by adding calibrated random noise to query results. This prevents an attacker from inferring individual records from aggregate statistics.

```python
import random

epsilon    = 0.5           # privacy budget — lower = more privacy, more noise
noise_scale = 1.0 / epsilon
noisy_value = true_value + random.gauss(0, noise_scale * 0.04)
```

`random.gauss(mean, std_dev)` draws from a Gaussian (normal) distribution. The noise is random but bounded — high enough to obscure individual data points, low enough that aggregate results remain useful.

---

## 6. The `time` Module — Rate Limiting and Circuit Breakers

Used in LLM08 (confirmation timeouts) and LLM10 (DoS mitigations).

```python
import time

# Rate limiting — sliding window
now = time.time()                          # seconds since Unix epoch (float)
if now - state["rpm_window"] > 60:
    state["rpm_count"] = 0                 # reset the 1-minute window
    state["rpm_window"] = now

# Circuit breaker — abort if search takes too long
start = time.time()
for doc in large_corpus:
    if time.time() - start > 0.5:         # 500ms hard timeout
        timed_out = True
        break
    process(doc)

# Timestamp for audit logs
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
```

---

## 7. The `base64` Module — Encoding Simulation

Used in LLM07 (secure data handling) to simulate encryption-in-transit.

```python
import base64

# Encode data to simulate what an encrypted payload looks like
encoded = base64.b64encode(json.dumps(data).encode()).decode()
# encoded is now a string like "eyJ1c2VyIjogImpvaG4ifQ=="
```

Note: this is encoding, not encryption. Real encryption uses libraries like `cryptography`. The project uses `base64` purely to make the concept visible in a demo context.

---

## 8. FastAPI — The LLM Service

FastAPI is the Python web framework powering `llm-service/`. It handles all 111 lab endpoints.

### Application Setup

```python
from fastapi import FastAPI, APIRouter
from pydantic import BaseModel

app = FastAPI(title="LLM Security Labs")
```

### Request Body with Pydantic

```python
class Prompt(BaseModel):
    text: str
```

Pydantic automatically parses the incoming JSON body and validates types. If `text` is missing or not a string, FastAPI returns a 422 error before the function even runs.

### Routers — Keeping Labs Separate

Each lab uses `APIRouter` instead of registering directly on `app`. This keeps each lab self-contained.

```python
# In labs/llm01.py
router = APIRouter(prefix="/llm01", tags=["LLM01 - Prompt Injection"])

@router.post("/vulnerable")
def llm01_vulnerable(prompt: Prompt):
    ...

# In main.py — one line to register the whole lab
app.include_router(llm01_router)
```

The `prefix="/llm01"` means `@router.post("/vulnerable")` becomes `POST /llm01/vulnerable` automatically.

### Auto-Generated Docs

Once running, FastAPI generates interactive API documentation automatically:
- `http://localhost:8000/docs` — Swagger UI, try endpoints in the browser
- `http://localhost:8000/redoc` — alternative documentation view

This is useful for testing lab endpoints directly without the frontend.

---

## 9. Flask — The API Gateway

Flask is the framework for `api/app.py`. It's a lighter-weight framework than FastAPI and is used here purely as a proxy — it receives browser requests, validates them, and forwards them to FastAPI.

```python
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/llm01/<mode>", methods=["POST", "OPTIONS"])
def llm01_proxy(mode):
    if request.method == "OPTIONS":
        return ("", 204)              # browser pre-flight check

    body = request.json or {}         # read the POST body as a dict
    resp = requests.post(             # forward to FastAPI
        f"http://llm-service:8000/llm01/{mode}",
        json={"text": json.dumps(body)},
        timeout=15,
    )
    return jsonify(resp.json())       # send FastAPI's response back to the browser
```

**Why Flask here instead of FastAPI?** Flask starts faster and has less overhead for a simple proxy. The project uses the right tool for each job.

### CORS Headers

Browsers block cross-origin requests unless the server adds CORS headers. The `@app.after_request` hook adds them to every response automatically.

```python
@app.after_request
def add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]  = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp
```

---

## 10. The `requests` Library — HTTP Between Services

Used in `api/app.py` to call FastAPI from Flask. This is a third-party library (installed via pip, listed in `requirements.txt`).

```python
import requests

response = requests.post(
    "http://llm-service:8000/llm01/vulnerable",
    json={"text": payload},
    timeout=15,             # never wait more than 15 seconds
)
data = response.json()      # parse the JSON response body
```

Note: `http://llm-service:8000` works because Docker Compose puts all services on the same network and lets them reach each other by service name — not by `localhost`.

---

## 11. Pydantic — Data Validation

Pydantic is FastAPI's validation layer. Every request body in this project is a `Prompt` object defined in `shared.py`.

```python
from pydantic import BaseModel

class Prompt(BaseModel):
    text: str
```

When FastAPI receives `{"text": "hello"}`, it automatically creates a `Prompt(text="hello")` object. If the body is missing `text`, or it's not a string, FastAPI rejects the request with a clear error before your code runs.

---

## 12. Uvicorn — ASGI Server

Uvicorn is what actually runs the FastAPI application. You don't write code against it directly, but you need to know the startup command.

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

- `main` — the Python file (`main.py`)
- `app` — the FastAPI instance inside that file
- `--reload` — restart automatically when code changes (development only)

---

## 13. Docker and Docker Compose

The project runs in containers. You need to understand these concepts to run, debug, and modify it.

### Key Docker Compose Concepts

**Service names as hostnames.** When Flask calls `http://llm-service:8000`, it works because Docker Compose creates a shared network where every service is reachable by its name. `localhost` would not work here.

**Volumes.** The `volumes:` section mounts your local directory into the container. This means code changes take effect without rebuilding the image.

**Ports.** `"8080:80"` maps port 8080 on your machine to port 80 inside the container. You access `localhost:8080`, the container sees port 80.

### Commands You'll Use

```bash
# Start everything (rebuild images if code changed)
docker compose up --build

# Stop everything
docker compose down

# See logs from a specific service
docker compose logs llm-service -f

# Rebuild and restart one service only
docker compose up --build llm-service

# Run a command inside a running container
docker compose exec llm-service bash
```

---

## 14. Security Concepts Behind the Code

Understanding the code is one thing. Understanding *why* each pattern is dangerous requires knowing these concepts.

### Prompt Injection (LLM01)
When user input is concatenated directly into a system prompt, the model treats both with equal trust. An attacker can insert instructions that override the original ones. The fix is to clearly separate trusted instructions from untrusted input — using delimiters like `<USER_INPUT>` tags — and filter both input and output.

### Cross-Site Scripting / XSS (LLM02)
`element.innerHTML = untrustedHTML` tells the browser to parse and execute any JavaScript inside the string. If an LLM generates `<script>alert(1)</script>` and it's rendered directly, the script runs. The fix is to sanitise HTML output — strip script tags and event attributes — before rendering.

### SQL Injection (LLM07)
Building SQL by string concatenation (`f"WHERE id='{user_input}'"`) lets an attacker inject SQL keywords. Typing `' OR 1=1 --` as the input turns a specific lookup into "return everything". The fix is parameterised queries where user input is bound as data, never interpolated as code.

### SSRF — Server-Side Request Forgery (LLM07)
When a server fetches a URL controlled by the user, an attacker can point it at internal services that aren't exposed to the public internet — admin panels, cloud metadata APIs, internal databases. The fix is an allowlist of permitted URL schemes and hosts.

### Supply Chain Attacks (LLM05)
If a dependency, model, or dataset is compromised before it reaches you, every application using it is affected. Defences include hash verification (confirm a file matches its expected SHA-256 before loading), dependency scanning (check packages against CVE databases), and private registries.

### PII Leakage (LLM06)
Models trained on data containing personal information can regurgitate it in responses, especially when prompted with partial matches. Defences include sanitising training data before ingestion, filtering model outputs with PII detection patterns, and access control on who can query what.

### Excessive Agency (LLM08)
An LLM that can take real-world actions (send emails, make payments, modify systems) can cause serious harm if it acts on vague, misinterpreted, or maliciously crafted instructions. The principle of least agency means granting only the minimum permissions needed, requiring explicit human confirmation for consequential actions, and never letting a CRITICAL-risk action execute autonomously.

### Overreliance (LLM09)
LLMs produce confident-sounding output that can be completely wrong — fabricated case citations, incorrect medication dosages, broken security code. Without disclaimers, confidence indicators, and verification guidance, users treat AI output as authoritative. Secure design makes limitations visible and actively discourages blind trust.

### Model Denial of Service (LLM10)
LLM inference is computationally expensive. Unbounded inputs, recursive prompts, or counter tasks that grow quadratically can exhaust resources and inflate costs. Defences are layered: input length caps, token estimation, rate limiting per user, output token limits, expansion ratio circuit breakers, and per-tier service limits.

### Differential Privacy
Querying aggregate statistics can leak individual records. If the average salary of a department drops by exactly $50K when one person joins, you've inferred their salary. Differential privacy adds calibrated Gaussian or Laplace noise to results, making individual inference computationally infeasible while keeping aggregate results statistically useful. The privacy budget `epsilon` controls the tradeoff — smaller epsilon means more noise, stronger privacy.

### Hash Integrity
SHA-256 produces a fixed 64-character fingerprint of any file. If even one byte changes, the hash changes completely. This makes it a reliable way to verify that a model file, dataset, or software package is exactly what the trusted source signed — detecting tampering, corruption, or substitution attacks.

---

## Learning Path

If you're building up from scratch, this sequence works well:

1. **Python basics** — functions, dicts, lists, f-strings, try/except, list comprehensions
2. **`re` module** — `search`, `sub`, `match`, `IGNORECASE` — foundational for all security checks here
3. **`json`** — `loads` and `dumps` — every request and response uses these
4. **FastAPI** — `BaseModel`, `APIRouter`, `@router.post`, `app.include_router`
5. **Flask** — `@app.route`, `request.json`, `jsonify`, `after_request`
6. **`requests`** — making HTTP calls between services
7. **`hashlib`, `math`, `random`, `time`** — used for specific security features
8. **Docker Compose** — service networking, volumes, ports, startup commands
9. **Security concepts** — the table above — the "why" behind all the code choices

---

## Quick Reference — What's in Each File

| File | Purpose | Key Python used |
|------|---------|----------------|
| `llm-service/main.py` | FastAPI app entry point, registers all routers | FastAPI, `include_router` |
| `llm-service/labs/shared.py` | Shared utilities: Prompt model, PII redaction, embeddings, SQL/SSRF detection | `re`, `math`, `json`, Pydantic |
| `llm-service/labs/llm01.py` | Prompt injection | `re.search`, `re.sub` |
| `llm-service/labs/llm02.py` | Insecure output handling | `re.sub`, `re.DOTALL` |
| `llm-service/labs/llm03.py` | Training data poisoning | `dict` lookups |
| `llm-service/labs/llm04.py` | Vector DB vulnerabilities | `math`, `random`, `re`, `time`, `hashlib` |
| `llm-service/labs/llm05.py` | Supply chain | `hashlib`, `re`, `json`, `base64` |
| `llm-service/labs/llm06.py` | Sensitive information disclosure | `re`, `json`, `random`, `math`, `time` |
| `llm-service/labs/llm07.py` | Insecure plugin design | `re`, `json`, `time` |
| `llm-service/labs/llm08.py` | Excessive agency | `re`, `json`, `time` |
| `llm-service/labs/llm09.py` | Overreliance | `re`, `json`, `time` |
| `llm-service/labs/llm10.py` | Model denial of service | `re`, `math`, `random`, `time`, `json` |
| `api/app.py` | Flask gateway proxy | Flask, `requests`, `json` |
| `frontend/index.html` | Browser UI — all 10 lab panels | JavaScript, Fetch API |
