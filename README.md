# LLM Security Labs

A hands-on learning playground for the **OWASP Top 10 for Large Language Model Applications**. Every vulnerability from LLM01 to LLM10 has its own interactive lab where you can trigger the attack and immediately compare it against the secure version — all in your browser, all running locally.

No real AI model is used. The behaviours are simulated so the labs work offline, stay fast, and are safe to experiment with.

---

## What You Can Learn

Each lab covers one vulnerability. You pick an attack type, type a query, and click **Vulnerable** or **Secure** to see what happens side by side.

| Lab | Vulnerability | What You'll See |
|-----|--------------|-----------------|
| LLM01 | Prompt Injection | A secret API key leaking when you inject "ignore your instructions" |
| LLM02 | Insecure Output Handling | JavaScript executing in the browser from LLM-generated HTML |
| LLM03 | Training Data Poisoning | A model giving wrong facts and triggering hidden backdoor responses |
| LLM04 | Vector DB Vulnerabilities | Confidential documents leaking through semantic search, SQL-like attacks on a RAG system |
| LLM05 | Supply Chain Vulnerabilities | Typosquatted packages stealing credentials, backdoored models, malicious plugins exfiltrating data |
| LLM06 | Sensitive Information Disclosure | PII and system prompts leaking through completion tricks and indirect queries |
| LLM07 | Insecure Plugin Design | SQL injection through a DB plugin, SSRF through a web searcher, command execution via excessive permissions |
| LLM08 | Excessive Agency | An AI assistant sending emails, paying bills, or deleting server files without asking |
| LLM09 | Overreliance | Medical, legal, and security code advice that sounds confident but is dangerously wrong |
| LLM10 | Model Denial of Service | Token stuffing, recursive expansion, and context flooding exhausting compute resources |

Each lab also has a **Mitigations panel** with 7 defensive techniques you can run interactively.

---

## How to Run It

You need Docker installed. That's it.

```bash
git clone <your-repo-url>
cd llm-security-labs
docker compose up --build
```

Then open your browser at **http://localhost:8080**

Click any lab card on the dashboard to get started.

---

## Project Structure

```
llm-security-labs/
│
├── frontend/               Static HTML/CSS/JS — the browser UI
│   └── index.html          Single page with all 10 lab panels
│
├── api/                    Flask gateway (Python)
│   └── app.py              Thin proxy — routes browser requests to the LLM service
│
├── llm-service/            FastAPI service (Python) — all the lab logic lives here
│   ├── main.py             Registers all lab routers, runs on port 8000
│   ├── labs/
│   │   ├── shared.py       Shared utilities used across labs
│   │   ├── llm01.py        Prompt Injection
│   │   ├── llm02.py        Insecure Output Handling
│   │   ├── llm03.py        Training Data Poisoning
│   │   ├── llm04.py        Vector DB Vulnerabilities
│   │   ├── llm05.py        Supply Chain
│   │   ├── llm06.py        Sensitive Information Disclosure
│   │   ├── llm07.py        Insecure Plugin Design
│   │   ├── llm08.py        Excessive Agency
│   │   ├── llm09.py        Overreliance
│   │   └── llm10.py        Model Denial of Service
│
└── docker-compose.yml      Wires everything together
```

The browser talks to the Flask API (port 5000), which forwards requests to the FastAPI LLM service (port 8000). A Qdrant vector database (port 6333) is included for the LLM04 RAG demonstrations.

---

## How Each Lab Is Built

Every lab follows the same pattern:

- **Vulnerable endpoint** — shows the attack working, with real consequences explained
- **Secure endpoint** — applies the mitigation and shows what was blocked and why
- **7 Mitigation strategies** — interactive demos of each defensive technique from the OWASP guidance

There is no real LLM. The service simulates model responses just enough to demonstrate each vulnerability clearly. This means the labs work without an API key, without GPU, and without an internet connection.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Plain HTML, CSS, JavaScript — no framework |
| API Gateway | Python / Flask |
| LLM Service | Python / FastAPI |
| Vector DB | Qdrant |
| Container | Docker + Docker Compose |

---

## Prerequisites

- Docker Desktop (Mac / Windows) or Docker Engine (Linux)
- A browser

No Python installation needed — everything runs inside containers.

---

## Useful Commands

```bash
# Start everything
docker compose up --build

# Stop everything
docker compose down

# View logs from the LLM service
docker compose logs llm-service -f

# Rebuild after code changes
docker compose up --build llm-service
```

---

## Based On

[OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — the definitive reference for LLM security risks.
