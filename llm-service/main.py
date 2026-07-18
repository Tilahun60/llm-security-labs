"""
main.py — LLM Security Labs: FastAPI entry point
=================================================
Registers one router per OWASP LLM Top 10 lab.
Each lab lives in its own module under labs/ — keeping concerns separated
and making it easy to add, modify, or disable individual labs.

Run with:
    uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI

from labs.llm01 import router as llm01_router
from labs.llm02 import router as llm02_router
from labs.llm03 import router as llm03_router
from labs.llm04 import router as llm04_router
from labs.llm05 import router as llm05_router
from labs.llm06 import router as llm06_router
from labs.llm07 import router as llm07_router
from labs.llm08 import router as llm08_router
from labs.llm09 import router as llm09_router
from labs.llm10 import router as llm10_router

app = FastAPI(
    title="LLM Security Labs",
    description=(
        "Interactive playground for the OWASP Top 10 for LLM Applications. "
        "Each lab demonstrates a specific vulnerability and its mitigation."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# Register lab routers
# Each router owns its own prefix (/llm01, /llm02, …)
# ---------------------------------------------------------------------------
app.include_router(llm01_router)
app.include_router(llm02_router)
app.include_router(llm03_router)
app.include_router(llm04_router)
app.include_router(llm05_router)
app.include_router(llm06_router)
app.include_router(llm07_router)
app.include_router(llm08_router)
app.include_router(llm09_router)
app.include_router(llm10_router)


# ---------------------------------------------------------------------------
# Root health check
# ---------------------------------------------------------------------------
@app.get("/", tags=["Health"])
def root():
    return {
        "service": "LLM Security Labs",
        "status": "running",
        "labs": [f"LLM0{i}" if i < 10 else "LLM10" for i in range(1, 11)],
    }


@app.post("/generate", tags=["Health"])
def generate(prompt: dict):
    """Legacy endpoint kept for backwards compatibility with the frontend."""
    from labs.llm01 import _simulate_model
    return {"generated_text": _simulate_model(prompt.get("text", ""))}
