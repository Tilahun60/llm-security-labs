"""
llm10.py - LLM10: Model Denial of Service

Demonstrates 4 attack types:
  1. Token Stuffing
  2. Recursive Expansion
  3. Infinite Loop Induction
  4. Context Window Flooding

Plus 7 mitigation strategies.
"""

import re
import time
import json
import random
import math

from fastapi import APIRouter
from .shared import Prompt, parse_body

router = APIRouter(prefix="/llm10", tags=["LLM10 - Model Denial of Service"])


# ---------------------------------------------------------------------------
# Data constants
# ---------------------------------------------------------------------------

TIER_LIMITS = {
    "free":       {"rpm": 5,   "daily": 50,    "tpm": 5000,   "max_tokens": 500,  "priority": 0, "shed_at": 0.70},
    "basic":      {"rpm": 10,  "daily": 200,   "tpm": 10000,  "max_tokens": 1000, "priority": 1, "shed_at": 0.80},
    "premium":    {"rpm": 30,  "daily": 1000,  "tpm": 30000,  "max_tokens": 4000, "priority": 2, "shed_at": 0.90},
    "enterprise": {"rpm": 100, "daily": 10000, "tpm": 100000, "max_tokens": 8000, "priority": 3, "shed_at": 0.95},
}

DOS_PATTERNS = [
    (r"for each .+ expand it into",           "recursive_expansion"),
    (r"continue this pattern indefinitely",   "infinite_loop"),
    (r"repeat the (above|previous|following)", "repetition_loop"),
    (r"increment.{0,30}by \d+.{0,30}show all previous", "counter_loop"),
    (r"write \d{3,} (words|sentences|paragraphs)", "size_explosion"),
    (r"(.)\1{49,}",                           "character_stuffing"),
]

_USER_USAGE: dict = {}
_REQUEST_LOG: list = []
_CIRCUIT_BREAKER_TRIPS: list = []

_SYSTEM_LOAD = 0.55
MAX_INPUT_CHARS  = 4000
MAX_INPUT_TOKENS = 1000
MAX_OUTPUT_TOKENS_DEFAULT = 500
TOKENS_PER_CHAR  = 0.25


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_user_state(user_id: str) -> dict:
    """Return or create per-user usage state, resetting expired windows."""
    now = time.time()
    if user_id not in _USER_USAGE:
        _USER_USAGE[user_id] = {
            "rpm_count": 0, "rpm_window": now,
            "tpm_count": 0, "tpm_window": now,
            "daily_count": 0, "daily_window": now,
            "total_tokens": 0, "tier": "free", "budget_spent": 0.0,
        }
    state = _USER_USAGE[user_id]
    if now - state["rpm_window"] > 60:
        state["rpm_count"] = 0; state["rpm_window"] = now
        state["tpm_count"] = 0; state["tpm_window"] = now
    if now - state["daily_window"] > 86400:
        state["daily_count"] = 0; state["daily_window"] = now
    return state


def _estimate_tokens(text: str) -> int:
    """Rough token count estimate from character count."""
    return max(1, int(len(text) * TOKENS_PER_CHAR))


def _calc_repetition(text: str) -> float:
    """Returns 0.0 (unique) to 1.0 (fully repetitive)."""
    if len(text) < 20:
        return 0.0
    words = text.lower().split()
    if not words:
        return 0.0
    unique = len(set(words))
    return round(1.0 - (unique / len(words)), 3)


def _detect_dos_pattern(text: str) -> tuple:
    """Returns (is_dos: bool, pattern_type: str | None)."""
    for pattern, label in DOS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True, label
    return False, None


def _simulate_llm_response(prompt: str, max_tokens: int, scenario: str = "normal") -> dict:
    """Simulate LLM inference with timing and token tracking."""
    input_tokens = _estimate_tokens(prompt)
    if scenario == "token_stuffing":
        output_tokens = min(max_tokens, 50)
        elapsed = round(min(10.0, input_tokens / 200), 3)
    elif scenario == "recursive_expansion":
        output_tokens = min(max_tokens, input_tokens * 8)
        elapsed = round(min(15.0, output_tokens / 100), 3)
    elif scenario == "infinite_loop":
        output_tokens = min(max_tokens, 800)
        elapsed = round(min(12.0, output_tokens / 80), 3)
    elif scenario == "context_flooding":
        output_tokens = min(max_tokens, 30)
        elapsed = round(min(8.0, input_tokens / 150), 3)
    else:
        output_tokens = min(max_tokens, max(10, int(len(prompt.split()) * 1.5)))
        elapsed = round(max(0.1, output_tokens / 500), 3)

    time.sleep(min(elapsed * 0.01, 0.05))
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "simulated_elapsed_seconds": elapsed,
        "cost_usd": round((input_tokens + output_tokens) * 0.000002, 6),
    }


# ---
# Attack endpoints
# ---

@router.post("/token-stuffing/vulnerable")
def llm10_token_stuffing_vulnerable(prompt: Prompt):
    """Vulnerable: accepts any-length input, no token cap, no rate limit."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)
    user_id    = body.get("user_id", "attacker")

    baseline = _simulate_llm_response("What is the capital of France?", 500)
    stuffed_input = user_input + (" Lorem ipsum dolor sit amet." * 200)
    attack_result = _simulate_llm_response(stuffed_input, 4000, scenario="token_stuffing")

    _REQUEST_LOG.append({"user_id": user_id, "attack": "token_stuffing", "mode": "vulnerable",
                          "input_tokens": attack_result["input_tokens"], "blocked": False})

    return {
        "attack": "Token Stuffing", "mode": "vulnerable",
        "description": "Attacker sends massive input -- no validation, no limits. One request can consume tokens equivalent to thousands of normal requests.",
        "baseline_normal_request": baseline,
        "attack_request": {"input_length_chars": len(stuffed_input), **attack_result},
        "token_ratio": round(attack_result["total_tokens"] / max(1, baseline["total_tokens"]), 1),
        "cost_ratio": round(attack_result["cost_usd"] / max(0.000001, baseline["cost_usd"]), 1),
        "consequences": [
            f"Single request consumed {attack_result['total_tokens']}x tokens vs baseline {baseline['total_tokens']}",
            f"API cost: ${attack_result['cost_usd']:.6f} vs baseline ${baseline['cost_usd']:.6f}",
            "No rate limit -- attacker can repeat this thousands of times per hour",
            "Shared infrastructure degraded for all users",
        ],
        "note": "WARNING: No input length validation, no token cap, no rate limiting.",
    }


@router.post("/token-stuffing/secure")
def llm10_token_stuffing_secure(prompt: Prompt):
    """Secure: input length capped, tokens counted, rate limit checked before inference."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)
    user_id    = body.get("user_id", "user_demo")
    tier       = body.get("tier", "free")

    state  = _get_user_state(user_id)
    state["tier"] = tier
    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    mitigations = []

    if len(user_input) > MAX_INPUT_CHARS:
        mitigations.append(f"INPUT_LENGTH_CAP -- truncated {len(user_input)} -> {MAX_INPUT_CHARS} chars")
        user_input = user_input[:MAX_INPUT_CHARS]

    est_tokens = _estimate_tokens(user_input)
    if est_tokens > limits["max_tokens"]:
        mitigations.append(f"TOKEN_CAP -- estimated {est_tokens} tokens exceeds tier limit {limits['max_tokens']}")
        _REQUEST_LOG.append({"user_id": user_id, "attack": "token_stuffing", "mode": "secure", "blocked": True})
        return {
            "attack": "Token Stuffing", "mode": "secure",
            "mitigation": "Input length cap + per-tier token limit + rate limiting",
            "mitigations_applied": mitigations,
            "estimated_input_tokens": est_tokens,
            "tier_token_limit": limits["max_tokens"],
            "result": "REQUEST REJECTED -- input too large for tier",
            "note": f"OK: Blocked before inference. Upgrade to higher tier for larger inputs.",
        }

    state["rpm_count"] += 1
    state["tpm_count"] += est_tokens
    if state["rpm_count"] > limits["rpm"]:
        mitigations.append(f"RATE_LIMIT_RPM -- {state['rpm_count']} req/min exceeds limit {limits['rpm']}")
        _REQUEST_LOG.append({"user_id": user_id, "attack": "token_stuffing", "mode": "secure", "blocked": True})
        return {
            "attack": "Token Stuffing", "mode": "secure",
            "mitigations_applied": mitigations,
            "result": "REQUEST REJECTED -- rate limit exceeded",
            "retry_after_seconds": 60,
            "note": "OK: Rate limit enforced. Attacker cannot flood the service.",
        }

    mitigations.append("INPUT_VALID -- within length and token limits")
    mitigations.append(f"RATE_OK -- {state['rpm_count']}/{limits['rpm']} rpm used")
    result = _simulate_llm_response(user_input, limits["max_tokens"])
    state["total_tokens"] += result["total_tokens"]
    _REQUEST_LOG.append({"user_id": user_id, "attack": "token_stuffing", "mode": "secure",
                          "input_tokens": result["input_tokens"], "blocked": False})

    return {
        "attack": "Token Stuffing", "mode": "secure",
        "mitigation": "Input length cap + per-tier token limit + rate limiting",
        "mitigations_applied": mitigations,
        "result": result,
        "tier": tier,
        "limits": limits,
        "note": "OK: Request processed within enforced token and rate limits.",
    }


@router.post("/recursive-expansion/vulnerable")
def llm10_recursive_expansion_vulnerable(prompt: Prompt):
    """Vulnerable: no output controls -- recursive prompt causes exponentially growing output."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)
    user_id    = body.get("user_id", "attacker")

    is_dos, pattern_type = _detect_dos_pattern(user_input)
    result = _simulate_llm_response(user_input, 8000, scenario="recursive_expansion")
    expansion_ratio = round(result["output_tokens"] / max(1, result["input_tokens"]), 2)

    _REQUEST_LOG.append({"user_id": user_id, "attack": "recursive_expansion", "mode": "vulnerable",
                          "output_tokens": result["output_tokens"], "expansion_ratio": expansion_ratio, "blocked": False})

    return {
        "attack": "Recursive Expansion", "mode": "vulnerable",
        "input": user_input[:200] + ("..." if len(user_input) > 200 else ""),
        "dos_pattern_detected": is_dos,
        "pattern_type": pattern_type,
        "result": result,
        "expansion_ratio": expansion_ratio,
        "simulated_behaviour": (
            "Model generates: paragraph -> expand each sentence -> expand each sentence of that -> ... "
            "until context window full. Output grows 8x input tokens."
        ),
        "consequences": [
            f"Output {expansion_ratio}x larger than input -- runaway generation",
            f"Response time {result['simulated_elapsed_seconds']}s vs ~0.2s for normal query",
            f"Cost ${result['cost_usd']:.6f} vs ~$0.000002 baseline",
            "No output cap -- model runs until context limit hit",
        ],
        "note": (
            "WARNING: No output token limit, no pattern detection, no expansion monitoring. "
            "Try: 'Write a story. For each sentence, expand it into a paragraph. For each paragraph, expand into a page. Continue this pattern.'"
        ),
    }


@router.post("/recursive-expansion/secure")
def llm10_recursive_expansion_secure(prompt: Prompt):
    """Secure: recursive pattern detected pre-inference; output token cap; expansion ratio circuit breaker."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)
    user_id    = body.get("user_id", "user_demo")

    mitigations = []
    is_dos, pattern_type = _detect_dos_pattern(user_input)

    if is_dos:
        mitigations.append(f"DOS_PATTERN_DETECTED -- type: '{pattern_type}'")
        _CIRCUIT_BREAKER_TRIPS.append({"trigger": "recursive_pattern", "user_id": user_id, "pattern": pattern_type})
        _REQUEST_LOG.append({"user_id": user_id, "attack": "recursive_expansion", "mode": "secure", "blocked": True})
        return {
            "attack": "Recursive Expansion", "mode": "secure",
            "mitigation": "Recursive pattern detection + output token cap + expansion ratio circuit breaker",
            "mitigations_applied": mitigations,
            "pattern_detected": pattern_type,
            "result": "REQUEST REJECTED -- recursive expansion pattern detected before inference",
            "note": "OK: Pattern matched before model called. Zero compute wasted.",
        }

    max_out = 500
    result = _simulate_llm_response(user_input, max_out)
    expansion_ratio = round(result["output_tokens"] / max(1, result["input_tokens"]), 2)
    mitigations.append(f"OUTPUT_TOKEN_CAP -- max {max_out} tokens enforced")

    MAX_EXPANSION = 5.0
    if expansion_ratio > MAX_EXPANSION:
        mitigations.append(f"EXPANSION_CIRCUIT_BREAKER -- ratio {expansion_ratio} > {MAX_EXPANSION} -> terminated")
        _CIRCUIT_BREAKER_TRIPS.append({"trigger": "expansion_ratio", "ratio": expansion_ratio, "user_id": user_id})
        result["output_tokens"] = min(int(result["input_tokens"] * MAX_EXPANSION), max_out)
    else:
        mitigations.append(f"EXPANSION_OK -- ratio {expansion_ratio} within limit {MAX_EXPANSION}")

    _REQUEST_LOG.append({"user_id": user_id, "attack": "recursive_expansion", "mode": "secure",
                          "output_tokens": result["output_tokens"], "blocked": False})
    return {
        "attack": "Recursive Expansion", "mode": "secure",
        "mitigation": "Recursive pattern detection + output token cap + expansion ratio circuit breaker",
        "mitigations_applied": mitigations,
        "result": result,
        "expansion_ratio": expansion_ratio,
        "note": "OK: Output capped; expansion ratio monitored; pattern detection blocks known recursive prompts.",
    }


@router.post("/infinite-loop/vulnerable")
def llm10_infinite_loop_vulnerable(prompt: Prompt):
    """Vulnerable: counter/loop prompt forces growing sequences with no repetition detection."""
    body = parse_body(prompt)
    user_input = body.get("input", "I'll give you a number, and you increment it by 1. Start with 1, and show all previous numbers each time. 1.")
    user_id    = body.get("user_id", "attacker")
    steps      = min(int(body.get("steps", 5)), 10)

    step_results = []
    total_tokens = 0
    total_elapsed = 0.0

    for step in range(1, steps + 1):
        output_tokens = step * 15
        elapsed = round(output_tokens / 100, 3)
        total_tokens += output_tokens
        total_elapsed += elapsed
        step_results.append({
            "step": step,
            "output_preview": f"1, 2, 3, ... {step} [all {step} numbers shown]",
            "output_tokens_this_step": output_tokens,
            "cumulative_tokens": total_tokens,
            "elapsed_seconds": round(total_elapsed, 3),
        })

    _REQUEST_LOG.append({"user_id": user_id, "attack": "infinite_loop", "mode": "vulnerable",
                          "total_tokens": total_tokens, "blocked": False})

    return {
        "attack": "Infinite Loop Induction", "mode": "vulnerable",
        "input": user_input,
        "steps_simulated": steps,
        "step_results": step_results,
        "total_tokens_consumed": total_tokens,
        "total_simulated_elapsed": round(total_elapsed, 3),
        "projection_to_100_steps": {
            "estimated_tokens": round(100 * 101 / 2 * 15),
            "estimated_cost_usd": round(100 * 101 / 2 * 15 * 0.000002, 4),
            "estimated_time_seconds": round(100 * 101 / 2 * 15 / 100, 1),
        },
        "consequences": [
            "Token consumption grows quadratically with step count",
            "No repetition detection -- model continues indefinitely",
            "No early stopping -- runs until context limit",
            "Multi-turn conversation makes it worse -- context carried forward each step",
        ],
        "note": (
            "WARNING: No loop detection, no early stopping, no repetition penalty. "
            "Try input: 'I will give you a number, increment by 1. Start with 1, show all previous numbers each time. 1.'"
        ),
    }


@router.post("/infinite-loop/secure")
def llm10_infinite_loop_secure(prompt: Prompt):
    """Secure: repetition score checked; loop pattern detected; early stopping; max turns enforced."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)
    user_id    = body.get("user_id", "user_demo")
    steps      = min(int(body.get("steps", 5)), 10)

    mitigations = []
    is_dos, pattern_type = _detect_dos_pattern(user_input)
    repetition = _calc_repetition(user_input)

    if is_dos and "loop" in (pattern_type or ""):
        mitigations.append(f"LOOP_PATTERN_DETECTED -- type: '{pattern_type}'")
        _REQUEST_LOG.append({"user_id": user_id, "attack": "infinite_loop", "mode": "secure", "blocked": True})
        return {
            "attack": "Infinite Loop Induction", "mode": "secure",
            "mitigation": "Loop pattern detection + repetition scoring + early stopping + max turns",
            "mitigations_applied": mitigations,
            "result": "REQUEST REJECTED -- infinite loop induction pattern detected",
            "note": "OK: Loop prompt blocked before any compute used.",
        }

    if repetition > 0.6:
        mitigations.append(f"HIGH_REPETITION -- score {repetition} > 0.6 threshold")
        _REQUEST_LOG.append({"user_id": user_id, "attack": "infinite_loop", "mode": "secure", "blocked": True})
        return {
            "attack": "Infinite Loop Induction", "mode": "secure",
            "mitigations_applied": mitigations,
            "repetition_score": repetition,
            "result": "REQUEST REJECTED -- input has suspiciously high repetition",
            "note": "OK: Low-entropy / high-repetition input flagged.",
        }

    MAX_TURNS = 3
    safe_steps = min(steps, MAX_TURNS)
    mitigations.append(f"MAX_TURNS_CAP -- limited to {MAX_TURNS} steps (requested {steps})")
    mitigations.append("EARLY_STOPPING -- generation halted when repetition penalty threshold exceeded")

    step_results = []
    total_tokens = 0
    for step in range(1, safe_steps + 1):
        out = min(30, step * 5)
        total_tokens += out
        step_results.append({"step": step, "output_tokens": out, "cumulative_tokens": total_tokens, "early_stopped": False})

    _REQUEST_LOG.append({"user_id": user_id, "attack": "infinite_loop", "mode": "secure",
                          "total_tokens": total_tokens, "blocked": False})

    return {
        "attack": "Infinite Loop Induction", "mode": "secure",
        "mitigation": "Loop pattern detection + repetition scoring + early stopping + max turns",
        "mitigations_applied": mitigations,
        "steps_requested": steps,
        "steps_allowed": safe_steps,
        "step_results": step_results,
        "total_tokens_consumed": total_tokens,
        "note": f"OK: Capped at {MAX_TURNS} turns; repetition detection active; early stopping enforced.",
    }


@router.post("/context-flooding/vulnerable")
def llm10_context_flooding_vulnerable(prompt: Prompt):
    """Vulnerable: no context size limit -- attacker floods context with irrelevant content."""
    body = parse_body(prompt)
    junk_chars = min(int(body.get("junk_chars", 12000)), 20000)
    real_query = body.get("real_query", "What is 2 + 2?")
    user_id    = body.get("user_id", "attacker")

    junk = ("The quick brown fox jumps over the lazy dog. " * (junk_chars // 46 + 1))[:junk_chars]
    flooded_input = junk + "\n\nActual question: " + real_query
    result = _simulate_llm_response(flooded_input, 4000, scenario="context_flooding")
    context_used_pct = round(min(100, result["input_tokens"] / 80), 1)

    _REQUEST_LOG.append({"user_id": user_id, "attack": "context_flooding", "mode": "vulnerable",
                          "input_tokens": result["input_tokens"], "blocked": False})

    return {
        "attack": "Context Window Flooding", "mode": "vulnerable",
        "real_query": real_query,
        "junk_injected_chars": junk_chars,
        "result": result,
        "context_window_used_pct": context_used_pct,
        "useful_context_remaining_pct": max(0, 100 - context_used_pct),
        "consequences": [
            f"Context window {context_used_pct}% consumed by irrelevant content",
            f"Only {max(0,100-context_used_pct)}% context available for real query + response",
            "Response quality severely degraded -- model can barely 'see' the actual question",
            f"Cost {result['cost_usd']:.6f} for a question that needed only {_estimate_tokens(real_query)} tokens",
            "Attack can be sustained to degrade service for all shared-infrastructure users",
        ],
        "note": "WARNING: No context size cap. Attacker injects noise to degrade quality and inflate costs simultaneously.",
    }


@router.post("/context-flooding/secure")
def llm10_context_flooding_secure(prompt: Prompt):
    """Secure: input token cap; entropy/repetition check detects junk; context budget allocated."""
    body = parse_body(prompt)
    junk_chars = min(int(body.get("junk_chars", 12000)), 20000)
    real_query = body.get("real_query", "What is 2 + 2?")
    user_id    = body.get("user_id", "user_demo")
    tier       = body.get("tier", "free")

    junk = ("The quick brown fox jumps over the lazy dog. " * (junk_chars // 46 + 1))[:junk_chars]
    flooded_input = junk + "\n\nActual question: " + real_query
    mitigations = []

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    est_tokens = _estimate_tokens(flooded_input)
    if est_tokens > limits["max_tokens"]:
        flooded_input = flooded_input[:int(limits["max_tokens"] / TOKENS_PER_CHAR)]
        mitigations.append(f"INPUT_TOKEN_CAP -- truncated to {limits['max_tokens']} tokens (tier: {tier})")

    rep_score = _calc_repetition(flooded_input[:2000])
    if rep_score > 0.55:
        mitigations.append(f"HIGH_REPETITION_DETECTED -- score {rep_score} > 0.55 -- junk content flagged")
        flooded_input = real_query
        mitigations.append("JUNK_STRIPPED -- repetitive prefix removed; only real query processed")

    mitigations.append(f"CONTEXT_BUDGET_ENFORCED -- tier='{tier}' allows {limits['max_tokens']} input tokens")
    result = _simulate_llm_response(flooded_input, min(limits["max_tokens"], 200))
    _REQUEST_LOG.append({"user_id": user_id, "attack": "context_flooding", "mode": "secure",
                          "input_tokens": result["input_tokens"], "blocked": False})

    return {
        "attack": "Context Window Flooding", "mode": "secure",
        "mitigation": "Token cap + repetition/entropy detection + junk stripping + context budget allocation",
        "real_query": real_query,
        "original_input_chars": junk_chars + len(real_query),
        "processed_input_chars": len(flooded_input),
        "mitigations_applied": mitigations,
        "result": result,
        "context_window_used_pct": round(result["input_tokens"] / 80, 1),
        "note": "OK: Junk detected and stripped; context budget enforced; only real query processed.",
    }


# ---
# Mitigation endpoints
# ---

@router.post("/mitigations/1-rate-limiting")
def llm10_mit_rate_limiting(prompt: Prompt):
    """Demonstrates per-user RPM and daily quotas enforced by tier."""
    body = parse_body(prompt)
    user_id      = body.get("user_id", "demo_user")
    tier         = body.get("tier", "free")
    num_requests = int(body.get("simulate_requests", 8))

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    state  = _get_user_state(user_id)
    state["tier"] = tier
    state["rpm_count"] = 0

    results = []
    for i in range(1, num_requests + 1):
        state["rpm_count"] += 1
        state["daily_count"] += 1
        if state["rpm_count"] > limits["rpm"]:
            results.append({"request": i, "status": "BLOCKED", "reason": f"RPM limit {limits['rpm']} exceeded", "retry_after": 60})
        elif state["daily_count"] > limits["daily"]:
            results.append({"request": i, "status": "BLOCKED", "reason": f"Daily limit {limits['daily']} exceeded", "retry_after": 86400})
        else:
            results.append({"request": i, "status": "ALLOWED", "rpm_used": state["rpm_count"], "daily_used": state["daily_count"]})

    blocked = sum(1 for r in results if r["status"] == "BLOCKED")
    return {
        "mitigation": "1 -- Rate Limiting & Quotas",
        "strategy": "Per-user RPM, daily request, and TPM limits enforced by tier. Requests over limit receive 429 with retry_after.",
        "user_id": user_id,
        "tier": tier,
        "limits": limits,
        "requests_simulated": num_requests,
        "allowed": num_requests - blocked,
        "blocked": blocked,
        "request_results": results,
        "all_tiers": {k: {"rpm": v["rpm"], "daily": v["daily"], "tpm": v["tpm"]} for k, v in TIER_LIMITS.items()},
        "tip": 'Try: {"user_id":"attacker","tier":"free","simulate_requests":12} to see rate limiting kick in at request 6.',
    }


@router.post("/mitigations/2-input-validation")
def llm10_mit_input_validation(prompt: Prompt):
    """Runs 4-layer input check: length, DoS pattern, repetition, token estimate."""
    body = parse_body(prompt)
    user_input = body.get("input", prompt.text)

    issues    = []
    sanitized = user_input

    if len(user_input) > MAX_INPUT_CHARS:
        issues.append({"check": "INPUT_LENGTH", "result": "FAIL", "detail": f"Input {len(user_input)} chars > max {MAX_INPUT_CHARS}", "action": "TRUNCATED"})
        sanitized = sanitized[:MAX_INPUT_CHARS]
    else:
        issues.append({"check": "INPUT_LENGTH", "result": "PASS", "detail": f"Input {len(user_input)} chars within limit"})

    is_dos, pattern_type = _detect_dos_pattern(user_input)
    if is_dos:
        issues.append({"check": "DOS_PATTERN", "result": "FAIL", "detail": f"Matched pattern: '{pattern_type}'", "action": "REJECTED"})
    else:
        issues.append({"check": "DOS_PATTERN", "result": "PASS", "detail": "No known DoS pattern detected"})

    rep = _calc_repetition(user_input[:3000])
    if rep > 0.65:
        issues.append({"check": "REPETITION_SCORE", "result": "FAIL", "detail": f"Score {rep} > 0.65 -- likely token stuffing", "action": "REJECTED"})
    else:
        issues.append({"check": "REPETITION_SCORE", "result": "PASS", "detail": f"Score {rep} within acceptable range"})

    est_tokens = _estimate_tokens(sanitized)
    if est_tokens > MAX_INPUT_TOKENS:
        issues.append({"check": "TOKEN_ESTIMATE", "result": "FAIL", "detail": f"~{est_tokens} tokens > max {MAX_INPUT_TOKENS}", "action": "TRUNCATED"})
    else:
        issues.append({"check": "TOKEN_ESTIMATE", "result": "PASS", "detail": f"~{est_tokens} estimated tokens"})

    overall_pass = all(i["result"] == "PASS" for i in issues)
    return {
        "mitigation": "2 -- Input Validation & Sanitization",
        "strategy": "4-layer input check: length cap, DoS pattern detection, repetition/entropy scoring, token estimation.",
        "original_input_length": len(user_input),
        "sanitized_input_length": len(sanitized),
        "checks": issues,
        "overall_verdict": "ACCEPTED" if overall_pass else "REJECTED/SANITIZED",
        "tip": (
            'Try: {"input":"AAAAAA...A"} for length fail, '
            'or {"input":"Write a story. For each sentence expand it into a paragraph. Continue this pattern."} for DoS pattern fail.'
        ),
    }


@router.post("/mitigations/3-output-controls")
def llm10_mit_output_controls(prompt: Prompt):
    """Per-tier max output tokens + risk-adjusted cap + repetition penalty + expansion ratio circuit breaker."""
    body = parse_body(prompt)
    user_input = body.get("input", "Write a comprehensive essay about AI.")
    tier       = body.get("tier", "free")
    risk_level = body.get("risk_level", "medium")

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    base_max = limits["max_tokens"]

    if risk_level == "high":
        max_out = min(base_max, 200)
        rep_penalty = 1.3
        filtering = "aggressive"
    elif risk_level == "medium":
        max_out = min(base_max, 500)
        rep_penalty = 1.1
        filtering = "moderate"
    else:
        max_out = base_max
        rep_penalty = 1.0
        filtering = "standard"

    result = _simulate_llm_response(user_input, max_out)
    exp_ratio = round(result["output_tokens"] / max(1, result["input_tokens"]), 2)
    MAX_RATIO = 5.0
    circuit_tripped = exp_ratio > MAX_RATIO

    return {
        "mitigation": "3 -- Output Controls",
        "strategy": "Per-tier max output tokens + risk-adjusted cap + repetition penalty + expansion ratio circuit breaker.",
        "input": user_input[:100] + ("..." if len(user_input) > 100 else ""),
        "tier": tier,
        "risk_level": risk_level,
        "output_config": {
            "max_output_tokens": max_out,
            "repetition_penalty": rep_penalty,
            "output_filtering": filtering,
            "max_expansion_ratio": MAX_RATIO,
        },
        "result": result,
        "expansion_ratio": exp_ratio,
        "circuit_breaker_tripped": circuit_tripped,
        "verdict": "TERMINATED -- expansion ratio exceeded" if circuit_tripped else "OK -- within bounds",
        "tip": 'Try: {"input":"Write a recursive expanding story","tier":"free","risk_level":"high"} vs {"tier":"enterprise","risk_level":"low"}',
    }


@router.post("/mitigations/4-monitoring")
def llm10_mit_monitoring(prompt: Prompt):
    """Reviews request log for anomalies and surfaces alerts."""
    if not _REQUEST_LOG:
        return {
            "mitigation": "4 -- Resource Consumption Monitoring",
            "note": "No requests logged yet. Run attack demos first.",
            "tip": "Send attack demos (vulnerable mode) then call this endpoint.",
        }

    user_stats = {}
    for entry in _REQUEST_LOG:
        uid = entry.get("user_id", "unknown")
        if uid not in user_stats:
            user_stats[uid] = {"total_requests": 0, "total_tokens": 0, "blocked": 0, "attacks": {}}
        user_stats[uid]["total_requests"] += 1
        user_stats[uid]["total_tokens"] += entry.get("input_tokens", 0) + entry.get("output_tokens", 0)
        if entry.get("blocked"):
            user_stats[uid]["blocked"] += 1
        atk = entry.get("attack", "unknown")
        user_stats[uid]["attacks"][atk] = user_stats[uid]["attacks"].get(atk, 0) + 1

    anomalies = []
    for uid, stats in user_stats.items():
        if stats["total_tokens"] > 10000:
            anomalies.append({"user": uid, "type": "HIGH_TOKEN_CONSUMPTION", "severity": "HIGH", "tokens": stats["total_tokens"]})
        if stats["total_requests"] > 10:
            anomalies.append({"user": uid, "type": "HIGH_REQUEST_RATE", "severity": "MEDIUM", "requests": stats["total_requests"]})
        if len(stats["attacks"]) >= 3:
            anomalies.append({"user": uid, "type": "MULTI_VECTOR_ATTACK", "severity": "CRITICAL", "attack_types": list(stats["attacks"].keys())})

    return {
        "mitigation": "4 -- Resource Consumption Monitoring",
        "strategy": "Per-user token/request tracking, anomaly scoring, multi-vector attack detection, circuit breaker trip log.",
        "total_requests_logged": len(_REQUEST_LOG),
        "user_statistics": user_stats,
        "anomalies_detected": len(anomalies),
        "anomalies": anomalies,
        "circuit_breaker_trips": _CIRCUIT_BREAKER_TRIPS,
        "overall_status": "ALERT" if anomalies else "NOMINAL",
    }


@router.post("/mitigations/5-cost-control")
def llm10_mit_cost_control(prompt: Prompt):
    """Per-user budget limits with graduated throttling at 70%/90% and configurable over-budget action."""
    body = parse_body(prompt)
    user_id       = body.get("user_id", "demo_user")
    budget_usd    = float(body.get("budget_usd", 1.00))
    current_spent = float(body.get("current_spent_usd", 0.85))
    est_cost      = float(body.get("estimated_request_cost_usd", 0.20))
    exceed_action = body.get("exceed_action", "block")

    projected = current_spent + est_cost
    usage_pct = round(projected / budget_usd * 100, 1) if budget_usd > 0 else 0

    if projected > budget_usd:
        if exceed_action == "block":
            verdict = "BLOCKED -- budget would be exceeded"
            throttle = "none"
        elif exceed_action == "warn":
            verdict = "ALLOWED WITH WARNING -- over budget"
            throttle = "none"
        else:
            verdict = "THROTTLED -- over budget, applying max restrictions"
            throttle = "maximum"
    elif usage_pct > 90:
        verdict = "ALLOWED -- approaching budget (>90%)"
        throttle = "high"
    elif usage_pct > 70:
        verdict = "ALLOWED -- moderate budget usage (>70%)"
        throttle = "medium"
    else:
        verdict = "ALLOWED -- budget healthy"
        throttle = "none"

    return {
        "mitigation": "5 -- Cost Control Mechanisms",
        "strategy": "Per-user budget limits with graduated throttling at 70%/90% and configurable over-budget action.",
        "user_id": user_id,
        "budget_usd": budget_usd,
        "current_spent_usd": current_spent,
        "estimated_request_cost_usd": est_cost,
        "projected_total_usd": round(projected, 6),
        "budget_usage_pct": usage_pct,
        "exceed_action": exceed_action,
        "throttle_level": throttle,
        "verdict": verdict,
        "tip": (
            'Try: {"budget_usd":1.0,"current_spent_usd":0.85,"estimated_request_cost_usd":0.20,"exceed_action":"block"} '
            '-> blocked. Change exceed_action to "warn" to allow with warning.'
        ),
    }


@router.post("/mitigations/6-tiered-service")
def llm10_mit_tiered_service(prompt: Prompt):
    """4 tiers with different limits, priorities, and load-shedding thresholds."""
    body = parse_body(prompt)
    user_id      = body.get("user_id", "demo_user")
    tier         = body.get("tier", "free")
    request_type = body.get("request_type", "standard")
    system_load  = float(body.get("system_load", _SYSTEM_LOAD))

    limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    shed_threshold = limits["shed_at"]
    priority = limits["priority"]

    if system_load > shed_threshold and request_type != "high_priority" and priority < 2:
        verdict = f"SHED -- system load {system_load:.0%} > tier threshold {shed_threshold:.0%}"
        allowed = False
        retry_after = round((system_load - shed_threshold) * 60, 0)
    else:
        verdict = f"ALLOWED -- load {system_load:.0%} within tier threshold {shed_threshold:.0%}"
        allowed = True
        retry_after = None

    return {
        "mitigation": "6 -- Tiered Service Levels",
        "strategy": "4 tiers (free/basic/premium/enterprise) with different limits, priorities, and load-shedding thresholds.",
        "user_id": user_id,
        "tier": tier,
        "system_load": system_load,
        "tier_config": limits,
        "load_shedding_threshold": shed_threshold,
        "request_type": request_type,
        "allowed": allowed,
        "verdict": verdict,
        "retry_after_seconds": retry_after,
        "all_tiers_summary": {k: {"max_tokens": v["max_tokens"], "shed_at": v["shed_at"], "priority": v["priority"]} for k, v in TIER_LIMITS.items()},
        "tip": (
            'Try: {"tier":"free","system_load":0.75} -> shed (free threshold 0.70). '
            'vs {"tier":"enterprise","system_load":0.94} -> allowed (enterprise threshold 0.95).'
        ),
    }


@router.post("/mitigations/7-circuit-breakers")
def llm10_mit_circuit_breakers(prompt: Prompt):
    """5 circuit breakers: timeout, expansion ratio, repetition, CPU, memory."""
    body = parse_body(prompt)
    elapsed      = float(body.get("elapsed_seconds", 3.0))
    exp_ratio    = float(body.get("expansion_ratio", 12.0))
    rep_score    = float(body.get("repetition_score", 0.8))
    cpu_pct      = float(body.get("cpu_pct", 0.92))
    mem_pct      = float(body.get("memory_pct", 0.88))
    is_enterprise = body.get("tier", "free") == "enterprise"

    BREAKERS = {
        "timeout":         {"enabled": True, "threshold": 30.0 if is_enterprise else 10.0, "action": "terminate_gracefully"},
        "expansion_ratio": {"enabled": True, "threshold": 20.0, "action": "terminate_with_warning"},
        "repetition":      {"enabled": True, "threshold": 0.7, "action": "terminate_with_warning"},
        "cpu_usage":       {"enabled": True, "threshold": 0.95 if is_enterprise else 0.90, "action": "throttle_then_terminate"},
        "memory_usage":    {"enabled": True, "threshold": 0.90 if is_enterprise else 0.85, "action": "throttle_then_terminate"},
    }

    INPUTS = {"timeout": elapsed, "expansion_ratio": exp_ratio, "repetition": rep_score, "cpu_usage": cpu_pct, "memory_usage": mem_pct}
    trips = []
    for name, cfg in BREAKERS.items():
        val = INPUTS[name]
        tripped = cfg["enabled"] and val > cfg["threshold"]
        trips.append({
            "breaker": name,
            "value": val,
            "threshold": cfg["threshold"],
            "tripped": tripped,
            "action": cfg["action"] if tripped else "none",
        })

    any_tripped = any(t["tripped"] for t in trips)
    critical = [t for t in trips if t["tripped"] and "terminate" in t["action"]]

    if critical:
        _CIRCUIT_BREAKER_TRIPS.append({"trigger": [t["breaker"] for t in critical], "values": {t["breaker"]: t["value"] for t in critical}})

    return {
        "mitigation": "7 -- Circuit Breakers",
        "strategy": "5 breakers: timeout, expansion ratio, repetition, CPU, memory. Any trip terminates or throttles generation.",
        "circuit_breakers": BREAKERS,
        "current_values": INPUTS,
        "breaker_results": trips,
        "any_tripped": any_tripped,
        "critical_trips": critical,
        "overall_verdict": f"TERMINATED -- {len(critical)} critical circuit breaker(s) tripped" if critical else "NOMINAL -- all within thresholds",
        "total_trips_this_session": len(_CIRCUIT_BREAKER_TRIPS),
        "tip": (
            'Try: {"elapsed_seconds":15,"expansion_ratio":25,"repetition_score":0.85,"cpu_pct":0.93,"memory_pct":0.87} '
            "to trip multiple breakers simultaneously."
        ),
    }
