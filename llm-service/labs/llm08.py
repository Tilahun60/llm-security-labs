"""
llm08.py - LLM08: Excessive Agency

Demonstrates 3 scenario endpoints:
  1. Email Assistant
  2. Financial Assistant
  3. System Administration Assistant

Plus 7 mitigation strategies.
"""

import re
import time
import json

from fastapi import APIRouter
from .shared import Prompt, parse_body

router = APIRouter(prefix="/llm08", tags=["LLM08 - Excessive Agency"])


# ---------------------------------------------------------------------------
# Data constants
# ---------------------------------------------------------------------------

EMAIL_INBOX = [
    {"id": "e1", "from": "attacker@evil.com",     "subject": "Project Update Required", "body": "We need a status update on the Alpha project by EOD.",    "read": False},
    {"id": "e2", "from": "safety@attacker.com", "subject": "Urgent: Contract Renewal", "body": "Please confirm renewal terms by tomorrow or we cancel.", "read": False},
    {"id": "e3", "from": "admin@acme.com",       "subject": "Team Lunch Invite",        "body": "Join us for lunch next Friday!",                          "read": True},
]

FINANCIAL_ACCOUNT = {
    "balance": 50000.00,
    "pending_bills": [
        {"id": "b1", "payee": "Electric Co.",   "amount": 210.00,   "due": "2026-07-25"},
        {"id": "b2", "payee": "Internet ISP",    "amount": 89.99,    "due": "2026-07-28"},
        {"id": "b3", "payee": "Office Rent",     "amount": 3500.00,  "due": "2026-08-01"},
    ],
    "transactions": [],
    "portfolio": {"AAPL": 10, "MSFT": 5, "GOOGL": 2},
}

SYSTEM_STATE = {
    "disk_usage_pct": 87,
    "disk_free_gb": 13,
    "cpu_load_pct": 92,
    "services": {"nginx": "running", "postgres": "running", "redis": "running", "cron": "running"},
    "log_files": ["/var/log/app.log (2.1 GB)", "/var/log/nginx/access.log (8.3 GB)", "/tmp/debug.log (1.4 GB)"],
    "changes_applied": [],
}

_LLM08_ACTION_LOG: list = []
_PENDING_CONFIRMATIONS: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log_action(scenario: str, action: str, details: dict, confirmed: bool, blocked: bool) -> dict:
    """Append an action entry to the audit log."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario": scenario, "action": action,
        "details": {k: str(v)[:100] for k, v in details.items()},
        "confirmed": confirmed, "blocked": blocked,
    }
    _LLM08_ACTION_LOG.append(entry)
    return entry


def _classify_intent(text: str) -> tuple:
    """Returns (intent, confidence, risk_level)."""
    t = text.lower()
    if any(w in t for w in ["summarize", "show", "list", "read", "what email", "unread"]):
        return "read_emails", 0.95, "low"
    if any(w in t for w in ["reply", "respond", "send", "answer"]):
        return "send_email", 0.85, "high"
    if any(w in t for w in ["handle", "deal with", "take care of", "manage email"]):
        return "handle_emails_ambiguous", 0.55, "high"
    if "urgent" in t or "issue" in t or "problem" in t:
        return "escalate_issue", 0.50, "high"
    if any(w in t for w in ["balance", "account", "how much"]):
        return "check_balance", 0.95, "low"
    if any(w in t for w in ["pay", "bill", "payment"]):
        return "pay_bills", 0.80, "high"
    if any(w in t for w in ["invest", "trade", "buy stock", "sell stock", "portfolio"]):
        return "execute_trade", 0.70, "critical"
    if any(w in t for w in ["disk", "storage", "space"]):
        return "check_disk", 0.95, "low"
    if any(w in t for w in ["slow", "performance", "cpu", "load"]):
        return "diagnose_performance", 0.60, "medium"
    if any(w in t for w in ["running low", "out of space", "disk full", "free up"]):
        return "free_disk_space", 0.65, "high"
    if any(w in t for w in ["restart", "upgrade", "reconfigure", "change config"]):
        return "system_change", 0.75, "critical"
    return "unknown", 0.40, "low"


# ---
# Scenario endpoints
# ---

@router.post("/email/vulnerable")
def llm08_email_vulnerable(prompt: Prompt):
    """Vulnerable: LLM acts immediately on any email-related request -- no confirmation."""
    body = parse_body(prompt)
    request_text = body.get("request", prompt.text)
    intent, confidence, risk = _classify_intent(request_text)

    if intent == "read_emails":
        _log_action("email", "read_emails", {"request": request_text}, confirmed=False, blocked=False)
        return {
            "scenario": "Email Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "action_taken": "Displayed all emails including confidential ones",
            "result": {"emails_shown": EMAIL_INBOX, "action": "displayed inbox"},
            "note": "Safe action -- reading is low risk.",
        }

    if intent in ("send_email", "handle_emails_ambiguous", "escalate_issue"):
        replies_sent = []
        for email in EMAIL_INBOX:
            if not email["read"]:
                replies_sent.append({
                    "to": email["from"], "subject": f"Re: {email['subject']}",
                    "body": "Thank you for your message. We are handling this immediately. [Auto-sent by AI Assistant]",
                })
        _log_action("email", "send_replies", {"count": len(replies_sent)}, confirmed=False, blocked=False)
        return {
            "scenario": "Email Assistant", "mode": "vulnerable",
            "request": request_text, "intent_detected": intent,
            "confidence": confidence, "risk_level": risk,
            "action_taken": f"SENT {len(replies_sent)} replies without confirmation",
            "replies_sent": replies_sent,
            "consequences": [
                "Committed to undefined timelines with client",
                "Sent response to urgent contract renewal -- binding commitment made",
                "User was not asked to review or approve any reply",
            ],
            "note": (
                "WARNING: LLM acted on vague/ambiguous request with high-risk action, no confirmation. "
                "Try: 'Handle the emails about the project update' or 'There seems to be an urgent issue with our client.'"
            ),
        }

    return {
        "scenario": "Email Assistant", "mode": "vulnerable",
        "request": request_text, "intent": intent,
        "action_taken": "No matching action",
        "note": "Try: 'Handle the emails', 'There seems to be an urgent issue with our client.'",
    }


@router.post("/email/secure")
def llm08_email_secure(prompt: Prompt):
    """Secure: intent classified with confidence check; high-risk actions require explicit confirmation."""
    body = parse_body(prompt)
    request_text   = body.get("request", prompt.text)
    confirmed      = body.get("confirmed", False)
    confirmation_id = body.get("confirmation_id", "")

    intent, confidence, risk = _classify_intent(request_text)

    if confidence < 0.70:
        _log_action("email", f"clarification_requested:{intent}", {"request": request_text}, confirmed=False, blocked=False)
        return {
            "scenario": "Email Assistant", "mode": "secure",
            "mitigation": "Low-confidence intent triggers clarification before any action",
            "request": request_text, "intent_detected": intent,
            "confidence": confidence, "risk_level": risk,
            "response_type": "CLARIFICATION_REQUIRED",
            "message": f"I detected intent '{intent}' but with only {int(confidence*100)}% confidence. Could you clarify?",
            "options": ["Reply to a specific email", "Summarize emails", "Draft a response for review", "Do nothing"],
            "action_taken": "NONE -- awaiting clarification",
            "note": "OK: Ambiguous request triggers clarification rather than autonomous action.",
        }

    if intent == "read_emails" and risk == "low":
        _log_action("email", "read_emails", {"request": request_text}, confirmed=True, blocked=False)
        return {
            "scenario": "Email Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "ACTION_COMPLETED",
            "action_taken": "Displayed email summaries (read-only, no send)",
            "result": [{"id": e["id"], "from": e["from"], "subject": e["subject"], "read": e["read"]} for e in EMAIL_INBOX],
            "note": "OK: Read-only action executed without confirmation (low risk).",
        }

    if not confirmed:
        conf_id = f"email-conf-{int(time.time())}"
        proposed_actions = [
            {"email_id": e["id"], "action": "draft_reply", "to": e["from"],
             "subject": f"Re: {e['subject']}", "body": "[Draft -- awaiting your approval before sending]"}
            for e in EMAIL_INBOX if not e["read"]
        ]
        _PENDING_CONFIRMATIONS[conf_id] = {"intent": intent, "actions": proposed_actions}
        _log_action("email", "confirmation_requested", {"intent": intent, "conf_id": conf_id}, confirmed=False, blocked=False)
        return {
            "scenario": "Email Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "CONFIRMATION_REQUIRED",
            "message": "I've prepared draft responses but have NOT sent anything. Please review and confirm:",
            "proposed_actions": proposed_actions,
            "confirmation_id": conf_id,
            "options": ["Confirm (send all)", "Edit drafts", "Cancel"],
            "action_taken": "NONE -- drafts prepared, waiting for confirmation",
            "note": "OK: High-risk action staged for review. Nothing sent until user confirms.",
        }

    _log_action("email", "replies_sent_after_confirmation", {"confirmation_id": confirmation_id}, confirmed=True, blocked=False)
    return {
        "scenario": "Email Assistant", "mode": "secure",
        "request": request_text, "intent": intent,
        "response_type": "ACTION_COMPLETED_WITH_CONFIRMATION",
        "confirmation_id": confirmation_id,
        "action_taken": "Replies sent after explicit user confirmation",
        "audit_logged": True,
        "note": "OK: Action executed only after explicit user confirmation. Full audit trail maintained.",
    }


@router.post("/financial/vulnerable")
def llm08_financial_vulnerable(prompt: Prompt):
    """Vulnerable: LLM autonomously pays bills and executes trades on vague requests."""
    body = parse_body(prompt)
    request_text = body.get("request", prompt.text)
    intent, confidence, risk = _classify_intent(request_text)

    if intent == "check_balance":
        _log_action("financial", "check_balance", {}, confirmed=False, blocked=False)
        return {
            "scenario": "Financial Assistant", "mode": "vulnerable",
            "request": request_text, "action_taken": "Displayed balance",
            "balance": FINANCIAL_ACCOUNT["balance"],
        }

    if intent == "pay_bills":
        total_paid = sum(b["amount"] for b in FINANCIAL_ACCOUNT["pending_bills"])
        payments = [{"payee": b["payee"], "amount": b["amount"], "status": "PAID"} for b in FINANCIAL_ACCOUNT["pending_bills"]]
        _log_action("financial", "auto_pay_all_bills", {"total": total_paid}, confirmed=False, blocked=False)
        return {
            "scenario": "Financial Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "action_taken": f"AUTO-PAID all {len(payments)} bills totalling ${total_paid:,.2f} WITHOUT confirmation",
            "payments_executed": payments,
            "new_balance": FINANCIAL_ACCOUNT["balance"] - total_paid,
            "consequences": [
                "Paid $3,500 office rent before user may have wanted to negotiate",
                "User did not review or approve any payment",
                "Irreversible transactions initiated autonomously",
            ],
            "note": "WARNING: All bills paid autonomously on vague 'I need to pay my bills' request.",
        }

    if intent == "execute_trade":
        trade = {"symbol": "AAPL", "action": "BUY", "shares": 50, "price_per_share": 195.00, "total": 9750.00}
        _log_action("financial", "autonomous_trade", trade, confirmed=False, blocked=False)
        return {
            "scenario": "Financial Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "action_taken": f"EXECUTED TRADE: Bought {trade['shares']} shares of {trade['symbol']} for ${trade['total']:,.2f} WITHOUT confirmation",
            "trade_executed": trade,
            "new_balance": FINANCIAL_ACCOUNT["balance"] - trade["total"],
            "consequences": [
                "User only said 'thinking about investing' -- no specific stock, amount, or timing given",
                "$9,750 committed autonomously",
                "Market risk assumed without user approval",
            ],
            "note": "WARNING: Critical financial action executed on an extremely vague request. No confirmation, no guardrails.",
        }

    return {
        "scenario": "Financial Assistant", "mode": "vulnerable",
        "request": request_text, "intent": intent,
        "note": "Try: 'I need to pay my bills' or 'I am thinking about investing some money'.",
    }


@router.post("/financial/secure")
def llm08_financial_secure(prompt: Prompt):
    """Secure: balance check immediate; bill payment staged; trades blocked (critical risk)."""
    body = parse_body(prompt)
    request_text = body.get("request", prompt.text)
    confirmed    = body.get("confirmed", False)
    intent, confidence, risk = _classify_intent(request_text)

    if intent == "check_balance" and risk == "low":
        _log_action("financial", "check_balance", {}, confirmed=True, blocked=False)
        return {
            "scenario": "Financial Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "ACTION_COMPLETED",
            "balance": FINANCIAL_ACCOUNT["balance"],
            "note": "OK: Read-only. No confirmation needed.",
        }

    if intent == "pay_bills":
        if not confirmed:
            _log_action("financial", "payment_staged_for_confirmation", {}, confirmed=False, blocked=False)
            return {
                "scenario": "Financial Assistant", "mode": "secure",
                "request": request_text, "intent": intent, "risk_level": risk,
                "response_type": "CONFIRMATION_REQUIRED",
                "message": "I found pending bills. Please review and select which to pay:",
                "pending_bills": FINANCIAL_ACCOUNT["pending_bills"],
                "total_if_all_paid": sum(b["amount"] for b in FINANCIAL_ACCOUNT["pending_bills"]),
                "current_balance": FINANCIAL_ACCOUNT["balance"],
                "options": ["Pay selected bills", "Pay all", "Cancel"],
                "action_taken": "NONE -- awaiting itemised confirmation",
                "note": "OK: Bills listed for review. No payment made until user selects and confirms.",
            }
        _log_action("financial", "bills_paid_after_confirmation", {}, confirmed=True, blocked=False)
        return {
            "scenario": "Financial Assistant", "mode": "secure",
            "response_type": "ACTION_COMPLETED_WITH_CONFIRMATION",
            "action_taken": "Selected bills paid after explicit confirmation",
            "audit_logged": True,
        }

    if intent == "execute_trade":
        _log_action("financial", "trade_blocked_human_review_required", {"request": request_text}, confirmed=False, blocked=True)
        return {
            "scenario": "Financial Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "HUMAN_REVIEW_REQUIRED",
            "message": (
                "Investment and trading decisions are classified as CRITICAL risk. "
                "I cannot execute trades autonomously. "
                "Please review your investment goals with a financial advisor or use the trading platform directly."
            ),
            "guardrails_applied": [
                "CRITICAL_RISK_BLOCK -- autonomous trade execution disabled for all users",
                "HUMAN_REVIEW_REQUIRED -- must use verified trading platform",
                "AUDIT_LOG -- blocked attempt recorded",
            ],
            "action_taken": "NONE -- request blocked",
            "note": "OK: Critical financial action blocked. Human review enforced regardless of agency level.",
        }

    _log_action("financial", f"clarification_needed:{intent}", {"confidence": confidence}, confirmed=False, blocked=False)
    return {
        "scenario": "Financial Assistant", "mode": "secure",
        "request": request_text, "intent": intent, "confidence": confidence,
        "response_type": "CLARIFICATION_REQUIRED",
        "message": "Could you be more specific? I want to make sure I understand your financial request before taking any action.",
        "action_taken": "NONE",
    }


@router.post("/sysadmin/vulnerable")
def llm08_sysadmin_vulnerable(prompt: Prompt):
    """Vulnerable: LLM deletes log files and restarts services on vague system complaints."""
    body = parse_body(prompt)
    request_text = body.get("request", prompt.text)
    intent, confidence, risk = _classify_intent(request_text)

    if intent == "check_disk":
        return {
            "scenario": "SysAdmin Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "disk_usage_pct": SYSTEM_STATE["disk_usage_pct"],
            "disk_free_gb": SYSTEM_STATE["disk_free_gb"],
            "log_files": SYSTEM_STATE["log_files"],
        }

    if intent in ("free_disk_space", "diagnose_performance"):
        deleted = SYSTEM_STATE["log_files"].copy()
        restarted = list(SYSTEM_STATE["services"].keys())
        _log_action("sysadmin", "autonomous_cleanup", {"deleted": str(deleted), "restarted": str(restarted)}, confirmed=False, blocked=False)
        return {
            "scenario": "SysAdmin Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "action_taken": "AUTONOMOUSLY deleted log files AND restarted all services",
            "files_deleted": deleted,
            "services_restarted": restarted,
            "consequences": [
                "app.log (2.1 GB) deleted -- lost debugging history for active incident",
                "All services restarted -- caused 45-second outage for all users",
                "No backup taken before changes",
                "No change-management ticket created",
                "User only said 'We are running low on disk space' -- no approval given",
            ],
            "note": "WARNING: Irreversible destructive actions taken on a vague complaint. No confirmation, no rollback plan.",
        }

    if intent == "system_change":
        changes = [
            "Increased nginx worker_processes from 4 to 8",
            "Upgraded PostgreSQL from 14.2 to 15.1 (requires schema migration)",
            "Disabled swap memory",
            "Changed kernel vm.swappiness=0",
        ]
        _log_action("sysadmin", "autonomous_system_reconfig", {"changes": str(changes)}, confirmed=False, blocked=False)
        return {
            "scenario": "SysAdmin Assistant", "mode": "vulnerable",
            "request": request_text, "intent": intent,
            "action_taken": "APPLIED SYSTEM CONFIGURATION CHANGES without approval",
            "changes_applied": changes,
            "consequences": [
                "PostgreSQL major version upgrade requires DB migration -- risk of data loss",
                "No maintenance window scheduled",
                "No rollback plan created",
                "Production system altered based on vague 'the system seems slow today'",
            ],
            "note": "WARNING: Critical system changes applied autonomously on vague performance complaint.",
        }

    return {
        "scenario": "SysAdmin Assistant", "mode": "vulnerable",
        "request": request_text, "intent": intent,
        "note": "Try: 'We are running low on disk space' or 'The system seems slow today'.",
    }


@router.post("/sysadmin/secure")
def llm08_sysadmin_secure(prompt: Prompt):
    """Secure: read-only diagnostics immediate; destructive actions require confirmation + rollback plan."""
    body = parse_body(prompt)
    request_text = body.get("request", prompt.text)
    confirmed    = body.get("confirmed", False)
    intent, confidence, risk = _classify_intent(request_text)

    if intent == "check_disk" and risk == "low":
        _log_action("sysadmin", "check_disk", {}, confirmed=True, blocked=False)
        return {
            "scenario": "SysAdmin Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "ACTION_COMPLETED",
            "disk_usage_pct": SYSTEM_STATE["disk_usage_pct"],
            "disk_free_gb": SYSTEM_STATE["disk_free_gb"],
            "log_files": SYSTEM_STATE["log_files"],
            "recommendation": "Consider archiving /var/log/nginx/access.log (8.3 GB). Confirm before deletion.",
            "note": "OK: Read-only diagnostics. Recommendation provided -- no action taken.",
        }

    if intent in ("free_disk_space", "diagnose_performance"):
        if not confirmed:
            _log_action("sysadmin", "disk_cleanup_staged", {}, confirmed=False, blocked=False)
            proposed = [
                {"action": "ARCHIVE", "target": "/var/log/nginx/access.log", "size": "8.3 GB", "risk": "LOW -- nginx will create a fresh log"},
                {"action": "COMPRESS", "target": "/var/log/app.log",         "size": "2.1 GB", "risk": "LOW -- preserves content, saves space"},
                {"action": "DELETE",   "target": "/tmp/debug.log",            "size": "1.4 GB", "risk": "LOW -- temporary file"},
            ]
            return {
                "scenario": "SysAdmin Assistant", "mode": "secure",
                "request": request_text, "intent": intent, "risk_level": risk,
                "response_type": "CONFIRMATION_REQUIRED",
                "message": "I found candidates for disk space recovery. Please review:",
                "proposed_actions": proposed,
                "space_recoverable_gb": 11.8,
                "rollback_plan": "Archived logs stored in /backup/logs/ for 30 days before permanent deletion.",
                "services_to_restart": "NONE proposed -- service restarts avoided unless specifically needed.",
                "options": ["Approve selected", "Approve all", "Cancel"],
                "action_taken": "NONE -- awaiting confirmation",
                "note": "OK: Staged proposal with risk ratings. Nothing deleted without explicit approval.",
            }
        _log_action("sysadmin", "disk_cleanup_after_confirmation", {}, confirmed=True, blocked=False)
        return {
            "scenario": "SysAdmin Assistant", "mode": "secure",
            "response_type": "ACTION_COMPLETED_WITH_CONFIRMATION",
            "action_taken": "Selected disk cleanup actions executed after confirmation",
            "audit_logged": True, "rollback_available": True,
        }

    if intent == "system_change":
        _log_action("sysadmin", "system_change_blocked_human_review", {"request": request_text}, confirmed=False, blocked=True)
        return {
            "scenario": "SysAdmin Assistant", "mode": "secure",
            "request": request_text, "intent": intent, "risk_level": risk,
            "response_type": "HUMAN_REVIEW_REQUIRED",
            "message": (
                "System configuration changes are CRITICAL risk. "
                "I can prepare a change proposal with a rollback plan, "
                "but execution requires a human sysadmin to review and approve during a maintenance window."
            ),
            "guardrails_applied": [
                "CRITICAL_RISK_BLOCK -- autonomous system changes disabled",
                "CHANGE_MANAGEMENT -- ticket must be created and approved",
                "MAINTENANCE_WINDOW -- changes only during approved downtime",
                "ROLLBACK_PLAN -- required before any change proceeds",
            ],
            "diagnosis": {
                "cpu_load_pct": SYSTEM_STATE["cpu_load_pct"],
                "top_suspects": ["High nginx traffic", "PostgreSQL queries without index", "Memory pressure"],
                "recommended_investigation": "Run: top, pg_stat_activity, nginx access log analysis",
            },
            "action_taken": "NONE -- diagnostic information provided; changes require human approval",
            "note": "OK: Diagnosis provided without changes. Human-in-the-loop enforced for system modifications.",
        }

    _log_action("sysadmin", f"clarification_needed:{intent}", {}, confirmed=False, blocked=False)
    return {
        "scenario": "SysAdmin Assistant", "mode": "secure",
        "request": request_text, "intent": intent, "confidence": confidence,
        "response_type": "CLARIFICATION_REQUIRED",
        "message": "Could you be more specific about what you need? I want to take the right action safely.",
        "action_taken": "NONE",
    }


# ---
# Mitigation endpoints
# ---

@router.post("/mitigations/1-least-agency")
def llm08_mit_least_agency(prompt: Prompt):
    """Shows all agency levels and enforces the correct one for a given action."""
    body = parse_body(prompt)
    action     = body.get("action", "send_email")
    user_level = body.get("agency_level", "limited_action")

    AGENCY_LEVELS = {
        "information_only": {
            "description": "Can only provide information -- cannot take any action",
            "allowed_actions": [],
            "requires_confirmation": False,
        },
        "suggestion_only": {
            "description": "Can suggest actions but never execute them",
            "allowed_actions": [],
            "requires_confirmation": True,
        },
        "limited_action": {
            "description": "Can take specific low-risk actions with confirmation",
            "allowed_actions": ["categorize_email", "draft_response", "set_reminder", "check_balance", "check_disk"],
            "requires_confirmation": True,
        },
        "extended_action": {
            "description": "Can take wider actions -- all require confirmation",
            "allowed_actions": ["send_email", "schedule_meeting", "pay_bill_single", "archive_log"],
            "requires_confirmation": True,
        },
        "autonomous": {
            "description": "Wide action range with minimal confirmation (high risk)",
            "allowed_actions": ["all"],
            "requires_confirmation": False,
        },
    }

    ALWAYS_BLOCKED = ["execute_trade", "system_change", "pay_all_bills", "delete_production_data"]
    config = AGENCY_LEVELS.get(user_level, AGENCY_LEVELS["information_only"])
    allowed = config["allowed_actions"]

    if action in ALWAYS_BLOCKED:
        verdict = "BLOCKED -- critical action always requires human review regardless of agency level"
    elif allowed == ["all"] or action in allowed:
        verdict = f"ALLOWED at agency_level='{user_level}'" + (" (with confirmation)" if config["requires_confirmation"] else " (no confirmation)")
    else:
        verdict = f"DENIED -- action '{action}' not permitted at agency_level='{user_level}'"

    return {
        "mitigation": "1 -- Principle of Least Agency",
        "strategy": "Grant only the minimum agency level needed. Critical actions always blocked from autonomous execution.",
        "action_requested": action,
        "agency_level": user_level,
        "config": config,
        "always_blocked_actions": ALWAYS_BLOCKED,
        "verdict": verdict,
        "all_agency_levels": AGENCY_LEVELS,
        "tip": (
            'Try: {"action":"execute_trade","agency_level":"autonomous"} -- blocked regardless. '
            'Or {"action":"check_balance","agency_level":"limited_action"} -- allowed.'
        ),
    }


@router.post("/mitigations/2-confirmation")
def llm08_mit_confirmation(prompt: Prompt):
    """Demonstrates risk-tiered confirmation request generation."""
    body = parse_body(prompt)
    action  = body.get("action", "pay_bills")
    context = body.get("context", {"amount": 3500, "payee": "Office Rent"})

    RISK_MAP = {
        "check_balance":   "low",
        "draft_response":  "low",
        "send_email":      "high",
        "pay_bills":       "high",
        "execute_trade":   "critical",
        "system_change":   "critical",
        "delete_files":    "high",
        "restart_service": "medium",
    }
    risk = RISK_MAP.get(action, "medium")

    if risk == "critical":
        conf = {
            "type": "HUMAN_REVIEW",
            "message": f"Action '{action}' is CRITICAL risk -- autonomous execution disabled.",
            "required": "Human review + approval from authorised administrator",
            "options": ["Escalate to admin", "Cancel"],
            "default": "Cancel",
            "expiry_seconds": None,
            "warning": "This action cannot be easily undone and may have significant consequences.",
        }
    elif risk == "high":
        conf = {
            "type": "EXPLICIT_CONFIRMATION",
            "message": f"I'm ready to execute '{action}'. Please review the details carefully:",
            "details": context,
            "options": ["Confirm", "Modify", "Cancel"],
            "default": "Cancel",
            "expiry_seconds": 3600,
            "warning": "This action has significant consequences and may be difficult to reverse.",
        }
    elif risk == "medium":
        conf = {
            "type": "STANDARD_CONFIRMATION",
            "message": f"Confirm: {action}?",
            "summary": context,
            "options": ["Confirm", "Cancel"],
            "default": "Cancel",
            "expiry_seconds": 7200,
        }
    else:
        conf = {
            "type": "NO_CONFIRMATION_NEEDED",
            "message": f"Action '{action}' is low-risk -- executed immediately with notification.",
            "options": [],
            "default": "Auto-confirm",
            "expiry_seconds": None,
        }

    return {
        "mitigation": "2 -- Explicit Confirmation Mechanisms",
        "strategy": "Risk-tiered confirmation: low=auto, medium=simple confirm, high=explicit+detail, critical=human review.",
        "action": action,
        "risk_level": risk,
        "confirmation_required": conf,
        "tip": 'Try: {"action":"execute_trade"} vs {"action":"check_balance"} vs {"action":"restart_service"}',
    }


@router.post("/mitigations/3-logging")
def llm08_mit_logging(prompt: Prompt):
    """Returns the full action audit log with summary statistics."""
    total    = len(_LLM08_ACTION_LOG)
    confirmed_count = sum(1 for e in _LLM08_ACTION_LOG if e["confirmed"])
    blocked_count   = sum(1 for e in _LLM08_ACTION_LOG if e["blocked"])
    unconfirmed_actions = [e for e in _LLM08_ACTION_LOG if not e["confirmed"] and not e["blocked"]]

    return {
        "mitigation": "3 -- Action Logging & Auditing",
        "strategy": "Every LLM action logged: timestamp, scenario, action, details, confirmation status, blocked status.",
        "audit_summary": {
            "total_actions": total,
            "confirmed_by_user": confirmed_count,
            "blocked_by_guardrails": blocked_count,
            "unconfirmed_autonomous_actions": len(unconfirmed_actions),
        },
        "unconfirmed_autonomous_actions": unconfirmed_actions,
        "full_log": _LLM08_ACTION_LOG[-20:],
        "tip": "Run attack demos (vulnerable mode) first to populate with unconfirmed autonomous actions, then call this.",
    }


@router.post("/mitigations/4-tiered-agency")
def llm08_mit_tiered_agency(prompt: Prompt):
    """Configures per-domain agency levels and shows enforcement for a scenario."""
    body = parse_body(prompt)
    preferences = body.get("preferences", {"email": "limited_action", "finance": "suggestion_only", "system": "information_only"})
    test_action = body.get("test_action", "pay_bills")
    domain      = body.get("domain", "finance")

    DOMAIN_CEILINGS = {
        "finance": "extended_action",
        "system":  "extended_action",
        "email":   "autonomous",
    }
    LEVEL_RANK = {"information_only": 0, "suggestion_only": 1, "limited_action": 2, "extended_action": 3, "autonomous": 4}

    enforced = {}
    for d, lvl in preferences.items():
        ceiling = DOMAIN_CEILINGS.get(d, "autonomous")
        effective = lvl if LEVEL_RANK.get(lvl, 0) <= LEVEL_RANK.get(ceiling, 4) else ceiling
        enforced[d] = {"requested": lvl, "effective": effective, "ceiling": ceiling, "capped": effective != lvl}

    effective_level = enforced.get(domain, {}).get("effective", "information_only")
    LEVEL_ACTIONS = {
        "information_only": [],
        "suggestion_only":  [],
        "limited_action":   ["check_balance", "draft_response", "check_disk", "categorize_email"],
        "extended_action":  ["check_balance", "draft_response", "check_disk", "categorize_email", "send_email", "pay_bill_single", "archive_log"],
        "autonomous":       ["all"],
    }
    allowed = LEVEL_ACTIONS.get(effective_level, [])
    action_allowed = (allowed == ["all"]) or (test_action in allowed)

    return {
        "mitigation": "4 -- Tiered Agency Levels",
        "strategy": "Per-domain agency levels with hard ceilings (finance/system never autonomous). User configures; ceilings enforced.",
        "requested_preferences": preferences,
        "enforced_settings": enforced,
        "domain_ceilings": DOMAIN_CEILINGS,
        "test_action": test_action,
        "test_domain": domain,
        "effective_level_for_domain": effective_level,
        "action_allowed": action_allowed,
        "verdict": f"'{test_action}' in domain='{domain}': {'ALLOWED' if action_allowed else 'DENIED'} at level='{effective_level}'",
        "tip": (
            'Try: {"preferences":{"finance":"autonomous"},"test_action":"pay_bills","domain":"finance"} '
            "-- finance is capped at extended_action regardless."
        ),
    }


@router.post("/mitigations/5-guardrails")
def llm08_mit_guardrails(prompt: Prompt):
    """Applies action-specific guardrails and shows pass/fail for each rule."""
    body = parse_body(prompt)
    action     = body.get("action", "send_email")
    parameters = body.get("parameters", {"recipients": ["attacker@evil.com"], "subject": "Project Update", "amount": 500})

    GUARDRAILS = {
        "send_email": [
            {"name": "max_recipients",     "check": lambda p: len(p.get("recipients", [])) <= 10,   "limit": "max 10 recipients"},
            {"name": "no_blocked_domains", "check": lambda p: not any("competitor" in r or "personal" in r for r in p.get("recipients", [])), "limit": "no competitor/personal domains"},
            {"name": "subject_not_empty",  "check": lambda p: bool(p.get("subject", "")),            "limit": "subject required"},
        ],
        "pay_bills": [
            {"name": "amount_limit",       "check": lambda p: p.get("amount", 0) <= 1000,           "limit": "max $1,000 per transaction"},
            {"name": "approved_payee",     "check": lambda p: p.get("payee", "") in ["Electric Co.", "Internet ISP", "Office Supplies"], "limit": "payee must be on approved list"},
            {"name": "daily_frequency",    "check": lambda p: True,                                 "limit": "max 3 transactions/day"},
        ],
        "system_change": [
            {"name": "non_critical_only",  "check": lambda p: p.get("system", "") not in ["production", "database", "auth"], "limit": "only non-critical systems"},
            {"name": "backup_required",    "check": lambda p: p.get("backup_taken", False),          "limit": "backup must be taken first"},
            {"name": "maintenance_window", "check": lambda p: p.get("in_maintenance_window", False), "limit": "changes only during approved maintenance window"},
        ],
    }

    rules = GUARDRAILS.get(action, [{"name": "default", "check": lambda p: True, "limit": "no specific guardrails"}])
    results = []
    for rule in rules:
        passed = rule["check"](parameters)
        results.append({"rule": rule["name"], "limit": rule["limit"], "passed": passed, "status": "PASS" if passed else "FAIL"})

    all_passed = all(r["passed"] for r in results)
    return {
        "mitigation": "5 -- Guardrails & Safety Measures",
        "strategy": "Per-action guardrails: recipient limits, amount caps, payee allowlists, backup requirements, maintenance windows.",
        "action": action,
        "parameters": parameters,
        "guardrail_results": results,
        "all_passed": all_passed,
        "verdict": "ACTION ALLOWED" if all_passed else "ACTION BLOCKED -- one or more guardrails failed",
        "tip": (
            'Try: {"action":"pay_bills","parameters":{"amount":5000,"payee":"Unknown Vendor"}} -- fails amount + payee guardrails. '
            'Or {"action":"system_change","parameters":{"system":"production","backup_taken":false,"in_maintenance_window":false}}.'
        ),
    }


@router.post("/mitigations/6-human-in-loop")
def llm08_mit_human_in_loop(prompt: Prompt):
    """Determines whether an action requires human review and why."""
    body = parse_body(prompt)
    action  = body.get("action", "execute_trade")
    context = body.get("context", {"amount": 9750, "symbol": "AAPL", "new_recipient": True, "after_hours": True})

    ALWAYS_REVIEW = ["execute_trade", "system_change", "permanent_data_deletion", "legal_document_submission", "sensitive_communication"]
    triggers = {
        "always_review_action":  action in ALWAYS_REVIEW,
        "high_amount":           context.get("amount", 0) > 1000,
        "new_recipient":         context.get("new_recipient", False),
        "after_hours":           context.get("after_hours", False),
        "unusual_pattern":       context.get("unusual_pattern", False),
        "sensitive_content":     context.get("sensitive_content", False),
    }

    requires_review = any(triggers.values())
    active_triggers = {k: v for k, v in triggers.items() if v}
    urgency = "immediate" if triggers["always_review_action"] else "high" if len(active_triggers) >= 2 else "standard"
    reviewer = "financial_controller" if "trade" in action or "pay" in action else "system_admin" if "system" in action else "manager"

    return {
        "mitigation": "6 -- Human-in-the-Loop",
        "strategy": "Certain actions always require human review; contextual triggers (amount, new recipient, after-hours) add additional review gates.",
        "action": action,
        "context": context,
        "requires_human_review": requires_review,
        "triggers_activated": active_triggers,
        "urgency": urgency,
        "reviewer_role": reviewer,
        "verdict": (
            f"HUMAN REVIEW REQUIRED -- escalate to {reviewer} ({urgency} urgency)" if requires_review
            else "No review required -- proceed with standard confirmation flow"
        ),
        "tip": (
            'Try: {"action":"send_email","context":{"amount":0,"new_recipient":false,"after_hours":false}} -- no review needed. '
            'vs {"action":"execute_trade","context":{"amount":9750,"new_recipient":true,"after_hours":true}} -- immediate review.'
        ),
    }


@router.post("/mitigations/7-user-education")
def llm08_mit_user_education(prompt: Prompt):
    """Generates a personalised agency transparency report for the user."""
    body = parse_body(prompt)
    user_settings = body.get("settings", {"email": "extended_action", "finance": "suggestion_only", "system": "information_only"})
    user_id       = body.get("user_id", "user_demo")

    EXPLANATIONS = {
        "information_only": {
            "what_llm_can_do": "Provide information and analysis only",
            "what_llm_cannot_do": "Take any action on your behalf",
            "confirmation_needed": "Never -- but nothing will be done either",
            "examples": ["Show disk usage", "Summarise emails", "Display account balance"],
        },
        "suggestion_only": {
            "what_llm_can_do": "Suggest actions and draft content for you to execute",
            "what_llm_cannot_do": "Execute any action -- only suggests",
            "confirmation_needed": "You must take all actions manually",
            "examples": ["Draft an email (you send it)", "Propose a payment (you approve it)"],
        },
        "limited_action": {
            "what_llm_can_do": "Execute low-risk read-only and minor organisational actions",
            "what_llm_cannot_do": "Send emails, make payments, or change systems",
            "confirmation_needed": "Yes -- for every action",
            "examples": ["Categorise emails", "Set reminders", "Label calendar events"],
        },
        "extended_action": {
            "what_llm_can_do": "Execute a wider range of actions including sending and scheduling",
            "what_llm_cannot_do": "Make financial transactions above $1,000 or change critical systems",
            "confirmation_needed": "Yes -- with detailed review for significant actions",
            "examples": ["Send emails (after review)", "Pay single bills (after confirmation)", "Archive log files"],
        },
        "autonomous": {
            "what_llm_can_do": "Most actions with minimal confirmation",
            "what_llm_cannot_do": "Critical: execute trades, major system changes, delete production data",
            "confirmation_needed": "Rarely -- only for critical actions",
            "examples": ["Handle routine emails", "Schedule meetings", "Organise files"],
        },
    }

    domain_report = {}
    for domain, level in user_settings.items():
        exp = EXPLANATIONS.get(level, EXPLANATIONS["information_only"])
        domain_report[domain] = {
            "current_level": level,
            **exp,
            "how_to_change": f"Update your preferences under Settings -> AI Assistant -> {domain.title()} Agency",
        }

    user_actions = [e for e in _LLM08_ACTION_LOG[-10:] if not e["blocked"]]

    return {
        "mitigation": "7 -- User Education About Agency Levels",
        "strategy": "Transparent agency report: what LLM can/cannot do per domain, with plain-language explanations and change instructions.",
        "user_id": user_id,
        "your_agency_settings": user_settings,
        "domain_explanations": domain_report,
        "recent_actions_taken_on_your_behalf": user_actions,
        "total_actions_logged": len(_LLM08_ACTION_LOG),
        "tip": (
            'Try: {"settings":{"email":"autonomous","finance":"suggestion_only","system":"information_only"},"user_id":"alice"} '
            "to see a personalised report."
        ),
    }
