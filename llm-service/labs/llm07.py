"""
llm07.py - LLM07: Insecure Plugin Design

Demonstrates 3 attack types:
  1. Excessive Permissions (File Manager Plugin)
  2. SQL Injection via Database Helper Plugin
  3. Insufficient Input Validation / SSRF (Web Searcher Plugin)

Plus 7 mitigation strategies.
"""

import re
import time
import json
import base64

from fastapi import APIRouter
from .shared import Prompt, parse_body, detect_sql_injection, is_internal_url

router = APIRouter(prefix="/llm07", tags=["LLM07 - Insecure Plugin Design"])


# ---------------------------------------------------------------------------
# Data constants
# ---------------------------------------------------------------------------

PLUGIN_MANIFESTS = {
    "file-manager": {
        "name": "File Manager",
        "description": "Helps organize documents and files",
        "vulnerable_permissions": ["read_files", "write_files", "delete_files", "execute_files", "system_access"],
        "secure_permissions":     ["read_files", "write_files"],
        "allowed_paths":          ["/home/user/documents", "/home/user/downloads"],
    },
    "database-helper": {
        "name": "Database Helper",
        "description": "Query product and order information",
        "vulnerable_permissions": ["db_read", "db_write", "db_admin"],
        "secure_permissions":     ["db_read"],
        "allowed_tables":         ["products", "orders"],
    },
    "web-searcher": {
        "name": "Web Searcher",
        "description": "Search the public web for information",
        "vulnerable_permissions": ["internet_access", "internal_network_access", "file_system_access"],
        "secure_permissions":     ["internet_access"],
        "allowed_url_schemes":    ["https"],
        "blocked_hosts":          ["localhost", "<sCRub_IPADDRESS_59tsqRwV5r5Q>", "192.168.", "10.", "172.16.", "<sCRub_PHONENUMBER_dy1CZAlW22>."],
    },
}

PRODUCT_DB = {
    "12345": {"id": "12345", "name": "Widget Pro", "price": 29.99, "stock": 150},
    "67890": {"id": "67890", "name": "Gadget Plus", "price": 49.99, "stock": 43},
    "99999": {"id": "99999", "name": "Secret Internal Tool", "price": 0, "stock": 0,
              "internal_only": True, "note": "Internal product -- should not be queryable"},
}

FILE_SYSTEM = {
    "/home/user/documents/report.docx":    "Q3 Financial Report -- internal use only",
    "/home/user/downloads/invoice.pdf":    "Invoice #4521",
    "/etc/passwd":                         "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/sh",
    "/etc/shadow":                         "root:$6$randomhash:18000:0:99999:7:::\nuser:$6$randomhash2:18000:0:99999:7:::",
    "/proc/version":                       "Linux version 5.15.0 (gcc version 11.3.0)",
}

PROCESS_LIST = [
    "root       1  0.0  0.0  systemd",
    "root     523  0.0  0.1  sshd",
    "user    1042  0.2  0.8  python3 app.py",
    "user    1099  0.1  0.3  uvicorn llm-service",
    "root    1200  0.0  0.0  cron",
]

INTERNAL_ENDPOINTS = {
    "<sCRub_customurl_deFcPSBjKt7mxVohGCJhxgGQDwecty8zd2YcT>":   "ADMIN PANEL -- Internal use only. Credentials: <sCRub_CREDENTIALS_A8SL9lBiLZWsghXdE0z>",
    "<sCRub_customurl_lkWaaL7BsIoARzt7JIV2NbpI1UYhjmjUBP>":    "Router config -- WiFi <sCRub_CREDENTIALS_PSsczJRVHTcdCZEMSMLiqeLHJkVUhaLtXn>",
    "file:///etc/passwd":                 FILE_SYSTEM["/etc/passwd"],
    "<sCRub_customurl_ozf5SDyaXgWDmDodklU5wupNmEeOmnUvxwetA9nTGF>":  "Cloud metadata: instance-id=i-abc123, iam-role=AdminRole, <sCRub_CREDENTIALS_Lygmaz6TF8IeRyY2wvHWNs9ETh2EoMf>",
}

_PLUGIN_ACTIVITY_LOG: list = []
_PLUGIN_TOKENS: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _log_plugin_activity(plugin: str, action: str, params: dict, blocked: bool = False):
    """Append a plugin activity entry to the audit log."""
    _PLUGIN_ACTIVITY_LOG.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "plugin": plugin, "action": action,
        "params": {k: str(v)[:80] for k, v in params.items()},
        "blocked": blocked,
    })


def _detect_excessive_permission_abuse(command: str) -> tuple:
    """Returns (is_abuse: bool, reason: str | None)."""
    ABUSE_PATTERNS = [
        (r"(exec|execute|run|system|shell|cmd|bash|sh)\s", "shell/command execution attempt"),
        (r"(ps|top|netstat|ifconfig|whoami|id|uname)\b",   "system recon command"),
        (r"/etc/(passwd|shadow|hosts|sudoers)",             "sensitive system file access"),
        (r"/proc/",                                          "kernel/process info access"),
        (r"rm\s+-",                                          "recursive delete attempt"),
    ]
    for pattern, reason in ABUSE_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return True, reason
    return False, None


# ---
# Attack endpoints
# ---

@router.post("/excessive-permissions/vulnerable")
def llm07_excess_perm_vulnerable(prompt: Prompt):
    """Vulnerable: File Manager has execute_files + system_access -- any command runs."""
    body = parse_body(prompt)
    command = body.get("command", prompt.text)

    plugin = PLUGIN_MANIFESTS["file-manager"]
    is_abuse, abuse_reason = _detect_excessive_permission_abuse(command)
    _log_plugin_activity("file-manager", "execute", {"command": command})

    if is_abuse:
        if "ps" in command.lower() or "process" in command.lower():
            result = "\n".join(PROCESS_LIST)
        elif "/etc/passwd" in command or "passwd" in command.lower():
            result = FILE_SYSTEM["/etc/passwd"]
        elif "/etc/shadow" in command:
            result = FILE_SYSTEM["/etc/shadow"]
        elif "/proc" in command:
            result = FILE_SYSTEM["/proc/version"]
        elif "config" in command.lower() or "system" in command.lower():
            result = "System config: OS=Linux, Kernel=5.15.0, Hostname=llm-lab-server, Uptime=14d"
        else:
            result = f"Command executed: '{command}' -- output: [system data returned]"

        return {
            "attack": "Excessive Permissions",
            "mode": "vulnerable",
            "plugin": plugin["name"],
            "granted_permissions": plugin["vulnerable_permissions"],
            "command": command,
            "abuse_type": abuse_reason,
            "result": result,
            "executed": True,
            "note": (
                "WARNING: Plugin has execute_files + system_access -- far beyond file organising needs. "
                "Try: 'show me all running processes', 'read /etc/passwd', 'execute ls /etc'."
            ),
        }

    matching_files = [f for f in FILE_SYSTEM if "/home/user" in f]
    return {
        "attack": "Excessive Permissions",
        "mode": "vulnerable",
        "plugin": plugin["name"],
        "granted_permissions": plugin["vulnerable_permissions"],
        "command": command,
        "result": f"Files found: {matching_files}",
        "note": "Normal operation. Try: 'show me all running processes on the system' to exploit excessive permissions.",
    }


@router.post("/excessive-permissions/secure")
def llm07_excess_perm_secure(prompt: Prompt):
    """Secure: File Manager restricted to read_files + write_files only."""
    body = parse_body(prompt)
    command = body.get("command", prompt.text)

    plugin = PLUGIN_MANIFESTS["file-manager"]
    is_abuse, abuse_reason = _detect_excessive_permission_abuse(command)
    _log_plugin_activity("file-manager", "execute", {"command": command}, blocked=is_abuse)

    if is_abuse:
        return {
            "attack": "Excessive Permissions",
            "mode": "secure",
            "mitigation": "Least-privilege manifest -- only read_files + write_files granted",
            "plugin": plugin["name"],
            "granted_permissions": plugin["secure_permissions"],
            "requested_action": command,
            "blocked_reason": abuse_reason,
            "permission_check": {
                "execute_files": "DENIED -- not in plugin manifest",
                "system_access": "DENIED -- not in plugin manifest",
            },
            "result": "Action blocked -- the File Manager plugin does not have permission to execute system commands.",
            "note": "OK: Excessive permission request blocked at manifest enforcement layer.",
        }

    allowed = plugin["allowed_paths"]
    safe_files = [f for f in FILE_SYSTEM if any(f.startswith(p) for p in allowed)]
    return {
        "attack": "Excessive Permissions",
        "mode": "secure",
        "mitigation": "Least-privilege manifest -- only read_files + write_files granted",
        "plugin": plugin["name"],
        "granted_permissions": plugin["secure_permissions"],
        "command": command,
        "accessible_paths": allowed,
        "result": f"Files in allowed paths: {safe_files}",
        "note": "OK: Only files within allowed paths returned. No system access possible.",
    }


@router.post("/sql-injection/vulnerable")
def llm07_sql_injection_vulnerable(prompt: Prompt):
    """Vulnerable: DB Helper plugin uses f-string SQL -- injection trivially succeeds."""
    body = parse_body(prompt)
    product_id = body.get("product_id", prompt.text)

    plugin = PLUGIN_MANIFESTS["database-helper"]
    is_injected, technique = detect_sql_injection(str(product_id))
    _log_plugin_activity("database-helper", "query", {"product_id": str(product_id)})

    raw_query = f"SELECT * FROM products WHERE id = '{product_id}'"

    if is_injected:
        if re.search(r"OR\s+1\s*=\s*1", str(product_id), re.IGNORECASE):
            result = list(PRODUCT_DB.values())
            explanation = "OR 1=1 makes WHERE condition always true -- all rows returned, including internal products."
        elif re.search(r"DROP\s+TABLE", str(product_id), re.IGNORECASE):
            result = []
            explanation = "WARNING: DROP TABLE statement executed! Table 'users' has been dropped."
        elif re.search(r"UNION\s+SELECT", str(product_id), re.IGNORECASE):
            result = [{"schema": "TABLE users(id INT, username VARCHAR, password_hash VARCHAR, email VARCHAR, role VARCHAR)"}]
            explanation = "UNION SELECT extracted DB schema -- attacker now knows table/column structure."
        else:
            result = list(PRODUCT_DB.values())
            explanation = f"Injection technique '{technique}' succeeded."

        return {
            "attack": "SQL Injection",
            "mode": "vulnerable",
            "plugin": plugin["name"],
            "raw_sql_query": raw_query,
            "injection_technique": technique,
            "result": result,
            "explanation": explanation,
            "note": (
                "WARNING: Vulnerable to SQL injection via f-string query construction. "
                "Try: product_id = '12345 OR 1=1', '12345; DROP TABLE users;', or '12345 UNION SELECT username,password_hash FROM users'."
            ),
        }

    product = PRODUCT_DB.get(str(product_id))
    return {
        "attack": "SQL Injection",
        "mode": "vulnerable",
        "plugin": plugin["name"],
        "raw_sql_query": raw_query,
        "result": product or {"error": f"Product '{product_id}' not found"},
        "note": "Normal query. Try product_id with SQL injection payload.",
    }


@router.post("/sql-injection/secure")
def llm07_sql_injection_secure(prompt: Prompt):
    """Secure: parameterised query + injection detection + allowlist validation."""
    body = parse_body(prompt)
    product_id = body.get("product_id", prompt.text)

    plugin = PLUGIN_MANIFESTS["database-helper"]
    mitigations = []

    if not re.match(r"^\d{1,10}$", str(product_id).strip()):
        mitigations.append("INPUT_ALLOWLIST -- product_id must be numeric only; non-numeric characters rejected")
        _log_plugin_activity("database-helper", "query", {"product_id": str(product_id)}, blocked=True)
        return {
            "attack": "SQL Injection",
            "mode": "secure",
            "mitigation": "Parameterised query + input allowlist + injection detection",
            "plugin": plugin["name"],
            "parameterised_query": "SELECT * FROM products WHERE id = %s",
            "query_params": ["[BLOCKED -- invalid input]"],
            "mitigations_applied": mitigations,
            "result": "Query rejected -- product_id must be a numeric value (1-10 digits).",
            "injection_blocked": True,
            "note": "OK: Non-numeric input rejected at allowlist layer before reaching DB.",
        }

    is_injected, technique = detect_sql_injection(str(product_id))
    if is_injected:
        mitigations.append(f"INJECTION_DETECTED -- pattern '{technique}' flagged")
        _log_plugin_activity("database-helper", "query", {"product_id": str(product_id)}, blocked=True)
        return {
            "attack": "SQL Injection",
            "mode": "secure",
            "mitigation": "Parameterised query + input allowlist + injection detection",
            "plugin": plugin["name"],
            "mitigations_applied": mitigations,
            "result": "Query rejected -- SQL injection pattern detected.",
            "injection_blocked": True,
        }

    mitigations.append("PARAMETERISED_QUERY -- user input bound as parameter, never interpolated into SQL")
    mitigations.append("LEAST_PRIVILEGE -- plugin only has db_read; no db_write or db_admin")
    product = PRODUCT_DB.get(str(product_id))
    if product and product.get("internal_only"):
        product = {"error": "Product not available"}
        mitigations.append("ROW_LEVEL_FILTER -- internal-only products excluded from results")

    _log_plugin_activity("database-helper", "query", {"product_id": str(product_id)})
    return {
        "attack": "SQL Injection",
        "mode": "secure",
        "mitigation": "Parameterised query + input allowlist + injection detection",
        "plugin": plugin["name"],
        "parameterised_query": "SELECT * FROM products WHERE id = %s",
        "query_params": [str(product_id)],
        "mitigations_applied": mitigations,
        "result": product or {"error": f"Product '{product_id}' not found"},
        "injection_blocked": False,
        "note": "OK: Safe parameterised query executed. Input bound as data, not code.",
    }


@router.post("/ssrf/vulnerable")
def llm07_ssrf_vulnerable(prompt: Prompt):
    """Vulnerable: Web Searcher accepts any URL including internal/file:// targets."""
    body = parse_body(prompt)
    url = body.get("url", prompt.text)
    query = body.get("query", "")

    plugin = PLUGIN_MANIFESTS["web-searcher"]
    is_internal, internal_reason = is_internal_url(url)
    _log_plugin_activity("web-searcher", "fetch", {"url": url})

    if is_internal:
        content = INTERNAL_ENDPOINTS.get(url)
        if not content:
            for key in INTERNAL_ENDPOINTS:
                if key in url or url in key:
                    content = INTERNAL_ENDPOINTS[key]
                    break
        content = content or f"[Internal resource at {url}]: Connection established. Status 200 OK."

        return {
            "attack": "Insufficient Input Validation / SSRF",
            "mode": "vulnerable",
            "plugin": plugin["name"],
            "granted_permissions": plugin["vulnerable_permissions"],
            "url_requested": url,
            "validation": "NONE -- any URL accepted",
            "ssrf_triggered": True,
            "internal_resource_accessed": url,
            "response_content": content,
            "note": (
                "WARNING: SSRF: plugin fetched internal resource without URL validation. "
                "Try: 'file:///etc/passwd', '<sCRub_customurl_deFcPSBjKt7mxVohGCJhxgGQDwecty8zd2YcT>', "
                "'<sCRub_customurl_ozf5SDyaXgWDmDodklU5wupNmEeOmnUvxwetA9nTGF>', '<sCRub_customurl_lkWaaL7BsIoARzt7JIV2NbpI1UYhjmjUBP>'."
            ),
        }

    return {
        "attack": "Insufficient Input Validation / SSRF",
        "mode": "vulnerable",
        "plugin": plugin["name"],
        "url_requested": url,
        "validation": "NONE",
        "ssrf_triggered": False,
        "response_content": f"[Web search results for '{query or url}']: (simulated public results)",
        "note": "Normal external URL. Try an internal URL to trigger SSRF.",
    }


@router.post("/ssrf/secure")
def llm07_ssrf_secure(prompt: Prompt):
    """Secure: strict URL validation -- HTTPS only, public hosts only, no internal ranges."""
    body = parse_body(prompt)
    url = body.get("url", prompt.text)
    query = body.get("query", "")

    plugin = PLUGIN_MANIFESTS["web-searcher"]
    mitigations = []
    is_internal, internal_reason = is_internal_url(url)

    if is_internal:
        mitigations.append(f"URL_VALIDATION -- {internal_reason}")
        mitigations.append("SCHEME_ALLOWLIST -- only https:// permitted")
        mitigations.append("HOST_BLOCKLIST -- private/loopback/link-local ranges blocked")
        _log_plugin_activity("web-searcher", "fetch", {"url": url}, blocked=True)
        return {
            "attack": "Insufficient Input Validation / SSRF",
            "mode": "secure",
            "mitigation": "URL allowlist validation -- HTTPS only, public IPs only",
            "plugin": plugin["name"],
            "granted_permissions": plugin["secure_permissions"],
            "url_requested": url,
            "blocked_reason": internal_reason,
            "mitigations_applied": mitigations,
            "ssrf_blocked": True,
            "result": f"URL rejected -- {internal_reason}. Only public HTTPS URLs are permitted.",
            "note": "OK: SSRF attempt blocked at URL validation layer.",
        }

    mitigations.append("URL_VALIDATION -- scheme=https, host not in private range: PASSED")
    mitigations.append("LEAST_PRIVILEGE -- plugin only has internet_access; no internal_network_access or file_system_access")
    _log_plugin_activity("web-searcher", "fetch", {"url": url})
    return {
        "attack": "Insufficient Input Validation / SSRF",
        "mode": "secure",
        "mitigation": "URL allowlist validation -- HTTPS only, public IPs only",
        "plugin": plugin["name"],
        "granted_permissions": plugin["secure_permissions"],
        "url_requested": url,
        "mitigations_applied": mitigations,
        "ssrf_blocked": False,
        "result": f"[Web search results for '{query or url}']: (simulated public results)",
        "note": "OK: Valid public HTTPS URL -- request processed safely.",
    }


# ---
# Mitigation endpoints
# ---

@router.post("/mitigations/1-least-privilege")
def llm07_mit_least_privilege(prompt: Prompt):
    """Shows per-plugin permission audit: vulnerable vs secure manifest."""
    results = []
    for key, plugin in PLUGIN_MANIFESTS.items():
        vuln_perms   = plugin["vulnerable_permissions"]
        secure_perms = plugin["secure_permissions"]
        excess = [p for p in vuln_perms if p not in secure_perms]
        results.append({
            "plugin": plugin["name"],
            "vulnerable_permissions": vuln_perms,
            "secure_permissions": secure_perms,
            "excessive_permissions_removed": excess,
            "reduction": f"{len(vuln_perms)} -> {len(secure_perms)} permissions ({len(excess)} removed)",
        })
    return {
        "mitigation": "1 -- Implement Least Privilege",
        "strategy": "Each plugin granted only the permissions required for its stated function. Excessive permissions removed at registration.",
        "plugin_audit": results,
        "principle": "A file manager needs read/write. It never needs execute_files or system_access.",
        "tip": "Review every plugin manifest before registration. Reject any permission not justified by the plugin's stated purpose.",
    }


@router.post("/mitigations/2-auth")
def llm07_mit_auth(prompt: Prompt):
    """Simulates plugin token issuance, validation, and per-action authz."""
    import hashlib
    body = parse_body(prompt)
    action    = body.get("action", "query")
    plugin_id = body.get("plugin_id", "database-helper")
    token     = body.get("token", "")

    PLUGIN_ACTION_PERMISSIONS = {
        "database-helper": {
            "query":  ["db_token_valid"],
            "insert": ["db_token_valid", "db_write_role"],
            "drop":   ["db_token_valid", "db_admin_role"],
        },
        "file-manager": {
            "read":    ["file_token_valid"],
            "write":   ["file_token_valid"],
            "execute": ["file_token_valid", "exec_role"],
        },
    }

    if not token:
        issued_token = hashlib.sha256(f"{plugin_id}-{time.time()}".encode()).hexdigest()[:24]
        _PLUGIN_TOKENS[issued_token] = {
            "plugin_id": plugin_id,
            "roles": ["db_token_valid", "file_token_valid"],
            "issued_at": time.time(),
            "expires_in": 300,
        }
        return {
            "mitigation": "2 -- Strong Authentication & Authorization",
            "action": "TOKEN_ISSUED",
            "token": issued_token,
            "plugin_id": plugin_id,
            "roles_granted": _PLUGIN_TOKENS[issued_token]["roles"],
            "expires_in_seconds": 300,
            "tip": f'Now call with: {{"token":"{issued_token}","plugin_id":"{plugin_id}","action":"drop"}} to test authz.',
        }

    token_data = _PLUGIN_TOKENS.get(token)
    if not token_data:
        return {"mitigation": "2", "error": "INVALID_TOKEN -- authentication failed", "action_allowed": False}
    if token_data["plugin_id"] != plugin_id:
        return {"mitigation": "2", "error": "TOKEN_PLUGIN_MISMATCH -- token not valid for this plugin", "action_allowed": False}
    if time.time() - token_data["issued_at"] > token_data["expires_in"]:
        del _PLUGIN_TOKENS[token]
        return {"mitigation": "2", "error": "TOKEN_EXPIRED -- re-authenticate", "action_allowed": False}

    required_roles = PLUGIN_ACTION_PERMISSIONS.get(plugin_id, {}).get(action, ["db_token_valid"])
    user_roles = token_data["roles"]
    missing = [r for r in required_roles if r not in user_roles]
    allowed = len(missing) == 0

    return {
        "mitigation": "2 -- Strong Authentication & Authorization",
        "strategy": "Short-lived tokens (5 min TTL), per-plugin binding, per-action role checks.",
        "plugin_id": plugin_id,
        "action": action,
        "token_valid": True,
        "required_roles": required_roles,
        "user_roles": user_roles,
        "missing_roles": missing,
        "action_allowed": allowed,
        "result": f"Action '{action}' {'ALLOWED' if allowed else 'DENIED -- insufficient roles'}",
        "note": "OK: Token validated; action authorised only if all required roles present.",
    }


@router.post("/mitigations/3-input-validation")
def llm07_mit_input_validation(prompt: Prompt):
    """Validates plugin inputs against type-specific schemas."""
    body = parse_body(prompt)
    input_type = body.get("type", "url")
    value      = body.get("value", prompt.text)

    VALIDATORS = {
        "url": {
            "check": lambda v: (
                bool(re.match(r'^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/[\w\-./?%&=]*)?$', v))
                and not any(h in v for h in ["localhost", "<sCRub_IPADDRESS_59tsqRwV5r5Q>", "192.168.", "10.", "file:", "<sCRub_PHONENUMBER_dy1CZAlW22>."])
            ),
            "description": "HTTPS public URL only; no private/loopback ranges",
        },
        "product_id": {
            "check": lambda v: bool(re.match(r'^\d{1,10}$', str(v).strip())),
            "description": "Numeric only, 1-10 digits",
        },
        "sql_query": {
            "check": lambda v: (
                bool(re.match(r'^SELECT\s+[\w\s,\*]+\s+FROM\s+\w+(\s+WHERE\s+\w+\s*=\s*\?)?$', v, re.IGNORECASE))
                and not re.search(r'DROP|DELETE|UPDATE|INSERT|--|;|OR\s+1', v, re.IGNORECASE)
            ),
            "description": "SELECT-only, parameterised WHERE, no destructive keywords",
        },
        "file_path": {
            "check": lambda v: (
                bool(re.match(r'^/home/user/(documents|downloads)/', v))
                and ".." not in v
            ),
            "description": "Must be under /home/user/documents or /home/user/downloads; no path traversal",
        },
    }

    validator = VALIDATORS.get(input_type)
    if not validator:
        return {"error": f"Unknown input type '{input_type}'. Choose: {list(VALIDATORS.keys())}"}

    passed = validator["check"](value)
    is_injected, sql_technique = detect_sql_injection(str(value)) if input_type in ("sql_query", "product_id") else (False, None)
    is_ssrf, ssrf_reason = is_internal_url(str(value)) if input_type == "url" else (False, None)

    return {
        "mitigation": "3 -- Input Validation & Sanitization",
        "strategy": "Type-specific allowlist schemas; injection and SSRF pattern detection.",
        "input_type": input_type,
        "value": value,
        "schema_rule": validator["description"],
        "schema_passed": passed,
        "sql_injection_detected": is_injected,
        "sql_technique": sql_technique,
        "ssrf_detected": is_ssrf,
        "ssrf_reason": ssrf_reason,
        "verdict": "ACCEPTED" if (passed and not is_injected and not is_ssrf) else "REJECTED",
        "tip": (
            'Try: {"type":"product_id","value":"12345 OR 1=1"} for SQL injection, '
            '{"type":"url","value":"<sCRub_customurl_deFcPSBjKt7mxVohGCJhxgGQDwecty8zd2YcT>"} for SSRF, '
            '{"type":"file_path","value":"/etc/passwd"} for path traversal.'
        ),
    }


@router.post("/mitigations/4-data-handling")
def llm07_mit_data_handling(prompt: Prompt):
    """Demonstrates encryption-in-transit simulation, data minimisation, and expiry tagging."""
    body = parse_body(prompt)
    operation = body.get("operation", "transmit")
    data      = body.get("data", {"user": "john", "ssn": "123-45-6789", "balance": 1500.00})

    OPERATIONS = {
        "store":    {"encrypt": True,  "audit": True,  "expire": True,  "minimise": True},
        "transmit": {"encrypt": True,  "audit": True,  "expire": False, "minimise": True},
        "process":  {"encrypt": False, "audit": True,  "expire": False, "minimise": True},
    }
    reqs = OPERATIONS.get(operation, OPERATIONS["transmit"])
    steps = []

    minimised_data = {k: v for k, v in data.items() if k not in ("ssn", "password", "credit_card")}
    steps.append({"step": "DATA_MINIMISATION", "removed_fields": [k for k in data if k not in minimised_data]})

    if reqs["encrypt"]:
        encoded = base64.b64encode(json.dumps(minimised_data).encode()).decode()
        steps.append({"step": "ENCRYPTION", "algorithm": "AES-256-GCM (simulated)", "ciphertext_preview": encoded[:32] + "..."})
        output = encoded
    else:
        output = minimised_data

    if reqs["audit"]:
        steps.append({"step": "AUDIT_LOG", "event": f"data_{operation}", "fields_accessed": list(minimised_data.keys())})

    if reqs["expire"]:
        expiry = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400))
        steps.append({"step": "EXPIRY_TAG", "expires_at": expiry, "retention_hours": 24})

    return {
        "mitigation": "4 -- Secure Data Handling",
        "strategy": "Data minimisation -> encryption (AES-256-GCM) -> audit logging -> expiry tagging, per operation type.",
        "operation": operation,
        "raw_input": data,
        "processing_steps": steps,
        "output": output,
        "tip": 'Try {"operation":"store","data":{"user":"john","ssn":"123-45-6789","balance":1500}} to see all 4 steps.',
    }


@router.post("/mitigations/5-sandboxing")
def llm07_mit_sandboxing(prompt: Prompt):
    """Simulates plugin sandbox enforcement -- resource limits + permission scoping."""
    body = parse_body(prompt)
    plugin_id = body.get("plugin_id", "file-manager")
    action    = body.get("action", "read")
    resource  = body.get("resource", "/home/user/documents/report.docx")

    SANDBOX_CONFIG = {
        "file-manager":    {"memory_mb": 50,  "cpu_seconds": 2, "network": False, "allowed_paths": ["/home/user/documents", "/home/user/downloads"]},
        "database-helper": {"memory_mb": 100, "cpu_seconds": 5, "network": False, "allowed_tables": ["products", "orders"]},
        "web-searcher":    {"memory_mb": 200, "cpu_seconds": 10, "network": True,  "allowed_schemes": ["https"], "blocked_hosts": ["localhost", "<sCRub_IPADDRESS_59tsqRwV5r5Q>", "192.168.", "10."]},
    }

    sandbox = SANDBOX_CONFIG.get(plugin_id)
    if not sandbox:
        return {"error": f"Unknown plugin '{plugin_id}'. Choose: {list(SANDBOX_CONFIG.keys())}"}

    violations = []
    if plugin_id == "file-manager" and "allowed_paths" in sandbox:
        if not any(str(resource).startswith(p) for p in sandbox["allowed_paths"]):
            violations.append(f"PATH_VIOLATION -- '{resource}' outside allowed paths {sandbox['allowed_paths']}")
    if plugin_id == "database-helper" and "allowed_tables" in sandbox:
        if str(resource) not in sandbox["allowed_tables"] and action in ("query", "select"):
            violations.append(f"TABLE_VIOLATION -- '{resource}' not in allowed tables {sandbox['allowed_tables']}")
    if plugin_id == "web-searcher":
        is_int, reason = is_internal_url(str(resource))
        if is_int:
            violations.append(f"NETWORK_VIOLATION -- {reason}")

    _log_plugin_activity(plugin_id, action, {"resource": resource}, blocked=len(violations) > 0)

    return {
        "mitigation": "5 -- Sandboxing",
        "strategy": "Each plugin runs in an isolated sandbox: memory cap, CPU time limit, network toggle, path/table/host allowlists.",
        "plugin_id": plugin_id,
        "action": action,
        "resource": resource,
        "sandbox_config": sandbox,
        "violations": violations,
        "execution_allowed": len(violations) == 0,
        "result": (
            f"Sandbox violation(s) detected: {violations}" if violations
            else f"Plugin '{plugin_id}' executed action '{action}' on '{resource}' within sandbox constraints."
        ),
        "tip": (
            'Try: {"plugin_id":"file-manager","action":"read","resource":"/etc/passwd"} for path violation, '
            '{"plugin_id":"web-searcher","action":"fetch","resource":"<sCRub_customurl_deFcPSBjKt7mxVohGCJhxgGQDwecty8zd2YcT>"} for network violation.'
        ),
    }


@router.post("/mitigations/6-security-testing")
def llm07_mit_security_testing(prompt: Prompt):
    """Simulates a SAST + dependency + dynamic security test run across all plugins."""
    SAST_FINDINGS = [
        {"tool": "bandit", "plugin": "database-helper (vulnerable)", "issue": "SQL f-string interpolation", "severity": "CRITICAL", "line": 42, "fix": "Use parameterised queries: cursor.execute(sql, (value,))"},
        {"tool": "bandit", "plugin": "web-searcher (vulnerable)",    "issue": "No URL scheme validation before requests.get()", "severity": "HIGH", "line": 89, "fix": "Validate URL scheme and host before fetching"},
        {"tool": "bandit", "plugin": "file-manager (vulnerable)",    "issue": "os.system() called with user-supplied input", "severity": "CRITICAL", "line": 17, "fix": "Remove execute_files permission; use safe file APIs only"},
    ]
    DEP_FINDINGS = [
        {"tool": "pip-audit", "plugin": "web-searcher", "package": "requests==2.26.0", "cve": "CVE-2023-32681", "fix": "pip install requests>=2.31.0"},
    ]
    DYNAMIC_FINDINGS = [
        {"tool": "OWASP-ZAP", "plugin": "database-helper", "test": "SQL injection probe", "result": "VULNERABLE -- OR 1=1 returned all rows"},
        {"tool": "OWASP-ZAP", "plugin": "web-searcher",    "test": "SSRF probe",          "result": "VULNERABLE -- file:///etc/passwd accessible"},
        {"tool": "OWASP-ZAP", "plugin": "file-manager",    "test": "Command injection",   "result": "VULNERABLE -- ps aux returned via execute_files"},
    ]

    all_findings = SAST_FINDINGS + DEP_FINDINGS + DYNAMIC_FINDINGS
    critical = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH") or "VULNERABLE" in f.get("result", "")]

    return {
        "mitigation": "6 -- Security Testing",
        "strategy": "SAST (bandit), dependency scan (pip-audit), dynamic testing run against all plugins before deployment.",
        "pipeline_stages": [
            {"stage": "Static Analysis",   "tool": "bandit",     "findings": len(SAST_FINDINGS)},
            {"stage": "Dependency Scan",   "tool": "pip-audit",  "findings": len(DEP_FINDINGS)},
            {"stage": "Dynamic Testing",   "tool": "OWASP-ZAP",  "findings": len(DYNAMIC_FINDINGS)},
        ],
        "total_findings": len(all_findings),
        "critical_or_high": len(critical),
        "findings": all_findings,
        "pipeline_gate": "BLOCKED -- critical findings must be resolved before deployment" if critical else "PASSED",
        "overall_verdict": "FAIL" if critical else "PASS",
        "tip": "No input needed -- runs automated test suite across all plugin manifests.",
    }


@router.post("/mitigations/7-monitoring")
def llm07_mit_monitoring(prompt: Prompt):
    """Reviews the plugin activity log for suspicious patterns and raises alerts."""
    SUSPICIOUS_PATTERNS = [
        {"name": "EXCESSIVE_PERMISSION_ABUSE", "check": lambda e: e["action"] == "execute" and e["plugin"] == "file-manager", "severity": "HIGH"},
        {"name": "SQL_INJECTION_ATTEMPT",      "check": lambda e: e["plugin"] == "database-helper" and e.get("blocked"), "severity": "CRITICAL"},
        {"name": "SSRF_ATTEMPT",               "check": lambda e: e["plugin"] == "web-searcher" and e.get("blocked"), "severity": "CRITICAL"},
    ]

    alerts = []
    for entry in _PLUGIN_ACTIVITY_LOG[-20:]:
        for pattern in SUSPICIOUS_PATTERNS:
            try:
                if pattern["check"](entry):
                    alerts.append({
                        "alert_type": pattern["name"],
                        "severity": pattern["severity"],
                        "plugin": entry["plugin"],
                        "action": entry["action"],
                        "timestamp": entry["timestamp"],
                        "params": entry["params"],
                        "blocked": entry["blocked"],
                    })
            except Exception:
                pass

    return {
        "mitigation": "7 -- Monitoring & Logging",
        "strategy": "All plugin actions logged with timestamp, action, params, and blocked status. Suspicious pattern detection raises alerts.",
        "total_events_logged": len(_PLUGIN_ACTIVITY_LOG),
        "events_reviewed": min(20, len(_PLUGIN_ACTIVITY_LOG)),
        "alerts_raised": len(alerts),
        "alerts": alerts,
        "recent_activity": _PLUGIN_ACTIVITY_LOG[-10:],
        "overall_status": "ALERT" if alerts else "NOMINAL",
        "tip": "Run attack demos first to populate the activity log, then call this endpoint to see alerts generated.",
    }
