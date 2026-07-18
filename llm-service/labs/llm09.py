"""
llm09.py - LLM09: Overreliance

Demonstrates 3 scenario endpoints:
  1. Medical Advice
  2. Legal Advice
  3. Code Security

Plus 7 mitigation strategies.
"""

import re
import time
import json

from fastapi import APIRouter
from .shared import Prompt, parse_body

router = APIRouter(prefix="/llm09", tags=["LLM09 - Overreliance"])


# ---------------------------------------------------------------------------
# Data constants
# ---------------------------------------------------------------------------

MEDICAL_RESPONSES = {
    "vulnerable": {
        "response": (
            "Based on your symptoms of headaches and dizziness for the past week, here are the most likely causes:\n\n"
            "1. Dehydration -- drink more water immediately\n"
            "2. Tension headache -- take ibuprofen 400mg every 6 hours\n"
            "3. High blood pressure -- monitor with a home cuff\n"
            "4. Brain tumor (rare but possible) -- monitor for vision changes\n"
            "5. Inner ear disorder -- try antihistamines for dizziness\n\n"
            "Treatment: Rest, hydrate, and take OTC pain relievers. "
            "If symptoms persist beyond 2 weeks, consider seeing a doctor."
        ),
        "flaws": [
            "No essential diagnostic questions asked (age, medications, severity, onset pattern)",
            "Lists brain tumour alongside dehydration without triage context",
            "Recommends specific medication dosages without knowing patient history",
            "Buries 'see a doctor' as an afterthought after 2 weeks",
            "No disclaimer that this is not medical advice",
            "Presents speculation as diagnosis with false confidence",
        ],
    },
    "secure": {
        "response": (
            "I can share some general information about headaches and dizziness, but I want to be clear upfront:\n\n"
            "WARNING DISCLAIMER: I am an AI, not a doctor. This is NOT medical advice. "
            "Persistent headaches and dizziness lasting a week warrant evaluation by a qualified healthcare professional -- please consult one.\n\n"
            "General information (LOW-MEDIUM confidence -- individual cases vary widely):\n"
            "YELLOW Common causes include tension, dehydration, or sleep disruption.\n"
            "RED However, a week of persistent symptoms should not be self-diagnosed.\n"
            "RED The specific combination of headache + dizziness can indicate conditions requiring tests that only a clinician can perform.\n\n"
            "What I cannot do:\n"
            "- Ask you the diagnostic questions a doctor would (age, medications, other symptoms, severity scale)\n"
            "- Examine you or order tests\n"
            "- Safely recommend specific medications without knowing your history\n\n"
            "Please contact your GP, urgent care, or emergency services if symptoms are severe, sudden, or worsening."
        ),
        "mitigations": [
            "Prominent upfront disclaimer -- not medical advice",
            "Confidence indicators on each claim",
            "Explicit list of what AI cannot do that a doctor can",
            "Strong recommendation to seek professional care -- not buried",
            "No medication dosage recommendations",
            "Verification guidance: GP / urgent care / emergency",
        ],
    },
}

LEGAL_RESPONSES = {
    "vulnerable": {
        "response": (
            "Your landlord entering without notice is illegal in most places. Here is what you should do:\n\n"
            "1. Under tenant rights law, landlords must give 24-48 hours notice before entry.\n"
            "2. Document the incident -- date, time, reason given.\n"
            "3. Send a formal written warning to your landlord citing the Residential Tenancies Act.\n"
            "4. If it happens again, file a complaint with your local housing authority.\n"
            "5. You may be entitled to terminate your lease without penalty.\n"
            "6. Consider small claims court for damages -- you could recover $500-$2,000.\n\n"
            "This is a clear violation of your rights. Act quickly -- you have 30 days to file a complaint."
        ),
        "flaws": [
            "No jurisdiction asked -- laws differ enormously by country/state/province",
            "Cites 'Residential Tenancies Act' generically -- may not exist or apply in user's location",
            "Claims '30 days to file' without knowing applicable statute of limitations",
            "Specific damages range ($500-$2,000) fabricated without jurisdictional basis",
            "May miss exceptions (emergency entry, abandoned property, lease terms)",
            "No disclaimer that this is not legal advice",
            "Presented as authoritative legal analysis",
        ],
    },
    "secure": {
        "response": (
            "WARNING DISCLAIMER: I am an AI, not a lawyer. This is NOT legal advice. Laws on landlord entry vary significantly "
            "by jurisdiction -- what applies in one country/state may be completely different in another. "
            "Please consult a qualified attorney or tenant rights organisation in your area.\n\n"
            "General information (MODERATE confidence -- jurisdiction-dependent):\n"
            "GREEN Many jurisdictions do require landlords to give advance notice (commonly 24-48 hours) before non-emergency entry.\n"
            "YELLOW However, exceptions typically exist for emergencies, abandonment, or specific lease provisions.\n"
            "RED I do not know your jurisdiction -- the specific law, notice period, penalties, and time limits to file a complaint all depend on where you live.\n\n"
            "What I cannot do:\n"
            "- Confirm which law applies to your specific location\n"
            "- Tell you accurate filing deadlines or recoverable damages\n"
            "- Review your lease for relevant clauses\n\n"
            "Verification steps:\n"
            "- Search '[your city/state] landlord entry notice law'\n"
            "- Contact a local tenant rights organisation (often free)\n"
            "- Consult a housing attorney -- many offer free initial consultations"
        ),
        "mitigations": [
            "Upfront disclaimer -- not legal advice",
            "Explicit jurisdiction caveat -- laws vary by location",
            "Confidence indicators per claim",
            "No fabricated statute names, deadlines, or damages",
            "Clear list of what AI cannot determine",
            "Concrete verification steps provided",
        ],
    },
}

CODE_SECURITY_RESPONSES = {
    "vulnerable": {
        "response": (
            "Here's a function to securely store user passwords:\n\n"
            "```python\n"
            "import hashlib\n\n"
            "def store_password(username, password, db):\n"
            "    # Hash the password using SHA-256\n"
            "    hashed = hashlib.sha256(password.encode()).hexdigest()\n"
            "    db.execute('INSERT INTO users (username, password) VALUES (?, ?)',\n"
            "               (username, hashed))\n"
            "    db.commit()\n"
            "    print('Password stored securely!')\n"
            "```\n\n"
            "This uses SHA-256 hashing which is a strong cryptographic algorithm. "
            "Your passwords are now safely stored!"
        ),
        "flaws": [
            "SHA-256 is a general-purpose hash -- NOT designed for passwords (too fast, GPU-crackable)",
            "No salt -- identical passwords produce identical hashes (rainbow table attack)",
            "No iteration/work factor -- brute-force is trivial with modern hardware",
            "Should use bcrypt, scrypt, or Argon2 instead",
            "Presented as 'secure' with false confidence -- dangerous for security-critical code",
            "No recommendation to have code security-reviewed",
            "Vulnerable to timing attacks in comparison (no constant-time compare)",
        ],
    },
    "secure": {
        "response": (
            "WARNING SECURITY DISCLAIMER: Password hashing is security-critical code. "
            "AI-generated security code should ALWAYS be reviewed by a security professional before production use.\n\n"
            "RED AVOID (common mistakes):\n"
            "```python\n"
            "# INSECURE -- DO NOT USE\n"
            "import hashlib\n"
            "hashed = hashlib.sha256(password.encode()).hexdigest()  # No salt, wrong algorithm\n"
            "```\n\n"
            "GREEN RECOMMENDED (bcrypt -- designed for password hashing):\n"
            "```python\n"
            "import bcrypt  # pip install bcrypt\n\n"
            "def store_password(username, password, db):\n"
            "    # bcrypt automatically generates a salt and is deliberately slow\n"
            "    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))\n"
            "    db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',\n"
            "               (username, password_hash))\n"
            "    db.commit()\n\n"
            "def verify_password(password, stored_hash):\n"
            "    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)  # Constant-time\n"
            "```\n\n"
            "Why bcrypt over SHA-256:\n"
            "GREEN Built-in salt (prevents rainbow tables)\n"
            "GREEN Configurable work factor (rounds=12 slows brute-force)\n"
            "GREEN Designed specifically for password storage\n"
            "YELLOW Consider Argon2 (argon2-cffi) for new projects -- current OWASP recommendation\n\n"
            "Next steps: Have this code reviewed by a security engineer before deployment."
        ),
        "mitigations": [
            "Security disclaimer upfront -- AI code must be reviewed",
            "Explicit 'AVOID' section showing the dangerous pattern",
            "Confidence indicators on each recommendation",
            "Correct algorithm (bcrypt/Argon2) with explanation of WHY",
            "Points to OWASP as verification source",
            "Recommends professional security review before production",
        ],
    },
}

HALLUCINATION_EXAMPLES = [
    {
        "domain": "legal",
        "query": "Cite cases supporting fair use in software APIs",
        "hallucinated_response": "In Oracle v. Google (2021), the Supreme Court ruled 9-0 that all API interfaces are inherently non-copyrightable, establishing a broad safe harbour for any software API reuse.",
        "actual_fact": "Oracle v. Google (2021) ruled 6-2 (not 9-0) on fair use grounds -- it did NOT rule APIs are non-copyrightable. The hallucinated response misstates both the vote and the holding.",
        "risk": "A lawyer citing this fabricated ruling could face sanctions from the court.",
    },
    {
        "domain": "medical",
        "query": "What is the standard dosage of metformin for Type 2 diabetes?",
        "hallucinated_response": "The standard starting dose is 1000mg twice daily. Metformin has no contraindications and is safe for all patients including those with kidney disease.",
        "actual_fact": "Starting dose is typically 500mg once or twice daily, titrated up. Metformin IS contraindicated in significant renal impairment (eGFR < 30). The hallucination could cause serious harm.",
        "risk": "Patient with kidney disease given contraindicated medication due to AI misinformation.",
    },
    {
        "domain": "finance",
        "query": "What is the current capital gains tax rate in the US?",
        "hallucinated_response": "The long-term capital gains rate is 15% for all income levels. Short-term gains are taxed at 25%.",
        "actual_fact": "Long-term rates are 0%, 15%, or 20% depending on income. Short-term rates match ordinary income tax brackets (up to 37%). Both figures in the hallucination are wrong.",
        "risk": "Incorrect tax planning leading to underpayment penalties.",
    },
]

_LLM09_INTERACTION_LOG: list = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_domain(query: str) -> str:
    """Classify query into a domain category."""
    q = query.lower()
    if any(w in q for w in ["headache", "dizzy", "symptom", "medical", "pain", "treatment", "dose", "medication", "diagnos"]):
        return "medical"
    if any(w in q for w in ["landlord", "tenant", "lease", "legal", "law", "lawsuit", "court", "attorney", "contract", "rights"]):
        return "legal"
    if any(w in q for w in ["password", "hash", "encrypt", "code", "function", "security", "sql", "inject", "crypto", "auth"]):
        return "security"
    if any(w in q for w in ["invest", "stock", "tax", "financial", "return", "portfolio", "fund", "capital gain"]):
        return "financial"
    return "general"


def _confidence_score(domain: str) -> float:
    """Simulated confidence -- medical/legal/financial are inherently lower for AI."""
    return {"medical": 0.45, "legal": 0.40, "security": 0.60, "financial": 0.50, "general": 0.70}.get(domain, 0.65)


# ---
# Scenario endpoints
# ---

@router.post("/medical/vulnerable")
def llm09_medical_vulnerable(prompt: Prompt):
    """Vulnerable: authoritative-sounding response with no disclaimer or confidence indicators."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "medical", "mode": "vulnerable", "query": query[:80]})
    data = MEDICAL_RESPONSES["vulnerable"]
    return {
        "scenario": "Medical Advice", "mode": "vulnerable",
        "query": query,
        "response": data["response"],
        "disclaimer_present": False,
        "confidence_indicators": False,
        "verification_guidance": False,
        "known_flaws": data["flaws"],
        "overreliance_risk": "HIGH -- patient may self-diagnose and self-medicate based on authoritative-sounding but unverified AI output.",
        "note": "WARNING: Response sounds authoritative. No disclaimer. Medication dosages recommended without knowing patient history.",
    }


@router.post("/medical/secure")
def llm09_medical_secure(prompt: Prompt):
    """Secure: prominent disclaimer, confidence indicators, explicit limitations, professional referral."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "medical", "mode": "secure", "query": query[:80]})
    data = MEDICAL_RESPONSES["secure"]
    return {
        "scenario": "Medical Advice", "mode": "secure",
        "query": query,
        "response": data["response"],
        "disclaimer_present": True,
        "confidence_indicators": True,
        "verification_guidance": True,
        "mitigations_applied": data["mitigations"],
        "domain_confidence": _confidence_score("medical"),
        "note": "OK: Prominent disclaimer, confidence indicators, explicit limitations, strong referral to professional care.",
    }


@router.post("/legal/vulnerable")
def llm09_legal_vulnerable(prompt: Prompt):
    """Vulnerable: cites jurisdiction-specific laws and damages without knowing the user's location."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "legal", "mode": "vulnerable", "query": query[:80]})
    data = LEGAL_RESPONSES["vulnerable"]
    return {
        "scenario": "Legal Advice", "mode": "vulnerable",
        "query": query,
        "response": data["response"],
        "disclaimer_present": False,
        "jurisdiction_asked": False,
        "sources_cited": False,
        "known_flaws": data["flaws"],
        "overreliance_risk": "HIGH -- user may take legal action based on fabricated statutes and inapplicable law.",
        "note": "WARNING: Cites specific statutes, deadlines, and damages without knowing the user's jurisdiction. All may be wrong.",
    }


@router.post("/legal/secure")
def llm09_legal_secure(prompt: Prompt):
    """Secure: jurisdiction caveat, no fabricated statutes, explicit limitations, verification steps."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "legal", "mode": "secure", "query": query[:80]})
    data = LEGAL_RESPONSES["secure"]
    return {
        "scenario": "Legal Advice", "mode": "secure",
        "query": query,
        "response": data["response"],
        "disclaimer_present": True,
        "jurisdiction_caveat": True,
        "confidence_indicators": True,
        "verification_steps_provided": True,
        "mitigations_applied": data["mitigations"],
        "domain_confidence": _confidence_score("legal"),
        "note": "OK: Jurisdiction caveat, no fabricated statutes, explicit limitations, concrete verification steps.",
    }


@router.post("/code-security/vulnerable")
def llm09_code_security_vulnerable(prompt: Prompt):
    """Vulnerable: insecure SHA-256 password hashing presented as 'secure'."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "code-security", "mode": "vulnerable", "query": query[:80]})
    data = CODE_SECURITY_RESPONSES["vulnerable"]
    return {
        "scenario": "Code Security", "mode": "vulnerable",
        "query": query,
        "response": data["response"],
        "security_disclaimer_present": False,
        "review_recommended": False,
        "known_flaws": data["flaws"],
        "overreliance_risk": "CRITICAL -- insecure password storage code deployed to production, all user passwords crackable.",
        "note": "WARNING: SHA-256 without salt is cryptographically broken for password storage. Presented as 'secure' without caveats.",
    }


@router.post("/code-security/secure")
def llm09_code_security_secure(prompt: Prompt):
    """Secure: security disclaimer, AVOID section, correct bcrypt usage, professional review recommended."""
    body = parse_body(prompt)
    query = body.get("query", prompt.text)
    _LLM09_INTERACTION_LOG.append({"scenario": "code-security", "mode": "secure", "query": query[:80]})
    data = CODE_SECURITY_RESPONSES["secure"]
    return {
        "scenario": "Code Security", "mode": "secure",
        "query": query,
        "response": data["response"],
        "security_disclaimer_present": True,
        "avoid_section_included": True,
        "correct_algorithm_explained": True,
        "owasp_reference_included": True,
        "review_recommended": True,
        "mitigations_applied": data["mitigations"],
        "domain_confidence": _confidence_score("security"),
        "note": "OK: Security disclaimer, AVOID pattern shown, correct bcrypt usage, Argon2 mentioned, professional review recommended.",
    }


# ---
# Mitigation endpoints
# ---

@router.post("/mitigations/1-disclaimers")
def llm09_mit_disclaimers(prompt: Prompt):
    """Generates domain-specific disclaimers + confidence-adjusted warnings."""
    body = parse_body(prompt)
    domain     = body.get("domain", "medical")
    confidence = float(body.get("confidence", 0.45))

    DOMAIN_DISCLAIMERS = {
        "medical":   "This information is NOT medical advice. The AI may make mistakes or omit critical information. Always consult a qualified healthcare professional for medical concerns.",
        "legal":     "This information is NOT legal advice. Laws vary significantly by jurisdiction. The AI may cite outdated or inapplicable information. Consult a qualified attorney.",
        "financial": "This information is NOT financial advice. The AI may miss important factors. Consult a qualified financial advisor before making decisions.",
        "security":  "This code has NOT been security audited. The AI may suggest insecure practices. Security-critical code must be reviewed by a security professional.",
        "general":   "This information was generated by an AI and may contain errors. Verify important information from reliable sources.",
    }

    if confidence < 0.3:
        conf_note = "LOW confidence -- verification strongly recommended before any use."
    elif confidence < 0.7:
        conf_note = "MODERATE confidence -- verification recommended for important decisions."
    else:
        conf_note = "HIGH confidence -- but even high-confidence AI outputs should be verified for critical matters."

    base = DOMAIN_DISCLAIMERS.get(domain, DOMAIN_DISCLAIMERS["general"])
    return {
        "mitigation": "1 -- Clear Disclaimers & Limitations",
        "strategy": "Domain-specific disclaimers + confidence-adjusted warnings shown prominently before/after every response.",
        "domain": domain,
        "confidence_score": confidence,
        "base_disclaimer": base,
        "confidence_note": conf_note,
        "full_disclaimer": f"{base} {conf_note}",
        "placement_guidance": "Show disclaimer BEFORE the response -- not buried at the bottom where users may not read it.",
        "tip": 'Try: {"domain":"legal","confidence":0.35} or {"domain":"security","confidence":0.60}',
    }


@router.post("/mitigations/2-citations")
def llm09_mit_citations(prompt: Prompt):
    """Generates citation-enhanced responses for factual claims."""
    body = parse_body(prompt)
    query  = body.get("query", "What is bcrypt and why is it used for passwords?")
    domain = body.get("domain", _get_domain(body.get("query", "")))

    CITATION_MAP = {
        "security": [
            {"claim": "bcrypt is recommended for password hashing", "source": "OWASP Password Storage Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html", "confidence": "high"},
            {"claim": "SHA-256 is not suitable for password storage", "source": "NIST SP 800-63B Digital Identity Guidelines", "url": "https://pages.nist.gov/800-63-3/sp800-63b.html", "confidence": "high"},
            {"claim": "Argon2 is the current Password Hashing Competition winner", "source": "Password Hashing Competition (PHC)", "url": "https://www.password-hashing.net/", "confidence": "high"},
        ],
        "medical": [
            {"claim": "Persistent headache lasting >1 week warrants clinical evaluation", "source": "Mayo Clinic -- Headache Symptoms", "url": "https://www.mayoclinic.org/symptoms/headache/basics/when-to-see-doctor/sym-20050800", "confidence": "high"},
            {"claim": "Do not self-diagnose neurological symptoms", "source": "NHS -- When to seek urgent help", "url": "https://www.nhs.uk/conditions/headaches/", "confidence": "high"},
        ],
        "legal": [
            {"claim": "Landlord entry notice requirements vary by jurisdiction", "source": "Nolo -- Tenant Rights by State", "url": "https://www.nolo.com/legal-encyclopedia/tenant-rights.html", "confidence": "high"},
        ],
        "general": [
            {"claim": "General AI-generated information", "source": "No specific source -- verify independently", "url": None, "confidence": "low"},
        ],
    }

    citations = CITATION_MAP.get(domain, CITATION_MAP["general"])
    return {
        "mitigation": "2 -- Source Citations & References",
        "strategy": "Factual claims tagged with authoritative sources. Uncited claims explicitly flagged as unverified.",
        "query": query,
        "domain": domain,
        "citations": citations,
        "uncited_claims_note": "Note: Some claims in AI responses cannot be sourced -- treat those with extra caution.",
        "verification_instruction": "Click each source URL to verify the claim independently before relying on it.",
        "tip": 'Try: {"query":"How do I store passwords securely?","domain":"security"} or {"domain":"medical"}',
    }


@router.post("/mitigations/3-confidence-indicators")
def llm09_mit_confidence(prompt: Prompt):
    """Labels each response segment with confidence level."""
    body = parse_body(prompt)
    domain = body.get("domain", "medical")

    SEGMENT_ANALYSIS = {
        "medical": [
            {"text": "Headaches can be caused by tension or dehydration.", "confidence": 0.85, "indicator": "GREEN HIGH -- well-established general knowledge"},
            {"text": "Dizziness combined with headache may indicate inner ear issues.", "confidence": 0.60, "indicator": "YELLOW MEDIUM -- plausible but requires clinical assessment"},
            {"text": "This specific combination rules out brain tumour.", "confidence": 0.10, "indicator": "RED LOW -- AI cannot rule out serious conditions without examination"},
            {"text": "Take 400mg ibuprofen every 6 hours.", "confidence": 0.20, "indicator": "RED LOW -- medication advice without patient history is dangerous"},
        ],
        "legal": [
            {"text": "Many jurisdictions require 24-48 hours notice for landlord entry.", "confidence": 0.70, "indicator": "YELLOW MEDIUM -- generally true but highly jurisdiction-dependent"},
            {"text": "The Residential Tenancies Act Section 26(2) applies to your case.", "confidence": 0.15, "indicator": "RED LOW -- fabricated specific citation; jurisdiction unknown"},
            {"text": "You have 30 days to file a complaint.", "confidence": 0.10, "indicator": "RED LOW -- deadline depends entirely on jurisdiction; do not rely on this"},
        ],
        "security": [
            {"text": "bcrypt is designed for password hashing.", "confidence": 0.95, "indicator": "GREEN HIGH -- verifiable technical fact (OWASP, NIST)"},
            {"text": "SHA-256 should not be used for passwords.", "confidence": 0.93, "indicator": "GREEN HIGH -- verifiable security consensus"},
            {"text": "rounds=12 provides adequate security for 2024.", "confidence": 0.70, "indicator": "YELLOW MEDIUM -- reasonable guidance, but hardware evolves; verify current OWASP recommendations"},
        ],
        "general": [
            {"text": "General statement.", "confidence": 0.65, "indicator": "YELLOW MEDIUM -- verify from primary sources"},
        ],
    }

    segments = SEGMENT_ANALYSIS.get(domain, SEGMENT_ANALYSIS["general"])
    legend = {
        "GREEN HIGH": ">80% -- based on well-established facts",
        "YELLOW MEDIUM": "50-80% -- plausible but verify",
        "RED LOW": "<50% -- speculative or unverifiable; do not rely on without independent confirmation",
    }

    return {
        "mitigation": "3 -- Confidence Indicators",
        "strategy": "Each response segment labelled with confidence level. Low-confidence segments flagged prominently.",
        "domain": domain,
        "segments_with_confidence": segments,
        "legend": legend,
        "overall_domain_confidence": _confidence_score(domain),
        "note": "Present confidence indicators visually (colour-coded) before each claim so users can assess reliability at a glance.",
        "tip": 'Try: {"domain":"legal"} to see how specific fabricated citations score vs general statements.',
    }


@router.post("/mitigations/4-verification-prompts")
def llm09_mit_verification(prompt: Prompt):
    """Provides domain-specific, actionable verification steps."""
    body = parse_body(prompt)
    domain = body.get("domain", "medical")
    topic  = body.get("topic", "headache and dizziness")

    VERIFICATION_METHODS = {
        "medical":   ["Consult your GP or a qualified physician", "Check Mayo Clinic (mayoclinic.org) or NHS (nhs.uk)", "If urgent: call 111 (UK), 811 (Canada), or emergency services", "Do not delay care based on AI advice"],
        "legal":     ["Search '[your state/country] + [topic] + law' on official government sites (.gov)", "Contact a local tenant rights or legal aid organisation (often free)", "Consult a licensed attorney -- many offer free initial consultations", "Verify any statute names before citing them"],
        "security":  ["Cross-check against OWASP cheat sheets (cheatsheetseries.owasp.org)", "Reference NIST guidelines (nist.gov)", "Have security code reviewed by a qualified security engineer", "Run through a security linter (bandit, semgrep) before deployment"],
        "financial": ["Consult a certified financial planner (CFP)", "Check official government tax/investment sites (.gov)", "Verify current rates/rules -- AI knowledge may be outdated", "Never make irreversible financial decisions based solely on AI output"],
        "general":   ["Verify from at least 2 independent reliable sources", "Check the publication/update date of sources", "Prefer .gov, .edu, or established organisations over AI output", "Apply critical thinking -- does this make sense?"],
    }

    methods = VERIFICATION_METHODS.get(domain, VERIFICATION_METHODS["general"])
    return {
        "mitigation": "4 -- Verification Prompts",
        "strategy": "Every response includes domain-specific, actionable verification steps -- not generic 'check with a professional'.",
        "domain": domain,
        "topic": topic,
        "verification_steps": methods,
        "call_to_action": f"Before acting on any AI advice about '{topic}', complete at least 2 of the verification steps above.",
        "reminder": "AI-generated information should be a starting point, not a final answer.",
        "tip": 'Try: {"domain":"legal","topic":"landlord entry"} or {"domain":"security","topic":"password hashing"}',
    }


@router.post("/mitigations/5-alternative-viewpoints")
def llm09_mit_alt_viewpoints(prompt: Prompt):
    """Presents multiple legitimate perspectives for complex topics."""
    body = parse_body(prompt)
    topic  = body.get("topic", "password hashing algorithms")
    domain = body.get("domain", _get_domain(body.get("topic", "")))

    COMPLEX_TOPICS = {
        "password hashing": {
            "is_complex": True,
            "viewpoints": [
                {"perspective": "Security Purists", "summary": "Use Argon2id exclusively -- PHC winner, memory-hard, most resistant to GPU attacks.", "supporting": ["PHC recommendation", "Resistant to parallel GPU attacks", "Memory hardness prevents ASIC attacks"]},
                {"perspective": "Pragmatic Engineers", "summary": "bcrypt is fine for most applications -- battle-tested, widely supported, sufficient work factor.", "supporting": ["20+ years of production use", "Native support in most frameworks", "Well-understood failure modes"]},
                {"perspective": "NIST / Government", "summary": "Use approved algorithms from NIST SP 800-63B -- Argon2, bcrypt, scrypt, or PBKDF2 all acceptable.", "supporting": ["Regulatory compliance requires NIST-approved algorithms", "PBKDF2 may be required in FIPS environments"]},
            ],
        },
        "landlord entry": {
            "is_complex": True,
            "viewpoints": [
                {"perspective": "Tenant Advocates", "summary": "Any entry without proper notice is a violation of quiet enjoyment and actionable.", "supporting": ["Tenant rights are fundamental", "Notice requirements protect privacy"]},
                {"perspective": "Landlord Perspective", "summary": "Emergency situations may justify immediate entry; lease terms govern the relationship.", "supporting": ["Property protection in emergencies", "Lease may specify different notice terms"]},
                {"perspective": "Legal Nuance", "summary": "Outcome depends entirely on jurisdiction, specific circumstances, and lease language.", "supporting": ["Laws vary enormously by location", "Emergency exception exists in most jurisdictions"]},
            ],
        },
    }

    matched = None
    for key in COMPLEX_TOPICS:
        if key.lower() in topic.lower():
            matched = COMPLEX_TOPICS[key]
            break

    if not matched:
        return {
            "mitigation": "5 -- Alternative Viewpoints",
            "topic": topic,
            "is_complex": False,
            "note": "No competing viewpoints identified for this specific topic. For complex/contested topics, the system presents multiple perspectives.",
            "tip": 'Try: {"topic":"password hashing algorithms"} or {"topic":"landlord entry rights"}',
        }

    return {
        "mitigation": "5 -- Alternative Viewpoints",
        "strategy": "Complex topics presented with multiple legitimate perspectives -- prevents false certainty from single authoritative-sounding answer.",
        "topic": topic,
        "domain": domain,
        "is_complex": matched["is_complex"],
        "viewpoints": matched["viewpoints"],
        "critical_thinking_note": "Consider all perspectives and consult domain experts before forming a conclusion.",
        "tip": 'Try: {"topic":"password hashing algorithms"} or {"topic":"landlord entry rights"}',
    }


@router.post("/mitigations/6-human-review")
def llm09_mit_human_review(prompt: Prompt):
    """Routes high-stakes queries to human expert review."""
    body = parse_body(prompt)
    query   = body.get("query", "What medications should I take for my headache?")
    domain  = body.get("domain", _get_domain(body.get("query", "")))
    context = body.get("context", {})

    RISK_TRIGGERS = {
        "involves_treatment_recommendation": any(w in query.lower() for w in ["take", "dose", "medication", "treat", "prescribe", "surgery"]),
        "involves_legal_filing":             any(w in query.lower() for w in ["file", "sue", "court", "claim", "complaint", "submit"]),
        "involves_financial_commitment":     any(w in query.lower() for w in ["invest", "buy", "sell", "transfer", "commit", "sign"]),
        "involves_security_deployment":      any(w in query.lower() for w in ["deploy", "production", "release", "publish", "store"]),
        "low_ai_confidence":                 _confidence_score(domain) < 0.55,
        "vulnerable_population":             any(w in query.lower() for w in ["child", "elderly", "pregnant", "immunocompromised"]),
    }

    active_triggers = {k: v for k, v in RISK_TRIGGERS.items() if v}
    requires_review = len(active_triggers) > 0 or domain in ["medical", "legal"]

    reviewer = {
        "medical":   "Qualified physician or pharmacist",
        "legal":     "Licensed attorney in the relevant jurisdiction",
        "financial": "Certified financial planner (CFP)",
        "security":  "Qualified security engineer or penetration tester",
    }.get(domain, "Domain expert")

    return {
        "mitigation": "6 -- Human-in-the-Loop for Critical Domains",
        "strategy": "High-stakes domains and risk-trigger patterns route to human expert review before AI output is acted upon.",
        "query": query,
        "domain": domain,
        "ai_confidence": _confidence_score(domain),
        "risk_triggers_detected": active_triggers,
        "requires_human_review": requires_review,
        "recommended_reviewer": reviewer,
        "verdict": (
            f"HUMAN REVIEW REQUIRED -- consult {reviewer} before acting on this AI output"
            if requires_review else
            "Standard AI response -- verify independently before use"
        ),
        "hallucination_examples": HALLUCINATION_EXAMPLES[:2],
        "tip": (
            'Try: {"query":"What medications should I take for my headache?","domain":"medical"} '
            'vs {"query":"What is bcrypt?","domain":"security"}'
        ),
    }


@router.post("/mitigations/7-user-agency")
def llm09_mit_user_agency(prompt: Prompt):
    """Empowers users as decision-makers; frames LLM as a preparatory tool, not an authority."""
    body = parse_body(prompt)
    domain     = body.get("domain", "medical")
    complexity = body.get("complexity", "high")
    query      = body.get("query", "What could cause my symptoms?")

    AGENCY_PATTERNS = {
        "medical": {
            "framing": "I am a tool to help you prepare for a conversation with your doctor -- not a replacement for one.",
            "empowerment_prompts": [
                "What questions should I ask my doctor about this?",
                "What should I monitor and track before my appointment?",
                "What information should I bring to my consultation?",
            ],
            "user_options": ["Ask for more general information", "Get a list of questions for my doctor", "Understand what NOT to do before seeing a doctor", "Explore alternative explanations"],
        },
        "legal": {
            "framing": "I can help you understand the landscape, but you need a lawyer who knows your jurisdiction.",
            "empowerment_prompts": [
                "What documentation should I gather?",
                "What are the key questions to ask a tenant rights lawyer?",
                "What should I NOT do that might hurt my case?",
            ],
            "user_options": ["Understand general principles", "Get questions for a lawyer", "Understand documentation to gather", "Learn what to avoid doing"],
        },
        "security": {
            "framing": "This code is a starting point. Security-critical code must be reviewed by a security professional.",
            "empowerment_prompts": [
                "What security review checklist applies to this code?",
                "What automated tools can I run to check this?",
                "What are the OWASP guidelines for this area?",
            ],
            "user_options": ["Review against OWASP checklist", "Run automated security linter", "Get questions for a security engineer", "See common mistakes in this area"],
        },
        "general": {
            "framing": "Use this as a starting point for your own research, not a final answer.",
            "empowerment_prompts": ["Where should I look to verify this?", "What are the key uncertainties?", "What might this response be missing?"],
            "user_options": ["Get verification sources", "Explore alternative perspectives", "Understand limitations", "Ask a follow-up question"],
        },
    }

    patterns = AGENCY_PATTERNS.get(domain, AGENCY_PATTERNS["general"])
    interaction_count = len([e for e in _LLM09_INTERACTION_LOG if e.get("scenario") == domain])

    return {
        "mitigation": "7 -- Design for Appropriate User Agency",
        "strategy": "Interface design empowers users as decision-makers; LLM is framed as a preparatory tool, not an authority.",
        "domain": domain,
        "complexity": complexity,
        "query": query,
        "ai_framing": patterns["framing"],
        "empowerment_prompts": patterns["empowerment_prompts"],
        "user_options_presented": patterns["user_options"],
        "design_principles": [
            "Frame AI as a tool, not an authority",
            "Offer follow-up options that lead to verification and expert consultation",
            "Never present a single answer as definitive for complex domains",
            "Reward critical thinking -- show users what questions to ask, not just answers",
            "Make verification easier than blind acceptance",
        ],
        "interactions_in_domain": interaction_count,
        "tip": 'Try: {"domain":"legal","query":"My landlord entered without notice"} or {"domain":"security","query":"password hashing"}',
    }
