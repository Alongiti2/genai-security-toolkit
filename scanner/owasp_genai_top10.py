# placeholder — full code coming
# scanner/owasp_genai_top10.py
# OWASP GenAI Top 10 — 2025 Edition
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College

OWASP_GENAI_TOP10 = {
    "LLM01": {
        "name": "Prompt Injection",
        "severity": "Critical",
        "description": "Malicious inputs manipulate LLM behavior by overriding instructions.",
        "workforce_risk": "Injected instructions inside RAG documents or user-supplied input hijack model behavior.",
        "controls": ["Input validation", "Output monitoring", "Privilege separation", "Sandboxed execution"]
    },
    "LLM02": {
        "name": "Insecure Output Handling",
        "severity": "High",
        "description": "LLM output is used downstream without validation or sanitization.",
        "workforce_risk": "XSS, command injection, or data exfiltration via unsanitized model responses.",
        "controls": ["Output sanitization", "Content-type enforcement", "Allow-list validation"]
    },
    "LLM03": {
        "name": "Training Data Poisoning",
        "severity": "High",
        "description": "Malicious data introduced during training corrupts model behavior.",
        "workforce_risk": "Vendor model trained on poisoned data produces biased or backdoored outputs.",
        "controls": ["Vendor training data audit", "Model provenance verification", "Output behavioral testing"]
    },
    "LLM04": {
        "name": "Model Denial of Service",
        "severity": "Medium",
        "description": "Attackers craft inputs that consume excessive model resources.",
        "workforce_risk": "Productivity tools become unavailable during critical business operations.",
        "controls": ["Rate limiting", "Input length restrictions", "Query cost monitoring"]
    },
    "LLM05": {
        "name": "Supply Chain Vulnerabilities",
        "severity": "High",
        "description": "Compromised components in the LLM supply chain affect model integrity.",
        "workforce_risk": "Third-party plugins, fine-tuned models, or APIs introduce unvetted vulnerabilities.",
        "controls": ["Vendor SOC2 review", "Model signing", "Dependency scanning", "TPRM assessment"]
    },
    "LLM06": {
        "name": "Sensitive Information Disclosure",
        "severity": "Critical",
        "description": "LLM reveals sensitive data from training or context window.",
        "workforce_risk": "Employee PII, internal strategy, or customer data leaked via model responses.",
        "controls": ["Data minimization", "PII detection on outputs", "Context window access controls"]
    },
    "LLM07": {
        "name": "Insecure Plugin Design",
        "severity": "High",
        "description": "LLM plugins lack proper access controls or input validation.",
        "workforce_risk": "Plugins with broad permissions allow lateral movement or data exfiltration.",
        "controls": ["Least-privilege plugin permissions", "Plugin input validation", "Audit logging"]
    },
    "LLM08": {
        "name": "Excessive Agency",
        "severity": "Critical",
        "description": "LLM agents take consequential actions without adequate human oversight.",
        "workforce_risk": "Agentic tools send emails, modify files, or call APIs autonomously on behalf of employees.",
        "controls": ["Human-in-the-loop gates", "Action scope restrictions", "Approval workflows for write actions"]
    },
    "LLM09": {
        "name": "Overreliance",
        "severity": "Medium",
        "description": "Users trust LLM outputs without verification, leading to errors.",
        "workforce_risk": "Employees act on incorrect legal, financial, or technical guidance from the model.",
        "controls": ["Accuracy disclaimers", "Human review requirements", "Output confidence scoring"]
    },
    "LLM10": {
        "name": "Model Theft",
        "severity": "Medium",
        "description": "Attackers extract proprietary model weights or behavior through queries.",
        "workforce_risk": "Fine-tuned internal models containing business logic are reconstructed by adversaries.",
        "controls": ["Query rate limiting", "Output watermarking", "Access logging and anomaly detection"]
    }
}

SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}

RISK_RATINGS = {
    "HIGH": "Do not approve — mitigations required before deployment",
    "MEDIUM": "Conditional approval — implement required controls first",
    "LOW": "Approved with standard security monitoring"
}

def get_threat(threat_id):
    return OWASP_GENAI_TOP10.get(threat_id, None)

def get_all_threats():
    return OWASP_GENAI_TOP10

def get_critical_threats():
    return {k: v for k, v in OWASP_GENAI_TOP10.items() if v["severity"] == "Critical"}

def score_to_rating(score):
    if score >= 20:
        return "HIGH"
    elif score >= 10:
        return "MEDIUM"
    return "LOW"
