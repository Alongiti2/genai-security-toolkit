# placeholder — full code coming
# scanner/tprm_questionnaire.py
# TPRM Vendor Questionnaire — GenAI Assessment
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College

from datetime import datetime


TPRM_QUESTIONS = {
    "data_handling": {
        "category": "Data Handling & Privacy",
        "weight": "Critical",
        "questions": [
            {
                "id": "DH-01",
                "risk": "Critical",
                "question": "Is user prompt/conversation data used for model training?",
                "guidance": "Any use of employee inputs for training creates data leakage risk.",
                "fail_triggers": ["yes", "opt-in", "may be used"],
                "pass_triggers": ["no", "never", "opt-out by default"],
                "required_control": "Require contractual opt-out from training data usage."
            },
            {
                "id": "DH-02",
                "risk": "High",
                "question": "What is the maximum data retention period for conversations?",
                "guidance": "Indefinite retention increases breach exposure window.",
                "fail_triggers": ["indefinite", "unlimited", "no policy"],
                "pass_triggers": ["30 days", "7 days", "no retention", "zero retention"],
                "required_control": "Require maximum 30-day retention with deletion API."
            },
            {
                "id": "DH-03",
                "risk": "High",
                "question": "Can conversation data be deleted on demand via API?",
                "guidance": "Deletion capability is required for compliance and incident response.",
                "fail_triggers": ["no", "not available", "manual process only"],
                "pass_triggers": ["yes", "api available", "self-service"],
                "required_control": "Require deletion API or documented deletion SLA."
            },
            {
                "id": "DH-04",
                "risk": "Critical",
                "question": "Is data processed outside the contracted geographic region?",
                "guidance": "Cross-border data transfer may violate GDPR and data residency requirements.",
                "fail_triggers": ["yes", "global processing", "no guarantee"],
                "pass_triggers": ["no", "us only", "eu only", "region locked"],
                "required_control": "Add data residency clause to vendor contract."
            },
            {
                "id": "DH-05",
                "risk": "High",
                "question": "Does the vendor share data with any third-party subprocessors?",
                "guidance": "Subprocessors extend the trust boundary beyond the primary vendor.",
                "fail_triggers": ["yes", "multiple subprocessors", "undisclosed"],
                "pass_triggers": ["no", "none", "disclosed and limited"],
                "required_control": "Require complete subprocessor list and right to object."
            }
        ]
    },

    "access_control": {
        "category": "Access Control & Authentication",
        "weight": "Critical",
        "questions": [
            {
                "id": "AC-01",
                "risk": "Critical",
                "question": "Does the OAuth integration request more permissions than minimum required?",
                "guidance": "Excessive OAuth scopes are a primary risk vector for GenAI workforce tools.",
                "fail_triggers": ["yes", "broad permissions", "readwrite.all"],
                "pass_triggers": ["no", "minimal scopes", "least privilege"],
                "required_control": "Renegotiate OAuth scopes before deployment approval."
            },
            {
                "id": "AC-02",
                "risk": "High",
                "question": "Does the tool support SSO and MFA enforcement?",
                "guidance": "Without SSO/MFA, the tool creates an authentication gap.",
                "fail_triggers": ["no", "not supported", "username and password only"],
                "pass_triggers": ["yes", "saml", "oidc", "mfa supported"],
                "required_control": "Require SSO integration before enterprise deployment."
            },
            {
                "id": "AC-03",
                "risk": "High",
                "question": "Can access be provisioned and deprovisioned via SCIM?",
                "guidance": "Manual deprovisioning creates orphaned account risk.",
                "fail_triggers": ["no", "manual only", "not supported"],
                "pass_triggers": ["yes", "scim supported", "automated"],
                "required_control": "Require SCIM or document manual deprovisioning SLA."
            },
            {
                "id": "AC-04",
                "risk": "Medium",
                "question": "Does the vendor provide per-user audit logs of model interactions?",
                "guidance": "Without audit logs, insider threat detection is impossible.",
                "fail_triggers": ["no", "aggregate only", "not available"],
                "pass_triggers": ["yes", "per user", "exportable logs"],
                "required_control": "Require audit log API or SIEM integration capability."
            }
        ]
    },

    "genai_specific": {
        "category": "GenAI-Specific Security Controls",
        "weight": "Critical",
        "questions": [
            {
                "id": "GS-01",
                "risk": "Critical",
                "question": "Does the vendor have documented controls against prompt injection?",
                "guidance": "Prompt injection is OWASP LLM01 — the highest priority GenAI threat.",
                "fail_triggers": ["no", "not documented", "not applicable"],
                "pass_triggers": ["yes", "documented", "input validation implemented"],
                "required_control": "Require vendor to document prompt injection mitigations."
            },
            {
                "id": "GS-02",
                "risk": "Critical",
                "question": "If the tool uses RAG, are retrieval boundaries enforced per user?",
                "guidance": "Without per-user retrieval boundaries, cross-tenant data leakage is possible.",
                "fail_triggers": ["no", "shared index", "not enforced"],
                "pass_triggers": ["yes", "per user", "acl enforced", "not applicable"],
                "required_control": "Require ACL-enforced retrieval with documented architecture."
            },
            {
                "id": "GS-03",
                "risk": "Critical",
                "question": "If the tool is agentic, does each write action require explicit user approval?",
                "guidance": "Autonomous write actions without approval gates are OWASP LLM08.",
                "fail_triggers": ["no", "fully autonomous", "no approval required"],
                "pass_triggers": ["yes", "approval required", "not applicable"],
                "required_control": "Require human-in-the-loop approval gate for all write actions."
            },
            {
                "id": "GS-04",
                "risk": "High",
                "question": "Does the vendor publish a responsible AI or model safety policy?",
                "guidance": "Published AI safety policy signals vendor commitment to responsible deployment.",
                "fail_triggers": ["no", "not published", "internal only"],
                "pass_triggers": ["yes", "published", "publicly available"],
                "required_control": "Request internal AI safety policy under NDA if not published."
            },
            {
                "id": "GS-05",
                "risk": "High",
                "question": "Does the vendor notify customers of model updates that change behavior?",
                "guidance": "Silent model updates can change security-relevant output behavior.",
                "fail_triggers": ["no", "no notification", "updates are silent"],
                "pass_triggers": ["yes", "changelog published", "advance notice"],
                "required_control": "Require advance notice clause for model behavior changes."
            }
        ]
    },

    "incident_response": {
        "category": "Incident Response & Compliance",
        "weight": "High",
        "questions": [
            {
                "id": "IR-01",
                "risk": "High",
                "question": "Does the vendor have a documented AI incident response procedure?",
                "guidance": "AI incidents differ from traditional security incidents — vendor must be prepared.",
                "fail_triggers": ["no", "standard ir only", "not documented"],
                "pass_triggers": ["yes", "documented", "ai-specific"],
                "required_control": "Require AI incident response SLA in contract."
            },
            {
                "i
