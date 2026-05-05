# placeholder — full code coming
# scanner/genai_risk_scanner.py
# GenAI Risk Scanner — Core Assessment Engine
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College

from datetime import datetime
from owasp_genai_top10 import OWASP_GENAI_TOP10, SEVERITY_SCORES, RISK_RATINGS, score_to_rating


class GenAIRiskScanner:
    """
    Core assessment engine for evaluating GenAI tool risk
    against the OWASP GenAI Top 10 threat taxonomy.
    Designed for enterprise Workforce Security teams.
    """

    def __init__(self, vendor_name, integration_type):
        self.vendor = vendor_name
        self.integration_type = integration_type
        self.findings = []
        self.risk_score = 0
        self.assessed_at = datetime.now().isoformat()
        self.assessed_by = "Delphin A. Zaki"

    # ── LLM01: Prompt Injection ───────────────────────────────────────────
    def assess_prompt_injection(self, uses_rag=False, accepts_user_files=False):
        threat = OWASP_GENAI_TOP10["LLM01"].copy()
        if uses_rag and accepts_user_files:
            threat["finding"] = (
                "CRITICAL: RAG pipeline + user file uploads detected. "
                "Both document retrieval and user-supplied content can carry "
                "injected instructions into the model context."
            )
            threat["required_control"] = (
                "Implement chunk-level content filtering before RAG injection. "
                "Sanitize all user file content before processing."
            )
            self.risk_score += SEVERITY_SCORES["Critical"]
        elif uses_rag:
            threat["finding"] = (
                "HIGH: RAG pipeline detected. Retrieved document chunks "
                "are injected into the model context without sanitization."
            )
            threat["required_control"] = (
                "Validate and sanitize all retrieved document chunks. "
                "Apply instruction-pattern detection before context injection."
            )
            self.risk_score += SEVERITY_SCORES["High"]
        else:
            threat["finding"] = "LOW: No RAG pipeline or file upload detected. Standard input validation applies."
            threat["required_control"] = "Apply standard input length and content validation."
            self.risk_score += SEVERITY_SCORES["Low"]
        self.findings.append(threat)

    # ── LLM06: Sensitive Information Disclosure ───────────────────────────
    def assess_data_disclosure(self, stores_conversations=False, trains_on_data=False):
        threat = OWASP_GENAI_TOP10["LLM06"].copy()
        if trains_on_data:
            threat["finding"] = (
                "CRITICAL: Vendor uses conversation data for model training. "
                "Employee inputs — including PII, strategy, and internal data — "
                "may be incorporated into future model versions."
            )
            threat["required_control"] = (
                "Negotiate training data opt-out before deployment. "
                "Block tool access to sensitive data categories until resolved."
            )
            self.risk_score += SEVERITY_SCORES["Critical"]
        elif stores_conversations:
            threat["finding"] = (
                "HIGH: Vendor stores conversation history. "
                "Retention period and deletion policy must be contractually defined."
            )
            threat["required_control"] = (
                "Require maximum 30-day retention with deletion API access. "
                "Add data handling terms to vendor contract."
            )
            self.risk_score += SEVERITY_SCORES["High"]
        else:
            threat["finding"] = "LOW: No persistent conversation storage reported by vendor."
            threat["required_control"] = "Verify no-storage claim via vendor attestation."
            self.risk_score += SEVERITY_SCORES["Low"]
        self.findings.append(threat)

    # ── LLM08: Excessive Agency ───────────────────────────────────────────
    def assess_excessive_agency(self, can_send_emails=False,
                                can_modify_files=False, can_call_apis=False):
        threat = OWASP_GENAI_TOP10["LLM08"].copy()
        actions = []
        if can_send_emails:
            actions.append("send emails")
        if can_modify_files:
            actions.append("modify files")
        if can_call_apis:
            actions.append("call external APIs")

        if len(actions) >= 2:
            threat["finding"] = (
                f"CRITICAL: Agent can autonomously {', '.join(actions)} "
                f"on behalf of employees without per-action approval."
            )
            threat["required_control"] = (
                "Require explicit human approval gate before each write action. "
                "Implement action scope restrictions and audit logging."
            )
            self.risk_score += SEVERITY_SCORES["Critical"]
        elif len(actions) == 1:
            threat["finding"] = (
                f"HIGH: Agent can autonomously {actions[0]}. "
                "Single autonomous action capability requires approval controls."
            )
            threat["required_control"] = (
                "Add confirmation prompt before each autonomous action. "
                "Log all agent-initiated actions with user attribution."
            )
            self.risk_score += SEVERITY_SCORES["High"]
        else:
            threat["finding"] = "LOW: No autonomous write actions detected. Read-only access confirmed."
            threat["required_control"] = "Monitor for future capability additions by vendor."
            self.risk_score += SEVERITY_SCORES["Low"]
        self.findings.append(threat)

    # ── OAuth Scope Assessment ────────────────────────────────────────────
    def assess_oauth_scope(self, oauth_scopes=None):
        if not oauth_scopes:
            return
        dangerous_scopes = {
            "mail.readwrite": "Read and write access to all employee email",
            "files.readwrite.all": "Read and write access to all files",
            "directory.readwrite.all": "Full directory read/write — admin level",
            "calendars.readwrite": "Read and write access to all calendars",
            "user.readwrite.all": "Modify all user profiles in the tenant",
            "sites.readwrite.all": "Full SharePoint/OneDrive read/write"
        }
        found_dangerous = {
            scope: desc for scope, desc in dangerous_scopes.items()
            if scope in oauth_scopes
        }
        if found_dangerous:
            finding = {
                "name": "Excessive OAuth Scope",
                "severity": "Critical",
                "finding": (
                    f"CRITICAL: {len(found_dangerous)} dangerous OAuth scope(s) detected: "
                    f"{list(found_dangerous.keys())}. "
                    "Permissions significantly exceed minimum required for tool functionality."
                ),
                "required_control": (
                    "Renegotiate OAuth scopes to minimum required. "
                    "Do not approve deployment until scopes are reduced. "
                    "Document business justification for any retained broad scopes."
                ),
                "scope_details": found_dangerous
            }
            self.risk_score += SEVERITY_SCORES["Critical"] * len(found_dangerous)
            self.findings.append(finding)

    # ── LLM05: Supply Chain ───────────────────────────────────────────────
    def assess_supply_chain(self, has_soc2=False, has_pentest=False):
        threat = OWASP_GENAI_TOP10["LLM05"].copy()
        if not has_soc2 and not has_pentest:
            threat["finding"] = (
                "HIGH: Vendor has no SOC2 report and no third-party penetration test. "
                "Security posture is entirely self-attested."
            )
            threat["required_control"] = (
                "Require SOC2 Type II or equivalent third-party security audit "
                "before approving enterprise deployment."
            )
            self.risk_score += SEVERITY_SCORES["High"]
        elif not has_soc2:
            threat["finding"] = "MEDIUM: No SOC2 report. Penetration test exists but no continuous compliance audit."
            threat["required_control"] = "Request SOC2 Type II roadmap with committed timeline."
            self.risk_score += SEVERITY_SCORES["Medium"]
        else:
            threat["finding"] = "LOW: SOC2 Type II report available. Supply chain risk is managed."
            threat["required_control"] = "Review SOC2 exceptions section and monitor annual renewal."
            self.risk_score += SEVERITY_SCORES["Low"]
        self.findings.append(threat)

    # ── Generate Report ───────────────────────────────────────────────────
    def generate_report(self):
        rating_key = score_to_rating(self.risk_score)
        rating_text = RISK_RATINGS[rating_key]
        critical_count = sum(
            1 for f in self.findings
            if f.get("severity") == "Critical" or "CRITICAL" in f.get("finding", "")
        )
        return {
            "vendor": self.vendor,
            "integration_type": self.integration_type,
            "assessed_by": self.assessed_by,
            "assessed_at": self.assessed_at,
            "risk_score": self.risk_score,
            "risk_rating": rating_key,
            "risk_rating_description": rating_text,
            "critical_findings": critical_count,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "business_summary": self._business_summary(rating_key, critical_count),
            "approval_status": self._approval_status(rating_key)
        }

    def _business_summary(self, rating, critical_count):
        if rating == "HIGH":
            return (
                f"{self.vendor} presents HIGH risk for workforce deployment. "
                f"{critical_count} critical finding(s) identified. "
                "Deployment must not proceed until all critical controls are implemented and validated."
            )
        elif rating == "MEDIUM":
            return (
                f"{self.vendor} may be deployed conditionally. "
                f"{critical_count} critical finding(s) require remediation before go-live. "
                "Schedule follow-up assessment after controls are implemented."
            )
        return (
            f"{self.vendor} is approved for workforce deployment with standard monitoring. "
            "Review findings and implement recommended controls within 90 days."
        )

    def _approval_status(self, rating):
        statuses = {
            "HIGH": "BLOCKED — Do not deploy",
            "MEDIUM": "CONDITIONAL — Deploy only after required controls",
            "LOW": "APPROVED — Deploy with standard monitoring"
        }
        return statuses[rating]
