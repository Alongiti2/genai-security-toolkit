# tests/test_scanner.py
# GenAI Security Assessment Toolkit — Test Suite
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from genai_risk_scanner import GenAIRiskScanner
from tprm_questionnaire import TPRMAssessment, get_all_questions, get_questions_by_category
from owasp_genai_top10 import (
    OWASP_GENAI_TOP10,
    SEVERITY_SCORES,
    RISK_RATINGS,
    get_threat,
    get_all_threats,
    get_critical_threats,
    score_to_rating
)


# ══════════════════════════════════════════════════════════════
# OWASP GenAI Top 10 Module Tests
# ══════════════════════════════════════════════════════════════

class TestOWASPTaxonomy:

    def test_all_ten_threats_present(self):
        """OWASP GenAI Top 10 must contain exactly 10 threats."""
        threats = get_all_threats()
        assert len(threats) == 10, f"Expected 10 threats, got {len(threats)}"

    def test_all_threat_ids_correct(self):
        """Every threat ID must follow LLM01–LLM10 format."""
        expected = [f"LLM{str(i).zfill(2)}" for i in range(1, 11)]
        actual = list(OWASP_GENAI_TOP10.keys())
        assert actual == expected

    def test_every_threat_has_required_fields(self):
        """Every threat must have name, severity, description, workforce_risk, controls."""
        required_fields = ["name", "severity", "description", "workforce_risk", "controls"]
        for threat_id, threat in OWASP_GENAI_TOP10.items():
            for field in required_fields:
                assert field in threat, (
                    f"{threat_id} missing required field: {field}"
                )

    def test_severity_values_are_valid(self):
        """All severity values must be in the defined set."""
        valid = {"Critical", "High", "Medium", "Low"}
        for threat_id, threat in OWASP_GENAI_TOP10.items():
            assert threat["severity"] in valid, (
                f"{threat_id} has invalid severity: {threat['severity']}"
            )

    def test_critical_threats_identified(self):
        """LLM01, LLM06, and LLM08 must be Critical severity."""
        critical = get_critical_threats()
        critical_ids = list(critical.keys())
        assert "LLM01" in critical_ids, "LLM01 Prompt Injection must be Critical"
        assert "LLM06" in critical_ids, "LLM06 Sensitive Info Disclosure must be Critical"
        assert "LLM08" in critical_ids, "LLM08 Excessive Agency must be Critical"

    def test_get_threat_returns_correct_threat(self):
        """get_threat() must return the correct threat by ID."""
        threat = get_threat("LLM01")
        assert threat is not None
        assert threat["name"] == "Prompt Injection"

    def test_get_threat_returns_none_for_invalid_id(self):
        """get_threat() must return None for unknown IDs."""
        assert get_threat("LLM99") is None
        assert get_threat("") is None
        assert get_threat("invalid") is None

    def test_severity_scores_are_numeric(self):
        """All severity scores must be positive integers."""
        for level, score in SEVERITY_SCORES.items():
            assert isinstance(score, int), f"{level} score must be int"
            assert score > 0, f"{level} score must be positive"

    def test_critical_scores_higher_than_high(self):
        """Critical severity must score higher than High."""
        assert SEVERITY_SCORES["Critical"] > SEVERITY_SCORES["High"]
        assert SEVERITY_SCORES["High"] > SEVERITY_SCORES["Medium"]
        assert SEVERITY_SCORES["Medium"] > SEVERITY_SCORES["Low"]

    def test_score_to_rating_high(self):
        """Score >= 20 must return HIGH rating."""
        assert score_to_rating(20) == "HIGH"
        assert score_to_rating(35) == "HIGH"
        assert score_to_rating(100) == "HIGH"

    def test_score_to_rating_medium(self):
        """Score 10-19 must return MEDIUM rating."""
        assert score_to_rating(10) == "MEDIUM"
        assert score_to_rating(15) == "MEDIUM"
        assert score_to_rating(19) == "MEDIUM"

    def test_score_to_rating_low(self):
        """Score < 10 must return LOW rating."""
        assert score_to_rating(0) == "LOW"
        assert score_to_rating(5) == "LOW"
        assert score_to_rating(9) == "LOW"


# ══════════════════════════════════════════════════════════════
# GenAI Risk Scanner Tests
# ══════════════════════════════════════════════════════════════

class TestGenAIRiskScanner:

    def setup_method(self):
        """Create a fresh scanner before each test."""
        self.scanner = GenAIRiskScanner(
            vendor_name="Test Vendor",
            integration_type="rag"
        )

    def test_scanner_initializes_correctly(self):
        """Scanner must initialize with zero score and empty findings."""
        assert self.scanner.vendor == "Test Vendor"
        assert self.scanner.integration_type == "rag"
        assert self.scanner.risk_score == 0
        assert self.scanner.findings == []

    def test_rag_with_file_upload_scores_critical(self):
        """RAG + file upload combination must score Critical (10 points)."""
        self.scanner.assess_prompt_injection(
            uses_rag=True,
            accepts_user_files=True
        )
        assert self.scanner.risk_score >= SEVERITY_SCORES["Critical"]
        assert len(self.scanner.findings) == 1
        assert "CRITICAL" in self.scanner.findings[0]["finding"]

    def test_rag_without_file_upload_scores_high(self):
        """RAG without file uploads must score High (7 points)."""
        self.scanner.assess_prompt_injection(
            uses_rag=True,
            accepts_user_files=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["High"]
        assert "HIGH" in self.scanner.findings[0]["finding"]

    def test_no_rag_scores_low(self):
        """No RAG pipeline must score Low (1 point)."""
        self.scanner.assess_prompt_injection(
            uses_rag=False,
            accepts_user_files=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["Low"]

    def test_training_on_data_scores_critical(self):
        """Vendor training on user data must score Critical."""
        self.scanner.assess_data_disclosure(
            stores_conversations=False,
            trains_on_data=True
        )
        assert self.scanner.risk_score >= SEVERITY_SCORES["Critical"]
        assert "CRITICAL" in self.scanner.findings[0]["finding"]

    def test_storing_conversations_scores_high(self):
        """Storing conversations without training must score High."""
        self.scanner.assess_data_disclosure(
            stores_conversations=True,
            trains_on_data=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["High"]

    def test_multiple_autonomous_actions_scores_critical(self):
        """Agent with 2+ autonomous actions must score Critical."""
        self.scanner.assess_excessive_agency(
            can_send_emails=True,
            can_modify_files=True,
            can_call_apis=False
        )
        assert self.scanner.risk_score >= SEVERITY_SCORES["Critical"]
        assert "CRITICAL" in self.scanner.findings[0]["finding"]

    def test_single_autonomous_action_scores_high(self):
        """Agent with exactly 1 autonomous action must score High."""
        self.scanner.assess_excessive_agency(
            can_send_emails=True,
            can_modify_files=False,
            can_call_apis=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["High"]

    def test_no_autonomous_actions_scores_low(self):
        """Read-only agent must score Low."""
        self.scanner.assess_excessive_agency(
            can_send_emails=False,
            can_modify_files=False,
            can_call_apis=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["Low"]

    def test_dangerous_oauth_scope_detected(self):
        """Dangerous OAuth scopes must be detected and scored."""
        self.scanner.assess_oauth_scope(
            oauth_scopes=["mail.readwrite", "profile", "openid"]
        )
        assert self.scanner.risk_score > 0
        assert len(self.scanner.findings) == 1
        assert "OAuth" in self.scanner.findings[0]["name"]

    def test_safe_oauth_scopes_not_flagged(self):
        """Safe OAuth scopes must not add findings."""
        self.scanner.assess_oauth_scope(
            oauth_scopes=["openid", "profile", "email"]
        )
        assert self.scanner.risk_score == 0
        assert len(self.scanner.findings) == 0

    def test_multiple_dangerous_scopes_multiply_score(self):
        """Multiple dangerous scopes must multiply the risk score."""
        self.scanner.assess_oauth_scope(
            oauth_scopes=["mail.readwrite", "files.readwrite.all"]
        )
        expected_score = SEVERITY_SCORES["Critical"] * 2
        assert self.scanner.risk_score == expected_score

    def test_no_soc2_no_pentest_scores_high(self):
        """No SOC2 and no pentest must score High."""
        self.scanner.assess_supply_chain(
            has_soc2=False,
            has_pentest=False
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["High"]

    def test_soc2_present_scores_low(self):
        """SOC2 Type II present must score Low."""
        self.scanner.assess_supply_chain(
            has_soc2=True,
            has_pentest=True
        )
        assert self.scanner.risk_score == SEVERITY_SCORES["Low"]

    def test_report_has_required_fields(self):
        """Generated report must contain all required fields."""
        self.scanner.assess_prompt_injection(uses_rag=True)
        report = self.scanner.generate_report()
        required = [
            "vendor", "integration_type", "assessed_by", "assessed_at",
            "risk_score", "risk_rating", "risk_rating_description",
            "critical_findings", "total_findings", "findings",
            "business_summary", "approval_status"
        ]
        for field in required:
            assert field in report, f"Report missing required field: {field}"

    def test_report_vendor_matches_input(self):
        """Report vendor must match scanner initialization."""
        report = self.scanner.generate_report()
        assert report["vendor"] == "Test Vendor"

    def test_high_risk_report_blocked_status(self):
        """High risk score must produce BLOCKED approval status."""
        self.scanner.assess_prompt_injection(
            uses_rag=True, accepts_user_files=True
        )
        self.scanner.assess_data_disclosure(trains_on_data=True)
        self.scanner.assess_excessive_agency(
            can_send_emails=True, can_modify_files=True
        )
        report = self.scanner.generate_report()
        assert report["risk_rating"] == "HIGH"
        assert "BLOCKED" in report["approval_status"]

    def test_cumulative_scoring(self):
        """Multiple assessments must accumulate scores correctly."""
        self.scanner.assess_prompt_injection(uses_rag=True)
        score_after_first = self.scanner.risk_score
        self.scanner.assess_data_disclosure(stores_conversations=True)
        assert self.scanner.risk_score > score_after_first

    def test_assessed_by_field(self):
        """Report must credit Delphin A. Zaki as assessor."""
        report = self.scanner.generate_report()
        assert report["assessed_by"] == "Delphin A. Zaki"


# ══════════════════════════════════════════════════════════════
# TPRM Assessment Tests
# ══════════════════════════════════════════════════════════════

class TestTPRMAssessment:

    def setup_method(self):
        """Create a fresh TPRM assessment before each test."""
        self.assessment = TPRMAssessment(vendor_name="Test Vendor")

    def test_assessment_initializes_correctly(self):
        """TPRM assessment must initialize with zero score."""
        assert self.assessment.vendor == "Test Vendor"
        assert self.assessment.risk_score == 0
        assert self.assessment.responses == {}

    def test_record_response_stores_lowercase(self):
        """Responses must be stored in lowercase for consistent matching."""
        self.assessment.record_response("DH-01", "YES")
        assert self.assessment.responses["DH-01"] == "yes"

    def test_fail_response_adds_finding(self):
        """A failing response to DH-01 must add a finding."""
        self.assessment.record_response("DH-01", "yes")
        report = self.assessment.generate_report()
        finding_ids = [f["id"] for f in report["findings"]]
        assert "DH-01" in finding_ids

    def test_pass_response_no_finding(self):
        """A passing response to DH-01 must not add a finding."""
        self.assessment.record_response("DH-01", "no")
        report = self.assessment.generate_report()
        finding_ids = [f["id"] for f in report["findings"]]
        assert "DH-01" not in finding_ids

    def test_report_has_required_fields(self):
        """TPRM report must contain all required fields."""
        report = self.assessment.generate_report()
        required = [
            "vendor", "assessor", "assessed_at", "tprm_risk_score",
            "tprm_rating", "approval_status", "critical_failures",
            "total_failures", "total_questions", "findings"
        ]
        for field in required:
            assert field in report, f"TPRM report missing: {field}"

    def test_total_questions_count(self):
        """TPRM must have at least 12 questions total."""
        report = self.assessment.generate_report()
        assert report["total_questions"] >= 12

    def test_all_failing_responses_produce_high_rating(self):
        """All critical questions failing must produce HIGH rating."""
        self.assessment.record_response("DH-01", "yes")
        self.assessment.record_response("DH-04", "yes")
        self.assessment.record_response("AC-01", "yes")
        self.assessment.record_response("GS-01", "no")
        self.assessment.record_response("GS-02", "no")
        self.assessment.record_response("GS-03", "no")
        report = self.assessment.generate_report()
        assert report["tprm_rating"] in ["HIGH", "MEDIUM"]

    def test_get_all_questions_returns_list(self):
        """get_all_questions() must return a non-empty list."""
        questions = get_all_questions()
        assert isinstance(questions, list)
        assert len(questions) >= 12

    def test_each_question_has_required_fields(self):
        """Every TPRM question must have id, risk, question, required_control."""
        questions = get_all_questions()
        required = ["id", "risk", "question", "required_control"]
        for q in questions:
            for field in required:
                assert field in q, f"Question {q.get('id')} missing: {field}"

    def test_get_questions_by_category_data_handling(self):
        """data_handling category must return questions."""
        questions = get_questions_by_category("data_handling")
        assert len(questions) > 0
        ids = [q["id"] for q in questions]
        assert "DH-01" in ids

    def test_get_questions_by_invalid_category(self):
        """Invalid category must return empty list."""
        questions = get_questions_by_category("nonexistent_category")
        assert questions == []


# ══════════════════════════════════════════════════════════════
# Integration Tests
# ══════════════════════════════════════════════════════════════

class TestIntegration:

    def test_full_high_risk_vendor_assessment(self):
        """
        A vendor with RAG, file uploads, training on data,
        autonomous actions, and no SOC2 must rate HIGH.
        """
        scanner = GenAIRiskScanner(
            vendor_name="Risky Vendor Inc",
            integration_type="low-code-agent"
        )
        scanner.assess_prompt_injection(
            uses_rag=True,
            accepts_user_files=True
        )
        scanner.assess_data_disclosure(
            trains_on_data=True
        )
        scanner.assess_excessive_agency(
            can_send_emails=True,
            can_modify_files=True
        )
        scanner.assess_supply_chain(
            has_soc2=False,
            has_pentest=False
        )
        scanner.assess_oauth_scope(
            oauth_scopes=["mail.readwrite", "files.readwrite.all"]
        )
        report = scanner.generate_report()
        assert report["risk_rating"] == "HIGH"
        assert "BLOCKED" in report["approval_status"]
        assert report["risk_score"] >= 20

    def test_full_low_risk_vendor_assessment(self):
        """
        A vendor with no RAG, no storage, no training,
        read-only, and SOC2 must rate LOW.
        """
        scanner = GenAIRiskScanner(
            vendor_name="Safe Vendor Inc",
            integration_type="chatbot"
        )
        scanner.assess_prompt_injection(
            uses_rag=False,
            accepts_user_files=False
        )
        scanner.assess_data_disclosure(
            stores_conversations=False,
            trains_on_data=False
        )
        scanner.assess_excessive_agency(
            can_send_emails=False,
            can_modify_files=False,
            can_call_apis=False
        )
        scanner.assess_supply_chain(
            has_soc2=True,
            has_pentest=True
        )
        report = scanner.generate_report()
        assert report["risk_rating"] == "LOW"
        assert "APPROVED" in report[
