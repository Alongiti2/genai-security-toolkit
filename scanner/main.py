# placeholder — full code coming
# main.py
# GenAI Security Assessment Toolkit — CLI Entry Point
# Delphin A. Zaki | CIS 410 Cybersecurity Automation | Highline College

import argparse
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scanner"))

from genai_risk_scanner import GenAIRiskScanner
from tprm_questionnaire import TPRMAssessment
from owasp_genai_top10 import score_to_rating, RISK_RATINGS


BANNER = """
╔══════════════════════════════════════════════════════════════╗
║         GenAI Security Assessment Toolkit  v1.0             ║
║         Delphin A. Zaki | CISSP | CCSP | PCNSE              ║
║         CIS 410 Cybersecurity Automation | Highline College  ║
╚══════════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(BANNER)


def print_divider():
    print("─" * 64)


def run_owasp_scan(args):
    """Run OWASP GenAI Top 10 risk assessment."""
    print_banner()
    print(f"  Vendor:           {args.vendor}")
    print(f"  Integration type: {args.type}")
    print(f"  Assessment date:  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print_divider()

    scanner = GenAIRiskScanner(
        vendor_name=args.vendor,
        integration_type=args.type
    )

    # Run all assessments based on flags
    scanner.assess_prompt_injection(
        uses_rag=(args.rag == "yes"),
        accepts_user_files=(args.files == "yes")
    )

    scanner.assess_data_disclosure(
        stores_conversations=(args.stores == "yes"),
        trains_on_data=(args.trains == "yes")
    )

    scanner.assess_excessive_agency(
        can_send_emails=(args.emails == "yes"),
        can_modify_files=(args.modifies == "yes"),
        can_call_apis=(args.apis == "yes")
    )

    scanner.assess_supply_chain(
        has_soc2=(args.soc2 == "yes"),
        has_pentest=(args.pentest == "yes")
    )

    if args.oauth:
        scopes = [s.strip() for s in args.oauth.split(",")]
        scanner.assess_oauth_scope(oauth_scopes=scopes)

    # Generate report
    report = scanner.generate_report()

    # Print findings to terminal
    print("\n  OWASP GenAI Top 10 — Findings:\n")
    for finding in report["findings"]:
        severity = finding.get("severity", "")
        name = finding.get("name", "")
        text = finding.get("finding", "")
        control = finding.get("required_control", "")
        print(f"  [{severity.upper():8}] {name}")
        print(f"           {text}")
        print(f"           Control: {control}")
        print()

    print_divider()
    print(f"  Risk Score:    {report['risk_score']}")
    print(f"  Risk Rating:   {report['risk_rating']}")
    print(f"  Status:        {report['approval_status']}")
    print(f"  Summary:       {report['business_summary']}")
    print_divider()

    # Save report to file
    os.makedirs("reports", exist_ok=True)
    safe_vendor = args.vendor.replace(" ", "_").replace("/", "-")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"reports/{safe_vendor}_{date_str}_owasp.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Report saved: {filename}")
    print()
    return report


def run_tprm_scan(args):
    """Run TPRM vendor questionnaire assessment."""
    print_banner()
    print(f"  TPRM Assessment: {args.vendor}")
    print(f"  Assessment date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print_divider()

    assessment = TPRMAssessment(vendor_name=args.vendor)

    # Load responses from JSON file if provided
    if args.responses:
        if not os.path.exists(args.responses):
            print(f"  ERROR: Responses file not found: {args.responses}")
            sys.exit(1)
        with open(args.responses, "r") as f:
            responses = json.load(f)
        for question_id, response in responses.items():
            assessment.record_response(question_id, response)
        print(f"  Loaded {len(responses)} responses from {args.responses}")
    else:
        # Run interactive questionnaire
        print("\n  Interactive TPRM Questionnaire")
        print("  Answer each question based on vendor documentation.\n")
        from tprm_questionnaire import get_all_questions
        questions = get_all_questions()
        for q in questions:
            print(f"  [{q['risk']:8}] {q['id']}: {q['question']}")
            print(f"           Guidance: {q['guidance']}")
            response = input("  Your answer: ").strip()
            assessment.record_response(q["id"], response)
            print()

    report = assessment.generate_report()

    # Print summary
    print("\n  TPRM Assessment Results:\n")
    for finding in report["findings"]:
        print(f"  [FAIL] {finding['id']} — {finding['question'][:60]}...")
        print(f"         Risk: {finding['risk']}")
        print(f"         Control: {finding['required_control']}")
        print()

    print_divider()
    print(f"  TPRM Score:      {report['tprm_risk_score']}")
    print(f"  TPRM Rating:     {report['tprm_rating']}")
    print(f"  Approval Status: {report['approval_status']}")
    print(f"  Critical Fails:  {report['critical_failures']}")
    print(f"  Total Fails:     {report['total_failures']} / {report['total_questions']}")
    print_divider()

    # Save report
    os.makedirs("reports", exist_ok=True)
    safe_vendor = args.vendor.replace(" ", "_").replace("/", "-")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"reports/{safe_vendor}_{date_str}_tprm.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Report saved: {filename}")
    print()
    return report


def run_full_scan(args):
    """Run both OWASP and TPRM assessments and combine results."""
    print_banner()
    print(f"  FULL ASSESSMENT: {args.vendor}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print_divider()

    owasp_report = run_owasp_scan(args)
    tprm_report = run_tprm_scan(args)

    combined_score = owasp_report["risk_score"] + tprm_report["tprm_risk_score"]
    combined_rating = score_to_rating(combined_score)

    combined = {
        "vendor": args.vendor,
        "assessed_by": "Delphin A. Zaki",
        "assessed_at": datetime.now().isoformat(),
        "combined_risk_score": combined_score,
        "combined_rating": combined_rating,
        "combined_status": RISK_RATINGS[combined_rating],
        "owasp_assessment": owasp_report,
        "tprm_assessment": tprm_report
    }

    os.makedirs("reports", exist_ok=True)
    safe_vendor = args.vendor.replace(" ", "_").replace("/", "-")
    date_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"reports/{safe_vendor}_{date_str}_full.json"

    with open(filename, "w") as f:
        json.dump(combined, f, indent=2)

    print_divider()
    print(f"  COMBINED RISK SCORE:  {combined_score}")
    print(f"  COMBINED RATING:      {combined_rating}")
    print(f"  FINAL STATUS:         {RISK_RATINGS[combined_rating]}")
    print_divider()
    print(f"\n  Full report saved: {filename}\n")


def main():
    parser = argparse.ArgumentParser(
        description="GenAI Security Assessment Toolkit — Workforce Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick OWASP scan:
  python main.py --vendor "Microsoft Copilot" --type rag --rag yes

  # Full scan with all flags:
  python main.py --vendor "Anthropic Claude" --type rag \\
    --rag yes --files yes --trains no --stores yes \\
    --soc2 yes --pentest yes --mode owasp

  # TPRM with response file:
  python main.py --vendor "Google Gemini" --type agent \\
    --mode tprm --responses responses/google_gemini.json

  # Full combined assessment:
  python main.py --vendor "OpenAI ChatGPT Enterprise" \\
    --type low-code-agent --mode full --rag yes --emails yes
        """
    )

    # Required
    parser.add_argument("--vendor",   required=True,  help="Vendor name (e.g. 'Anthropic Claude')")
    parser.add_argument("--type",     required=True,
                        choices=["rag", "agent", "low-code-agent", "chatbot", "search", "other"],
                        help="Integration type")

    # Mode
    parser.add_argument("--mode",     default="owasp",
                        choices=["owasp", "tprm", "full"],
                        help="Assessment mode (default: owasp)")

    # OWASP flags
    parser.add_argument("--rag",      default="no",  choices=["yes", "no"], help="Uses RAG pipeline?")
    parser.add_argument("--files",    default="no",  choices=["yes", "no"], help="Accepts user file uploads?")
    parser.add_argument("--trains",   default="no",  choices=["yes", "no"], help="Trains on user data?")
    parser.add_argument("--stores",   default="no",  choices=["yes", "no"], help="Stores conversations?")
    parser.add_argument("--emails",   default="no",  choices=["yes", "no"], help="Can send emails autonomously?")
    parser.add_argument("--modifies", default="no",  choices=["yes", "no"], help="Can modify files?")
    parser.add_argument("--apis",     default="no",  choices=["yes", "no"], help="Can call external APIs?")
    parser.add_argument("--soc2",     default="no",  choices=["yes", "no"], help="Has SOC2 Type II?")
    parser.add_argument("--pentest",  default="no",  choices=["yes", "no"], help="Has third-party pentest?")
    parser.add_argument("--oauth",    default=None,  help="Comma-separated OAuth scopes to check")

    # TPRM flags
    parser.add_argument("--responses", default=None, help="Path to JSON file with pre-filled TPRM responses")

    args = parser.parse_args()

    if args.mode == "owasp":
        run_owasp_scan(args)
    elif args.mode == "tprm":
        run_tprm_scan(args)
    elif args.mode == "full":
        run_full_scan(args)


if __name__ == "__main__":
    main()
