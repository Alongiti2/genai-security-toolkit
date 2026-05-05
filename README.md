# GenAI Security Assessment Toolkit

![Tests](https://github.com/Alongiti2/genai-security-toolkit/actions/workflows/security-scan.yml/badge.svg)
![OWASP](https://img.shields.io/badge/OWASP-GenAI%20Top%2010-red)
![Python](https://img.shields.io/badge/Python-3.11-blue)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## What this is

A Python toolkit for Workforce Security teams evaluating GenAI tool adoption.
Automates OWASP GenAI Top 10 risk scoring, TPRM vendor assessments,
and produces executive-ready risk reports — so engineers focus on
decisions that require human judgment, not data gathering.

## Why I built this

Enterprise teams are adopting GenAI tools — Anthropic Claude,
Microsoft Copilot, Google Gemini — faster than security teams
can evaluate them. This toolkit automates the risk assessment
baseline for workforce-facing GenAI deployments.

## What it covers

- OWASP GenAI Top 10 risk scoring per vendor
- TPRM vendor questionnaire automation (12 GenAI-specific checks)
- Prompt injection attack surface mapping
- RAG pipeline retrieval boundary analysis
- MCP/A2A integration trust boundary assessment
- OAuth scope excessive permission detection
- Executive risk summary — JSON + structured report
- GitHub Actions CI/CD with weekly automated scanning
- Docker containerized — runs anywhere in one command

## Quick start

```bash
git clone https://github.com/Alongiti2/genai-security-toolkit
cd genai-security-toolkit
pip install -r requirements.txt
python main.py --vendor "Anthropic Claude" --type "rag"
```

## Project structure

```
genai-security-toolkit/
├── scanner/
│ ├── genai_risk_scanner.py # Core assessment engine
│ ├── owasp_genai_top10.py # OWASP GenAI threat taxonomy
│ └── tprm_questionnaire.py # Vendor questionnaire
├── reports/
│ └── sample_report.json # Example assessment output
├── docs/
│ ├── OWASP_GenAI_Top10.md # Threat reference guide
│ └── TPRM_methodology.md # Assessment framework
├── docker/
│ └── Dockerfile
├── tests/
│ └── test_scanner.py
├── main.py
└── requirements.txt
```

## Built by

Delphin A. Zaki — CISSP, CCSP, PCNSE
CIS 410 Cybersecurity Automation — Highline College
[LinkedIn](https://linkedin.com/in/delphinzaki)
