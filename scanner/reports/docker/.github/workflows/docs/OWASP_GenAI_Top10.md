# TPRM Methodology — GenAI Vendor Assessment Framework

**Author:** Delphin A. Zaki | CISSP | CCSP | PCNSE  
**Course:** CIS 410 – Cybersecurity Automation | Highline College  
**Purpose:** Four-phase TPRM framework for enterprise GenAI tool evaluation

---

## Overview

Traditional Third-Party Risk Management programs were designed for
SaaS and cloud vendors. GenAI tools require an additional assessment
layer — because the risk is not just in the vendor's security controls,
but in what the model does with data, how it behaves autonomously,
and what threats it introduces that have no equivalent in non-AI tools.

This framework extends classical TPRM with a GenAI-specific lens,
covering four phases from initial intake through ongoing monitoring.

---

## Phase 1 — Intake & Tiering

### Goal
Classify the tool by data sensitivity and integration depth before
investing in a full assessment. Not every tool needs the same scrutiny.

### Tiering criteria

| Tier | Criteria | Assessment depth |
|------|----------|-----------------|
| Tier 1 | Accesses sensitive data, agentic, or RAG-based | Full assessment — all 4 phases |
| Tier 2 | Accesses internal data, read-only | Phases 1-3 |
| Tier 3 | No internal data access, public data only | Phase 1 + questionnaire |

### Intake questions
1. What data will the tool access or process?
2. Is the tool agentic — can it take actions on behalf of users?
3. Does the tool use RAG or connect to internal knowledge bases?
4. What OAuth scopes or API permissions does it request?
5. Is the tool from a named vendor — Anthropic, OpenAI, Google, Microsoft?

### Output
- Tier classification
- Assessment scope decision
- Assigned security engineer

---

## Phase 2 — Architecture Review & Threat Modeling

### Goal
Map the tool's data flow, integration points, and trust boundaries.
Identify the specific OWASP GenAI threats that apply to this
tool's architecture before technical testing begins.

### Data flow mapping
Document answers to these questions:

**Data in:**
- What data enters the model context? (user input, RAG chunks, files)
- Who controls what enters the context?
- Is there input validation before context injection?

**Data processed:**
- Where does inference happen — vendor cloud, on-premises, or hybrid?
- What geographic region processes the data?
- Does the vendor log prompts and completions?

**Data out:**
- Where do model outputs go? (user UI, downstream APIs, storage)
- Is output validated before use?
- Can the model trigger write actions?

### Trust boundary analysis
For each integration point — OAuth, MCP, API key, SSO — document:
- What the integration can read
- What the integration can write
- Whether actions require user approval
- How the integration is revoked when an employee offboards

### OWASP threat mapping
Using the data flow map, identify which OWASP GenAI Top 10 threats
are in scope for this specific tool. A read-only chatbot has a
different threat profile than a low-code agentic platform.

### Output
- Data flow diagram
- Trust boundary map
- OWASP threats in scope for this tool

---

## Phase 3 — Technical Validation

### Goal
Validate vendor security claims through direct testing, documentation
review, and control-based attestation.

### Vendor questionnaire
Run the automated TPRM questionnaire from this toolkit:

```bash
python main.py --vendor "Vendor Name" --type rag --mode tprm
```

The questionnaire covers four categories with 17 questions total:

**Data Handling (5 questions)**
- Training data usage policy
- Conversation retention period
- On-demand deletion capability
- Geographic data processing
- Subprocessor disclosure

**Access Control (4 questions)**
- OAuth scope minimization
- SSO and MFA support
- SCIM provisioning/deprovisioning
- Per-user audit log availability

**GenAI-Specific Controls (5 questions)**
- Prompt injection mitigation documentation
- RAG retrieval boundary enforcement
- Agentic action approval requirements
- Responsible AI policy publication
- Model update notification policy

**Incident Response (3 questions)**
- AI incident response procedure
- Breach notification timeline
- SOC2 Type II audit status

### Documentation review
Request and review from the vendor:
- SOC2 Type II report — focus on exceptions section
- Most recent third-party penetration test executive summary
- Responsible AI or model safety policy
- Data processing agreement (DPA)
- Subprocessor list

### Hands-on validation
Where a sandbox environment is available:
- Test prompt injection with benign payloads
- Verify OAuth scope claims against actual token permissions
- Confirm RAG retrieval boundaries with cross-tenant test queries
- Validate that agentic approval gates function as documented

### Output
- Completed TPRM questionnaire with vendor responses
- Documentation review findings
- Technical validation results
- Preliminary risk score

---

## Phase 4 — Risk Rating & Decision

### Goal
Produce a clear, business-readable risk rating and approval decision
that the appropriate business owner can act on.

### Risk scoring
Combine the OWASP GenAI scan score and TPRM questionnaire score:

```bash
python main.py --vendor "Vendor Name" --type rag --mode full
```

| Combined Score | Rating | Decision |
|---------------|--------|----------|
| 30+ | HIGH | BLOCKED — do not deploy |
| 15–29 | MEDIUM | CONDITIONAL — deploy after controls |
| 0–14 | LOW | APPROVED — standard monitoring |

### Risk summary format
Write a one-page risk summary for the business owner:

**Paragraph 1 — What we assessed**
Name the tool, integration type, and scope of assessment.

**Paragraph 2 — What we found**
State the risk rating, number of critical findings, and the
two or three most significant risks in plain language.

**Paragraph 3 — What needs to happen**
List the specific conditions that must be met before or after
deployment. Be explicit — not "improve security" but
"implement chunk-level content filtering on the RAG pipeline
before go-live and confirm via architecture review."

**Paragraph 4 — Decision**
State the approval status clearly:
BLOCKED / CONDITIONAL (with conditions) / APPROVED

### Output
- Risk summary document (one page, business audience)
- Full technical report (JSON from this toolkit)
- Approval conditions list
- Next review date

---

## Ongoing Monitoring

A TPRM assessment is not a one-time event. GenAI tools evolve
rapidly — capabilities change, data handling policies update,
and new threats emerge.

### Monitoring schedule

| Activity | Frequency |
|----------|-----------|
| Automated OWASP scan | Weekly (via GitHub Actions) |
| Vendor terms of service review | Quarterly |
| Full reassessment — Tier 1 vendors | Annually |
| Immediate reassessment trigger | Any major model update or incident |

### Reassessment triggers
Immediately reassess when:
- Vendor announces new agentic capabilities
- Vendor changes data retention or training policy
- A security incident affects the vendor
- The tool's OAuth scope or integration changes
- A new OWASP GenAI threat is published that applies to this tool

---

## Running the full assessment

```bash
# Full OWASP + TPRM combined assessment:
python main.py \
  --vendor "Microsoft Copilot" \
  --type low-code-agent \
  --rag yes \
  --files yes \
  --trains no \
  --stores yes \
  --emails yes \
  --modifies yes \
  --soc2 yes \
  --pentest yes \
  --mode full
```

Reports are saved to `reports/` as JSON files, ready for
SIEM ingestion, ticket attachment, or executive distribution.

---

*Built by Delphin A. Zaki — CISSP | CCSP | PCNSE*  
*CIS 410 Cybersecurity Automation — Highline College*  
*github.com/Alongiti2/genai-security-toolkit*
