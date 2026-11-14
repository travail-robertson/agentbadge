# 🪪 AgentBadge

**Govern AI agents the way companies govern employees.** Each agent gets an inventory record, an onboarding approval, least-privilege access, runtime enforcement, an audit trail and periodic access reviews.

> Portfolio prototype built with Python's standard library. All data is fake.

---

## The problem

AI agents often run under a human's credentials and inherit **everything that person can access**. Most organizations:

- have **no inventory** of the agents running in their environment,
- have **no owner or approval** on record for each agent,
- rely on **static configuration**, which attackers get around at runtime with **prompt injection**: hiding instructions in an email, invoice or code comment that the agent reads and obeys.

## The approach

AgentBadge applies the identity and access governance lifecycle that GRC teams already run for people:

| Employee governance | AgentBadge feature |
|---|---|
| HR record | **Agent registry**: name, owner, purpose, risk level, status, created date |
| New-hire approval | **Onboarding gate**: checklist + independent approver before activation |
| Role-based access | **Access policy**: allowed actions, resources, roles and an expiration date |
| Badge reader at every door | **Runtime checker**: ALLOW / BLOCK / FLAG on every request |
| Security camera footage | **Audit log**: every decision, hash-chained to detect tampering |
| Quarterly user access review | **Access-review report**: expired, unused, orphaned, over-privileged |

## How a request is decided

```
Agent request ─► R1 Registered? ─► R2 Active? ─► R3 Has policy? ─► R4 Not expired?
              ─► R5 No injection phrases? ─► R6 Action allowed? ─► R7 Resource allowed?
              ─► R8 High-risk action? ──yes──► FLAG (human review)
                                       └─no──► ALLOW
     Any "no" above ─► BLOCK          Every decision ─► Audit log
```

**Defense in depth:** in REQ-08, the injected text has no known trigger phrase, so detection (R5) misses it. Least privilege (R6) still blocks it, because pushing code isn't in the agent's job.

## Demo results

```
[ALLOW] REQ-01 AGT-001 read -> finance/invoices/INV-1001
[BLOCK] REQ-03 AGT-001 send_email -> email/outbound/attacker@evil.example
         R5: Possible prompt injection detected: 'ignore all previous instructions'
[BLOCK] REQ-07 AGT-003 merge -> repo/payments-api/pr-43
         R5: Possible prompt injection detected: 'disregard your rules'
[BLOCK] REQ-08 AGT-003 push -> repo/payments-api/main
         R6: Action 'push' is not in this agent's allowed actions
[BLOCK] REQ-09 AGT-004 send_email -> email/outbound/customers
         R4: Access expired on 2026-09-30
[FLAG ] REQ-10 AGT-005 delete -> ad/users/jsmith
         R8: 'delete' is allowed but high-risk; human review required
[BLOCK] REQ-13 AGT-999 read -> finance/invoices/*
         R1: Agent is not in the registry (unregistered/shadow agent)
...
Original log:  Audit log integrity verified: no entries altered or removed
Tampered copy: Entry 3 was modified after it was written
```

The access review found **10 issues** across 9 agents, including an expired policy, a self-approved agent with wildcard access and `Domain Admins`, an orphaned agent idle for 196 days, and two agents targeted by prompt injection. See the [sample report](output/access_review_report.md).

## Quick start

Requires Python 3.10 or newer. Nothing to install.

```bash
git clone https://github.com/YOUR-USERNAME/agentbadge.git
cd agentbadge
python main.py                       # run the full demo
python -m unittest discover tests    # run the 10 automated tests
```

Outputs are written to `output/`:

| File | What it is |
|---|---|
| `audit_log.jsonl` | Every decision, one JSON record per line, hash-chained |
| `access_review_report.md` / `.csv` | Reviewer-ready findings (CSV opens in Excel) |
| `agents_after_run.json` | Registry after onboarding |

## Project structure

```
agentbadge/
├── main.py                 Runs the end-to-end demo
├── agentbadge/
│   ├── registry.py         Agent inventory
│   ├── onboarding.py       Approval gate (separation of duties)
│   ├── policy.py           Least-privilege entitlements + expiry
│   ├── checker.py          Runtime ALLOW / BLOCK / FLAG engine
│   ├── audit.py            Tamper-evident audit log
│   └── review.py           Access-review report
├── data/                   Sample agents, policies, requests
├── tests/                  Unit tests for the controls
└── docs/
    ├── BUILD_GUIDE.md      Step-by-step beginner walkthrough
    ├── CONTROL_MAPPING.md  NIST AI RMF / CSF 2.0 / least-privilege mapping
    └── PORTFOLIO_SUMMARY.md
```

## Framework alignment

| Feature | NIST AI RMF 1.0 | NIST CSF 2.0 | Least privilege |
|---|---|---|---|
| Registry | GOVERN 1.6, GOVERN 2.1, MAP 1.1 | ID.AM-02, ID.AM-05, GV.RR-02 | Every agent has its own identity and owner |
| Onboarding | GOVERN 1.4, GOVERN 2.1 | PR.AA-01, PR.AA-05, ID.AM-08 | Policy before activation; separation of duties |
| Access policies | GOVERN 1.4, MAP 3.5 | PR.AA-05 | Explicit allow-lists; time-bound access |
| Runtime checker | MEASURE 2.4, MEASURE 2.7, MANAGE 2.4, GOVERN 3.2 | PR.AA-05, DE.CM-09, DE.AE-02 | Deny by default; human review for high-risk actions |
| Audit log | MANAGE 4.1, MEASURE 2.4 | PR.PS-04, DE.CM-03, PR.DS-01 | Logging of privileged actions |
| Access review | GOVERN 1.5, GOVERN 1.7, MANAGE 4.1 | PR.AA-05, ID.AM-08, GV.OV | Periodic re-certification; remove unused access |

Also relevant: OWASP Top 10 for LLM Applications (LLM01 Prompt Injection, LLM06 Excessive Agency) and NIST SP 800-53 AC-2, AC-5, AC-6, AU-9. Full rationale is in [docs/CONTROL_MAPPING.md](docs/CONTROL_MAPPING.md).

## Limitations (on purpose)

This is a learning prototype, not a product:

- Injection detection is a simple phrase list. The real protection here comes from least-privilege enforcement.
- Data lives in JSON files, not a database or identity provider.
- The checker trusts the agent to report its own request. In production it would sit in the path as a gateway or proxy, so it sees requests directly.

## Roadmap

SQLite storage · Streamlit dashboard · Entra ID / Okta group sync · auto-suspend after repeated blocks · FLAG → ticket queue for human approval · classifier-based injection detection

## About

Built by **[Your Name]**, a GRC professional with 9 years in compliance and IT asset governance, moving into cybersecurity. [LinkedIn](https://linkedin.com/in/your-profile)
