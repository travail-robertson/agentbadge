# Portfolio Summary Text

## Resume: project entry

**AgentBadge: AI Agent Governance Prototype** (Python) | github.com/travail-robertson/agentbadge

- Built an identity-governance prototype that applies the employee access lifecycle to AI agents: inventory, onboarding approval, least-privilege policies, runtime enforcement, audit logging and access reviews.
- Wrote a runtime policy engine (9 ordered rules) that allows, blocks or flags each agent action. It blocked 3 of 3 simulated prompt-injection attempts, including one that got past keyword detection and was stopped by least-privilege enforcement.
- Built a tamper-evident, hash-chained audit log and an automated access review that flagged 10 issues (expired, orphaned, self-approved and over-privileged agents) across 9 sample agents.
- Mapped every feature to NIST AI RMF 1.0, NIST CSF 2.0 and NIST SP 800-53 access-control principles; added 10 unit tests to verify each control.

*(One-line version:)* Built AgentBadge, a Python prototype for governing AI agents (registry, approvals, least-privilege runtime enforcement, tamper-evident audit log, access reviews) mapped to NIST AI RMF and CSF 2.0.

## LinkedIn: Projects section

**AgentBadge: Governing AI Agents Like Employees**
AI agents often run under a person's credentials and can reach everything that person can, with no inventory, owner or review. AgentBadge is my Python prototype that applies the governance lifecycle I've run for 9 years to AI agents: a registry with accountable owners, an onboarding approval with separation of duties, time-bound least-privilege policies, a runtime checker that allows, blocks or flags every action, a tamper-evident audit log and an automated access review. In the demo it stops simulated prompt-injection attacks, including one that slips past detection and is still blocked by least privilege. Each feature is mapped to NIST AI RMF and NIST CSF 2.0.
Skills: Python · AI Governance · Identity & Access Management · NIST AI RMF · NIST CSF 2.0 · GRC

## LinkedIn: post announcing it

After 9 years in GRC and IT asset governance, I've been asking myself: who's running the access review for AI agents?

Agents often run on a human's credentials. They can reach everything that person can, and most companies can't say how many agents they have or who owns each one.

So I built **AgentBadge**, a beginner Python prototype that governs agents the way we govern employees:
🪪 Registry: every agent has an owner, a purpose and a risk level
✅ Onboarding: no activation without an independent approval
🔐 Least privilege: explicit, expiring access per agent
🛑 Runtime checks: allow, block or flag every action
📜 Audit log: tamper-evident evidence of every decision
🔍 Access review: expired, orphaned and over-privileged agents flagged automatically

My favorite lesson: one simulated prompt injection got past my detection rules entirely. It was still blocked, because the agent was never allowed to do that action in the first place. Least privilege is the control that catches what detection misses.

Mapped to NIST AI RMF and CSF 2.0. Code and write-up: https://github.com/travail-robertson/agentbadge


#AIGovernance #Cybersecurity #GRC #IAM #NIST #CareerChange

## 30-second interview pitch

"AgentBadge applies the identity governance lifecycle to AI agents. Every agent is registered with an owner and risk level, approved by someone other than its owner, and given expiring, least-privilege access. A runtime checker evaluates each action as it happens, because prompt injection changes behavior at runtime, where static config can't help. Every decision goes into a hash-chained audit log, and an access review flags expired, orphaned and over-privileged agents. The big lesson: detection will miss attacks, so least privilege has to be the backstop."
