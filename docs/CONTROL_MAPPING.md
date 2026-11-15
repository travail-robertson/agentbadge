# Control Mapping

How each AgentBadge feature supports NIST AI RMF 1.0, NIST CSF 2.0 and least privilege.

> **Wording matters in interviews:** a prototype *supports* or *demonstrates* a control. It does not *satisfy* or *certify* it. Before you present this, check each ID against the official documents (NIST AI 100-1 and its Playbook, NIST CSWP 29 for CSF 2.0, NIST SP 800-53 Rev. 5).

## Summary table

| # | Feature | NIST AI RMF 1.0 | NIST CSF 2.0 | Least privilege / supporting controls |
|---|---|---|---|---|
| 1 | Agent registry | GOVERN 1.6 (AI system inventory), GOVERN 2.1 (roles & accountability), MAP 1.1 (intended purpose documented) | ID.AM-02 (software/systems inventory), ID.AM-05 (assets prioritized by criticality), GV.RR-02 (roles & responsibilities) | SP 800-53 AC-2 (account management), CM-8 (component inventory). No agent without a named owner. |
| 2 | Onboarding approval | GOVERN 1.4 (transparent risk policies), GOVERN 2.1, MAP 1.1 | PR.AA-01 (identities managed), PR.AA-05 (least privilege & separation of duties), ID.AM-08 (lifecycle management) | AC-2 (approval before account creation), AC-5 (separation of duties: owner can't self-approve) |
| 3 | Access policies | GOVERN 1.4, MAP 3.5 (human-oversight processes defined) | PR.AA-05 (permissions defined in policy, managed, reviewed) | AC-6 (least privilege), AC-2(3) (disable after a set period, via the expiration date), AC-3 (access enforcement) |
| 4 | Runtime action checker | MEASURE 2.4 (monitoring in production), MEASURE 2.7 (security & resilience), MANAGE 2.4 (disengage/deactivate on out-of-scope behavior), GOVERN 3.2 (human-AI oversight roles, via FLAG) | PR.AA-05 (enforced), DE.CM-09 (runtime environments monitored), DE.AE-02 (adverse events analyzed) | AC-3, AC-6, SI-10 (input validation). OWASP Top 10 for LLMs: LLM01 Prompt Injection, LLM06 Excessive Agency |
| 5 | Audit log (hash-chained) | MANAGE 4.1 (post-deployment monitoring), MEASURE 2.4 | PR.PS-04 (log records generated), DE.CM-03 (technology usage monitored), PR.DS-01 (data integrity) | AU-2/AU-3 (event logging & content), AU-9 (protecting audit information), AC-6(9) (log use of privileged functions) |
| 6 | Access-review report | GOVERN 1.5 (ongoing monitoring & periodic review), GOVERN 1.7 (decommissioning), MANAGE 4.1 | PR.AA-05 (reviewed), ID.AM-08, GV.OV (oversight), ID.IM (improvement) | AC-2(j) (periodic account review), AC-6(7) (review of privileges), AC-2(3) (disable inactive accounts) |

## Feature by feature, in plain language

**1. Registry → "You can't govern what you can't see."**
GOVERN 1.6 asks for an inventory of AI systems. ID.AM-02 asks for a software and systems inventory. The `owner` field is accountability (GOVERN 2.1, GV.RR-02), and `risk_level` is prioritization (ID.AM-05). The checker's rule R1 blocks unregistered "shadow" agents, which puts the inventory into practice.

**2. Onboarding → "No badge until the paperwork is done."**
This is joiner-mover-leaver for agents. Approval needs a policy *before* activation, so least privilege is designed in rather than added later. The owner can't approve their own agent, and high-risk agents need a security reviewer (separation of duties, AC-5).

**3. Access policies → "Only what the job needs, and only for a while."**
Allowed actions and resources are explicit entitlements (PR.AA-05, AC-6). Roles map to how access is granted in real directories. The expiration date makes access time-bound by default, so access ends unless someone re-certifies it.

**4. Runtime checker → "Check the badge at every door, every time."**
Static configuration isn't enough, because prompt injection changes what an agent *tries* to do at runtime. The checker evaluates each request when it happens (DE.CM-09, MEASURE 2.4). It has two layers:
- R5 catches known injection phrases (OWASP LLM01).
- R6/R7 enforce the policy even when R5 misses the attack (REQ-08 in the demo). This is the real control: it limits *excessive agency* (OWASP LLM06), so a fooled agent still can't step outside its job.
- R8 FLAGs high-risk actions for a human, which is human-in-the-loop oversight (GOVERN 3.2, MAP 3.5).

**5. Audit log → "If it isn't logged, it didn't happen."**
Every decision, including ALLOWs, is recorded with who, what, where, the decision, the rule and the reason (AU-3, PR.PS-04). Hash chaining makes tampering detectable (AU-9), and the demo shows a modified entry being caught.

**6. Access review → "The quarterly UAR, automated for agents."**
The review flags expired, expiring, unused, orphaned, self-approved and over-privileged agents (wildcards, admin roles, high-risk verbs), plus agents targeted by injection. That covers periodic review (AC-2(j), AC-6(7), GOVERN 1.5) and decommissioning triggers (GOVERN 1.7).

## Least-privilege principles shown

| Principle | Where it appears |
|---|---|
| Deny by default | Checker blocks unless every rule passes (R1–R7) |
| Minimum necessary access | Explicit action and resource lists; wildcards flagged as over-privileged |
| Time-bound access | `expires` on every policy; R4 blocks expired access |
| Separation of duties | Owner cannot approve own agent; review flags self-approval |
| Privileged access is exceptional | Admin roles and high-risk actions flagged; high-risk actions need a human (FLAG) |
| Agents get their own identity | Each agent has its own ID and policy, not a borrowed human credential |
