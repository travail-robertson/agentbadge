"""
main.py - Runs the whole AgentBadge demo from start to finish.

How to run (from inside the agentbadge folder):
    python main.py         (on Mac/Linux you may need: python3 main.py)

What happens, in order:
    1. Load the sample agents and policies
    2. Show the agent registry
    3. Onboard a new agent (one approval denied, one approved)
    4. Send 14 sample actions through the runtime checker
    5. Prove the audit log hasn't been tampered with
    6. Run the access review and save the report

Nothing in the data/ folder is changed. All results go to output/,
so you can run this as many times as you like.
"""

import json
import os
from datetime import date

from agentbadge.registry import load_agents, save_agents, register_agent, find_agent, print_registry
from agentbadge.policy import load_policies
from agentbadge.onboarding import approve_agent
from agentbadge.checker import check_action
from agentbadge.audit import AuditLog, read_log, verify_log
from agentbadge.review import run_access_review, write_report_csv, write_report_markdown

# A fixed "today" keeps the demo results identical every time you run it.
# Change to: AS_OF = date.today()   to use the real current date.
AS_OF = date(2026, 11, 13)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
OUT = os.path.join(HERE, "output")

# Little symbols to make the terminal output easy to scan
ICON = {"ALLOW": "[ALLOW]", "BLOCK": "[BLOCK]", "FLAG": "[FLAG ]"}


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def main():
    os.makedirs(OUT, exist_ok=True)

    # ---- Step 1: load data -------------------------------------------------
    agents = load_agents(os.path.join(DATA, "agents.json"))
    policies = load_policies(os.path.join(DATA, "policies.json"))
    with open(os.path.join(DATA, "sample_actions.json"), encoding="utf-8") as f:
        requests = json.load(f)

    # ---- Step 2: registry --------------------------------------------------
    section("1. AGENT REGISTRY (who exists, who owns it, what risk it carries)")
    print_registry(agents)

    # ---- Step 3: onboarding ------------------------------------------------
    section("2. ONBOARDING (no badge until the checklist passes)")
    new_agent = register_agent(
        agents, "AGT-009", "MeetingNotesBot", "Chris Lee (Operations)",
        "Draft meeting notes from calendar invites", "low", AS_OF.isoformat())
    print(f"Registered {new_agent['agent_id']} {new_agent['name']} -> status: {new_agent['status']}")

    attempts = [
        ("AGT-009", "Chris Lee (Operations)"),   # owner tries to self-approve
        ("AGT-009", "Sam Rivera (Security)"),    # independent reviewer
        ("AGT-007", "Sam Rivera (Security)"),    # SupportTriage has no policy yet
    ]
    for agent_id, approver in attempts:
        agent = find_agent(agents, agent_id)
        ok, problems = approve_agent(agent, policies, approver, AS_OF)
        result = "APPROVED" if ok else "DENIED"
        print(f"\n{agent_id} {agent['name']} approval by {approver}: {result}")
        for p in problems:
            print(f"   - {p}")

    # ---- Step 4: runtime checks + audit log --------------------------------
    section("3. RUNTIME ACTION CHECKER (every request, at the moment it happens)")
    log_path = os.path.join(OUT, "audit_log.jsonl")
    log = AuditLog(log_path)

    for req in requests:
        result = check_action(req, agents, policies, AS_OF)
        log.record(req, result)
        # If the agent was allowed (or flagged) to act, note that it was used
        # today. The access review uses this to spot dormant agents.
        if result["decision"] in ("ALLOW", "FLAG"):
            find_agent(agents, req["agent_id"])["last_used"] = AS_OF.isoformat()
        print(f"{ICON[result['decision']]} {req['request_id']} {req['agent_id']} "
              f"{req['action']} -> {req['resource']}")
        print(f"         {result['rule']}: {result['reason']}")

    # ---- Step 5: audit integrity ------------------------------------------
    section("4. AUDIT LOG INTEGRITY")
    ok, message = verify_log(log_path)
    print(f"Original log:  {message}")

    # Simulate an insider changing one BLOCK into an ALLOW to hide it.
    entries = read_log(log_path)
    entries[2]["decision"] = "ALLOW"
    tampered_path = os.path.join(OUT, "audit_log_TAMPERED_demo.jsonl")
    with open(tampered_path, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    ok, message = verify_log(tampered_path)
    print(f"Tampered copy: {message}")

    # ---- Step 6: access review --------------------------------------------
    section("5. ACCESS REVIEW (expired, unused, orphaned, over-privileged)")
    audit_entries = read_log(log_path)
    findings = run_access_review(agents, policies, audit_entries, AS_OF)
    for f in findings:
        print(f"[{f['severity']:<6}] {f['agent_id']} {f['agent_name']:<20} "
              f"{f['issue']:<16} {f['detail']}")

    write_report_markdown(findings, agents, audit_entries, AS_OF,
                          os.path.join(OUT, "access_review_report.md"))
    write_report_csv(findings, os.path.join(OUT, "access_review_report.csv"))
    save_agents(agents, os.path.join(OUT, "agents_after_run.json"))

    section("DONE. See the output/ folder:")
    print("  audit_log.jsonl            every decision, hash-chained")
    print("  access_review_report.md    reviewer-ready report")
    print("  access_review_report.csv   same findings for Excel")
    print("  agents_after_run.json      registry after onboarding")


if __name__ == "__main__":
    main()
