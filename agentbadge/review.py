"""
review.py - FEATURE 6: The Access Review Report

Plain-language idea:
    The quarterly user access review you already know from GRC work, for
    agents. It looks at the registry, the policies and the audit log, and
    lists anything a reviewer should act on.

What gets flagged:
    EXPIRED          access end date has passed
    EXPIRING SOON    access ends within 30 days (time to re-certify)
    UNUSED           no activity in 90+ days (dormant account)
    ORPHANED         no human owner (nobody accountable)
    OVER-PRIVILEGED  wildcard (*) access, admin roles, or high-risk actions
    SELF-APPROVED    the owner approved their own agent
    NO POLICY        active agent with no access policy
    STALE PENDING    waiting for approval 14+ days
    INJECTION SEEN   the checker blocked a prompt-injection attempt
"""

import csv
from datetime import date

from .checker import HIGH_RISK_ACTIONS
from .policy import get_policy, days_until_expiry

UNUSED_AFTER_DAYS = 90
EXPIRY_WARNING_DAYS = 30
PENDING_WARNING_DAYS = 14
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


def _finding(agent, issue, severity, detail, recommendation):
    return {
        "agent_id": agent["agent_id"],
        "agent_name": agent["name"],
        "owner": agent["owner"] or "(none)",
        "issue": issue,
        "severity": severity,
        "detail": detail,
        "recommendation": recommendation,
    }


def run_access_review(agents, policies, audit_entries, today):
    """Return a list of findings, most severe first."""
    findings = []

    for agent in agents:
        if agent["status"] == "retired":
            continue  # retired agents are out of scope

        policy = get_policy(policies, agent["agent_id"])

        # --- Ownership & approval -------------------------------------
        if not agent["owner"].strip():
            findings.append(_finding(agent, "ORPHANED", "High",
                "No accountable human owner on record",
                "Assign an owner within 5 business days or retire the agent"))

        if agent["approved_by"] and agent["approved_by"] == agent["owner"]:
            findings.append(_finding(agent, "SELF-APPROVED", "High",
                "The agent's owner approved their own agent",
                "Re-approve through an independent security reviewer"))

        if agent["status"] == "pending":
            waiting = (today - date.fromisoformat(agent["created_date"])).days
            if waiting >= PENDING_WARNING_DAYS:
                findings.append(_finding(agent, "STALE PENDING", "Low",
                    f"Waiting for onboarding for {waiting} days",
                    "Complete onboarding or close the request"))

        # --- Policy checks --------------------------------------------
        if policy is None:
            if agent["status"] == "active":
                findings.append(_finding(agent, "NO POLICY", "High",
                    "Active agent with no access policy",
                    "Suspend until a least-privilege policy is approved"))
        else:
            days_left = days_until_expiry(policy, today)
            if days_left < 0:
                findings.append(_finding(agent, "EXPIRED", "High",
                    f"Access expired {policy['expires']} ({-days_left} days ago)",
                    "Revoke access or have the owner re-certify"))
            elif days_left <= EXPIRY_WARNING_DAYS:
                findings.append(_finding(agent, "EXPIRING SOON", "Low",
                    f"Access expires {policy['expires']} (in {days_left} days)",
                    "Owner to re-certify before expiry"))

            if "*" in policy["allowed_actions"] or "*" in policy["allowed_resources"]:
                findings.append(_finding(agent, "OVER-PRIVILEGED", "High",
                    "Wildcard (*) grants every action and/or resource",
                    "Replace wildcards with only the actions/resources needed"))

            admin_roles = [r for r in policy["roles"] if "admin" in r.lower()]
            if admin_roles:
                findings.append(_finding(agent, "OVER-PRIVILEGED", "High",
                    f"Holds privileged role(s): {', '.join(admin_roles)}",
                    "Remove admin roles; use a scoped service role"))

            risky = sorted(set(policy["allowed_actions"]) & HIGH_RISK_ACTIONS)
            if risky:
                findings.append(_finding(agent, "OVER-PRIVILEGED", "Medium",
                    f"Granted high-risk action(s): {', '.join(risky)}",
                    "Confirm business need; require human approval per use"))

        # --- Usage ----------------------------------------------------
        if agent["status"] == "active":
            if agent["last_used"] is None:
                findings.append(_finding(agent, "UNUSED", "Medium",
                    "Active but has never been used",
                    "Confirm need; suspend if not required"))
            else:
                idle = (today - date.fromisoformat(agent["last_used"])).days
                if idle >= UNUSED_AFTER_DAYS:
                    findings.append(_finding(agent, "UNUSED", "Medium",
                        f"No activity for {idle} days (last used {agent['last_used']})",
                        "Confirm need; suspend if not required"))

        # --- Runtime evidence from the audit log ----------------------
        injections = [e for e in audit_entries
                      if e["agent_id"] == agent["agent_id"] and e["rule"] == "R5"]
        if injections:
            findings.append(_finding(agent, "INJECTION SEEN", "Medium",
                f"{len(injections)} prompt-injection attempt(s) blocked "
                f"({', '.join(e['request_id'] for e in injections)})",
                "Investigate the data source that carried the injected text"))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["agent_id"]))
    return findings


def write_report_csv(findings, path):
    """Save findings as a CSV you can open in Excel."""
    columns = ["agent_id", "agent_name", "owner", "issue", "severity", "detail", "recommendation"]
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(findings)


def write_report_markdown(findings, agents, audit_entries, today, path):
    """Save a human-readable report (renders nicely on GitHub)."""
    counts = {}
    for e in audit_entries:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1

    lines = [
        "# AgentBadge Access Review Report",
        "",
        f"**Review date:** {today.isoformat()}  ",
        f"**Agents in scope:** {sum(1 for a in agents if a['status'] != 'retired')}  ",
        f"**Runtime decisions logged:** {len(audit_entries)} "
        f"(ALLOW {counts.get('ALLOW', 0)}, BLOCK {counts.get('BLOCK', 0)}, FLAG {counts.get('FLAG', 0)})  ",
        f"**Findings:** {len(findings)} "
        f"(High {sum(f['severity'] == 'High' for f in findings)}, "
        f"Medium {sum(f['severity'] == 'Medium' for f in findings)}, "
        f"Low {sum(f['severity'] == 'Low' for f in findings)})",
        "",
        "| Severity | Agent | Owner | Issue | Detail | Recommendation |",
        "|---|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f['severity']} | {f['agent_id']} {f['agent_name']} | {f['owner']} | "
                     f"{f['issue']} | {f['detail']} | {f['recommendation']} |")
    lines += ["", "_Generated by AgentBadge. Sample data only._", ""]

    with open(path, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))
