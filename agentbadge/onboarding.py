"""
onboarding.py - FEATURE 2: Onboarding Approval

Plain-language idea:
    A new hire doesn't get a badge on day one until HR, their manager and IT
    sign off. Here, a "pending" agent only becomes "active" if it passes a
    checklist AND is approved by the right person.

The checklist (every item must pass):
    1. The agent is currently "pending".
    2. It has a named human owner.
    3. It has a written purpose.
    4. It has a valid risk level.
    5. It has an access policy that has not expired.
    6. The approver is NOT the owner (separation of duties: you can't
       approve your own request).
    7. High-risk agents must be approved by someone on the security team.
"""

from .registry import VALID_RISK_LEVELS
from .policy import get_policy, is_expired

# In a real company this list would come from your identity system.
SECURITY_REVIEWERS = ["Sam Rivera (Security)", "Alex Morgan (Security)"]


def approve_agent(agent, policies, approver, today):
    """
    Try to approve an agent.

    Returns two things:
        approved  True or False
        problems  a list of reasons it failed (empty if it passed)
    """
    problems = []

    if agent["status"] != "pending":
        problems.append(f"Status is '{agent['status']}', only pending agents can be onboarded")
    if not agent["owner"].strip():
        problems.append("No accountable human owner")
    if not agent["purpose"].strip():
        problems.append("No documented purpose")
    if agent["risk_level"] not in VALID_RISK_LEVELS:
        problems.append("Risk level is missing or invalid")

    policy = get_policy(policies, agent["agent_id"])
    if policy is None:
        problems.append("No access policy defined (least privilege must be set BEFORE activation)")
    elif is_expired(policy, today):
        problems.append("Access policy is already expired")

    if approver == agent["owner"]:
        problems.append("Owner cannot approve their own agent (separation of duties)")
    if agent["risk_level"] == "high" and approver not in SECURITY_REVIEWERS:
        problems.append("High-risk agents need a security reviewer's approval")

    if problems:
        return False, problems

    # Everything passed: flip the agent to active and record who approved it.
    agent["status"] = "active"
    agent["approved_by"] = approver
    return True, []
