"""
policy.py - FEATURE 3: Access Policies

Plain-language idea:
    The registry says WHO the agent is. The policy says WHAT it may do.
    Keeping these separate mirrors how companies separate identity
    (the HR record) from entitlements (the access you are granted).

Each agent's policy has:
    allowed_actions    verbs the agent may perform, e.g. ["read", "comment"]
    allowed_resources  places it may touch, e.g. ["finance/invoices/*"]
                       The * is a wildcard meaning "anything under here".
    roles              groups it belongs to, like Active Directory groups
    expires            the date access ends unless someone re-approves it
"""

import json
from datetime import date


def load_policies(path):
    """
    Read policies from JSON. The file is a "dictionary" (a lookup table)
    where the key is the agent_id and the value is that agent's policy.
    """
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_policy(policies, agent_id):
    """Return the policy for one agent, or None if it has no policy."""
    return policies.get(agent_id)


def is_expired(policy, today):
    """True if the policy's expiration date is before today."""
    expires = date.fromisoformat(policy["expires"])  # turn "2027-03-31" into a real date
    return expires < today


def days_until_expiry(policy, today):
    """How many days are left (negative means already expired)."""
    return (date.fromisoformat(policy["expires"]) - today).days
