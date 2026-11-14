"""
registry.py - FEATURE 1: The Agent Registry

Plain-language idea:
    Every employee has a record in the HR system: name, manager, job title,
    start date. The registry is the same thing for AI agents. If an agent is
    not in the registry, it does not officially exist, and it is not allowed
    to do anything.

What is stored for each agent:
    agent_id      a unique ID, like an employee number ("AGT-001")
    name          a friendly name ("InvoiceBot")
    owner         the accountable HUMAN (every agent needs one)
    purpose       what the agent is for, in one sentence
    risk_level    low / medium / high
    status        pending / active / suspended / retired
    created_date  when it was registered (YYYY-MM-DD)
    approved_by   who approved it (filled in by onboarding)
    last_used     the last date it did something (used by the access review)
"""

import json

# These lists are the only values we accept. Checking input against a fixed
# list is called "validation" and stops typos like "hgih" from sneaking in.
VALID_RISK_LEVELS = ["low", "medium", "high"]
VALID_STATUSES = ["pending", "active", "suspended", "retired"]


def load_agents(path):
    """Read the agent list from a JSON file and return it as a Python list."""
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_agents(agents, path):
    """Write the agent list back out to a JSON file."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(agents, file, indent=2)


def find_agent(agents, agent_id):
    """Look through the list and return the agent with this ID (or None)."""
    for agent in agents:
        if agent["agent_id"] == agent_id:
            return agent
    return None  # "None" is Python's way of saying "nothing found"


def register_agent(agents, agent_id, name, owner, purpose, risk_level, created_date):
    """
    Add a NEW agent to the registry.

    New agents always start as "pending". They cannot act until someone
    approves them in onboarding.py. This is the "no badge until HR
    finishes your paperwork" rule.
    """
    if find_agent(agents, agent_id) is not None:
        raise ValueError(f"{agent_id} is already registered")
    if risk_level not in VALID_RISK_LEVELS:
        raise ValueError(f"risk_level must be one of {VALID_RISK_LEVELS}")
    if not owner.strip():
        raise ValueError("Every agent needs a named human owner")

    new_agent = {
        "agent_id": agent_id,
        "name": name,
        "owner": owner,
        "purpose": purpose,
        "risk_level": risk_level,
        "status": "pending",
        "created_date": created_date,
        "approved_by": None,
        "last_used": None,
    }
    agents.append(new_agent)
    return new_agent


def print_registry(agents):
    """Print the registry as a simple table in the terminal."""
    header = f"{'ID':<9}{'Name':<21}{'Owner':<32}{'Risk':<8}{'Status':<11}{'Created'}"
    print(header)
    print("-" * len(header))
    for a in agents:
        owner = a["owner"] or "(NO OWNER)"
        print(f"{a['agent_id']:<9}{a['name']:<21}{owner:<32}"
              f"{a['risk_level']:<8}{a['status']:<11}{a['created_date']}")
