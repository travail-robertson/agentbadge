"""
audit.py - FEATURE 5: The Audit Log

Plain-language idea:
    Auditors ask "show me the evidence". Every decision the checker makes,
    allowed, blocked or flagged, is written down with a timestamp and a reason.

Format:
    One JSON record per line ("JSON Lines", file ends in .jsonl). It's easy for
    humans to read and easy for tools like Splunk or Excel/Power Query to load.

Tamper evidence (a bonus feature):
    Each entry stores a "fingerprint" (a SHA-256 hash) of itself plus the
    fingerprint of the entry before it, like links in a chain. If anyone
    edits or deletes an old entry, the chain breaks and verify_log() reports
    it. That's how you show auditors the log hasn't been altered.
"""

import hashlib
import json
from datetime import datetime, timezone


def _fingerprint(entry):
    """Create a SHA-256 hash of an entry (excluding its own hash field)."""
    data = {k: v for k, v in entry.items() if k != "entry_hash"}
    text = json.dumps(data, sort_keys=True)  # sort_keys = same text every time
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AuditLog:
    """
    A "class" bundles data and the functions that use it. Here it remembers
    where the log file is and what the last fingerprint was.
    """

    def __init__(self, path, start_fresh=True):
        self.path = path
        self.entries = []
        if start_fresh:
            # For the demo we start a new log each run. In production a log
            # would only ever be appended to, never wiped.
            open(path, "w", encoding="utf-8").close()

    def record(self, request, result):
        previous_hash = self.entries[-1]["entry_hash"] if self.entries else "GENESIS"
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "request_id": request.get("request_id"),
            "agent_id": request["agent_id"],
            "action": request["action"],
            "resource": request["resource"],
            "decision": result["decision"],
            "rule": result["rule"],
            "reason": result["reason"],
            "previous_hash": previous_hash,
        }
        entry["entry_hash"] = _fingerprint(entry)
        self.entries.append(entry)
        with open(self.path, "a", encoding="utf-8") as file:
            file.write(json.dumps(entry) + "\n")
        return entry


def read_log(path):
    """Load every entry from a .jsonl audit log."""
    with open(path, "r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def verify_log(path):
    """Check the hash chain. Returns (True, message) or (False, message)."""
    previous_hash = "GENESIS"
    for number, entry in enumerate(read_log(path), start=1):
        if entry["previous_hash"] != previous_hash:
            return False, f"Chain broken at entry {number}: an entry was removed or reordered"
        if _fingerprint(entry) != entry["entry_hash"]:
            return False, f"Entry {number} was modified after it was written"
        previous_hash = entry["entry_hash"]
    return True, "Audit log integrity verified: no entries altered or removed"
