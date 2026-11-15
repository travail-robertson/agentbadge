"""
make_dashboard.py - Turns the demo results into a visual dashboard page.

How to run (AFTER running main.py, because it reads the output/ folder):
    python make_dashboard.py

It creates output/dashboard.html. Double-click that file to open it in any
web browser. Nothing needs to be installed: the page is plain HTML and CSS
(the languages web pages are written in), built here as one long text string.

Plain-language idea:
    main.py does the governance work and writes the evidence to output/.
    This script only READS that evidence and lays it out visually, the same
    way a GRC tool's dashboard sits on top of its database.
"""

import json
import os
from datetime import date
from html import escape  # makes text safe to put inside a web page

from agentbadge.audit import read_log
from agentbadge.policy import load_policies
from agentbadge.registry import load_agents
from agentbadge.review import run_access_review

AS_OF = date(2026, 11, 13)  # keep in sync with main.py

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "output")

# Status colors: each one ALWAYS appears with an icon and a word,
# so meaning never depends on color alone (accessibility).
DECISION_STYLE = {
    "ALLOW": ("#0ca30c", "#ffffff", "✓", "Allowed"),
    "BLOCK": ("#d03b3b", "#ffffff", "✕", "Blocked"),
    "FLAG":  ("#fab219", "#0b0b0b", "!", "Flagged"),
}
SEVERITY_STYLE = {
    "High":   ("#d03b3b", "#ffffff"),
    "Medium": ("#ec835a", "#ffffff"),
    "Low":    ("#fab219", "#0b0b0b"),
}
STATUS_STYLE = {
    "active":    ("#0ca30c", "#ffffff"),
    "pending":   ("#fab219", "#0b0b0b"),
    "suspended": ("#898781", "#ffffff"),
    "retired":   ("#898781", "#ffffff"),
}


def pill(text, background, ink, icon=""):
    """A small colored label, like a badge."""
    icon_html = f'<span class="icon">{icon}</span>' if icon else ""
    return f'<span class="pill" style="background:{background};color:{ink}">{icon_html}{escape(text)}</span>'


def stat_tile(number, label, note=""):
    note_html = f'<div class="note">{note}</div>' if note else ""
    return f'<div class="tile"><div class="num">{number}</div><div class="label">{escape(label)}</div>{note_html}</div>'


def decision_bar(counts, total):
    """One horizontal bar split into ALLOW / BLOCK / FLAG segments."""
    parts = []
    for decision in ["ALLOW", "BLOCK", "FLAG"]:
        n = counts.get(decision, 0)
        if n == 0:
            continue
        color, ink, icon, word = DECISION_STYLE[decision]
        width = n / total * 100
        parts.append(
            f'<div class="seg" style="width:{width:.2f}%;background:{color};color:{ink}" '
            f'title="{word}: {n} of {total}">{icon} {word} {n}</div>')
    return f'<div class="bar">{"".join(parts)}</div>'


def build_html(agents, policies, log, findings):
    counts = {}
    for e in log:
        counts[e["decision"]] = counts.get(e["decision"], 0) + 1
    injections = sum(1 for e in log if e["rule"] == "R5")
    # REQ-08 is the injection with no trigger phrase that least privilege still blocked
    requests = {}
    with open(os.path.join(HERE, "data", "sample_actions.json"), encoding="utf-8") as f:
        for r in json.load(f):
            requests[r["request_id"]] = r
    injection_ids = {"REQ-03", "REQ-07", "REQ-08"}
    high = sum(f["severity"] == "High" for f in findings)
    findings_by_agent = {}
    for f in findings:
        findings_by_agent[f["agent_id"]] = findings_by_agent.get(f["agent_id"], 0) + 1

    # ---- Stat tiles -------------------------------------------------------
    tiles = "".join([
        stat_tile(len(agents), "Agents in registry",
                  f'{sum(a["status"] == "active" for a in agents)} active'),
        stat_tile(len(log), "Runtime decisions logged", "hash-chained audit log"),
        stat_tile(counts.get("BLOCK", 0), "Actions blocked",
                  f"incl. {len(injection_ids)} prompt-injection attempts"),
        stat_tile(len(findings), "Access-review findings", f"{high} high severity"),
    ])

    # ---- Runtime decision rows --------------------------------------------
    decision_rows = []
    for e in log:
        color, ink, icon, word = DECISION_STYLE[e["decision"]]
        tag = '<span class="tag">Prompt injection</span>' if e["request_id"] in injection_ids else ""
        excerpt = ""
        if e["request_id"] in injection_ids:
            text = requests[e["request_id"]]["content"]
            excerpt = f'<div class="excerpt">“{escape(text[:110])}{"…" if len(text) > 110 else ""}”</div>'
        decision_rows.append(f"""
        <tr>
          <td>{pill(word, color, ink, icon)}</td>
          <td class="mono">{escape(e["agent_id"])}</td>
          <td><span class="mono">{escape(e["action"])}</span> → <span class="mono muted">{escape(e["resource"])}</span>{tag}{excerpt}</td>
          <td><span class="rule">{escape(e["rule"])}</span> {escape(e["reason"])}</td>
        </tr>""")

    # ---- Registry rows ----------------------------------------------------
    registry_rows = []
    for a in agents:
        bg, ink = STATUS_STYLE[a["status"]]
        policy = policies.get(a["agent_id"])
        expires = policy["expires"] if policy else "No policy"
        n = findings_by_agent.get(a["agent_id"], 0)
        owner = escape(a["owner"]) if a["owner"] else '<span class="warn-text">No owner</span>'
        registry_rows.append(f"""
        <tr>
          <td class="mono">{escape(a["agent_id"])}</td>
          <td><strong>{escape(a["name"])}</strong><div class="sub">{escape(a["purpose"])}</div></td>
          <td>{owner}</td>
          <td><span class="risk risk-{a["risk_level"]}">{a["risk_level"].title()}</span></td>
          <td>{pill(a["status"].title(), bg, ink)}</td>
          <td class="mono">{escape(expires)}</td>
          <td class="num-cell">{n if n else "–"}</td>
        </tr>""")

    # ---- Findings rows ----------------------------------------------------
    finding_rows = []
    for f in findings:
        bg, ink = SEVERITY_STYLE[f["severity"]]
        finding_rows.append(f"""
        <tr>
          <td>{pill(f["severity"], bg, ink)}</td>
          <td><strong>{escape(f["agent_name"])}</strong><div class="sub mono">{escape(f["agent_id"])}</div></td>
          <td class="issue">{escape(f["issue"])}</td>
          <td>{escape(f["detail"])}</td>
          <td class="muted">{escape(f["recommendation"])}</td>
        </tr>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentBadge Dashboard</title>
<style>
  :root {{
    --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
    --line:#e1e0d9; --ring:rgba(11,11,11,0.10); --accent:#2a78d6;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--page); color:var(--ink);
         font-family:system-ui,-apple-system,"Segoe UI",sans-serif; font-size:14px; line-height:1.45; }}
  .wrap {{ max-width:1180px; margin:0 auto; padding:32px 28px 48px; }}
  header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:16px; margin-bottom:24px; }}
  h1 {{ font-size:28px; margin:0; letter-spacing:-0.01em; }}
  h1 .badge {{ display:inline-block; background:var(--accent); color:#fff; border-radius:8px;
              padding:2px 10px; margin-right:10px; font-size:22px; }}
  .tagline {{ color:var(--ink2); margin-top:6px; font-size:15px; }}
  .meta {{ color:var(--muted); font-size:13px; text-align:right; }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:22px; }}
  .tile {{ background:var(--surface); border:1px solid var(--ring); border-radius:12px; padding:16px 18px; }}
  .tile .num {{ font-size:34px; font-weight:700; font-variant-numeric:tabular-nums; }}
  .tile .label {{ font-weight:600; }}
  .tile .note {{ color:var(--ink2); font-size:13px; }}
  section {{ background:var(--surface); border:1px solid var(--ring); border-radius:12px;
            padding:20px 22px; margin-bottom:18px; }}
  h2 {{ font-size:17px; margin:0 0 4px; }}
  .lead {{ color:var(--ink2); margin:0 0 14px; }}
  .bar {{ display:flex; gap:2px; height:34px; margin-bottom:16px; }}
  .seg {{ display:flex; align-items:center; justify-content:center; font-weight:600; font-size:13px;
          border-radius:4px; white-space:nowrap; overflow:hidden; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:0.04em;
        color:var(--muted); font-weight:600; padding:6px 10px; border-bottom:1px solid var(--line); }}
  td {{ padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  tbody tr:hover td {{ background:#f3f2ee; }}
  .pill {{ display:inline-flex; align-items:center; gap:5px; border-radius:999px; padding:2px 10px;
           font-size:12px; font-weight:700; white-space:nowrap; }}
  .pill .icon {{ font-weight:800; }}
  .mono {{ font-family:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace; font-size:12.5px; }}
  td.mono {{ white-space:nowrap; }}
  .muted {{ color:var(--ink2); }}
  .sub {{ color:var(--muted); font-size:12px; }}
  .rule {{ display:inline-block; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px;
           border:1px solid var(--line); border-radius:4px; padding:0 5px; color:var(--ink2); margin-right:4px; }}
  .tag {{ display:inline-block; margin-left:8px; font-size:11px; font-weight:700; color:#d03b3b;
          border:1px solid #d03b3b; border-radius:4px; padding:0 6px; }}
  .excerpt {{ margin-top:5px; font-size:12px; color:var(--ink2); font-style:italic;
              border-left:3px solid #d03b3b; padding-left:8px; }}
  .risk {{ font-size:12px; font-weight:600; }}
  .risk-high {{ font-weight:800; }}
  .risk-high::before {{ content:"▲ "; }}
  .warn-text {{ color:#d03b3b; font-weight:700; }}
  .num-cell {{ text-align:center; font-variant-numeric:tabular-nums; font-weight:600; }}
  .issue {{ font-weight:700; white-space:nowrap; font-size:12.5px; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .chip {{ border:1px solid var(--line); border-radius:6px; padding:3px 8px; font-size:12.5px; }}
  .callout {{ background:#f3f2ee; border-radius:8px; padding:10px 14px; color:var(--ink2); margin-top:14px; }}
  footer {{ color:var(--muted); font-size:12px; text-align:center; margin-top:8px; }}
  @media (max-width:800px) {{ .tiles{{grid-template-columns:1fr 1fr}} .grid2{{grid-template-columns:1fr}} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1><span class="badge">AgentBadge</span>AI Agent Governance Dashboard</h1>
      <div class="tagline">Govern AI agents the way companies govern employees.</div>
    </div>
    <div class="meta">Review date: {AS_OF.isoformat()}<br>Sample data only</div>
  </header>

  <div class="tiles">{tiles}</div>

  <section>
    <h2>Runtime action checks</h2>
    <p class="lead">Every request is checked at the moment it happens, against the agent's registry status and least-privilege policy.</p>
    {decision_bar(counts, len(log))}
    <table>
      <thead><tr><th>Decision</th><th>Agent</th><th>Requested action → resource</th><th>Rule &amp; reason</th></tr></thead>
      <tbody>{"".join(decision_rows)}</tbody>
    </table>
    <div class="callout"><strong>Defense in depth:</strong> REQ-08 has no known injection phrase, so detection (R5) misses it.
    Least privilege (R6) still blocks it, because pushing code was never part of CodeReviewer's job.</div>
  </section>

  <section>
    <h2>Access-review findings</h2>
    <p class="lead">The automated user access review, applied to agents: expired, orphaned, self-approved, over-privileged and dormant access.</p>
    <table>
      <thead><tr><th>Severity</th><th>Agent</th><th>Issue</th><th>Detail</th><th>Recommendation</th></tr></thead>
      <tbody>{"".join(finding_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>Agent registry</h2>
    <p class="lead">Every agent has an ID, an accountable human owner, a purpose, a risk level and time-bound access.</p>
    <table>
      <thead><tr><th>ID</th><th>Agent</th><th>Owner</th><th>Risk</th><th>Status</th><th>Access expires</th><th>Findings</th></tr></thead>
      <tbody>{"".join(registry_rows)}</tbody>
    </table>
  </section>

  <section>
    <h2>Framework alignment</h2>
    <div class="grid2">
      <div><p class="lead"><strong>NIST AI RMF 1.0</strong></p><div class="chips">
        <span class="chip">GOVERN 1.6 Inventory</span><span class="chip">GOVERN 2.1 Accountability</span>
        <span class="chip">GOVERN 1.5 Periodic review</span><span class="chip">MAP 1.1 Intended purpose</span>
        <span class="chip">MEASURE 2.4 Production monitoring</span><span class="chip">MEASURE 2.7 Security</span>
        <span class="chip">MANAGE 2.4 Disengage</span><span class="chip">MANAGE 4.1 Post-deployment</span></div></div>
      <div><p class="lead"><strong>NIST CSF 2.0 &amp; least privilege</strong></p><div class="chips">
        <span class="chip">ID.AM-02 Inventory</span><span class="chip">PR.AA-05 Least privilege &amp; SoD</span>
        <span class="chip">PR.PS-04 Logging</span><span class="chip">DE.CM-09 Runtime monitoring</span>
        <span class="chip">SP 800-53 AC-6</span><span class="chip">AC-5 Separation of duties</span>
        <span class="chip">AU-9 Audit protection</span><span class="chip">OWASP LLM01 / LLM06</span></div></div>
    </div>
  </section>

  <footer>Generated by make_dashboard.py from AgentBadge demo output · github.com/travail-robertson/agentbadge</footer>
</div>
</body>
</html>"""


def main():
    agents = load_agents(os.path.join(OUT, "agents_after_run.json"))
    policies = load_policies(os.path.join(HERE, "data", "policies.json"))
    log = read_log(os.path.join(OUT, "audit_log.jsonl"))
    findings = run_access_review(agents, policies, log, AS_OF)

    path = os.path.join(OUT, "dashboard.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_html(agents, policies, log, findings))
    print(f"Dashboard written to {path}. Open it in your browser.")


if __name__ == "__main__":
    main()
