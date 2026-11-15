# AgentBadge Build Guide (for beginners)

This guide walks you through the project one step at a time. You don't need coding experience. Each step says **what** you're doing and **why** a security or GRC person cares.

---

## Step 0: Set up your computer (about 15 minutes)

1. **Install Python** (3.10 or newer) from python.org. On Windows, tick **"Add Python to PATH"** during install.
2. **Install VS Code** (code.visualstudio.com). It's a free editor where you'll read and edit the files.
3. **Open a terminal.** A terminal is a window where you type commands.
   - Mac: open the app called *Terminal*.
   - Windows: open *PowerShell*, or use the terminal inside VS Code (menu: Terminal → New Terminal).
4. Check that Python works by typing:
   ```
   python --version
   ```
   (On Mac you may need `python3` instead of `python` in every command.)

You don't need to install anything else. AgentBadge only uses tools that come with Python.

---

## Step 1: Understand the folder layout

```
agentbadge/
├── main.py              ← the "play" button: runs the whole demo
├── agentbadge/          ← the actual code, one file per feature
│   ├── registry.py      ← Feature 1: agent inventory
│   ├── onboarding.py    ← Feature 2: approval before activation
│   ├── policy.py        ← Feature 3: access policies
│   ├── checker.py       ← Feature 4: allow / block / flag at runtime
│   ├── audit.py         ← Feature 5: tamper-evident audit log
│   └── review.py        ← Feature 6: access-review report
├── data/                ← fake sample data (JSON files)
├── output/              ← results appear here when you run it
├── tests/               ← automated checks that the rules still work
└── docs/                ← this guide + control mapping + resume text
```

**Why it's split up:** each file does one job. That's how real software is organized, and it lets you explain each control on its own.

---

## Step 2: Read the sample data (no code yet)

Open the three files in `data/`. They're written in **JSON**, a common format that is basically labeled lists.

- `agents.json` lists 8 fake agents. Look for the planted problems: an agent with **no owner** (LegacyReportBot), one that's **pending**, one that's **suspended**.
- `policies.json` gives each agent's allowed actions, resources, roles and expiration date. Spot the risky one: ITOpsAgent has `"*"` (everything) and `Domain Admins`.
- `sample_actions.json` holds 14 requests agents try to make, including **prompt-injection attempts** hidden in an invoice (REQ-03) and in pull-request text (REQ-07, REQ-08).

**JSON in 30 seconds:**
- `{ }` holds one record with labeled fields: `{"name": "InvoiceBot"}`
- `[ ]` holds a list: `["read", "comment"]`
- Text goes in double quotes. `null` means "empty".

---

## Step 3: Run it

In the terminal, go into the project folder and run the demo:

```
cd path/to/agentbadge
python main.py
```

You'll see five sections print out: the registry, onboarding, runtime decisions, the audit integrity check and the access review. Then open the `output/` folder.

---

## Step 4: Learn the code, one feature at a time

Open each file in VS Code. Every file starts with a plain-English explanation, and comments (lines starting with `#`) explain the tricky parts.

A few Python words you'll see everywhere:

| Word | Meaning |
|---|---|
| `def name(...):` | defines a **function**: a named, reusable set of steps |
| `return` | the answer a function hands back |
| `if ...:` | do something only when a condition is true |
| `for x in list:` | repeat for each item in a list |
| `import` | borrow code from another file or from Python's built-ins |
| `None` | "nothing" / "not found" |
| `f"Hello {name}"` | text with a value inserted into it |

### 4.1 `registry.py`: the inventory
- `find_agent()` loops through agents and returns the one with a matching ID.
- `register_agent()` adds a new agent. It **refuses** a missing owner or an invalid risk level, and every new agent starts as `pending`.
- **GRC link:** this is your asset inventory. No owner means nobody is accountable.

### 4.2 `onboarding.py`: approval gate
- `approve_agent()` runs a checklist and collects every problem it finds in a list called `problems`.
- If the list is empty, the agent becomes `active`. If not, it stays pending and you see why.
- **Try it:** in the demo, the owner tries to approve their own agent and is denied (separation of duties).

### 4.3 `policy.py`: entitlements
- `is_expired()` compares the expiration date to today.
- **GRC link:** time-bound access, so nothing is granted forever.

### 4.4 `checker.py`: the guard (most important file)
- `check_action()` runs rules R1 to R9 **in order**. The first rule that fails returns BLOCK.
- R5 looks for injection phrases like "ignore all previous instructions".
- R6/R7 check the action and resource against the policy. `fnmatch` handles wildcards, so `repo/*` matches `repo/payments-api/pr-42`.
- R8 returns FLAG for dangerous-but-allowed actions like `delete`.
- **The key insight:** REQ-08 contains no trigger phrase, so R5 misses it. R6 still blocks it because `push` isn't in CodeReviewer's job. **Least privilege catches what detection misses.**

### 4.5 `audit.py`: evidence
- Each decision becomes one line in `output/audit_log.jsonl`.
- Each line includes a **hash** (a fingerprint) of itself and of the previous line. Change any old line and the chain breaks.
- The demo edits a BLOCK into an ALLOW in a copy of the log, and `verify_log()` catches it.

### 4.6 `review.py`: the access review
- `run_access_review()` checks every agent against the rules a reviewer would use (expired, unused for 90+ days, orphaned, wildcards, admin roles, self-approved and so on).
- It writes `output/access_review_report.md` (readable on GitHub) and `.csv` (opens in Excel).

---

## Step 5: Run the tests

```
python -m unittest discover tests
```

You should see `OK`. Tests show employers that you verify your controls work. That's the same mindset as control testing in an audit.

---

## Step 6: Experiment (this is how you really learn)

Make one change, run `python main.py` again, and see what happens:

1. In `policies.json`, change SalesEmailer's `expires` to `"2027-06-30"`. REQ-09 should now be **ALLOW**.
2. Add `"push"` to CodeReviewer's `allowed_actions`. Now REQ-08 gets through, which shows why over-granting is dangerous. (Change it back.)
3. Add your own injection phrase to `INJECTION_PATTERNS` in `checker.py`, plus a new request in `sample_actions.json` that uses it.
4. Give LegacyReportBot an owner and watch the ORPHANED finding disappear.
5. In `main.py`, change `AS_OF = date(2026, 11, 13)` to `AS_OF = date.today()` to use the real date.

---

## Step 7: Put it on GitHub

1. Create a free account at github.com.
2. Click **New repository**, name it `agentbadge`, make it **Public**, and don't add a README (you already have one).
3. Easiest route: on the new repo page, click **"uploading an existing file"** and drag in the whole project folder's contents.
4. Or use git in the terminal:
   ```
   git init
   git add .
   git commit -m "AgentBadge: AI agent governance prototype"
   git branch -M main
   git remote add origin https://github.com/YOUR-USERNAME/agentbadge.git
   git push -u origin main
   ```
5. Pin the repo to your GitHub profile.

---

## Ideas for version 2 (talk about these in interviews)

- Store data in SQLite instead of JSON files
- A simple web dashboard (Streamlit or Flask)
- Map agents to real identity groups (Entra ID / Okta) through their APIs
- Better injection detection (a classifier instead of a phrase list)
- Separate "trusted instructions" from "untrusted content" in every request
- Auto-suspend an agent after repeated blocked attempts
- Send FLAG decisions to a ticket queue for human approval
