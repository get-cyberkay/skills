---
name: xsoar-playbook-documenter
description: Produces a standard organisational documentation MD file for any Cortex XSOAR playbook that handles QRadar offenses. The output format is fixed and repeatable. Invoke with /xsoar-playbook-documenter <path-to-playbook-directory>.
trigger: /xsoar-playbook-documenter
---

# /xsoar-playbook-documenter

Produce a complete, standard-format documentation MD file for a Cortex XSOAR playbook directory. The output follows a fixed 13-section structure and is designed to be converted to DOCX for organisational submission.

---

## What You Must Do When Invoked

### Step 0 — Locate the Directory

If the user provided a path, use it. If not, use the current working directory.

Run `ls` on the directory to enumerate all files before doing anything else. Do not proceed until you have the file list.

---

### Step 1 — Verify Required Files

Check the file list against the following requirements. Stop and ask the user if **any Required file is missing**. Do not proceed until the user confirms or provides the missing files.

#### Required (without these the documentation cannot be completed)

| File | How to Identify | Used For |
|---|---|---|
| **Main playbook YAML** | A `.yml` file whose filename matches the playbook or offense name (not a helper script name). Contains `tasks:`, `inputs:`, `name:` at the root level. | Source of truth for all workflow steps, conditions, inputs, and task connections. |
| **Playbook screenshot / diagram** | A `.png` (or `.jpg`) file in the directory. | Embedded in the document as the playbook diagram. |

#### Optional (collect if present — they enrich the documentation)

| File | How to Identify | Used For |
|---|---|---|
| Helper automation script YAMLs | `.yml` files that are **not** the main playbook. Contain `scriptName:` or `script:` at the root and lack a `tasks:` block. Common names include `ParseBluecoatPayload.yml`, `QradarGetIssueCustomFields.yml`. | Section 9 — Helper Automation Scripts. |
| Email notification templates | `.html` files. | Section 10 — Notification Templates (email subjects, CC behaviour). |
| Existing documentation | Any `.md` file in the directory. | Additional context — do not copy it, use it only to fill gaps the YAML does not answer. |

If optional files are missing, continue without them and note `(not provided)` in the relevant section.

---

### Step 2 — Read All Files

Read files in this order. For large YAMLs (> 2000 lines), read in chunks using `offset` and `limit` until you have read the entire file. Do not skip any portion of the main playbook YAML.

1. Existing `.md` documentation (if present) — read first for context.
2. Main playbook `.yml` — read fully, all tasks.
3. Helper script `.yml` files — read fully.
4. `.html` email templates — read to extract email subjects and CC behaviour.
5. The diagram image — read it to confirm it is the correct playbook.

---

### Step 3 — Resolve Ambiguous Fields

Before writing the document, you must confirm values for the following fields. If a value can be extracted unambiguously from the files, use it without asking. If it cannot be determined, ask the user.

Work through this checklist:

#### 3a. Document Metadata (Header Table)

| Field | How to Resolve |
|---|---|
| **Playbook Name** | Read from `name:` at the root of the main YAML. |
| **Playbook ID** | Read from `id:` at the root of the main YAML. |
| **Version** | Read from `version:` at the root of the main YAML. |
| **Platform** | Always `Cortex XSOAR`. |
| **Log Source** | Infer from the directory name or offense description in the YAML description field. If ambiguous, **ask the user**. |
| **Triggering Rule** | Read from the YAML `description:` field at the root. Typically stated as the QRadar rule name. If not present, **ask the user**. |
| **SOC Contact** | Find the email address used in `send-mail` task arguments (`to:` field). If multiple different addresses are used, **ask the user which is the primary SOC address**. |
| **Document Date** | Use today's date in `DD Month YYYY` format. |
| **Classification** | Default to `Internal — DFIR Use Only`. If the user has specified otherwise, use their value. If unsure, **ask the user**. |
| **Organisation Name** | Extract from the HTML email templates (look for a name in the email header/banner text). If not found, **ask the user for their organisation name** — it appears in email banners. |

#### 3b. Workflow Ambiguities

For each condition task in the YAML (tasks with `type: condition`), verify:
- All branch labels are captured (including `#default#`).
- The `next task ID` for each branch maps to a task that exists in the `tasks:` map.

If a branch leads to a task ID that is not defined, or a task references a script or sub-playbook that cannot be identified, note it as `(unresolved — verify in XSOAR)` rather than guessing.

#### 3c. Helper Scripts

For each helper script YAML, identify:
- All arguments and whether they are required or optional.
- What context key the script writes to.
- Whether it uses polling (check for `xdr-xql-get-query-results` or similar) and the retry count and interval.

If a helper script does something that cannot be determined from the YAML alone, **ask the user to describe what it does**.

#### 3d. EDL and Blocking Behaviour

Identify:
- Which command adds entries to the EDL (look for `reputrack-add-edl-entries` or equivalent).
- What value is added (host? IP? domain?) — read the `items:` argument.
- Which list ID is used — read the `list_id:` argument.
- Whether IPs are ever added — if an `ip` reputation command result feeds an EDL task, **ask the user** whether this is intentional before documenting it as an IP block.

#### 3e. QRadar Closing Reason IDs

Collect every distinct `closing_reason_id` value used in `qradar-offense-update` tasks. For each one, check whether a label is given in the task description. If the label cannot be inferred, **ask the user for the label that corresponds to each closing reason ID**.

---

### Step 4 — Build the Task Map

Before writing the document, construct an internal ordered task map:

1. Start at `starttaskid`.
2. For each task, record: task ID, task name, task type, script/command (if applicable), all branch labels and their next task IDs.
3. Follow every branch to termination (tasks with no `nexttasks` or `nexttasks: {}` are terminal — they close the investigation).
4. Group tasks into logical phases (e.g. Context Retrieval, Severity Mapping, Enrichment, Payload Parsing, Classification, Closure Paths).

This map is your outline for Section 7 (Workflow) and Section 8 (Decision Flow Summary).

---

### Step 5 — Write the Documentation

Write the output file to the playbook directory as:

```
<PlaybookName_without_spaces>_Playbook_Documentation.md
```

Use underscores, not spaces. Do not overwrite an existing file with the same name — if one exists, ask the user whether to overwrite it.

The document must contain all 13 sections below, in order. Do not omit any section. If data for a section is genuinely unavailable, write `(Not available — verify with the DFIR team)` rather than omitting the section.

---

## Output Format — 13 Mandatory Sections

### Section 1 — Header Table

```markdown
# <Playbook Name> — Playbook Documentation

---

| Field | Detail |
|---|---|
| **Playbook Name** | <from YAML name:> |
| **Playbook ID** | `<from YAML id:>` |
| **Version** | <from YAML version:> |
| **Platform** | Cortex XSOAR |
| **Log Source** | <inferred or user-provided> |
| **Triggering Rule** | `<QRadar rule name>` |
| **SOC Contact** | <email from send-mail tasks> |
| **Document Date** | <today DD Month YYYY> |
| **Classification** | <Internal — DFIR Use Only, or user-provided> |
```

---

### Section 2 — Executive Summary

Write a numbered list (8–12 items) describing what the playbook does at a high level, in plain English. Each item should be one action or capability:

1. What it retrieves/normalises.
2. What it maps (severity, etc.).
3. What it optionally does (additional logs, enrichment).
4. What it parses.
5. What it checks first (whitelist, classification).
6. What secondary checks it runs.
7. What it auto-closes.
8. What it routes to an analyst.

End with a one-sentence statement of the playbook's overall purpose (reduce alert fatigue, ensure containment, etc.).

---

### Section 3 — Playbook Diagram

```markdown
## 3. Playbook Diagram

![<Playbook Name>](<image filename>)
```

Use a relative path — just the filename. If no image was found, write:

```markdown
> **Note:** No playbook diagram image was found in this directory. Insert the exported playbook screenshot here.
```

---

### Section 4 — Purpose and Scope

Three subsections:

**4.1 Purpose** — 2–4 sentences on the objectives of the playbook.

**4.2 Scope** — What log source and offense type this playbook covers. One instance per execution. The primary artifact it analyses.

**4.3 Design Constraints** — List every intentional design decision that is non-obvious. These are found in task `description:` fields that contain the word "deliberately", "intentionally", "NOT", "never", or "by design". Examples: no IP blocking, single payload parse, one whitelist path. For each constraint, state what the playbook does NOT do and why (the reason is almost always in the task description).

---

### Section 5 — Required Integrations and Dependencies

A table with all integrations and XSOAR objects the playbook calls. Identify these by scanning every task in the YAML for `brand:`, `script:`, `scriptName:`, and `playbookName:` fields.

```markdown
| Integration / Object | Purpose |
|---|---|
| **<name>** | <what it does in this playbook, one sentence> |
```

Include: all `brand:` integrations, all sub-playbooks (`type: playbook` tasks), all automation scripts (`type: regular` tasks with a `scriptName:`), all XSOAR lists used in conditions (`lists.<name>`), and all generic commands used (`|||url`, `|||ip`, `|||send-mail`, etc.).

---

### Section 6 — Playbook Inputs

A table of all inputs declared in the `inputs:` section at the root of the YAML.

```markdown
| Input Name | Default Value | Description |
|---|---|---|
| `<key>` | `<value>` | <description from YAML, condensed to one clear sentence> |
```

For each input: note if the default value conflicts with the description (e.g., default is `false` but description says "default is true for phishing offenses"). Flag these as: `> **Note:** Default value conflicts with description — confirm deployed value before production import.`

---

### Section 7 — Playbook Workflow

This is the longest section. Document every task in the playbook, in execution order, grouped into named phases.

**Phase naming convention:** Name phases after what they accomplish, not after tool names. Examples: "Context Retrieval", "Severity Mapping", "Optional Log Retrieval", "Optional Indicator Enrichment", "Payload Parsing", "Whitelist Check", "URL Classification", "Secondary Reputation Checks", "Manual Investigation".

**For each closure path**, create a clearly labelled sub-section: "Closure Path A — <Name> (Auto-Close)" or "Manual Closure Path — <Verdict>".

**For each task, write:**

```markdown
#### Step N: <Task Name> (Task <ID>)

**Type:** <Regular action / Condition / Sub-playbook / Script execution / Collection (manual input)>

<One paragraph describing exactly what this task does, what inputs it reads, and what it outputs or sets.>

[For conditions — a branch table:]

| Branch | Condition | Next Step |
|---|---|---|
| **<label>** | `<condition expression>` | Proceed to Step X (<Task Name>) |
| **Default** | <all other cases> | Proceed to Step Y (<Task Name>) |
```

For `send-mail` tasks, always state the exact email subject line and recipient.

For `qradar-offense-update` tasks, always state the `closing_reason_id` and its label.

For `reputrack-add-edl-entries` (or equivalent), always state what is added, to which list ID, and the comment.

---

### Section 8 — Complete Decision Flow Summary

An ASCII text tree showing every decision point and all branches from start to each terminal end state. Use this template structure:

```
START
│
├─ [Condition] <Condition name>?
│     ├─ YES → <action>
│     └─ NO  → <action>
│
...
└─ [Terminal end state label]
```

Every end state should be labelled (e.g., `[END A — Phishing Simulation]`, `[END B — Confirmed Malicious, auto-closed]`).

---

### Section 9 — Helper Automation Scripts

One subsection per helper script found in the directory. If no helper scripts were found, write `(No helper scripts found in this directory)`.

For each script:

```markdown
### 9.N <Script Name>

**File:** `<filename>`

**Purpose:** <one sentence>

**Arguments:**

| Argument | Type | Required | Description |
|---|---|---|---|
| `<arg>` | String | Yes/No | <description> |

**Execution:** <step-by-step of what the script does internally>

**Output context:** <context key and fields written>
```

---

### Section 10 — Notification Templates

A table of all email notifications sent by the playbook. Identify these by scanning all `send-mail` tasks for `subject:` and `to:` and `cc:` arguments.

```markdown
| Template | Trigger | Subject | Recipient | CC |
|---|---|---|---|---|
| <scenario name> | <what triggers it> | `<exact subject>` | <to address> | <cc address or "None"> |
```

After the table, write one paragraph stating what fields are common to all emails (offense ID, user, source IP, destination host, QRadar link, etc.).

---

### Section 11 — End States and Expected Outcomes

A table of every terminal outcome.

```markdown
| Outcome | Trigger | QRadar Closing Reason | EDL Action | Closed By |
|---|---|---|---|---|
| **<name>** | <what causes it> | <ID — Label> | <domain/IP added to list X, or None> | Automation / Analyst |
```

---

### Section 12 — Operational Notes

Numbered list of non-obvious operational considerations. Source these from:
- Task `description:` fields that contain warnings, caveats, or recommendations.
- Conditions that check for something unusual (e.g., `isEmpty` guard against double-execution).
- Input default vs. description conflicts identified in Section 6.
- Spelling errors in artifact names that must be preserved exactly (search for inconsistencies between how things are named vs. how you would expect them to be spelled).
- Any `list_id:` or hardcoded value that an operator would need to know about.
- Any sub-playbook that runs with `separatecontext: true` (important for understanding what context is and is not available).

Write at least one note per major behavioural constraint. Do not pad with generic advice.

---

### Section 13 — Reference Appendices

#### 13a. Key Context Paths

A table of every context path the playbook reads or writes, grouped by source.

```markdown
| Context Path | Source | Meaning |
|---|---|---|
| `<path>` | <script/integration> | <what it contains> |
```

#### 13b. QRadar Closing Reason IDs

A table of every `closing_reason_id` used in the playbook.

```markdown
| ID | Label |
|---|---|
| **<id>** | <label> |
```

End the document with:

```markdown
---
*Document prepared by the <Organisation> DFIR team. For questions or amendments, contact <SOC email>.*
```

---

## Checklist Before Declaring Complete

Before telling the user the documentation is done, verify:

- [ ] All tasks in the YAML `tasks:` map are accounted for in Section 7.
- [ ] Every terminal task (no `nexttasks`) corresponds to a named end state in Section 11.
- [ ] Every `closing_reason_id` in the YAML appears in Section 13b.
- [ ] Every `send-mail` task's exact subject line appears in Section 10.
- [ ] Every condition's branch labels exactly match what is in the YAML (including spelling errors).
- [ ] The playbook image filename in Section 3 matches a file that exists in the directory.
- [ ] No section is blank or missing.
- [ ] The output filename does not collide with an existing file (or the user approved the overwrite).
- [ ] The document ends with the footer line.
