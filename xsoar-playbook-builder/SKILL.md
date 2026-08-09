---
name: xsoar-playbook-builder
description: Builds a complete, importable Cortex XSOAR playbook YAML and all supporting HTML email templates from a playbook idea and sample alert/offense data, then validates the task graph and dry-runs it against scenarios before handing it over. Follows the organisation's established task patterns and best security practices. Invoke with /xsoar-playbook-builder.
trigger: /xsoar-playbook-builder
argument-hint: "<brief description of the offense the playbook should handle>"
---

# /xsoar-playbook-builder

Build a production-ready Cortex XSOAR playbook by **adapting the closest existing reference playbook** — never building from a blank template. The reference playbooks in `reference-playbooks/` are the canonical structural model. Output: a new folder containing the main `.yml` playbook, `scripts/` with any custom automation scripts, and `emails-html/` with one HTML template per closure path.

---

## Rule 0 — Only Include Integrations the Playbook Actually Needs

**This overrides every "always include" instruction below.** The reference playbooks are QRadar-sourced Bluecoat proxy playbooks that block via Reputrack. Not every playbook is. Copying a reference wholesale drags in integrations the new alert has no use for, and a task calling an integration that is not wired up (or not licensed) in the tenant fails at runtime.

Before including any integration, confirm it belongs:

| Component | Include only when | Otherwise |
|---|---|---|
| `QRadar v3\|\|\|*` (offense update, note create) | The alert is a **QRadar offense** | Drop all QRadar tasks. Close via `closeInvestigation` alone, or the source SIEM's own command |
| `QradarGetIssueCustomFields` | Same — QRadar-sourced | Drop the context-retrieval phase, or replace with the equivalent for the real source |
| `RunAdditionalSeach` input + `QRadar - Get Offense Logs` | QRadar-sourced **and** extra log retrieval is wanted | Drop the input *and* the sub-playbook together — never leave one without the other |
| `\|\|\|reputrack-add-edl-entries` | The org's **Reputrack** EDL integration is the intended blocking path | Use the tenant's actual blocking integration, or drop the auto-block path entirely and route to manual |
| `ParseBluecoatPayload` | The log source is Bluecoat/Symantec pipe-delimited | Write the parser for the real format (Step 5c), or drop parsing if the fields already arrive structured |
| `PaloAltoNGFWURLReputation\|\|\|url` | Web/proxy offense **and** PAN-DB is licensed | Skip straight to VT reputation |
| VT / AbuseIPDB reputation | The alert carries the matching indicator type | Skip that phase — do not enrich indicators the alert does not contain |
| Closing reason IDs `155/157/158/159` | Closing a **QRadar** offense | These are QRadar-specific. A non-QRadar playbook has no `closing_reason_id` at all |

**When in doubt, ask — never assume.** If you cannot tell from the sample data and the user's description whether an integration is present, licensed, or wanted, add it to the Step 1 questions. It is always cheaper to ask than to ship a playbook that fails on import or silently no-ops a containment step.

Corollary: if a phase has nothing to do for this alert type, **delete the phase** rather than including it wired to a pass-through. Dead tasks mislead the next person who tunes the playbook.

---

## Reputrack — Org-Built Integration

`reputrack-add-edl-entries` is a **custom, in-house integration**. It is deliberately absent from xsoar.pan.dev, so its absence there is **not** a red flag and must not be reported as UNVERIFIED. Treat it as known-good when the target tenant has it.

What still applies: confirm with the user that Reputrack is deployed in the target tenant and get the real `list_id` values (Step 1, Category B). Never guess a list ID — a wrong one silently blocks nothing, or blocks the wrong list. The same holds for `QradarGetIssueCustomFields` and `ParseBluecoatPayload`, both org-built and shipped with this skill.

---

## What You Must Do When Invoked

### Step 0 — Parse the Input

Read the user's `$ARGUMENTS` (the playbook idea) and any sample issues they have pasted in the conversation.

From the sample issues, infer:
- **Log source type** — If the sample shows pipe-delimited `key=value` data, it is Bluecoat/Symantec proxy format. If it is CEF, JSON, Windows Event, Palo Alto, or other, note that separately.
- **Indicator types** — Which artifacts are present: destination host/URL (`cs_host`), destination IP (`dst`), source IP (`src`), port (`dstport`), byte counts (`sc_bytes`/`cs_bytes`), username, file hash, process name, etc.
- **Offense variants** — If multiple sample issues are given with different rule names (e.g., "Upload" vs "Download"), a single multi-variant playbook should handle both.
- **Payload fields** — List every `key=value` field present in the sample payload.

Do this analysis silently — do not narrate it before asking questions.

---

### Step 0b — Read the Reference Playbooks

Before asking any questions, read both reference playbooks from this skill's directory:

```
~/.claude/skills/xsoar-playbook-builder/reference-playbooks/QRadar_Proxy_Successful_Phishing.yml
~/.claude/skills/xsoar-playbook-builder/reference-playbooks/QRadar_Proxy_Excesive_Downloads_and_Uploads.yml
```

Read them in full (use chunked reads — both exceed 3000 lines). Build a mental model of each:

| Reference | Best match for offenses that… |
|---|---|
| `QRadar_Proxy_Successful_Phishing.yml` | Involve a single indicator type (URL/host), use PAN-DB URL category as first classification, have NO IP blocking, and have a single direction (no upload/download split) |
| `QRadar_Proxy_Excesive_Downloads_and_Uploads.yml` | Involve byte-transfer offenses with direction detection (upload vs download), include IP blocking, use VT + AbuseIPDB thresholds without PAN-DB, and have a multi-variant flow |

**Choose the closest reference.** The new playbook will be built by copying the chosen reference's task structure and replacing only the values that differ (thresholds, EDL list IDs, whitelist names, indicator context paths, offense-specific task names, email content). The structural skeleton — task types, phase order, condition operator patterns, QRadar note/close/email/CloseInvestigation chain — is inherited unchanged.

If the new offense does not clearly match either reference, ask the user which flow is closer before proceeding.

#### Known defect in the reference — do not inherit it

`QRadar_Proxy_Excesive_Downloads_and_Uploads.yml` task `118` (`Check verdict`) declares a `True Positive` condition label but has **no `nexttasks` entry for it**, and no `#default#`. An analyst selecting True Positive there stalls the playbook with the offense left open. It also duplicates the correctly-wired `Incident Verdict` ask task (`77`).

When adapting this reference: wire every declared branch, or drop task `118` entirely if `Incident Verdict` already covers the verdict routing. Running `validate_playbook.py` against the reference reproduces this as a CRITICAL finding — use that output to confirm you have not carried it forward. Mention the defect to the user, since their live playbook has it too.

---

### Step 1 — Ask Clarification Questions

Ask all questions in a single message, grouped by category. Do not ask questions whose answers can be reliably inferred from the sample issues.

#### Category 0 — Integration Scope (always ask, unless obvious from the samples)

These decide which phases exist at all. Get them before anything else — see Rule 0.

0a. **Alert source** — Is this a QRadar offense, or another source (Cortex XDR, Defender, CrowdStrike, a custom feed)? If not QRadar, all QRadar tasks, closing reason IDs, and the `RunAdditionalSeach` input come out.

0b. **Blocking integration** — Is Reputrack the blocking path in this tenant, or something else (PAN-OS EDL, a different EDL service)? If no blocking integration is available, say so — the playbook routes those verdicts to manual containment instead of auto-blocking.

0c. **Available reputation integrations** — Which of VirusTotal, AbuseIPDB, PAN-DB are actually licensed and configured? Only enrich with what exists.

0d. **Log retrieval** — Should the playbook pull additional logs beyond what the alert carries? If no, the log-retrieval phase and its input are both omitted.

#### Category A — Offense Identification (always ask)

1. **Exact QRadar rule name(s)** — What is the full rule name as it appears in QRadar (e.g., `GTBNIG 045 - Proxy - Successful phishing detected`)? If multiple variants, list all.
2. **Multiple variants in one playbook?** — Should one playbook handle multiple related rules (like download AND upload), or one playbook per rule?

#### Category B — Blocking and Containment (always ask)

3. **Block IPs?** — Should the destination IP ever be added to an EDL?
   - For **phishing/web content offenses**: almost always NO (CDN-fronted destinations make IP blocking harmful — phishing sites sit behind Cloudflare etc. and blocking the IP breaks unrelated legitimate sites).
   - For **exfiltration/C2/download offenses**: usually YES (dedicated servers have stable IPs).
   - Ask the user explicitly if it is not obvious from the offense type.
4. **EDL list ID(s)** — What EDL list ID(s) to use? (URL/domain list, IP list if applicable.) These are environment-specific and cannot be guessed.

#### Category C — Whitelisting (always ask)

5. **Whitelist XSOAR list name(s)** — What XSOAR list names should be checked before running reputation enrichment? (e.g., `lists.Phishing Simulation Domains`, `lists.Url-Large Downloads`, `lists.large Downloads`). Provide exact names including spaces and capitalisation.
6. **Whitelist QRadar close reason** — When a destination is whitelisted, what closing reason ID should be used? (Default: `157` — Benign True Positive BAU, meaning the detection was real but the destination is approved.)

#### Category D — Enrichment and Thresholds

7. **Use PAN-DB?** — Should Palo Alto URL category (`PaloAltoNGFWURLReputation`) be used as the first classification step? Only applicable for web/proxy offenses. If yes, a `DBotScore == 3` from PAN-DB triggers auto-block.
8. **VT threshold** — VirusTotal malicious detection count for auto-block. (Default: `10`. Lower = more aggressive blocking.)
9. **AbuseIPDB threshold** — AbuseIPDB confidence score for auto-block. (Default: `20` for transfers, `30` for phishing.) Only relevant if IP reputation is checked.

#### Category E — Payload and Context

10. **Parser needed?** — If the log is Bluecoat pipe-delimited format, `ParseBluecoatPayload` handles it. If the payload is in a different format (CEF, JSON, Windows Event Log, etc.), describe the format so a custom parser script can be written.
11. **Key fields for emails** — Beyond the standard fields (offense ID, source IP, destination IP/host, port), what additional fields from the payload should appear in notification emails? (e.g., `XferBytes`, `Username`, `ProcessName`)

#### Category F — Notification Preferences

12. **SOC email** — What is the SOC notification email address? (Default: `dfir@gtbank.com`.)
13. **Analyst form questions** — What should the manual investigation form ask the analyst? (Default: closing reason only. The phishing playbook also asks for user-response actions like credential reset.)

Do not proceed until the user has answered all non-defaultable questions (A, B, C, and D7).

---

### Step 2 — Confirm the Blueprint

Before generating any files, present a **Playbook Blueprint** to the user for approval. The blueprint must include:

```
PLAYBOOK: <name>
FOLDER: <folder path>
TRIGGERING RULES: <list>

PHASES:
  Phase 1 — Context Retrieval (QradarGetIssueCustomFields if needed)
  Phase 2 — Severity Mapping
  Phase 3 — Optional Log Retrieval (QRadar - Get Offense Logs)
  Phase 4 — Optional Indicator Enrichment (Entity Enrichment - Generic v3)
  Phase 5 — Payload Parsing (<parser script>)
  [Phase 5b — Direction Detection (if multi-variant)]
  Phase 6 — Whitelist Check (<list names>)
  [Phase 7 — PAN-DB URL Category (if enabled)]
  Phase 8 — URL Reputation (VT >= <threshold>)
  Phase 9 — IP Reputation (VT >= <threshold>, AbuseIPDB >= <threshold>) [if IP blocking enabled]
  Phase 10 — Manual Investigation

CLOSURE PATHS:
  A — Whitelisted (auto, QRadar reason <ID>)
  B — Auto True Positive — URL blocked to EDL <list_id>
  [C — Auto True Positive — IP blocked to EDL <list_id>]  [if IP blocking]
  D — Manual True Positive (QRadar reason 155)
  E — Manual False Positive (QRadar reason 158)
  F — Manual BTP-BAU (QRadar reason 157)
  G — Manual BTP-Security Testing (QRadar reason 159)

EDL ACTIONS:
  URL/host → EDL list <id>
  [IP → EDL list <id>]

WHITELIST LISTS:
  <list names>

HELPER SCRIPTS: <list>
EMAIL TEMPLATES: <list — one per closure path>
```

Ask for explicit approval before generating any files. If the user requests changes, update the blueprint and ask again.

---

### Step 3 — Generate UUIDs

Generate a UUID for every task in the playbook using:

```bash
python3 -c "import uuid; [print(uuid.uuid4()) for _ in range(<N>)]"
```

Generate at least 40 UUIDs (more for complex playbooks). Assign one UUID per task. The task's outer `id` field is a sequential integer string (`"0"`, `"1"`, etc.); the `taskid` and inner `task.id` both use the UUID.

---

### Step 4 — Create the Folder Structure

```bash
mkdir -p "<parent_dir>/<offense_name>/scripts"
mkdir -p "<parent_dir>/<offense_name>/emails-html"
```

The `<offense_name>` folder name should match the offense description, using the same capitalisation style as the existing playbooks (spaces allowed, preserve the original rule naming style).

---

### Step 5 — Generate Helper Scripts

#### 5a. QradarGetIssueCustomFields (QRadar-sourced playbooks only — see Rule 0)

Copy verbatim from this skill's own directory:
```
<skill_dir>/scripts/QradarGetIssueCustomFields.yml
```
Where `<skill_dir>` is `~/.claude/skills/xsoar-playbook-builder/` (or the equivalent on the current machine — the file ships with the skill in `scripts/`). This script is identical across all playbooks — do not modify it.

#### 5b. ParseBluecoatPayload (if Bluecoat log source)

Copy verbatim from this skill's own directory:
```
<skill_dir>/scripts/ParseBluecoatPayload.yml
```
This script ships with the skill in `scripts/` and is identical across all Bluecoat playbooks — do not modify it.

#### 5c. Custom parser (if non-Bluecoat log source)

If the payload format is not Bluecoat pipe-delimited, write a custom `Parse<LogSource>Payload.yml` automation script. The script must:
- Accept `payload` as a required argument.
- Parse the format (CEF: split on `|` then on `=`; JSON: use `json.loads()`; Windows Event: parse XML; custom: as described by the user).
- Normalise key names (replace special characters with `_`).
- Write results to `EntryContext["<LogSource>"]`.
- Render a human-readable Markdown table of the parsed fields.

Use the same Docker image and script structure as `ParseBluecoatPayload` unless the format requires additional libraries.

---

### Step 6 — Generate HTML Email Templates

Generate one HTML file per closure path. Store all files in `emails-html/`.

#### Email filename convention:
| Closure Path | Filename |
|---|---|
| Manual investigation required | `manual_investigation.html` |
| Whitelisted (auto-close) | `whitelisted_autoclose.html` |
| Auto-closed true positive | `true_positive.html` |
| Manual true positive | `manual_true_positive.html` |
| Manual false positive | `false_positive.html` |
| Manual BTP-BAU | `manual_btp_bau.html` |
| Manual BTP-security testing | `manual_btp_sectest.html` |

#### Email template rules:
1. Use the exact HTML structure from the org's existing templates: outer `<table>` full-width, inner `<table width="600">`, header row, banner row, intro paragraph, details table, reputation results (where relevant), closure info table, button, footer.
2. **Header colour per closure type:**
   - Manual Investigation Required: `#854f0b` (amber)
   - Whitelisted/Auto-Closed: `#475569` (slate)
   - True Positive (auto or manual): `#b91c1c` (red)
   - False Positive: `#0f766e` (teal)
   - BTP-BAU: `#1d4ed8` (blue)
   - BTP-Security Testing: `#6d28d9` (purple)
3. **Subject line** — Embed in the YAML `send-mail` task, NOT in the HTML file. The HTML file contains only the body.
   - **Manual investigation emails MUST begin their subject with `[Manual Investigation Required]`** — this prefix is mandatory and must appear first, before any offense name or ID, e.g.:
     `[Manual Investigation Required] QRadar Offense - ${Offense.offense_id} - ${Offense.offense_description}`
   - All other email subject lines should NOT carry this prefix.
4. **Canonical QRadar closing reason IDs** — these are fixed org-wide values; always use them exactly:

   | ID | Label | When to use |
   |---|---|---|
   | `155` | True Positive | Confirmed malicious activity — attacker intent verified |
   | `157` | Benign True Positive — Business As Usual | Real event, destination/behaviour is approved (whitelisted, known-good) |
   | `158` | False Positive | Detection fired incorrectly — rule misidentified benign activity as malicious |
   | `159` | Benign True Positive — Security Testing | Real event triggered by authorised pen-test, red team, or phishing simulation |

   These IDs are embedded in every `qradar-offense-update` task as `closing_reason_id`. Never invent new IDs. If the user requests a reason not in this list, ask them for the numeric ID from their QRadar instance.

5. **Required context variables in all emails:**
   - `${issue.id}` — XSOAR investigation ID
   - `${Offense.offense_id}` — QRadar offense ID
   - `${Offense.offense_description}` — QRadar offense name
   - `${Offense.offense_src_ip}` — Source IP
   - `${Offense.offense_dst_ip}` — Destination IP
   - `${Offense.offense_hostname}` — Source hostname
   - `${Offense.offense_link}` — QRadar offense link (used in button)
   - `${incident.closingUserId}` — XSOAR closing user (manual closure emails)
   - `${Provide closing reason.Answers.name}` — CC target (manual closure emails)
6. **Add playbook-specific fields** from the payload context (e.g., `${Bluecoat.cs_host}`, `${Bluecoat.dst}`, `${XferBytes}`, `${XferTitle}ed`) where relevant to the offense type.
7. **Reputation results section** — Include VirusTotal and AbuseIPDB scores in emails where reputation enrichment ran (true positive and manual investigation templates).
8. **Footer**: `<playbook display name> &middot; Issue ID ${issue.id}.`

---

### Step 7 — Generate the Main Playbook YAML

Write the YAML file as `<OffenseName>.yml` (no spaces — use underscores or the original name with spaces, matching existing conventions).

#### CRITICAL: Use the Reference Playbook as the Structural Model

Do **not** assemble the playbook from the generic task templates below as a first pass. Instead:

1. **Start with the reference playbook chosen in Step 0b.** Copy its complete task map as the base.
2. **Replace only what differs for the new offense:**
   - Playbook `id` (new UUID), `name`, `description`
   - Task names where they reference the old offense type
   - Condition thresholds (VT count, AbuseIPDB score)
   - EDL `list_id` values
   - Whitelist `lists.<name>` values in condition operators
   - Context paths that reference the parsed payload (e.g., `${Bluecoat.cs_host}` stays `${Bluecoat.cs_host}` unless the new offense uses a different parser and context key)
   - Email `htmlBody` and `subject` content
   - QRadar rule names in task descriptions
3. **Keep identical across all playbooks:**
   - Phase structure and order (Context Retrieval → Severity → Log Retrieval → Enrichment → Parsing → Whitelist → Reputation → Manual)
   - `QradarGetIssueCustomFields` script task (copy verbatim)
   - `ParseBluecoatPayload` script task (copy verbatim if Bluecoat log source)
   - Severity mapping task and `ScaleToSetSeverityFrom` logic
   - `QRadar - Get Offense Logs` sub-playbook task structure
   - `Entity Enrichment - Generic v3` sub-playbook task structure
   - QRadar note task → `qradar-offense-update` close task → `send-mail` task → `CloseInvestigation` terminal task — this 4-step chain is the same in every closure path
   - The `Builtin|||setIncident` closeNotes task before the verdict condition
   - The verdict condition reply options and branch labels (including `Fasle Positive`)
   - The `inputs:` block — but only the keys whose phases survive Rule 0
   - `sourceplaybookid: QRadar Generic`
4. **Generate fresh UUIDs** for every task — never reuse UUIDs from the reference playbooks.
5. **Renumber task IDs sequentially** from `"0"` — do not preserve the reference playbook's task ID numbers.

The task templates below are provided as a fallback reference for structural details only. The reference playbook takes precedence.

#### YAML root structure:

```yaml
id: <UUID>
version: 1
vcShouldKeepItemLegacyProdMachine: false
aclrelations: []
aclowner:
  id: ""
  type: ""
  name: ""
name: <Playbook Name>
description: <one-sentence description of what this playbook does>
starttaskid: "0"
tasks:
  <all tasks>
outlinetasks: {}
view: |-
  {
    "linkLabelsPosition": {},
    "paper": {
      "dimensions": {
        "height": <total_height>,
        "width": <total_width>,
        "x": 50,
        "y": 50
      }
    }
  }
inputs:
  <all inputs>
inputSections:
- inputs:
  - <all input key names>
  name: General (Inputs group)
  description: Generic group for inputs
outputSections:
- outputs: []
  name: General (Outputs group)
  description: Generic group for outputs
outputs: []
sourceplaybookid: QRadar Generic
dirtyInputs: true
adopted: true
possibleresponses: []
```

#### Standard inputs block

Include the inputs the playbook actually uses. The block below is the full QRadar-sourced set; per Rule 0, drop the ones whose phases you removed — `RunAdditionalSeach`, `MaxLogsCount`, `GetOnlyCREEvents`, and `Fields` all belong to the QRadar log-retrieval phase and come out together with it.

```yaml
inputs:
- key: Enrich
  value:
    simple: "false"
  required: false
  description: Determines whether to enrich all indicators in the incident.
  playbookInputQuery: null
- key: OnCall
  value:
    simple: "false"
  required: false
  description: Set to true to assign only the user that is currently on shift. Requires Cortex XSOAR v5.5 or later.
  playbookInputQuery: null
- key: SocEmailAddress
  value:
    simple: <soc_email>
  required: false
  description: The SOC team's email address.
  playbookInputQuery: null
- key: SocMailSubject
  value:
    simple: 'XSOAR Summary report, ID - '
  required: false
  description: The subject of the email to send to the SOC.
  playbookInputQuery: null
- key: SiemAdminEmailAddress
  value:
    simple: <soc_email>
  required: false
  description: The SIEM admin's email address.
  playbookInputQuery: null
- key: UseCalculateSeverity
  value:
    simple: "true"
  required: false
  description: Determines whether to use the Calculate Severity playbook to calculate the incident severity.
  playbookInputQuery: null
- key: SiemAdminMailSubject
  value:
    simple: 'Adjustment/Exclusion for offense '
  required: false
  description: The subject of the email to send to the SIEM admin.
  playbookInputQuery: null
- key: UseCustomSeveritySettings
  value:
    simple: "true"
  required: false
  description: Determines whether to use the default mapping in the QRadar generic mapper to set the XSOAR incident severity, or set the severity using the FieldToSetSeverityFrom and ScaleToSetSeverityFrom playbook inputs.
  playbookInputQuery: null
- key: FieldToSetSeverityFrom
  value:
    complex:
      root: incident
      accessor: magnitudeoffense
  required: false
  description: Specifies the field to use for calculating the incident severity.
  playbookInputQuery: null
- key: ScaleToSetSeverityFrom
  value:
    simple: 1,1,2,2,2,3,3,3,4,4
  required: false
  description: "Maps QRadar magnitude 1-10 to XSOAR severity 0-4: 1-2→Low, 3-5→Medium, 6-8→High, 9-10→Critical."
  playbookInputQuery: null
- key: RunAdditionalSeach
  value:
    simple: "false"
  required: false
  description: By default the incident fetches the events defined in the integration instance settings. To fetch additional events, change this setting to true.
  playbookInputQuery: null
- key: MaxLogsCount
  value:
    simple: "50"
  required: false
  description: Maximum number of log entries to query from QRadar.
  playbookInputQuery: null
- key: GetOnlyCREEvents
  value:
    simple: OnlyNotCRE
  required: false
  description: "If this value is 'OnlyCRE', get only events made by CRE. Values: OnlyCRE, OnlyNotCRE, All."
  playbookInputQuery: null
- key: Fields
  value:
    simple: QIDNAME(qid), LOGSOURCENAME(logsourceid), CATEGORYNAME(highlevelcategory),
      CATEGORYNAME(category), PROTOCOLNAME(protocolid), sourceip, sourceport, destinationip,
      destinationport, QIDDESCRIPTION(qid), username, PROTOCOLNAME(protocolid), RULENAME("creEventList"),
      sourcegeographiclocation, sourceMAC, sourcev6, destinationgeographiclocation,
      destinationv6, LOGSOURCETYPENAME(devicetype), credibility, severity, magnitude,
      eventcount, eventDirection, postNatDestinationIP, postNatDestinationPort, postNatSourceIP,
      postNatSourcePort, preNatDestinationPort, preNatSourceIP, preNatSourcePort,
      UTF8(payload), starttime, devicetime
  required: false
  description: A comma-separated list of extra fields to get from each event.
  playbookInputQuery: null
- key: IndicatorTag
  value:
    simple: block
  required: false
  description: The tag to provide for true positive indicators, for example to use the indicators in an EDL.
  playbookInputQuery: null
- key: ExcludeIndicatorsInXSOAR
  value:
    simple: "false"
  required: false
  description: If this value is not false, add indicators to the XSOAR exclude list.
  playbookInputQuery: null
```

> **Note:** The `RunAdditionalSeach` key name contains a deliberate spelling error (`Seach` instead of `Search`). This is the exact key name used across all org playbooks — it must be preserved.

#### Task YAML templates:

Use these exact structures for each task type. Replace `<ANGLE_BRACKET>` placeholders with real values. Generate fresh UUIDs — never reuse UUIDs from existing playbooks.

---

**START task** (always task "0"):
```yaml
  "0":
    id: "0"
    taskid: <UUID>
    type: start
    task:
      id: <UUID>
      version: -1
      name: ""
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#none#':
      - "<next_id>"
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": 1555,
          "y": 50
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

---

**CONDITION task** (branching logic):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: condition
    task:
      id: <UUID>
      version: -1
      name: <task name>
      description: <description of what is being tested and why>
      type: condition
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#default#':
      - "<default_next_id>"
      <BranchLabel>:
      - "<branch_next_id>"
    separatecontext: false
    conditions:
    - label: <BranchLabel>
      condition:
      - - operator: <operator>
          left:
            value:
              simple: ${<context.path>}
            iscontext: true
          right:
            value:
              simple: "<value>"
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

Common operators: `isNotEmpty`, `isEmpty`, `isEqualString`, `isNotEqualString`, `greaterThanOrEqual`, `inList`, `containsString`

---

**REGULAR task — script/command**:
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: regular
    task:
      id: <UUID>
      version: -1
      name: <task name>
      description: <description>
      script: '<brand>|||<command>'
      type: regular
      iscommand: true
      brand: <brand>
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#none#':
      - "<next_id>"
    scriptarguments:
      <arg_name>:
        simple: <value>
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

For automation scripts (not integration commands), use `scriptName:` instead of `script:` and set `iscommand: false`:
```yaml
      scriptName: <ScriptName>
      type: regular
      iscommand: false
      brand: ""
```

---

**SUB-PLAYBOOK task** (`separatecontext: true` for QRadar Get Offense Logs and Entity Enrichment):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: playbook
    task:
      id: <UUID>
      version: -1
      name: <sub-playbook name>
      description: <description>
      playbookName: <sub-playbook name>
      type: playbook
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#none#':
      - "<next_id>"
    scriptarguments:
      <arg>:
        simple: <value>
    separatecontext: true
    continueonerrortype: ""
    loop:
      iscommand: false
      exitCondition: ""
      wait: 1
      max: 100
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

---

**COLLECTION task** (manual analyst form):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: collection
    task:
      id: <UUID>
      version: -1
      name: <task name>
      type: collection
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#none#':
      - "<next_id>"
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    message:
      to: null
      subject: null
      body: null
      methods: []
      format: ""
      bcc: null
      cc: null
      timings:
        retriescount: 2
        retriesinterval: 360
        completeafterreplies: 1
        completeafterv2: true
        completeaftersla: false
    form:
      questions:
      - id: "0"
        label: ""
        labelarg:
          simple: <question text>
        required: false
        gridcolumns: []
        defaultrows: []
        type: longText
        options: []
        optionsarg: []
        fieldassociated: ""
        placeholder: ""
        tooltip: ""
        readonly: false
      title: Provide closing reason
      description: ""
      sender: ""
      expired: false
      totalanswers: 0
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

---

**USER-REPLY CONDITION task** (verdict selection after manual form):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: condition
    task:
      id: <UUID>
      version: -1
      name: Incident Verdict
      type: condition
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      True Positive:
      - "<tp_next_id>"
      Fasle Positive:
      - "<fp_next_id>"
      BTP - BAU:
      - "<bau_next_id>"
      BTP - Security Testing:
      - "<sec_next_id>"
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    message:
      to: null
      subject: null
      body:
        simple: What is the verdict of the incident
      methods: []
      format: ""
      bcc: null
      cc: null
      timings:
        retriescount: 2
        retriesinterval: 360
        completeafterreplies: 1
        completeafterv2: true
        completeaftersla: false
      replyOptions:
      - True Positive
      - Fasle Positive
      - BTP - BAU
      - BTP - Security Testing
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

> **Critical:** The verdict option `Fasle Positive` is intentionally misspelled — this is the exact string stored in the org's existing playbooks and must be used verbatim.

---

**TITLE task** (section headers):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: title
    task:
      id: <UUID>
      version: -1
      name: <Section Title>
      type: title
      iscommand: false
      brand: ""
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    nexttasks:
      '#none#':
      - "<next_id>"
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

---

**TERMINAL task** (CloseInvestigation — always the last task in a path):
```yaml
  "<id>":
    id: "<id>"
    taskid: <UUID>
    type: regular
    task:
      id: <UUID>
      version: -1
      name: CloseInvestigation
      description: commands.local.cmd.close.inv
      script: Builtin|||closeInvestigation
      type: regular
      iscommand: true
      brand: Builtin
      playbooktaskmissingcomponent: null
      istaskmissingcomponenterrordismissed: false
    separatecontext: false
    continueonerrortype: ""
    view: |-
      {
        "position": {
          "x": <x>,
          "y": <y>
        }
      }
    note: false
    timertriggers: []
    ignoreworker: false
    skipunavailable: false
    quietmode: 0
    isoversize: false
    isautoswitchedtoquietmode: false
```

---

#### Canvas position guidelines:

Use these x-positions for the main flow. Each phase adds ~185px in y.

| Column | x value | Use |
|---|---|---|
| Far left | 50 | BTP-BAU closure |
| Left | 255–470 | FP / SecTest closure |
| Centre-left | 685–800 | Manual investigation branch |
| Centre | 1105–1217 | Upload path / secondary checks |
| Main | 1442–1555 | Primary flow |
| Right | 1667–1780 | Enrichment / download path |
| Far right | 1995–2322 | Whitelist closure |

Start at y=50 for task 0 and increment y by 185 per phase row.

---

#### Standard task chain patterns:

**Phase 1 — Context Retrieval:**
```
START(0) → Check offense fields(condition) → [QradarGetIssueCustomFields(regular)] → Severity check
```

**Phase 2 — Severity Mapping:**
```
Use custom severity?(condition) → [Set severity via setIncident(regular)] → Additional search check
```

**Phase 3 — Optional Log Retrieval:**
```
Run additional searches?(condition) → [QRadar - Get Offense Logs(playbook, separatecontext:true)] → Enrichment check
```

**Phase 4 — Optional Enrichment:**
```
Should indicators be enriched?(condition) → [Enrich Data(title) → extractIndicators(regular) → Entity Enrichment v3(playbook, separatecontext:true)] → Payload parse check
```

**Phase 5 — Payload Parsing:**
```
Check Context for <source> payload(condition) → [<Parser script>(regular)] → [Direction detection | Whitelist check]
```

**Phase 6 — Whitelist Check:**
```
Check URL in Whitelist(condition) → [Whitelisted branch →] Check IP in whitelist(condition) → [Whitelisted →] Reputation enrichment
```

**Phase 7 — PAN-DB (if enabled):**
```
Check URL via PaloAltoNGFWURLReputation|||url(regular) → DBotScore == 3?(condition) → [Malicious → EDL + Note + Close] | DBotScore == 2?(condition) → [VT reputation] | Default → [False Positive close]
```

**Phase 8 — URL Reputation:**
```
Check URL Reputation |||url(regular) → VT URL >= <threshold>?(condition) → [Add URL to EDL list <id>(regular) → QRadar note(regular) → Close QRadar TP(regular) → Send email(regular) → CloseInvestigation(terminal)]
```

**Phase 9 — IP Reputation (if enabled):**
```
Check IP Reputation |||ip(regular) → VT IP >= <threshold>?(condition) → [Add IP to EDL list <id>(regular)] | AbuseIPDB >= <threshold>?(condition) → [Add IP to EDL list <id>] | Neither → Manual investigation
```

**Phase 10 — Manual Investigation:**
```
Send manual investigation email(regular) → Analyst form(collection) → Set closeNotes(regular) → Incident Verdict(condition) → [True Positive | Fasle Positive | BTP-BAU | BTP-Security Testing] → [for each: Close QRadar(regular) → Send email(regular) → CloseInvestigation(terminal)]
```

**Whitelist auto-close:**
```
QRadar note "URL/IP whitelisted"(regular) → Close QRadar reason <whitelist_id>(regular) → Send whitelisted email(regular) → CloseInvestigation(terminal)
```

---

#### send-mail task pattern:

```yaml
    scriptarguments:
      cc:
        simple: ${Provide closing reason.Answers.name}   # only on manual closure emails
      htmlBody:
        simple: |
          <paste full HTML email body from emails-html/<template>.html>
      subject:
        simple: '<subject line with ${context.variables}>'
      to:
        simple: <soc_email>
```

The `htmlBody` for the YAML task is the full HTML content inline. The `.html` files in `emails-html/` are standalone reference copies of the same content.

---

#### QRadar closing reason IDs:

| ID | Label |
|---|---|
| `155` | True Positive |
| `157` | Benign True Positive — Business as Usual |
| `158` | False Positive |
| `159` | Benign True Positive — Security Testing |

Use the whitelist auto-close reason confirmed in Category C.

---

### Step 8 — Write All Files

Write files in this order:

1. `scripts/QradarGetIssueCustomFields.yml` — copy from org's existing scripts
2. `scripts/ParseBluecoatPayload.yml` (or custom parser) — copy or write
3. `emails-html/*.html` — one file per closure path
4. `<OffenseName>.yml` — the main playbook (write last, after all UUIDs and task wiring are finalised)

After writing the main YAML, verify with:
```bash
python3 -c "import yaml; yaml.safe_load(open('<path>/<OffenseName>.yml'))" && echo "YAML valid"
```

If the YAML fails to parse, fix the indentation or structure error and re-validate before reporting completion.

---

### Step 9 — Validate the Task Graph (automated)

Do not hand-check the graph. Run the validator that ships with this skill:

```bash
python3 ~/.claude/skills/xsoar-playbook-builder/scripts/validate_playbook.py "<path>/<OffenseName>.yml"
```

It parses the YAML into a task graph and reports, ranked by severity:

| Code | Severity | What it catches |
|---|---|---|
| `dangling-edge` | CRITICAL | `nexttasks` pointing at a task ID that does not exist |
| `unwired-branch` | CRITICAL | A condition label with no `nexttasks` — the defect in the downloads reference |
| `cycle` | CRITICAL | A loop with no exit — the playbook never terminates |
| `duplicate-uuid` | CRITICAL | Two tasks sharing a UUID; XSOAR drops all but one on import |
| `no-terminal` | CRITICAL | No `CloseInvestigation` anywhere — investigations never close |
| `no-default-branch` | HIGH | A condition with no `#default#`; non-matching alerts are silently dropped |
| `dead-end` | HIGH | A non-terminal task with no `nexttasks` — the incident stalls with no analyst signal |
| `unreachable` | HIGH | A task never reached from the start task |
| `missing-input` | HIGH | `QRadar - Get Offense Logs` called without the `RunAdditionalSeach` input |
| `verdict-label-drift` | HIGH | Reply option spelled `False Positive` where the org uses `Fasle Positive` |
| `unknown-close-reason` | HIGH | A `closing_reason_id` outside `155/157/158/159` |
| `unused-input` | MEDIUM | `RunAdditionalSeach` defined on a playbook that never calls QRadar (Rule 0) |
| `close-without-note` | MEDIUM | An offense closed with no note or closeNotes anywhere upstream |
| `shared-context` | MEDIUM | A sub-playbook running with `separatecontext: false` |
| `UNVERIFIED` | MEDIUM | A command neither on xsoar.pan.dev nor a known org integration — **ask the user** |
| `org-custom` | INFO | Reputrack and the org automations; expected, no action |

The QRadar-specific checks only fire when the playbook actually calls QRadar, so a non-QRadar playbook is not nagged about conventions that do not apply to it.

**Exit criteria: zero CRITICAL and zero HIGH findings.** MEDIUM findings must each be either fixed or explained to the user. `UNVERIFIED` always warrants a question — never assume the command exists.

Verify the checker itself with `--self-test` if you have modified it.

---

### Step 10 — Dry-Run the Branches

Static checks prove the graph is wired; they do not prove it routes correctly. Write a scenario file covering **every closure path** and run it:

```bash
python3 ~/.claude/skills/xsoar-playbook-builder/scripts/validate_playbook.py \
    "<path>/<OffenseName>.yml" -s "<path>/scenarios.json"
```

`scenarios.json` is a list of scenario objects:

```json
[
  {"name": "Destination whitelisted — auto-close BTP-BAU",
   "branches": {"Check URL in Whitelist": "yes"},
   "expected_path": ["0", "1", "14", "40", "41", "42"]},

  {"name": "VT above threshold — auto-block and close TP",
   "branches": {"Check URL in Whitelist": "#default#", "VT URL malicious >= 10": "yes"}},

  {"name": "Nothing conclusive — manual investigation",
   "branches": {}}
]
```

- `branches` maps a condition task's **name** (or ID) to the branch label to take. Unlisted conditions fall through to `#default#`.
- `expected_path` is optional. Omit it on the first run to capture the actual path, then paste that path back in as the expectation once you have confirmed it is correct — that locks the routing against future edits.

Cover, at minimum: each whitelist path, each auto-block threshold path, each manual verdict, and one edge case where the indicator field is absent so the parse/enrichment conditions fall through.

The simulator refuses to guess on a condition that fans out to multiple tasks, reporting it as a race — parallel branches sharing context is a real defect worth surfacing rather than papering over.

Two guards stop a scenario from passing without testing anything:

- **Unknown condition name** — a `branches` key matching no task in the playbook FAILs, rather than silently falling through to `#default#`. Catches typos and names copied from a different playbook.
- **Unreached condition** — if the walk finishes without ever visiting a condition the scenario chose a branch for, it FAILs. This means the path never went where you intended, so the scenario proved nothing. Steer the earlier conditions until the walk actually reaches it.

A scenario that FAILs on either guard is a broken *test*, not necessarily a broken playbook — fix the scenario and re-run.

**State plainly in your handover that this is logic validation only, not a substitute for testing in a live XSOAR tenant.** It cannot prove an integration command exists, that its arguments are valid, or that its real output matches what the playbook expects downstream.

---

### Step 11 — Final File Checks

The validator covers the graph. These are the things it cannot see:

- [ ] YAML parses (`python3 -c "import yaml; yaml.safe_load(open('<file>'))"`) — the validator does this implicitly, but check standalone if it errored.
- [ ] All EDL list IDs match the values confirmed in the blueprint (the validator cannot know the right ones).
- [ ] All whitelist list names in `inList` conditions match the blueprint exactly, including spaces and capitalisation.
- [ ] Each `send-mail` task carries the correct inline HTML body and subject line.
- [ ] Manual investigation subject lines begin with `[Manual Investigation Required]`.
- [ ] `emails-html/` contains one file per closure path.
- [ ] `scripts/` contains every helper script the playbook references — and none it does not (Rule 0).

---

## Command Reference — Verified vs Org-Custom

Cite the source for every command you use. Confirmed on xsoar.pan.dev:

| Command / component | Reference |
|---|---|
| `QRadar v3\|\|\|qradar-offense-update` (incl. `closing_reason_id`) | https://xsoar.pan.dev/docs/reference/integrations/q-radar-v3 |
| `QRadar v3\|\|\|qradar-offense-note-create` | https://xsoar.pan.dev/docs/reference/integrations/q-radar-v3 |
| `Builtin\|\|\|setIncident` | https://xsoar.pan.dev/docs/reference/scripts/set-incident |
| `Builtin\|\|\|extractIndicators` | https://xsoar.pan.dev/docs/reference/scripts/extract-indicators |
| `Set` | https://xsoar.pan.dev/docs/reference/scripts/set |
| `\|\|\|send-mail` | https://xsoar.pan.dev/docs/reference/integrations/mail-sender-v2 |
| `\|\|\|url` / `\|\|\|ip` (VirusTotal) | https://xsoar.pan.dev/docs/reference/integrations/virus-total-v3 |
| `QRadar - Get Offense Logs` | https://xsoar.pan.dev/docs/reference/playbooks/q-radar---get-offense-logs |
| `QRadar Generic` (the `sourceplaybookid`) | https://xsoar.pan.dev/docs/reference/playbooks/q-radar-generic |
| Generic EDL service (non-Reputrack tenants) | https://xsoar.pan.dev/docs/reference/integrations/edl |

**Org-built, intentionally not on xsoar.pan.dev** — treat as known-good, do not flag:
`reputrack-add-edl-entries` (Reputrack), `QradarGetIssueCustomFields`, `ParseBluecoatPayload`.

**Anything else:** if a command is neither in the table above nor an org integration, search xsoar.pan.dev before using it. If you cannot confirm it, label it **UNVERIFIED** in your output and ask the user whether it exists in their tenant. Do not invent commands, argument names, or context paths. A plausible-looking command that does not exist fails at runtime, mid-containment.

Keep `VERIFIED_COMMANDS` and `KNOWN_CUSTOM` in `scripts/validate_playbook.py` in sync with this table as new integrations come into use.

---

## Best Security Practice Rules

Apply these unconditionally when building any playbook:

| Rule | Rationale |
|---|---|
| Always add a QRadar note **before** closing the offense | Closing without a note leaves no audit trail in QRadar |
| Always whitelist-check **before** running external reputation queries | Prevents unnecessary API calls and false-positive blocks on known-good destinations |
| Never auto-block without a quantitative threshold | Prevents automation-induced outages from transient VT noise |
| Always provide a manual investigation fallback | When no threshold is met, an analyst must make the call — never drop offenses |
| For phishing / web content offenses: block domain only, never IP | Phishing infrastructure is CDN-fronted; IP blocking causes collateral outages |
| For exfiltration / C2 / transfer offenses: consider blocking both URL and IP | C2/exfil servers have stable IPs; both layers of blocking add defence-in-depth |
| Always CC the closing analyst on manual closure emails | Creates accountability chain; analyst can reply to SOC with context |
| Use `separatecontext: true` for `QRadar - Get Offense Logs` and `Entity Enrichment - Generic v3` | Prevents sub-playbook context from polluting the parent's context |
| Write the QRadar note text to describe the outcome, not just the action | e.g., `"True Positive - URL/IP has been blocked"` not `"EDL updated"` |
| Set closeNotes via `Builtin\|\|\|setIncident` before verdict condition | Ensures the analyst's rationale is recorded before the verdict routes |
| Whitelist auto-close reason: use `157` (BTP-BAU) not `158` (FP) | Whitelisted destinations are real events that are approved — not misdetections |
| Include `issue.closeNotes` in manual closure email bodies | Surfaces the analyst's closing rationale to all SOC members who receive the email |
