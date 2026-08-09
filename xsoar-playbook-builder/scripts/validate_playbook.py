#!/usr/bin/env python3
"""Static validator + dry-run simulator for Cortex XSOAR v2 playbook YAML.

Runs entirely outside XSOAR (stdlib + PyYAML only). It validates the task graph
and walks it against scenario definitions to prove which branch a given offense
context would take.

    ./validate_playbook.py <playbook.yml>                  # static checks only
    ./validate_playbook.py <playbook.yml> -s scenarios.json # + dry-run
    ./validate_playbook.py --self-test                     # check the checker

THIS IS A LOGIC VALIDATION TOOL, NOT A REPLACEMENT FOR LIVE TESTING. It proves
the graph is wired correctly and that branches route where you intended. It does
not prove an integration command exists, that its arguments are valid, or that
its real output matches the mock.

Scenario file format (JSON list):

    [{"name": "URL whitelisted",
      "branches": {"Check URL in Whitelist": "yes"},
      "expected_path": ["0", "1", "14", "40"]}]

`branches` maps a condition task's name (or id) to the branch label to take.
Unlisted conditions fall through to '#default#'. `expected_path` is optional;
omit it to just record the path the engine takes.
"""

import argparse
import json
import re
import sys

import yaml

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)

# Commands confirmed on xsoar.pan.dev. Anything used but absent from this map is
# reported as UNVERIFIED rather than assumed valid.
# ponytail: flat dict, not a doc scraper — add entries as new integrations appear.
VERIFIED_COMMANDS = {
    "QRadar v3|||qradar-offense-update": "https://xsoar.pan.dev/docs/reference/integrations/q-radar-v3",
    "QRadar v3|||qradar-offense-note-create": "https://xsoar.pan.dev/docs/reference/integrations/q-radar-v3",
    "Builtin|||closeInvestigation": "https://xsoar.pan.dev/docs/reference/api/close-investigation",
    "Builtin|||setIncident": "https://xsoar.pan.dev/docs/reference/scripts/set-incident",
    "Builtin|||extractIndicators": "https://xsoar.pan.dev/docs/reference/scripts/extract-indicators",
    "Builtin|||addToList": "https://xsoar.pan.dev/docs/reference/scripts/add-to-list",
    "|||send-mail": "https://xsoar.pan.dev/docs/reference/integrations/mail-sender-v2",
    "|||url": "https://xsoar.pan.dev/docs/reference/integrations/virus-total-v3",
    "|||ip": "https://xsoar.pan.dev/docs/reference/integrations/virus-total-v3",
    "PaloAltoNGFWURLReputation|||url": "https://xsoar.pan.dev/docs/reference/integrations/palo-alto-networks-url-filtering",
}
VERIFIED_SCRIPTS = {"Set": "https://xsoar.pan.dev/docs/reference/scripts/set"}

# Org-built, deliberately absent from xsoar.pan.dev. Known-good in this tenant,
# so they are reported as INFO, not as unverified guesses. Anything NOT in either
# map is a genuine unknown and gets flagged for confirmation with the user.
KNOWN_CUSTOM = {
    "|||reputrack-add-edl-entries": "Reputrack — org-built EDL integration",
    "QradarGetIssueCustomFields": "org-built automation (ships with this skill)",
    "ParseBluecoatPayload": "org-built automation (ships with this skill)",
}
VERIFIED_SUBPLAYBOOKS = {
    "QRadar - Get Offense Logs": "https://xsoar.pan.dev/docs/reference/playbooks/q-radar---get-offense-logs",
    "Entity Enrichment - Generic v3": "https://xsoar.pan.dev/docs/reference/playbooks/entity-enrichment---generic-v3",
}
CLOSING_REASON_IDS = {"155", "157", "158", "159"}
CLOSE_TASK = "Builtin|||closeInvestigation"
NOTE_TASK = "QRadar v3|||qradar-offense-note-create"
OFFENSE_UPDATE = "QRadar v3|||qradar-offense-update"

CRITICAL, HIGH, MEDIUM, INFO = "CRITICAL", "HIGH", "MEDIUM", "INFO"


class Finding:
    """One validation issue, ranked by production impact."""

    def __init__(self, severity, code, location, message, ref=""):
        self.severity, self.code = severity, code
        self.location, self.message, self.ref = location, message, ref

    def __str__(self):
        tail = f"  [{self.ref}]" if self.ref else ""
        return f"{self.severity:<8} {self.code:<22} {self.location:<28} {self.message}{tail}"


def command_of(task):
    """Return the integration command, `SCRIPT:name`, or `PB:name` a task invokes."""
    t = task["task"]
    if t.get("script"):
        return t["script"]
    if t.get("scriptName"):
        return "SCRIPT:" + t["scriptName"]
    if t.get("playbookName"):
        return "PB:" + t["playbookName"]
    return None


def successors(task):
    """All task ids this task can hand off to, flattened across branch labels."""
    return [nid for ids in (task.get("nexttasks") or {}).values() for nid in (ids or [])]


def check_graph(tasks, starttaskid, out):
    """Dangling edges, unreachable tasks, dead ends, and cycles."""
    if starttaskid not in tasks:
        out.append(Finding(CRITICAL, "missing-start", "starttaskid",
                           f"starttaskid {starttaskid!r} is not in the task map"))
        return

    for tid, task in sorted(tasks.items(), key=lambda kv: int(kv[0])):
        name = task["task"].get("name") or f"task {tid}"
        loc = f"tasks.{tid}"
        for label, ids in (task.get("nexttasks") or {}).items():
            for nid in ids or []:
                if nid not in tasks:
                    out.append(Finding(CRITICAL, "dangling-edge", loc,
                                       f"{name!r} branch {label!r} points at missing task {nid!r}"))
        if task["type"] == "condition":
            check_condition_branches(tid, task, name, loc, out)
        elif task["type"] != "start" and not successors(task) and command_of(task) != CLOSE_TASK:
            out.append(Finding(HIGH, "dead-end", loc,
                               f"{name!r} has no nexttasks and is not CloseInvestigation — "
                               "the incident stalls here with no analyst signal"))

    reachable, stack = set(), [starttaskid]
    while stack:
        tid = stack.pop()
        if tid in reachable or tid not in tasks:
            continue
        reachable.add(tid)
        stack.extend(successors(tasks[tid]))
    for tid in sorted(set(tasks) - reachable, key=int):
        out.append(Finding(HIGH, "unreachable", f"tasks.{tid}",
                           f"{tasks[tid]['task'].get('name')!r} is never reached from the start task"))

    for cycle in find_cycles(tasks, starttaskid):
        out.append(Finding(CRITICAL, "cycle", "tasks." + cycle[0],
                           "loop with no exit condition: " + " -> ".join(cycle)))


def check_condition_branches(tid, task, name, loc, out):
    """Every declared branch label needs a nexttasks entry, and vice versa."""
    nexttasks = task.get("nexttasks") or {}
    declared = {c["label"] for c in (task.get("conditions") or []) if c.get("label")}
    declared |= set((task.get("message") or {}).get("replyOptions") or [])
    for label in declared - set(nexttasks):
        out.append(Finding(CRITICAL, "unwired-branch", loc,
                           f"{name!r} declares branch {label!r} but has no nexttasks for it — "
                           "matching offenses stop dead"))
    if not nexttasks.get("#default#") and not (task.get("message") or {}).get("replyOptions"):
        out.append(Finding(HIGH, "no-default-branch", loc,
                           f"{name!r} has no '#default#' branch — offenses matching no condition are dropped"))


def find_cycles(tasks, start):
    """DFS for back-edges. Returns each cycle once, as an id list."""
    seen, stack, cycles = set(), [], []

    def walk(tid):
        if tid in stack:
            cycles.append(stack[stack.index(tid):] + [tid])
            return
        if tid in seen or tid not in tasks:
            return
        seen.add(tid)
        stack.append(tid)
        for nid in successors(tasks[tid]):
            walk(nid)
        stack.pop()

    walk(start)
    return cycles


def check_commands(tasks, out):
    """Flag commands, scripts, and sub-playbooks not confirmed on xsoar.pan.dev."""
    for tid, task in sorted(tasks.items(), key=lambda kv: int(kv[0])):
        cmd = command_of(task)
        if not cmd:
            continue
        known = (VERIFIED_COMMANDS if "|||" in cmd else
                 VERIFIED_SUBPLAYBOOKS if cmd.startswith("PB:") else VERIFIED_SCRIPTS)
        key = cmd.split(":", 1)[1] if cmd.startswith(("PB:", "SCRIPT:")) else cmd
        if key in known:
            continue
        if key in KNOWN_CUSTOM:
            out.append(Finding(INFO, "org-custom", f"tasks.{tid}",
                               f"{cmd!r} — {KNOWN_CUSTOM[key]}; not on xsoar.pan.dev by design"))
        else:
            out.append(Finding(MEDIUM, "UNVERIFIED", f"tasks.{tid}",
                               f"{cmd!r} is neither documented on xsoar.pan.dev nor a known org "
                               "integration — confirm with the user that it exists in the tenant"))


def upstream(tid, predecessors):
    """Every task that can run before `tid` on any path. Backward BFS."""
    seen, stack = set(), list(predecessors.get(tid, []))
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(predecessors.get(p, []))
    return seen


def uses_qradar(tasks):
    """True if this playbook actually talks to QRadar.

    Not every playbook is QRadar-sourced. The QRadar-specific conventions
    (closing reason IDs, offense notes, RunAdditionalSeach) only apply when the
    integration is genuinely in use — never bolt them onto a playbook that has
    no QRadar offense behind it.
    """
    return any((command_of(t) or "").startswith("QRadar v3|||") for t in tasks.values())


def check_closure_paths(tasks, out):
    """Audit trail, closing reason ids, and terminal coverage on every closure."""
    close_ids = [t for t in tasks if command_of(tasks[t]) == CLOSE_TASK]
    if not close_ids:
        out.append(Finding(CRITICAL, "no-terminal", "tasks",
                           "no CloseInvestigation task — investigations never close"))

    predecessors = {}
    for tid, task in tasks.items():
        for nid in successors(task):
            predecessors.setdefault(nid, []).append(tid)

    for tid, task in sorted(tasks.items(), key=lambda kv: int(kv[0])):
        if command_of(task) != OFFENSE_UPDATE:
            continue
        args = task.get("scriptarguments") or {}
        reason = (args.get("closing_reason_id") or {}).get("simple")
        if reason is None:
            continue  # a non-closing update (assignment, follow-up) is fine
        if str(reason) not in CLOSING_REASON_IDS:
            out.append(Finding(HIGH, "unknown-close-reason", f"tasks.{tid}",
                               f"closing_reason_id {reason!r} is not one of the org's canonical "
                               f"IDs {sorted(CLOSING_REASON_IDS)}",
                               "https://xsoar.pan.dev/docs/reference/integrations/q-radar-v3"))
        # The rationale may be recorded either as a QRadar offense note or as
        # incident closeNotes, anywhere upstream — not just one hop back.
        if not any(command_of(tasks[p]) in (NOTE_TASK, "Builtin|||setIncident")
                   for p in upstream(tid, predecessors)):
            out.append(Finding(MEDIUM, "close-without-note", f"tasks.{tid}",
                               f"{task['task'].get('name')!r} closes the offense with no "
                               "qradar-offense-note-create or closeNotes anywhere upstream — "
                               "the offense closes with no recorded rationale"))


def check_org_conventions(pb, tasks, out):
    """The two deliberate misspellings and the UUID convention are load-bearing.

    The RunAdditionalSeach input is QRadar-specific and is only required when a
    QRadar log-retrieval branch exists; a non-QRadar playbook must not carry it.
    """
    keys = {i["key"] for i in pb.get("inputs") or []}
    wants_logs = any(command_of(t) == "PB:QRadar - Get Offense Logs" for t in tasks.values())
    if wants_logs and "RunAdditionalSeach" not in keys:
        out.append(Finding(HIGH, "missing-input", "inputs",
                           "'RunAdditionalSeach' input is absent (note the org's deliberate "
                           "misspelling) but 'QRadar - Get Offense Logs' is called — "
                           "the log-retrieval branch will not evaluate"))
    if "RunAdditionalSeach" in keys and not uses_qradar(tasks):
        out.append(Finding(MEDIUM, "unused-input", "inputs",
                           "'RunAdditionalSeach' is defined but this playbook never calls QRadar — "
                           "drop the input rather than carrying dead config from the reference"))
    verdicts = [t for t in tasks.values() if (t.get("message") or {}).get("replyOptions")]
    for task in verdicts:
        opts = task["message"]["replyOptions"]
        if "False Positive" in opts:
            out.append(Finding(HIGH, "verdict-label-drift", "verdict task",
                               "reply option is 'False Positive'; org playbooks use the misspelled "
                               "'Fasle Positive' verbatim — branch labels will not match"))
    for tid, task in sorted(tasks.items(), key=lambda kv: int(kv[0])):
        for field, val in (("taskid", task.get("taskid")), ("task.id", task["task"].get("id"))):
            if not UUID_RE.match(str(val or "")):
                out.append(Finding(MEDIUM, "bad-uuid", f"tasks.{tid}",
                                   f"{field} {val!r} is not a UUID4"))
        if task.get("taskid") != task["task"].get("id"):
            out.append(Finding(MEDIUM, "uuid-mismatch", f"tasks.{tid}",
                               "taskid and task.id differ; XSOAR expects them identical"))
    seen = {}
    for tid, task in tasks.items():
        seen.setdefault(task.get("taskid"), []).append(tid)
    for uuid, ids in seen.items():
        if len(ids) > 1:
            out.append(Finding(CRITICAL, "duplicate-uuid", "tasks." + ids[0],
                               f"UUID {uuid} reused by tasks {sorted(ids, key=int)} — "
                               "XSOAR will drop all but one on import"))


# ponytail: no generic "unused input" scan. Several standard inputs
# (ScaleToSetSeverityFrom, SocEmailAddress, ...) are consumed by the platform or
# inlined literally, so a reference-count check fires on known-good playbooks.
# The targeted RunAdditionalSeach/QRadar check above carries the real signal.


def check_subplaybook_context(tasks, out):
    """Sub-playbooks must isolate context or they overwrite the parent's."""
    for tid, task in sorted(tasks.items(), key=lambda kv: int(kv[0])):
        if task["type"] == "playbook" and not task.get("separatecontext"):
            out.append(Finding(MEDIUM, "shared-context", f"tasks.{tid}",
                               f"sub-playbook {task['task'].get('playbookName')!r} runs with "
                               "separatecontext:false — its outputs pollute the parent context"))


def validate(pb):
    """Run every static check. Returns findings sorted most-severe first."""
    tasks = pb.get("tasks") or {}
    out = []
    if not tasks:
        return [Finding(CRITICAL, "no-tasks", "tasks", "playbook has no tasks")]
    check_graph(tasks, str(pb.get("starttaskid", "0")), out)
    check_commands(tasks, out)
    check_closure_paths(tasks, out)
    check_org_conventions(pb, tasks, out)
    check_subplaybook_context(tasks, out)
    order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, INFO: 3}
    return sorted(out, key=lambda f: (order[f.severity], f.location))


def simulate(pb, scenario, max_steps=500):
    """Walk the graph taking the scenario's chosen branch at each condition.

    Returns (path, error). `error` is None on a clean walk to a terminal task.
    """
    tasks = pb["tasks"]
    branches = scenario.get("branches") or {}
    tid, path = str(pb.get("starttaskid", "0")), []

    # A branch key naming no real task would silently fall through to #default#,
    # making a typo'd scenario "pass" without ever testing its branch.
    names = {t["task"].get("name") for t in tasks.values()} | set(tasks)
    unknown = sorted(k for k in branches if k not in names)
    if unknown:
        return path, (f"scenario names condition(s) {unknown} that match no task in this "
                      "playbook — fix the name, or the branch is never exercised")
    used = set()

    for _ in range(max_steps):
        if tid not in tasks:
            return path, f"task {tid!r} does not exist"
        task = tasks[tid]
        path.append(tid)
        name = task["task"].get("name") or ""
        nexttasks = task.get("nexttasks") or {}

        if not nexttasks:
            if command_of(task) == CLOSE_TASK:
                unused = sorted(set(branches) - used)
                if unused:
                    return path, (f"scenario chose branches for {unused} but the walk never reached "
                                  "those conditions — the intended path was not exercised")
                return path, None
            return path, f"stalled at {name!r} (task {tid}): no nexttasks and not a terminal task"

        if task["type"] == "condition":
            choice = branches.get(name, branches.get(tid))
            used.add(name if name in branches else tid)
            if choice is None:
                label = "#default#"
                if label not in nexttasks:
                    return path, (f"condition {name!r} (task {tid}) has no '#default#' and the "
                                  "scenario picked no branch")
            elif choice not in nexttasks:
                return path, (f"scenario picked branch {choice!r} at {name!r} (task {tid}); "
                              f"available: {sorted(nexttasks)}")
            else:
                label = choice
        else:
            label = next(iter(nexttasks))

        targets = nexttasks[label] or []
        if len(targets) > 1:
            return path, (f"{name!r} (task {tid}) fans out to {targets} — parallel branches race "
                          "on shared context; the simulator will not guess an order")
        if not targets:
            return path, f"branch {label!r} at {name!r} (task {tid}) is empty"
        tid = targets[0]

    return path, f"exceeded {max_steps} steps — probable infinite loop"


def run_scenarios(pb, scenarios):
    """Execute every scenario and print a per-scenario result block."""
    results = []
    for sc in scenarios:
        path, error = simulate(pb, sc)
        expected = sc.get("expected_path")
        if error:
            verdict, reason = "FAIL", error
        elif expected and path != expected:
            verdict, reason = "FAIL", f"path diverged; expected {expected}"
        else:
            verdict, reason = "PASS", ""
        results.append((sc.get("name", "unnamed"), path, expected, verdict, reason))

    for name, path, expected, verdict, reason in results:
        mark = "PASS" if verdict == "PASS" else "FAIL"
        print(f"\n[{mark}] {name}")
        print(f"  expected : {expected if expected else '(not specified)'}")
        print(f"  actual   : {path}")
        if reason:
            print(f"  reason   : {reason}")
    return results


def self_test():
    """Assert the checker actually catches a broken playbook. Run with --self-test."""
    def task(tid, ttype="regular", **kw):
        base = {"id": tid, "taskid": f"0000000{tid}-0000-4000-8000-000000000000",
                "type": ttype, "task": {"id": f"0000000{tid}-0000-4000-8000-000000000000",
                                        "name": f"t{tid}", "type": ttype}}
        base.update(kw)
        return base

    broken = {"starttaskid": "0", "inputs": [], "tasks": {
        "0": task("0", "start", nexttasks={"#none#": ["1"]}),
        "1": task("1", "condition", nexttasks={"yes": ["9"]},
                  conditions=[{"label": "yes"}, {"label": "no"}]),
        "2": task("2"),  # unreachable + dead end
    }}
    codes = {f.code for f in validate(broken)}
    assert "dangling-edge" in codes, codes      # 1 -> 9 does not exist
    assert "unwired-branch" in codes, codes     # branch "no" has no nexttasks
    assert "no-default-branch" in codes, codes
    assert "unreachable" in codes, codes        # task 2
    assert "dead-end" in codes, codes
    assert "no-terminal" in codes, codes
    # No QRadar commands here, so QRadar-specific conventions must NOT be demanded.
    assert "missing-input" not in codes, codes

    # RunAdditionalSeach is only required once the QRadar log sub-playbook is called.
    qradar = {"starttaskid": "0", "inputs": [], "tasks": {
        "0": task("0", "start", nexttasks={"#none#": ["1"]}),
        "1": task("1", "playbook", separatecontext=True, nexttasks={"#none#": ["2"]},
                  task={"id": "00000001-0000-4000-8000-000000000000", "name": "logs",
                        "type": "playbook", "playbookName": "QRadar - Get Offense Logs"}),
        "2": task("2", task={"id": "00000002-0000-4000-8000-000000000000", "name": "close",
                             "type": "regular", "script": CLOSE_TASK}),
    }}
    assert "missing-input" in {f.code for f in validate(qradar)}


    # Reputrack is org-built: known-custom (INFO), not an unverified guess.
    custom = json.loads(json.dumps(qradar))
    custom["tasks"]["2"]["task"]["script"] = "|||reputrack-add-edl-entries"
    codes_custom = {f.code for f in validate(custom)}
    assert "org-custom" in codes_custom and "UNVERIFIED" not in codes_custom, codes_custom

    looping = {"starttaskid": "0", "inputs": [], "tasks": {
        "0": task("0", "start", nexttasks={"#none#": ["1"]}),
        "1": task("1", nexttasks={"#none#": ["0"]}),
    }}
    assert "cycle" in {f.code for f in validate(looping)}

    dupes = {"starttaskid": "0", "inputs": [], "tasks": {
        "0": task("0", "start", nexttasks={"#none#": ["1"]}),
        "1": task("1", nexttasks={"#none#": ["0"]}),
    }}
    dupes["tasks"]["1"]["taskid"] = dupes["tasks"]["0"]["taskid"]
    assert "duplicate-uuid" in {f.code for f in validate(dupes)}

    # A scenario that picks a branch the condition does not have must FAIL, not crash.
    _, err = simulate(broken, {"name": "x", "branches": {"t1": "maybe"}})
    assert err and "available" in err, err

    # A branch key naming no task must FAIL loudly, not fall through and "pass".
    _, err = simulate(broken, {"name": "x", "branches": {"No Such Task": "yes"}})
    assert err and "match no task" in err, err

    print("self-test PASS — validator catches dangling edges, unwired branches, "
          "unreachable tasks, dead ends, cycles, duplicate UUIDs, and bad scenario branches")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("playbook", nargs="?", help="path to the playbook YAML")
    ap.add_argument("-s", "--scenarios", help="JSON file of dry-run scenarios")
    ap.add_argument("--self-test", action="store_true", help="verify the validator itself")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return 0
    if not args.playbook:
        ap.error("playbook path is required (or use --self-test)")

    with open(args.playbook) as fh:
        pb = yaml.safe_load(fh)

    print(f"=== {pb.get('name', args.playbook)} ===")
    print(f"tasks: {len(pb.get('tasks') or {})}   start: {pb.get('starttaskid')}\n")

    print("--- STATIC VALIDATION ---")
    findings = validate(pb)
    for f in findings:
        print(f)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in (CRITICAL, HIGH, MEDIUM)}
    if not findings:
        print("no findings")
    print(f"\n{len(findings)} finding(s): "
          f"{counts[CRITICAL]} critical, {counts[HIGH]} high, {counts[MEDIUM]} medium")

    failed = 0
    if args.scenarios:
        with open(args.scenarios) as fh:
            scenarios = json.load(fh)
        print("\n--- DRY-RUN SIMULATION ---")
        results = run_scenarios(pb, scenarios)
        failed = sum(1 for r in results if r[3] == "FAIL")
        print(f"\n{len(results)} scenario(s): {len(results) - failed} passed, {failed} failed")

    print("\nLogic validation only — not a substitute for testing in a live XSOAR tenant.")
    return 1 if (counts[CRITICAL] or failed) else 0


if __name__ == "__main__":
    sys.exit(main())
