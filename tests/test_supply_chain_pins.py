# In plain English: tests for the last links of the software supply chain: the base image under our code, the
# GitHub Actions that run our checks, the robot that proposes updates (Dependabot) and the scanner that
# looks inside the built image for known security flaws.
#
# Why it matters (OWASP A03): a name like "python:3.12-slim" or "actions/checkout@v4" is only a label, and
# whoever controls the label can change what it points to (this really happened to the Trivy GitHub Action
# in March 2026, when its version tags were rewritten to point at code that stole secrets). A digest or a
# commit number cannot be moved, so we pin to those, let Dependabot propose updates when we want them, and
# scan the finished image so flaws in the system packages under our code do not go unseen.
#
# These tests only read files, so they need no network.
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
DOCKERFILES = [path for path in (ROOT / "Dockerfile", ROOT / "ci" / "scanner" / "Dockerfile") if path.exists()]
HAS_IMAGE = (ROOT / "Dockerfile").exists()
LOCKS = list(ROOT.glob("requirements*.txt"))


def need_image():
    if not HAS_IMAGE:
        pytest.skip("this repo builds no image")


# ---------- Pinned images and pinned Actions ----------

@pytest.mark.owasp("A03", 1357)
def test_every_base_image_is_pinned_by_digest_and_keeps_a_readable_version():
    need_image()
    froms = []
    for dockerfile in DOCKERFILES:
        for line in dockerfile.read_text(encoding="utf-8").splitlines():
            if line.strip().upper().startswith("FROM "):
                froms.append((dockerfile.name, line.strip()))
    assert froms
    for name, line in froms:
        image = [part for part in line.split()[1:] if not part.startswith("--")][0]
        assert re.fullmatch(r"[A-Za-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}", image), f"{name}: {line}"
        assert ":latest@" not in image, f"{name}: {line}"


@pytest.mark.owasp("A03", 1357)
def test_every_github_action_is_pinned_to_a_commit_with_its_version_in_a_comment():
    found = 0
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            match = re.match(r"^\s*-?\s*uses:\s*(\S+)(?:\s+#\s*(.*))?$", line)
            if not match:
                continue
            found += 1
            where = f"{workflow.name}:{number}: {line.strip()}"
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", match.group(1)), where
            assert match.group(2) and re.match(r"v\d+\.\d+\.\d+", match.group(2)), f"{where} (the version must follow in a comment)"
    assert found, "no workflow uses an action, so there was nothing to check"


# ---------- Dependabot proposes updates ----------

def dependabot():
    path = ROOT / ".github" / "dependabot.yml"
    assert path.exists(), ".github/dependabot.yml is missing"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.owasp("A03", 1104, 1329)
def test_dependabot_is_set_up_for_every_kind_of_dependency_this_repo_has():
    document = dependabot()
    assert document["version"] == 2
    entries = document["updates"]
    wanted = {("github-actions", "/")}
    if LOCKS:
        wanted.add(("pip", "/"))
    for dockerfile in DOCKERFILES:
        folder = "/" + dockerfile.parent.relative_to(ROOT).as_posix().strip(".")
        wanted.add(("docker", folder.rstrip("/") or "/"))
    have = {(entry["package-ecosystem"], entry["directory"]) for entry in entries}
    assert wanted <= have, f"missing: {sorted(wanted - have)}"


@pytest.mark.owasp("A03", 1104, 1329)
def test_dependabot_checks_often_and_is_never_switched_off_or_told_to_ignore_everything():
    for entry in dependabot()["updates"]:
        label = f"{entry['package-ecosystem']} {entry['directory']}"
        assert entry["schedule"]["interval"] in ("daily", "weekly"), label
        assert entry.get("open-pull-requests-limit", 5) > 0, label
        for rule in entry.get("ignore", []):
            assert rule.get("dependency-name") not in ("*", None), f"{label} ignores everything"
            assert "update-types" in rule or "versions" in rule, f"{label} ignores a dependency completely"


@pytest.mark.owasp("A03", 1104, 1329)
def test_every_directory_dependabot_watches_exists():
    for entry in dependabot()["updates"]:
        assert (ROOT / entry["directory"].lstrip("/")).is_dir(), entry["directory"]


# ---------- The image scan ----------

def scan_workflow():
    need_image()
    path = WORKFLOWS / "image-scan.yml"
    assert path.exists(), "the image-scan workflow is missing"
    text = path.read_text(encoding="utf-8")
    return text, yaml.safe_load(text)


def run_steps(document):
    return [step for job in document["jobs"].values() for step in job["steps"] if "run" in step]


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_image_is_scanned_on_every_pull_request_on_main_and_every_week():
    _, document = scan_workflow()
    triggers = document.get(True) or document.get("on")
    assert {"pull_request", "push", "schedule"} <= set(triggers), triggers
    assert triggers["schedule"] and all(len(entry["cron"].split()) == 5 for entry in triggers["schedule"])


# ---------- Workflows use only allowed building blocks, and the scan workflows have exactly the steps below ----------

# In plain English: a workflow can only be made to pass without checking by using something extra: a step switched off by a condition,
# an error told to be ignored, a command that swallows its own failure. So instead of hunting for those tricks, a workflow may use ONLY
# the building blocks listed here, and the two scan workflows must consist of EXACTLY the steps listed here, word for word. Changing
# either means changing this file in the same pull request, which someone reads.
ALLOWED_ACTIONS = {"actions/checkout", "actions/setup-python"}
ALLOWED_TOP_KEYS = {"name", True, "permissions", "jobs"}  # YAML reads a bare "on" as True
ALLOWED_JOB_KEYS = {"runs-on", "steps", "env"}
ALLOWED_STEP_KEYS = {"name", "uses", "with", "run", "env", "if"}
# A step may carry a condition only if it is one of these exact steps: showing a log after a failure, or cleaning up. Never a real check.
ALLOWED_CONDITIONAL_STEPS = {
    ("failure()", "docker logs image-test"),
    ("always()", "docker rm -f image-test"),
}
ALLOWED_PERMISSIONS = {"contents": "read"}

CANARY_RUN = """\
status=0
docker run --rm -v "$PWD/ci/canary:/canary:ro" image-scanner:ci sbom:/canary/sbom.json --fail-on high || status=$?
if [ "$status" -ne 2 ]; then
  echo "The scanner did not flag a known-vulnerable library (exit code $status), so its results cannot be trusted." >&2
  exit 1
fi"""
SCAN_RUN = 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/.grype.yaml:/config/.grype.yaml:ro" image-scanner:ci -c /config/.grype.yaml docker:service-under-scan:ci --fail-on high --only-fixed'
AUDIT_RUN = "pip-audit --require-hashes --disable-pip --strict -r {lock}"
EXPECTED_STEPS = {
    "image-scan.yml": {
        "scan": [
            ("uses", "actions/checkout", {}),
            ("run", "docker build -t service-under-scan:ci ."),
            ("run", "docker build -t image-scanner:ci ci/scanner"),
            ("run", CANARY_RUN),
            ("run", SCAN_RUN),
        ]
    },
    "dependency-audit.yml": {
        "audit": [
            ("uses", "actions/checkout", {}),
            ("uses", "actions/setup-python", {"python-version": "3.12"}),
            ("run", "pip install --require-hashes --no-deps -r requirements-audit.txt"),
            ("run", AUDIT_RUN.format(lock="requirements.txt")),
            ("run", AUDIT_RUN.format(lock="requirements-dev.txt")),
            ("run", AUDIT_RUN.format(lock="requirements-audit.txt")),
        ]
    },
}


# In plain English: what is wrong with one workflow's keys, as plain sentences. Anything not in the allowed lists is a problem.
def workflow_shape_problems(document):
    problems = [f"top-level key '{key}'" for key in document if key not in ALLOWED_TOP_KEYS]
    if document.get("permissions") != ALLOWED_PERMISSIONS:
        problems.append(f"permissions {document.get('permissions')!r}")
    for job_name, job in document["jobs"].items():
        problems += [f"job '{job_name}' key '{key}'" for key in job if key not in ALLOWED_JOB_KEYS]
        for number, step in enumerate(job["steps"], 1):
            where = f"job '{job_name}' step {number}"
            problems += [f"{where} key '{key}'" for key in step if key not in ALLOWED_STEP_KEYS]
            if "if" in step and (step["if"], step.get("run", "").strip()) not in ALLOWED_CONDITIONAL_STEPS:
                problems.append(f"{where} has the condition {step['if']!r}, which only the listed log and clean-up steps may have")
            if ("uses" in step) == ("run" in step):
                problems.append(f"{where} must use exactly one of 'uses' and 'run'")
            if "uses" in step:
                action, _, pin = step["uses"].partition("@")
                if action not in ALLOWED_ACTIONS:
                    problems.append(f"{where} uses the action '{action}'")
    return problems


def outline_of(step):
    if "uses" in step:
        return ("uses", step["uses"].split("@")[0], step.get("with", {}))
    return ("run", step["run"].strip())


# In plain English: how a workflow's steps differ from the exact steps it must have, as plain sentences.
def step_problems(document, expected_jobs):
    if set(document["jobs"]) != set(expected_jobs):
        return [f"the jobs are {sorted(document['jobs'])}, expected {sorted(expected_jobs)}"]
    problems = []
    for job_name, expected in expected_jobs.items():
        actual = [outline_of(step) for step in document["jobs"][job_name]["steps"]]
        if actual != expected:
            problems.append(f"job '{job_name}' does not have exactly the expected steps")
    return problems


@pytest.mark.owasp("A03", 1035, 1395)
def test_every_workflow_uses_only_allowed_building_blocks():
    found = 0
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        found += 1
        assert workflow_shape_problems(yaml.safe_load(workflow.read_text(encoding="utf-8"))) == [], workflow.name
    assert found


@pytest.mark.owasp("A03", 1035, 1395)
@pytest.mark.parametrize("name", sorted(EXPECTED_STEPS))
def test_the_scan_workflows_have_exactly_the_expected_steps(name):
    path = WORKFLOWS / name
    if name == "image-scan.yml":
        need_image()
    assert path.exists(), f"{name} is missing"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert step_problems(document, EXPECTED_STEPS[name]) == []
    assert workflow_shape_problems(document) == []
    for job in document["jobs"].values():
        assert not any("if" in step for step in job["steps"]), "a scan step may never be switched off by a condition"


def scan_document():
    return yaml.safe_load("""\
name: x
on: {pull_request: null}
permissions: {contents: read}
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - run: echo hello
""")


def with_step(document, **step):
    document["jobs"]["scan"]["steps"].append(step)
    return document


BAD_WORKFLOWS = {
    "an error told to be ignored on a step": lambda d: with_step(d, run="echo x", **{"continue-on-error": True}),
    "an error told to be ignored on a job": lambda d: d["jobs"]["scan"].update({"continue-on-error": True}) or d,
    "a step switched off by a condition": lambda d: with_step(d, run="echo x", **{"if": "false"}),
    "a step that only runs on failure": lambda d: with_step(d, run="echo x", **{"if": "failure()"}),
    "a real check that only runs on failure": lambda d: with_step(d, run="docker run image-scanner:ci --fail-on high", **{"if": "failure()"}),
    "a listed step with another condition": lambda d: with_step(d, run="docker logs image-test", **{"if": "always()"}),
    "a listed condition on another step": lambda d: with_step(d, run="docker rm -f other", **{"if": "always()"}),
    "an action nobody listed": lambda d: with_step(d, uses="evil/action@" + "0" * 40),
    "an action from a workflow": lambda d: with_step(d, uses="./.github/actions/local"),
    "a step with neither uses nor run": lambda d: with_step(d, name="empty"),
    "a step with both uses and run": lambda d: with_step(d, uses="actions/checkout@" + "0" * 40, run="echo x"),
    "a step key nobody listed": lambda d: with_step(d, run="echo x", shell="bash"),
    "a job key nobody listed": lambda d: d["jobs"]["scan"].update({"timeout-minutes": 1}) or d,
    "a job that needs a secret environment": lambda d: d["jobs"]["scan"].update({"container": "x"}) or d,
    "a top-level key nobody listed": lambda d: d.update({"env": {"A": "b"}}) or d,
    "wider permissions": lambda d: d.update({"permissions": {"contents": "write"}}) or d,
    "extra permissions": lambda d: d.update({"permissions": {"contents": "read", "packages": "write"}}) or d,
    "no permissions at all": lambda d: d.pop("permissions") and d,
}


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_good_workflow_passes_the_shape_check():
    assert workflow_shape_problems(scan_document()) == []
    assert workflow_shape_problems(with_step(scan_document(), run="docker rm -f image-test", **{"if": "always()"})) == []
    assert workflow_shape_problems(with_step(scan_document(), run="docker logs image-test", **{"if": "failure()"})) == []


@pytest.mark.owasp("A03", 1035, 1395)
@pytest.mark.parametrize("label", sorted(BAD_WORKFLOWS))
def test_every_bad_workflow_is_refused_by_the_shape_check(label):
    assert workflow_shape_problems(BAD_WORKFLOWS[label](scan_document())) != [], label


def expected_scan_document():
    return {"jobs": {"scan": {"steps": [
        {"uses": "actions/checkout@" + "0" * 40},
        {"run": "docker build -t service-under-scan:ci ."},
        {"run": "docker build -t image-scanner:ci ci/scanner"},
        {"run": CANARY_RUN},
        {"run": SCAN_RUN},
    ]}}}


BAD_STEP_CHANGES = {
    "the scan made to pass whatever it finds": lambda s: s[4].update(run=s[4]["run"] + " || true"),
    "the scan no longer fails on high flaws": lambda s: s[4].update(run=s[4]["run"].replace("--fail-on high", "--fail-on none")),
    "the scan no longer fails on high flaws, another way": lambda s: s[4].update(run=s[4]["run"].replace("--fail-on high", "--fail-on critical")),
    "the scan told to ignore everything": lambda s: s[4].update(run=s[4]["run"] + " --ignore-states fixed"),
    "the scan followed by a command that succeeds": lambda s: s[4].update(run=s[4]["run"] + "; exit 0"),
    "the scan run with errors allowed": lambda s: s[4].update(run="set +e\n" + s[4]["run"]),
    "the canary no longer insists on the exit code": lambda s: s[3].update(run=s[3]["run"].replace("-ne 2", "-ne 0")),
    "the canary swallowed": lambda s: s[3].update(run=s[3]["run"] + " || true"),
    "the scanner image replaced": lambda s: s[2].update(run="docker pull evil/scanner"),
    "a step removed": lambda s: s.pop(3),
    "a step added": lambda s: s.append({"run": "echo done"}),
    "the steps reordered": lambda s: s.reverse(),
    "the checked image changed": lambda s: s[1].update(run="docker build -t service-under-scan:ci other"),
}


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_expected_steps_match_the_good_document():
    assert step_problems(expected_scan_document(), EXPECTED_STEPS["image-scan.yml"]) == []


@pytest.mark.owasp("A03", 1035, 1395)
def test_an_extra_job_or_a_missing_job_is_refused():
    extra = expected_scan_document()
    extra["jobs"]["other"] = {"steps": [{"run": "echo done"}]}
    assert step_problems(extra, EXPECTED_STEPS["image-scan.yml"]) != []
    assert step_problems({"jobs": {}}, EXPECTED_STEPS["image-scan.yml"]) != []


@pytest.mark.owasp("A03", 1035, 1395)
@pytest.mark.parametrize("label", sorted(BAD_STEP_CHANGES))
def test_every_change_to_the_scan_steps_is_refused(label):
    document = expected_scan_document()
    BAD_STEP_CHANGES[label](document["jobs"]["scan"]["steps"])
    assert step_problems(document, EXPECTED_STEPS["image-scan.yml"]) != [], label


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_canary_list_names_a_known_vulnerable_library():
    # A scanner whose flaw database is out of date keeps exiting with success while missing new flaws. So every run first scans a
    # tiny list that names a known-vulnerable library and must see it fail (the exact canary step is pinned above).
    need_image()
    sbom = (ROOT / "ci" / "canary" / "sbom.json").read_text(encoding="utf-8")
    assert "pkg:pypi/urllib3@1.26.4" in sbom


@pytest.mark.owasp("A03", 1035, 1395)
def test_the_scanner_is_a_pinned_image_that_dependabot_keeps_current():
    need_image()
    scanner = (ROOT / "ci" / "scanner" / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^FROM anchore/grype:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}\s*$", scanner, re.M), scanner
    assert ("docker", "/ci/scanner") in {(entry["package-ecosystem"], entry["directory"]) for entry in dependabot()["updates"]}


@pytest.mark.owasp("A03", 1035, 1395)
def test_every_exception_to_the_scan_names_one_flaw_and_gives_a_reason_and_a_date():
    need_image()
    config = ROOT / ".grype.yaml"
    assert config.exists(), ".grype.yaml is missing"
    lines = config.read_text(encoding="utf-8").splitlines()
    document = yaml.safe_load("\n".join(lines)) or {}
    ignores = document.get("ignore") or []
    for index, line in enumerate(lines):
        if re.match(r"^\s*-\s*vulnerability:", line):
            above = " ".join(lines[max(0, index - 3):index])
            assert re.search(r"\d{4}-\d{2}-\d{2}", above) and "#" in above, f"exception without a dated reason: {line.strip()}"
    for rule in ignores:
        assert re.fullmatch(r"(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3}|DSA-[\w-]+)", str(rule.get("vulnerability", ""))), rule
        assert set(rule) <= {"vulnerability", "package", "fix-state"}, rule
