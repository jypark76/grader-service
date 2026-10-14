# In plain English: these tests check the Kubernetes files BEFORE they reach a
# cluster. They build the final files for the laptop settings (the same thing
# "deploy.sh --preview" shows) and check them against a short list of rules, each
# one written because of something that went wrong or that we decided.
#
# A checker that never complains proves nothing, so the second half of the file
# feeds the checker deliberately broken files and confirms it complains about each
# one. Those self-tests need no Kubernetes tools and always run.
import copy
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
OVERLAY = ROOT / "k8s" / "overlays" / "local"
DEPLOY_SCRIPT = ROOT / "k8s" / "deploy.sh"

NAMESPACE = "grader"

# Kinds that do not live inside a namespace.
CLUSTER_WIDE = {"Namespace"}

# Kinds that run containers. Every rule about pods applies to all of them, so the
# one-time migration job cannot dodge a rule that the service has to follow.
WORKLOADS = {"Deployment", "Job"}

# The pods that must run locked down: a normal user, no extra privileges.
LOCKED_DOWN = {"grader-service", "grader-worker"}

# Things the pods point at that are NOT in the rendered files on purpose: the Secret with the grader's key for the knowledge
# service is created by hand and never stored in the repo.
MADE_OUTSIDE = {("Secret", "knowledge-lookup-key")}


# In plain English: builds the final Kubernetes files for the laptop settings and
# returns them as a list of Python dictionaries, one per object.
def render_overlay():
    result = subprocess.run(
        ["kubectl", "kustomize", str(OVERLAY)],
        capture_output=True,
        text=True,
        check=True,
    )
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


# In plain English: gives every container in a Deployment, whatever its name.
def containers_of(deployment):
    return deployment["spec"]["template"]["spec"].get("containers", [])


# In plain English: checks that a secret reaches a container as a mounted FILE and not as an environment variable.
# "setting" is the name the code uses (for example DB_PASSWORD). The container must have no setting by that name,
# must have SETTING_FILE pointing into /etc/secrets, and that path must be a read-only mount of exactly the named
# Secret and key.
def assert_secret_file(docs, container, setting, secret_name, key):
    env = {item["name"]: item for item in container.get("env", [])}
    assert setting not in env, f"{setting} must not be an environment variable"
    file_setting = env[f"{setting}_FILE"]
    assert "valueFrom" not in file_setting
    path = file_setting["value"]
    folder, _, file_name = path.rpartition("/")
    assert path.startswith("/etc/secrets/") and file_name == key, path
    owner = next(d for d in docs if d["kind"] in ("Deployment", "Job", "StatefulSet") and any(c is container for c in containers_of(d)))
    volumes = {volume["name"]: volume for volume in owner["spec"]["template"]["spec"].get("volumes", [])}
    mount = next(m for m in container["volumeMounts"] if m["mountPath"] == folder)
    assert mount.get("readOnly") is True
    secret = volumes[mount["name"]]["secret"]
    assert secret["secretName"] == secret_name
    assert secret["items"] == [{"key": key, "path": key}]


# In plain English: lists every ConfigMap and Secret that a Deployment points at,
# as (kind, name) pairs. It looks in all the places a pod can point at one:
# settings, settings from a whole ConfigMap, and mounted folders.
def references_of(deployment):
    found = set()
    pod = deployment["spec"]["template"]["spec"]
    for container in pod.get("containers", []):
        for env in container.get("env", []):
            source = env.get("valueFrom", {})
            if "secretKeyRef" in source:
                found.add(("Secret", source["secretKeyRef"]["name"]))
            if "configMapKeyRef" in source:
                found.add(("ConfigMap", source["configMapKeyRef"]["name"]))
        for entry in container.get("envFrom", []):
            if "configMapRef" in entry:
                found.add(("ConfigMap", entry["configMapRef"]["name"]))
            if "secretRef" in entry:
                found.add(("Secret", entry["secretRef"]["name"]))
    for volume in pod.get("volumes", []):
        if "configMap" in volume:
            found.add(("ConfigMap", volume["configMap"]["name"]))
        if "secret" in volume:
            found.add(("Secret", volume["secret"]["secretName"]))
        for source in volume.get("projected", {}).get("sources", []):
            if "configMap" in source:
                found.add(("ConfigMap", source["configMap"]["name"]))
            if "secret" in source:
                found.add(("Secret", source["secret"]["name"]))
    return found


# In plain English: the checker. It takes the list of Kubernetes objects and
# returns a list of plain sentences, one per rule that is broken. An empty list
# means every rule holds.
def find_problems(docs):
    problems = []
    defined = {(doc["kind"], doc["metadata"]["name"]) for doc in docs}

    for doc in docs:
        kind = doc["kind"]
        name = doc["metadata"]["name"]
        label = f"{kind}/{name}"

        # Rule 1: everything except the Namespace itself sits in our namespace.
        # A generated ConfigMap once had none and landed in the wrong room.
        if kind not in CLUSTER_WIDE and doc["metadata"].get("namespace") != NAMESPACE:
            problems.append(f"{label}: missing namespace '{NAMESPACE}'")

        # (A Secret in the repo, a Service that is not ClusterIP and a password written into a file are not checked here: the kinds and
        # settings allowed are listed in tests/allowed_paths.py, and anything else fails tests/test_allowed_manifests.py.)

        if kind not in WORKLOADS:
            continue

        for container in containers_of(doc):
            image = container.get("image", "")
            last_part = image.split("/")[-1]

            # Rule 3: a fixed version tag. Only a tag that starts with a digit is a version, so "latest", "stable" and no tag at all fail.
            name_and_tag = last_part.split("@")[0]
            if ":" not in name_and_tag:
                problems.append(f"{label}: image '{image}' has no version tag")
            elif not re.fullmatch(r"[0-9][A-Za-z0-9._-]*", name_and_tag.split(":", 1)[1]):
                problems.append(f"{label}: image '{image}' must have a fixed version tag, which starts with a digit")

            # Rule 6: a memory limit, so one pod cannot eat the whole machine.
            if not container.get("resources", {}).get("limits", {}).get("memory"):
                problems.append(f"{label}: container '{container['name']}' has no memory limit")

        # Rule 7: every ConfigMap or Secret a pod points at must exist in the
        # files, or be one of the few things made outside them on purpose.
        for reference in sorted(references_of(doc)):
            if reference not in defined and reference not in MADE_OUTSIDE:
                problems.append(f"{label}: points at {reference[0]} '{reference[1]}', which does not exist")

        # Rule 4: the service pod and the migration job are locked down.
        if name in LOCKED_DOWN:
            pod = doc["spec"]["template"]["spec"]
            pod_security = pod.get("securityContext", {})
            if pod_security.get("runAsNonRoot") is not True:
                problems.append(f"{label}: runAsNonRoot must be true")
            run_as = pod_security.get("runAsUser")
            if not isinstance(run_as, int) or run_as == 0:
                problems.append(f"{label}: runAsUser must be a non-zero number")
            for container in pod.get("containers", []):
                security = container.get("securityContext", {})
                if security.get("allowPrivilegeEscalation") is not False:
                    problems.append(f"{label}: allowPrivilegeEscalation must be false")
                if "ALL" not in security.get("capabilities", {}).get("drop", []):
                    problems.append(f"{label}: capabilities must drop ALL")

    return problems


# ---------------------------------------------------------------------------
# Tests on the REAL files. These need the kubectl tool.
# ---------------------------------------------------------------------------


# In plain English: skips when kubectl is not installed, so a normal run on a
# computer without it still works. In the pipeline REQUIRE_KUBECTL=1 is set, and
# then a missing kubectl is a failure, because a skipped check proves nothing.
@pytest.fixture
def real_docs():
    if shutil.which("kubectl") is None:
        if os.environ.get("REQUIRE_KUBECTL") == "1":
            pytest.fail("REQUIRE_KUBECTL is set but kubectl was not found")
        pytest.skip("kubectl is not installed")
    return render_overlay()


# In plain English: the real laptop files must break none of the rules. It also
# checks the render really produced our objects, so an empty result can never pass.
def test_real_overlay_breaks_no_rules(real_docs):
    kinds = {(doc["kind"], doc["metadata"]["name"]) for doc in real_docs}
    assert ("Deployment", "grader-service") in kinds
    assert ("Service", "grader-service") in kinds
    assert ("Deployment", "grader-worker") in kinds
    assert ("ConfigMap", "grader-service-config") in kinds
    assert ("Namespace", "grader") in kinds
    assert find_problems(real_docs) == []


# In plain English: the deploy script may run ONLY these kubectl commands, word for word, and may send output nowhere except to the error
# stream. So it cannot create or read a Secret, delete anything, or hide an error by sending it to the "bit bucket". Anything else needs
# a change to this list in a pull request that someone reads.
ALLOWED_KUBECTL = {
    "kubectl config current-context",
    'kubectl kustomize "$here/overlays/$overlay"',
    'kubectl apply -f "$here/base/namespace.yaml"',
    "kubectl get secret knowledge-lookup-key -n grader --ignore-not-found -o name",
    'kubectl apply -k "$here/overlays/$overlay"',
}
ALLOWED_REDIRECTS = {">&2"}


# In plain English: the kubectl commands a script runs (not the ones it only prints in a message), and every place it sends output.
def script_commands(text):
    commands, redirects = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("echo "):
            if line.startswith("echo "):
                redirects += re.findall(r"[0-9]*>+&?[0-9]*[^\s\"']*", line.rsplit('"', 1)[-1])
            continue
        if "kubectl" in line:
            command = line[line.index("kubectl"):]
            command = re.sub(r'\)"?$', "", command)
            commands.append(command)
        redirects += re.findall(r"[0-9]*>+&?[0-9]*[^\s\"']*", line)
    return commands, redirects


def script_problems(text):
    commands, redirects = script_commands(text)
    problems = [f"runs '{command}'" for command in commands if command not in ALLOWED_KUBECTL]
    problems += [f"sends output to '{redirect}'" for redirect in redirects if redirect not in ALLOWED_REDIRECTS]
    return problems


def test_the_deploy_script_runs_only_the_listed_kubectl_commands_and_hides_no_errors():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert script_problems(text) == []
    commands, redirects = script_commands(text)
    assert set(commands) == ALLOWED_KUBECTL  # a listed command nothing runs is a stale allowance
    assert redirects, "the script reports its refusals on the error stream"


BAD_SCRIPT_LINES = {
    "creating a Secret": "kubectl create secret generic x -n grader --from-literal=key=1",
    "reading a Secret": "kubectl get secret knowledge-lookup-key -n grader -o yaml",
    "deleting something": "kubectl delete namespace grader",
    "applying a file from elsewhere": "kubectl apply -f https://example.com/x.yaml",
    "applying with a Secret from stdin": "kubectl apply -f - <<< \"$secret\"",
    "an error sent to the bit bucket": "kubectl get secret knowledge-lookup-key -n grader --ignore-not-found -o name 2>/dev/null",
    "output sent to a file": "kubectl kustomize \"$here/overlays/$overlay\" > /tmp/out.yaml",
    "a message sent to the bit bucket": "echo \"x\" 2>/dev/null",
    "a message sent to the bit bucket another way": "echo \"x\" &>/dev/null",
    "an error sent to a file": "echo \"x\" 2>>/tmp/errors.txt",
    "a command that fails quietly": "kubectl config current-context || true",
    "a command run by another name": "k=kubectl; $k delete pods --all",
    "a command with another flag": "kubectl apply -k \"$here/overlays/$overlay\" --force",
}


@pytest.mark.parametrize("label", sorted(BAD_SCRIPT_LINES))
def test_every_other_deploy_script_command_is_refused(label):
    good = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert script_problems(good + "\n" + BAD_SCRIPT_LINES[label] + "\n") != [], label


# ---------------------------------------------------------------------------
# Self-tests: the checker must complain about broken files. No kubectl needed.
# ---------------------------------------------------------------------------


# In plain English: a small set of Kubernetes objects that breaks no rule. Each
# self-test copies it and breaks exactly one thing.
def good_docs():
    return [
        {"kind": "Namespace", "metadata": {"name": NAMESPACE}},
        {
            "kind": "ConfigMap",
            "metadata": {"name": "settings", "namespace": NAMESPACE},
            "data": {"MODE": "plain"},
        },
        {
            "kind": "Service",
            "metadata": {"name": "grader-service", "namespace": NAMESPACE},
            "spec": {"ports": [{"port": 8000}]},
        },
        {
            "kind": "Deployment",
            "metadata": {"name": "grader-service", "namespace": NAMESPACE},
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
                        "containers": [
                            {
                                "name": "grader-service",
                                "image": "grader-service:0.4.0",
                                "envFrom": [{"configMapRef": {"name": "settings"}}],
                                "env": [],
                                "resources": {"limits": {"memory": "256Mi"}},
                                "securityContext": {
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"]},
                                },
                            }
                        ],
                    }
                }
            },
        },
    ]


# In plain English: the control. Before trusting any "broken" case, the good
# files must come back clean, or a complaint could mean anything.
def test_good_files_come_back_clean():
    assert find_problems(good_docs()) == []


def deployment_of(docs):
    return next(doc for doc in docs if doc["kind"] == "Deployment")


def test_catches_a_missing_namespace():
    docs = good_docs()
    del docs[1]["metadata"]["namespace"]
    assert any("missing namespace" in problem for problem in find_problems(docs))


def test_catches_a_tag_that_is_not_a_version():
    for tag in ("stable", "main", "v1", "latest-1", "x1"):
        docs = good_docs()
        containers_of(deployment_of(docs))[0]["image"] = f"grader-service:{tag}"
        assert any("fixed version tag" in problem for problem in find_problems(docs)), tag


def test_accepts_a_version_tag_and_a_digest_pinned_one():
    for image in ("grader-service:0.4.0", "apache/kafka:3.9.0@sha256:" + "a" * 64, "grader-service:1"):
        docs = good_docs()
        containers_of(deployment_of(docs))[0]["image"] = image
        assert find_problems(docs) == [], image


def test_catches_the_latest_tag():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["image"] = "grader-service:latest"
    assert any("latest" in problem for problem in find_problems(docs))


def test_catches_a_missing_tag():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["image"] = "grader-service"
    assert any("no version tag" in problem for problem in find_problems(docs))


def test_catches_a_missing_memory_limit():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["resources"] = {}
    assert any("memory limit" in problem for problem in find_problems(docs))


def test_catches_a_pointer_to_something_that_does_not_exist():
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["envFrom"] = [{"configMapRef": {"name": "no-such-settings"}}]
    assert any("does not exist" in problem for problem in find_problems(docs))


def test_catches_a_name_mismatch_in_a_mounted_folder():
    docs = good_docs()
    pod = deployment_of(docs)["spec"]["template"]["spec"]
    pod["volumes"] = [{"name": "scripts", "projected": {"sources": [{"configMap": {"name": "scripts-1a2b3c"}}]}}]
    assert any("scripts-1a2b3c" in problem for problem in find_problems(docs))


@pytest.mark.owasp("A01", 276, 732)
def test_catches_a_pod_that_may_run_as_root():
    docs = good_docs()
    deployment_of(docs)["spec"]["template"]["spec"]["securityContext"] = {}
    problems = find_problems(docs)
    assert any("runAsNonRoot" in problem for problem in problems)
    assert any("runAsUser" in problem for problem in problems)


@pytest.mark.owasp("A01", 276, 732)
def test_catches_privilege_escalation_and_kept_capabilities():
    docs = good_docs()
    security = containers_of(deployment_of(docs))[0]["securityContext"]
    security["allowPrivilegeEscalation"] = True
    security["capabilities"] = {"drop": []}
    problems = find_problems(docs)
    assert any("allowPrivilegeEscalation" in problem for problem in problems)
    assert any("drop ALL" in problem for problem in problems)


# In plain English: a thing made outside the files on purpose (the hand-made
# Secret) must NOT be reported, or the checker would cry wolf on a healthy setup.
def test_allows_the_things_made_outside_on_purpose(monkeypatch):
    # The grader has no such things yet; this proves the allowance works for the day one is added on purpose.
    docs = good_docs()
    containers_of(deployment_of(docs))[0]["env"] = [
        {"name": "THING", "valueFrom": {"secretKeyRef": {"name": "thing-secret", "key": "value"}}}
    ]
    assert ("Secret", "thing-secret") in references_of(deployment_of(docs))
    assert any("thing-secret" in problem for problem in find_problems(docs))
    monkeypatch.setattr(sys.modules[__name__], "MADE_OUTSIDE", {("Secret", "thing-secret")})
    assert find_problems(docs) == []


# In plain English: the worker is its own Deployment from the SAME image as the web side, started with the worker
# command, and it is held to every pod rule (it is in LOCKED_DOWN). Its only settings come from the ConfigMap, and it
# holds no secret, so no password or key can sit in its environment.
def test_the_worker_runs_the_worker_code_from_the_same_image(real_docs):
    worker = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "grader-worker")
    service = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "grader-service")
    container = containers_of(worker)[0]
    assert container["image"] == containers_of(service)[0]["image"]
    assert container["command"] == ["python", "-m", "app.worker"]
    assert container["envFrom"] == [{"configMapRef": {"name": "grader-service-config"}}]
    assert references_of(worker) == {("ConfigMap", "grader-service-config"), ("Secret", "knowledge-lookup-key")}


# In plain English: the grader's key for the knowledge service reaches the worker as a read-only mounted file (never an
# environment variable), from exactly the named Secret and key, and the address of the knowledge service is a plain setting.
@pytest.mark.owasp("A02", 526)
@pytest.mark.owasp("A07", 798)
def test_the_lookup_key_is_a_mounted_file_and_the_address_is_a_setting(real_docs):
    worker = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "grader-worker")
    assert_secret_file(real_docs, containers_of(worker)[0], "KNOWLEDGE_KEY", "knowledge-lookup-key", "key")
    config = next(d for d in real_docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "grader-service-config")
    assert config["data"]["KNOWLEDGE_URL"] == "http://knowledge-service.knowledge.svc.cluster.local:8000"
    assert "KNOWLEDGE_KEY" not in config["data"]
    web = next(d for d in real_docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "grader-service")
    assert not any(("secret" in volume) for volume in web["spec"]["template"]["spec"].get("volumes", []))


# In plain English: the deploy script checks the key Secret exists and tells you the command if not. It never creates one.
def test_the_deploy_script_checks_the_lookup_key_and_never_creates_it():
    lines = [line.strip() for line in DEPLOY_SCRIPT.read_text(encoding="utf-8").splitlines()]
    assert any(line.startswith("key_secret=") and "get secret knowledge-lookup-key" in line for line in lines)
    assert not any(line.startswith("kubectl create secret") or line.startswith("kubectl apply -f - ") for line in lines)


def test_the_worker_is_held_to_the_pod_rules():
    assert "grader-worker" in LOCKED_DOWN
