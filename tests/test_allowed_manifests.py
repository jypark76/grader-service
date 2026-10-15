# In plain English: the guardrail for every Kubernetes file this repo deploys. For each kind of file, tests/allowed_paths.py lists the
# settings it may use. This test reads the real files, lists the settings they actually use, and fails when a file uses one that is not
# listed, or is of a kind that is not listed, or sets an environment variable whose name is not listed. It also fails when the list
# holds a setting nothing uses, because a stale allowance would quietly permit a future change.
#
# Why it is built this way: there are endless ways to expose a service or weaken a pod (a node port, a load balancer, an outside
# address, an ingress, the host's network, the host's disk, a privileged container, a secret loaded as a variable, a Secret saved in the
# repo). A list of those is an arms race. A list of what IS used has no such gap: none of them is on it, so all of them fail until a
# pull request that someone reads adds one on purpose.
#
# Why it matters (OWASP A01, CWE-668 exposure of a resource to the wrong sphere): the services have no login beyond the shared keys and
# nobody outside the cluster calls them. One careless line in a manifest would break that decision without any code changing. Also
# CWE-538, 540 and 798 (a Secret or a written-in password in a public repo), CWE-526 (a secret in an environment variable) and the
# other points of the pod rules that tests/test_pod_hardening.py requires.
#
# The check proves itself: a copy of a real file with one forbidden setting added must be refused, for every kind of setting.
import copy

import pytest

import allowed_yaml
from allowed_paths import ALLOWED_ENVIRONMENT_NAMES, ALLOWED_PATHS


def problems_of(document):
    return allowed_yaml.manifest_problems(document, ALLOWED_PATHS, ALLOWED_ENVIRONMENT_NAMES)


# ---------- The real files ----------

@pytest.mark.owasp("A01", 668, 538, 540)
@pytest.mark.owasp("A06", 1125, 419)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260, 526)
def test_every_kubernetes_file_uses_only_allowed_kinds_settings_and_variables():
    documents = allowed_yaml.real_documents()
    assert any(document.get("kind") == "Service" for document in documents), "no Service file was found, so there was nothing to check"
    problems = [problem for document in documents for problem in problems_of(document)]
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A01", 668)
def test_nothing_allowed_is_unused():
    documents = allowed_yaml.real_documents()
    for kind, paths in ALLOWED_PATHS.items():
        used = set()
        for document in documents:
            if document.get("kind") == kind:
                used |= allowed_yaml.key_paths(document, kind)
        assert sorted(set(paths) - used) == [], f"{kind}: allowed but unused"
    assert set(ALLOWED_PATHS) == {document["kind"] for document in documents}, "a kind is allowed that no file uses"
    used_names = set()
    for document in documents:
        used_names |= allowed_yaml.environment_names(document)
    assert sorted(set(ALLOWED_ENVIRONMENT_NAMES) - used_names) == []


@pytest.mark.owasp("A01", 538, 540)
def test_a_secret_is_not_an_allowed_kind():
    assert "Secret" not in ALLOWED_PATHS


# ---------- The check proves itself ----------

def real(kind):
    return copy.deepcopy(next(document for document in allowed_yaml.real_documents() if document.get("kind") == kind))


def pod(document):
    return document["spec"]["template"]["spec"]


def container(document):
    return pod(document)["containers"][0]


def with_service(**spec):
    document = real("Service")
    document["spec"].update(spec)
    return document


def with_pod(**settings):
    document = real("Deployment")
    pod(document).update(settings)
    return document


def with_container(**settings):
    document = real("Deployment")
    container(document).update(settings)
    return document


def with_security(**settings):
    document = real("Deployment")
    container(document).setdefault("securityContext", {}).update(settings)
    return document


def with_port(**port):
    document = real("Deployment")
    container(document)["ports"][0].update(port)
    return document


def with_env(**variable):
    document = real("Deployment")
    container(document).setdefault("env", []).append(variable)
    return document


BAD = {
    # ways of exposing a service
    "a node port service": lambda: with_service(type="NodePort"),
    "a load balancer service": lambda: with_service(type="LoadBalancer"),
    "an explicit ClusterIP type": lambda: with_service(type="ClusterIP"),
    "an external name": lambda: with_service(type="ExternalName", externalName="evil.example"),
    "a node port on a port": lambda: with_service(ports=[{"port": 80, "nodePort": 30080}]),
    "an outside address": lambda: with_service(externalIPs=["1.2.3.4"]),
    "a load balancer address": lambda: with_service(loadBalancerIP="1.2.3.4"),
    "traffic let in from anywhere": lambda: with_service(loadBalancerSourceRanges=["0.0.0.0/0"]),
    "an ingress": lambda: {"kind": "Ingress", "metadata": {"name": "x"}},
    "a gateway": lambda: {"kind": "Gateway", "metadata": {"name": "x"}},
    "a gateway route": lambda: {"kind": "HTTPRoute", "metadata": {"name": "x"}},
    # ways of weakening a pod
    "host networking": lambda: with_pod(hostNetwork=True),
    "host process ids": lambda: with_pod(hostPID=True),
    "host shared memory": lambda: with_pod(hostIPC=True),
    "a host port": lambda: with_port(hostPort=80),
    "the host's disk": lambda: with_pod(volumes=[{"name": "d", "hostPath": {"path": "/"}}]),
    "a privileged container": lambda: with_security(privileged=True),
    "an added capability": lambda: with_security(capabilities={"drop": ["ALL"], "add": ["NET_ADMIN"]}),
    "running as root": lambda: with_security(runAsUser=0),
    "a service account": lambda: with_pod(serviceAccountName="admin"),
    "a shared process namespace": lambda: with_pod(shareProcessNamespace=True),
    "an extra container": lambda: with_pod(initContainers=[{"name": "x", "image": "evil:1"}]),
    "a sysctl": lambda: with_pod(securityContext={"sysctls": [{"name": "net.core.somaxconn", "value": "1"}]}),
    "a projected service account token": lambda: with_pod(volumes=[{"name": "t", "projected": {"sources": [{"serviceAccountToken": {"path": "t"}}]}}]),
    "a config map volume": lambda: with_pod(volumes=[{"name": "c", "configMap": {"name": "x"}}]),
    "a command in a lifecycle hook": lambda: with_container(lifecycle={"postStart": {"exec": {"command": ["sh"]}}}),
    "a tty": lambda: with_container(tty=True),
    # ways of handling a secret
    "a secret loaded as variables": lambda: with_container(envFrom=[{"secretRef": {"name": "keys"}}]),
    "a secret in one variable": lambda: with_env(name="KNOWLEDGE_KEY_FILE", valueFrom={"secretKeyRef": {"name": "k", "key": "k"}}),
    "a password written into the file": lambda: with_env(name="DB_PASSWORD", value="hunter2"),
    "a variable nobody listed": lambda: with_env(name="DEBUG", value="1"),
    "a Secret saved in the repo": lambda: {"kind": "Secret", "metadata": {"name": "keys"}, "data": {"key": "eA=="}},
    # kinds nobody listed
    "a role": lambda: {"kind": "ClusterRole", "metadata": {"name": "x"}},
    "a service account object": lambda: {"kind": "ServiceAccount", "metadata": {"name": "x"}},
    "a role binding": lambda: {"kind": "ClusterRoleBinding", "metadata": {"name": "x"}},
    "a network policy": lambda: {"kind": "NetworkPolicy", "metadata": {"name": "x"}},
    "a file with no kind": lambda: {"metadata": {"name": "x"}},
    "a part of a file that is not an object": lambda: "text",
}


@pytest.mark.owasp("A01", 668, 538, 540)
@pytest.mark.owasp("A06", 1125, 419)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260, 526)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_forbidden_setting_is_refused(label):
    assert problems_of(BAD[label]()) != [], label


@pytest.mark.owasp("A01", 668)
@pytest.mark.parametrize("kind", sorted(ALLOWED_PATHS))
def test_a_real_file_is_clean(kind):
    assert problems_of(real(kind)) == []


@pytest.mark.owasp("A01", 668)
def test_a_free_map_accepts_any_name_but_a_map_nobody_listed_is_refused():
    document = real("ConfigMap")
    document["data"]["ANY_NAME_AT_ALL"] = "x"
    assert problems_of(document) == []  # the settings of a ConfigMap are free names
    document["metadata"]["labels"] = {"anything": "goes"}
    assert problems_of(document) != []  # this file has no labels listed, so a new "metadata.labels" is a new setting


@pytest.mark.owasp("A01", 668)
def test_the_environment_variables_of_init_containers_count_too():
    document = {"spec": {"template": {"spec": {"containers": [{"name": "a", "env": [{"name": "ONE"}]}], "initContainers": [{"name": "b", "env": [{"name": "TWO"}]}]}}}}
    assert allowed_yaml.environment_names(document) == {"ONE", "TWO"}
    assert allowed_yaml.environment_names({"spec": {}}) == set()
