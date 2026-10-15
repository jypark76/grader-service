# In plain English: the engine behind the "allowed Kubernetes files" guardrail (tests/test_allowed_manifests.py). Every Kubernetes file in
# the repo is a list of settings inside settings. This reads each file and lists every setting it uses, written as a path such as
# spec.template.spec.containers[].image. tests/allowed_paths.py lists, for every kind of file, the paths that kind may use. A path that
# is not on the list is a problem: a node port, a host network, a privileged container, a secret loaded as a variable, an outside
# address, a Secret itself. Nobody has to think of those in advance; they are simply not on the list.
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FOLDERS = [folder for folder in (ROOT / "k8s", ROOT / "kafka") if folder.exists()]

# Maps whose keys are free names chosen by the author (labels, settings): their children count as one path, "*".
FREE_MAPS = {"metadata.labels", "metadata.annotations", "spec.selector.matchLabels", "spec.template.metadata.labels", "data"}
SERVICE_FREE_MAPS = {"spec.selector"}  # a Service's selector is a map of labels; a Deployment's selector is not


def free_maps_for(kind):
    return FREE_MAPS | (SERVICE_FREE_MAPS if kind == "Service" else set())


# In plain English: every setting path used inside one document (lists are written with [], free maps with *).
def key_paths(node, kind, prefix="", found=None):
    found = set() if found is None else found
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.*" if prefix in free_maps_for(kind) else (f"{prefix}.{key}" if prefix else str(key))
            found.add(path)
            key_paths(value, kind, path, found)
    elif isinstance(node, list):
        for item in node:
            key_paths(item, kind, prefix + "[]", found)
    return found


# In plain English: the names of the environment variables a document's containers set.
def environment_names(document):
    names = set()
    pod = ((document.get("spec") or {}).get("template") or {}).get("spec") or {}
    for container in list(pod.get("containers") or []) + list(pod.get("initContainers") or []):
        for variable in container.get("env") or []:
            if isinstance(variable, dict) and "name" in variable:
                names.add(str(variable["name"]))
    return names


# In plain English: how one document breaks the allowed lists, as plain sentences.
def manifest_problems(document, allowed_paths, allowed_environment_names):
    if not isinstance(document, dict):
        return ["a file part that is not a Kubernetes object"]
    kind = document.get("kind")
    name = (document.get("metadata") or {}).get("name", "?")
    if kind not in allowed_paths:
        return [f"{kind} {name}: this kind of file is not allowed"]
    problems = [f"{kind} {name}: the setting '{path}' is not allowed" for path in sorted(key_paths(document, kind) - set(allowed_paths[kind]))]
    problems += [f"{kind} {name}: the environment variable '{variable}' is not allowed" for variable in sorted(environment_names(document) - set(allowed_environment_names))]
    return problems


def real_documents():
    documents = []
    for folder in FOLDERS:
        for path in sorted(folder.rglob("*.y*ml")):
            documents.extend(document for document in yaml.safe_load_all(path.read_text(encoding="utf-8")) if document)
    return documents
