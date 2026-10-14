# In plain English: a guardrail that keeps this service from ever reaching a place chosen by someone else. A message or a
# request must never be able to pick the address the service connects to, or the Kafka topic it reads or writes.
#
# HOW IT WORKS, and why it is built this way. There are only two outbound paths in the whole service, and each is one call:
#   - the knowledge-service lookup:  self.web.stream("POST", SEARCH_PATH, json=..., headers=...)   in app/lookup.py
#   - the Kafka send and read:       producer.produce(topic, ...), consumer.subscribe([TOPIC])    in app/worker.py
# So this test does not try to prove that arbitrary Python goes to a fixed place (that is an arms race with whoever writes the
# next trick). It PINS those calls, exactly, and bans every other way to reach the web or Kafka:
#   - only app/lookup.py may import the web library, only as a plain `import httpx`, and only a short list of its names may be used;
#   - the web client lives in one place (self.web) and may be used for one call with one exact shape: the method "POST", the
#     address given by the name SEARCH_PATH, and nothing but json and headers; no keyword address, no *args, no **kwargs, no
#     other method, no copy of the client under another name;
#   - SEARCH_PATH is bound exactly once in the file, by a text written at the top (checked against EVERY way Python can bind a
#     name, from the language's own list of syntax kinds and from Python's own symbol table, see the tests at the bottom);
#   - only app/worker.py may call produce or subscribe, each exactly once, with the topic a plain parameter or a constant bound
#     once at the top, and the send helper may only be called with the two fixed topic constants;
#   - getattr/setattr/delattr/globals/locals/vars, `import *` and a few dunder attributes are banned everywhere, because each is
#     a way around everything above.
# Why it matters: if a request or message could pick the address or the topic, an attacker could make the service call an
# internal system, leak data to their own server or read someone else's topic (OWASP A05 CWE-610, and the server-side request
# forgery family in A01).
import ast
import textwrap
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# Modules that open connections to other machines. Anything in app/ that uses one must be a deliberate decision, so adding it
# must change this list.
OUTBOUND_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "http", "socket", "aiohttp", "websockets", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "poplib", "imaplib", "paramiko", "grpc",
}

# The one deliberate exception: the file that is allowed to import an outbound module, and which one.
ALLOWED_OUTBOUND = {"lookup.py": {"httpx"}}
# The only names of the web library the lookup may use.
HTTPX_NAMES = {"Client", "URL", "Timeout", "InvalidURL", "HTTPError"}
# Names of methods that send something over a web client. In app/lookup.py only the one pinned call may use one; elsewhere none.
SENDING_NAMES = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send", "build_request"}
# The one file that may talk to Kafka, and the calls it may make.
KAFKA_FILES = {"worker.py"}
TOPIC_CALLS = {"produce", "subscribe", "assign", "seek", "consume"}
DANGEROUS_CALLS = {"getattr", "setattr", "delattr", "globals", "locals", "vars"}
DANGEROUS_ATTRIBUTES = {"__dict__", "__getattribute__", "__globals__", "__builtins__", "__import__", "__class__"}
STREAM_KEYWORDS = {"json", "headers"}
PRODUCE_KEYWORDS = {"key", "value", "headers", "on_delivery"}
FIXED_TOPICS = {"RESULT_TOPIC", "DEAD_LETTER_TOPIC"}


# In plain English: every name that ONE piece of code binds, meaning gives a value to, declares, imports, defines or deletes.
# This list is Python's own: it covers every syntax tree node type that can carry a name (a test below checks the list against the
# language itself, so a new kind of binding added by a future Python makes a test fail instead of slipping by).
def names_bound_by(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return {node.id}  # =, :=, +=, for, with ... as, comprehensions, del, tuple and star unpacking
    if isinstance(node, ast.arg):
        return {node.arg}  # every parameter of a def or a lambda, including *args, **kwargs, keyword-only and positional-only
    if isinstance(node, ast.ExceptHandler):
        return {node.name} if node.name else set()  # except ... as name, except* ... as name
    if isinstance(node, ast.alias):
        return {(node.asname or node.name).split(".")[0]}  # import x, import x as y, from x import y [as z]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchMapping):
        return {node.rest} if node.rest else set()
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return set(node.names)  # declaring that a name is rebound from inside a function is itself a re-binding
    if type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple"):
        return {node.name}  # def f[NAME](): ...  and  class C[NAME]: ...
    return set()


# In plain English: true if the name is bound exactly once in the whole file, and that one binding is a text written at the top
# of the file (`NAME = "..."` or `NAME: str = "..."`).
def is_a_text_constant_bound_once(tree, name):
    top_level_texts = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            top_level_texts += [target for target in node.targets if isinstance(target, ast.Name) and target.id == name]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            top_level_texts.append(node.target)
    bindings = sum(1 for node in ast.walk(tree) if name in names_bound_by(node))
    return len(top_level_texts) == 1 and bindings == 1


# In plain English: checks the lookup file's web use, and returns plain sentences, one per problem.
def lookup_problems(tree, name):
    problems = []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    # 1. The web library is only ever used through the few names listed, and the name httpx is never re-bound.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "httpx" and isinstance(node.ctx, ast.Load):
            holder = parents.get(node)
            if not (isinstance(holder, ast.Attribute) and holder.value is node and holder.attr in HTTPX_NAMES):
                problems.append(f"{name}:{node.lineno}: uses the web library other than through {sorted(HTTPX_NAMES)}")
    if sum(1 for node in ast.walk(tree) if "httpx" in names_bound_by(node)) != 1:
        problems.append(f"{name}: the name httpx must be bound exactly once, by 'import httpx'")
    # 2. The web client lives in self.web, which is set once from the constructor's parameter and used for one call.
    pinned_calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and ast.unparse(node) == "self.web":
            holder = parents.get(node)
            if isinstance(node.ctx, ast.Store):
                if not (isinstance(holder, ast.Assign) and isinstance(holder.value, ast.Name) and holder.value.id == "client"):
                    problems.append(f"{name}:{node.lineno}: self.web is set from something other than the client parameter")
            elif isinstance(holder, ast.Attribute) and holder.attr == "stream" and isinstance(parents.get(holder), ast.Call) and parents[holder].func is holder:
                pinned_calls.append(parents[holder])
            else:
                problems.append(f"{name}:{node.lineno}: self.web is used other than for the one pinned stream call")
    if len(pinned_calls) != 1:
        problems.append(f"{name}: there must be exactly one call on the web client, found {len(pinned_calls)}")
    for call in pinned_calls:
        shape_ok = (
            len(call.args) == 2
            and isinstance(call.args[0], ast.Constant) and call.args[0].value == "POST"
            and isinstance(call.args[1], ast.Name) and call.args[1].id == "SEARCH_PATH"
            and all(keyword.arg in STREAM_KEYWORDS for keyword in call.keywords)
        )
        if not shape_ok:
            problems.append(f"{name}:{call.lineno}: the web call is not exactly stream('POST', SEARCH_PATH, json=..., headers=...)")
    # 3. The constructor parameter "client" is read exactly once: to set self.web.
    reads = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "client" and isinstance(node.ctx, ast.Load)]
    if len(reads) > 1:
        problems.append(f"{name}: the client parameter is used more than once")
    # 4. The address name is a text bound once at the top of the file.
    if not is_a_text_constant_bound_once(tree, "SEARCH_PATH"):
        problems.append(f"{name}: SEARCH_PATH must be a text written once at the top of the file and never bound again")
    # 5. No other method that sends anything. (get, head and options are also ordinary dictionary and settings reads, so on their
    # own they are not flagged; they cannot be used on a web client anyway, because rule 2 allows the client to be used for only
    # the one stream call and rule 6 allows no other client to exist.)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in SENDING_NAMES - {"get", "head", "options"} and ast.unparse(node.value) != "self.web":
            problems.append(f"{name}:{node.lineno}: '{node.attr}' is a sending method and may only be the pinned call on self.web")
    # 6. The one web client is built in make_client and handed straight back; no other client exists.
    clients = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "httpx.Client"]
    for call in clients:
        function = call
        while function in parents and not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = parents[function]
        in_make_client = isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name == "make_client"
        if len(clients) != 1 or not in_make_client or not isinstance(parents.get(call), ast.Return):
            problems.append(f"{name}:{call.lineno}: the web client must be built exactly once, in make_client, and returned directly")
    return problems


# In plain English: checks the worker's Kafka calls, and returns plain sentences, one per problem.
def kafka_problems(tree, name):
    problems = []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    produces = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "produce"]
    subscribes = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "subscribe"]
    others = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in TOPIC_CALLS - {"produce", "subscribe"}]
    if len(produces) > 1 or len(subscribes) > 1 or others:
        problems.append(f"{name}: there may be at most one produce call, one subscribe call and no other topic call")
    for call in produces:
        function = call
        while function in parents and not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = parents[function]
        topic_is_a_parameter = isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and "topic" in {argument.arg for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
        rebound = set()
        if topic_is_a_parameter:
            for statement in function.body:
                for part in ast.walk(statement):
                    rebound |= names_bound_by(part)
        shape_ok = (
            len(call.args) == 1 and isinstance(call.args[0], ast.Name) and call.args[0].id == "topic"
            and topic_is_a_parameter and "topic" not in rebound
            and all(keyword.arg in PRODUCE_KEYWORDS for keyword in call.keywords)
        )
        if not shape_ok:
            problems.append(f"{name}:{call.lineno}: produce must be produce(topic, key=, value=, headers=, on_delivery=) with topic an unchanged parameter")
    for call in subscribes:
        topics = call.args[0] if call.args else None
        shape_ok = (
            len(call.args) == 1 and not call.keywords and isinstance(topics, ast.List) and len(topics.elts) == 1
            and isinstance(topics.elts[0], ast.Name) and is_a_text_constant_bound_once(tree, topics.elts[0].id)
        )
        if not shape_ok:
            problems.append(f"{name}:{call.lineno}: subscribe must be subscribe([NAME]) with NAME a text constant bound once")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_deliver":
            fixed = (
                len(node.args) >= 2 and not any(isinstance(argument, ast.Starred) for argument in node.args)
                and isinstance(node.args[1], ast.Name) and node.args[1].id in FIXED_TOPICS
                and is_a_text_constant_bound_once(tree, node.args[1].id)
                and all(keyword.arg not in (None, "topic") for keyword in node.keywords)
            )
            if not fixed:
                problems.append(f"{name}:{node.lineno}: _deliver must be called with one of {sorted(FIXED_TOPICS)} as its topic")
    return problems


# In plain English: reads one program's text and returns plain sentences, one per problem, each with its line number.
def find_unfixed_destinations(source, name="<code>"):
    tree = ast.parse(source)
    base = name.rsplit("/", 1)[-1]
    allowed = ALLOWED_OUTBOUND.get(base, set())
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in OUTBOUND_MODULES and root not in allowed:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}', which opens connections to other machines")
                if root in allowed and (alias.asname or alias.name != root):
                    problems.append(f"{name}:{node.lineno}: the web library must be imported plainly as 'import {root}'")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in OUTBOUND_MODULES:
                problems.append(f"{name}:{node.lineno}: imports from '{node.module}', which opens connections to other machines")
            if any(alias.name == "*" for alias in node.names):
                problems.append(f"{name}:{node.lineno}: 'import *' can silently re-bind any name")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
            problems.append(f"{name}:{node.lineno}: calls '{node.func.id}', which can reach any name or attribute")
        elif isinstance(node, ast.Attribute):
            if node.attr in DANGEROUS_ATTRIBUTES:
                problems.append(f"{name}:{node.lineno}: uses '{node.attr}', which can reach any name or attribute")
            if node.attr in SENDING_NAMES and not allowed and node.attr not in ("get", "head", "options"):
                problems.append(f"{name}:{node.lineno}: '{node.attr}' sends over a web client, which only app/lookup.py may do")
            if node.attr in TOPIC_CALLS and base not in KAFKA_FILES:
                problems.append(f"{name}:{node.lineno}: '{node.attr}' talks to Kafka, which only app/worker.py may do")
    if allowed:
        problems += lookup_problems(tree, name)
    if base in KAFKA_FILES:
        problems += kafka_problems(tree, name)
    return problems


def app_files():
    return sorted(APP.rglob("*.py"))


# In plain English: the real check. Every Python file in app/ must be clean.
@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.owasp("A07", 941)
def test_application_code_reaches_only_fixed_destinations():
    files = app_files()
    assert files, "no application files were found to check"
    problems = []
    for path in files:
        problems.extend(find_unfixed_destinations(path.read_text(encoding="utf-8"), f"app/{path.relative_to(APP).as_posix()}"))
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A05", 610)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "errors.py", "secret_files.py", "logsafe.py", "lookup.py", "worker.py"} <= names
    assert ALLOWED_OUTBOUND == {"lookup.py": {"httpx"}} and KAFKA_FILES == {"worker.py"}


# A good lookup file and a good worker file, written out in full. Every bad program below is one of these with one change.
LOOKUP = """\
import httpx

SEARCH_PATH = "/examples/search"


class KnowledgeLookup:
    def __init__(self, client):
        self.web = client

    def __call__(self, job):
@BODY@
"""
GOOD_CALL = '        with self.web.stream("POST", SEARCH_PATH, json={}, headers={}) as reply:\n            return reply'
WORKER = """\
TOPIC = "grading-jobs"
RESULT_TOPIC = "grading-results"
DEAD_LETTER_TOPIC = "grading-jobs.dead-letter"


def _deliver(producer, topic, key, value, headers=None):
@BODY@


def run(consumer, producer):
    consumer.subscribe([TOPIC])
    _deliver(producer, RESULT_TOPIC, 1, 2)
    _deliver(producer, DEAD_LETTER_TOPIC, 1, 2, headers=[])
"""
GOOD_PRODUCE = "    producer.produce(topic, key=key, value=value, headers=headers, on_delivery=None)"


def lookup(body):
    return LOOKUP.replace("@BODY@", body)


def worker(body):
    return WORKER.replace("@BODY@", body)


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
def test_the_good_programs_are_not_flagged():
    assert find_unfixed_destinations(lookup(GOOD_CALL), "app/lookup.py") == []
    assert find_unfixed_destinations(worker(GOOD_PRODUCE), "app/worker.py") == []


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
def test_the_real_lookup_and_worker_have_the_pinned_shapes():
    # The two real files are checked above; this proves the pins are really looking at the real code, not at nothing.
    text = (APP / "lookup.py").read_text(encoding="utf-8")
    assert text.count("self.web.stream(") == 1 and 'SEARCH_PATH = "/examples/search"' in text
    worker_text = (APP / "worker.py").read_text(encoding="utf-8")
    assert worker_text.count(".produce(") == 1 and worker_text.count(".subscribe(") == 1


# Every way the one web call could be changed to reach another place. Each replaces GOOD_CALL's call and must be caught.
BAD_CALLS = {
    "a computed address as a positional argument": '        return self.web.stream("POST", job.url, json={})',
    "an f-string address": '        return self.web.stream("POST", f"/x/{job.id}", json={})',
    "a text address instead of the named constant": '        return self.web.stream("POST", "/examples/search", json={})',
    "a keyword address": '        return self.web.stream("POST", SEARCH_PATH, url=job.url)',
    "the keyword address alone": '        return self.web.stream(method="POST", url=job.url)',
    "the keyword method": '        return self.web.stream(method="POST")',
    "another keyword": '        return self.web.stream("POST", SEARCH_PATH, json={}, timeout=job.t)',
    "unpacked positional arguments": "        return self.web.stream(*job.args)",
    "unpacked positional arguments after the method": '        return self.web.stream("POST", *job.args)',
    "unpacked keyword arguments": '        return self.web.stream("POST", SEARCH_PATH, **job.kw)',
    "the wrong method": '        return self.web.stream("GET", SEARCH_PATH)',
    "a computed method": "        return self.web.stream(job.method, SEARCH_PATH)",
    "a third positional argument": '        return self.web.stream("POST", SEARCH_PATH, job.extra)',
    "post instead of stream": "        return self.web.post(SEARCH_PATH)",
    "get instead of stream": "        return self.web.get(SEARCH_PATH)",
    "request instead of stream": '        return self.web.request("POST", SEARCH_PATH)',
    "send": "        return self.web.send(job.request)",
    "build_request": '        return self.web.build_request("POST", job.url)',
    "the client copied to another name": '        w = self.web\n        return w.stream("POST", job.url)',
    "the client's method copied to another name": "        post = self.web.post\n        return post(job.url)",
    "the client's method copied, stream": "        s = self.web.stream\n        return s('POST', job.url)",
    "the client given to another function": "        return helper(self.web, job.url)",
    "the client put in a list": "        return [self.web][0].stream('POST', job.url)",
    "a local variable as the address": "        address = job.url\n        return self.web.stream(\"POST\", address, json={})",
    "a variable that holds the constant, not the constant": "        address = SEARCH_PATH\n        return self.web.stream(\"POST\", address, json={})",
    "the good call and a copy of the client": "        w = self.web\n" + GOOD_CALL,
    "the good call and the client put in a list": "        w = [self.web]\n" + GOOD_CALL,
    "the good call and the client handed to a function": "        helper(self.web)\n" + GOOD_CALL,
    "the good call and a read of the client's method": "        m = self.web.post\n" + GOOD_CALL,
    "the good call and a second client that is never used": "        c = httpx.Client(base_url=job.url)\n" + GOOD_CALL,
    "the good call and a copy of the library": "        h = httpx\n" + GOOD_CALL,
    "the good call and a use of the constructor parameter": "        other = client\n" + GOOD_CALL,
    "the good call and the constructor parameter called": "        client.anything()\n" + GOOD_CALL,
    "the good call and another receiver's sending method": "        helper.post(job.url)\n" + GOOD_CALL,
    "the good call and another receiver's request method": "        helper.request('GET', job.url)\n" + GOOD_CALL,
    "the good call and another receiver's send method": "        helper.send(job.url)\n" + GOOD_CALL,
    "a second call as well":'        self.web.stream("POST", SEARCH_PATH, json={})\n        return self.web.stream("POST", SEARCH_PATH, json={})',
    "getattr on the client": '        return getattr(self.web, "post")(job.url)',
    "getattr by a computed name": "        return getattr(self.web, job.name)(job.url)",
    "the dictionary of the object": '        return self.__dict__["web"].post(job.url)',
    "globals": '        return globals()["httpx"].post(job.url)',
    "vars": '        return vars(self)["web"].post(job.url)',
    "the module level function post": "        return httpx.post(job.url)",
    "the module level function get": "        return httpx.get(job.url)",
    "the module level function stream": '        return httpx.stream("POST", job.url)',
    "a new client built and used": "        return httpx.Client().post(job.url)",
    "a new client built and used with get": "        return httpx.Client().get(job.url)",
    "a new client built, kept and used with get": "        c = httpx.Client()\n        return c.get(job.url)",
    "a new client built, kept and used with head": "        c = httpx.Client()\n        return c.head(job.url)",
    "a new client built, kept and used": "        c = httpx.Client()\n        return c.post(job.url)",
    "the library under another name": "        h = httpx\n        return h.post(job.url)",
    "the client parameter used directly": '        return client.stream("POST", job.url)',
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label", sorted(BAD_CALLS))
def test_every_other_way_to_reach_the_web_from_the_lookup_is_caught(label):
    source = lookup(BAD_CALLS[label])
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/lookup.py") != [], f"not caught: {label}"


ADDRESS_LINE = 'SEARCH_PATH = "/examples/search"'
# Setups that REPLACE the address line with something that is not one text written once.
BAD_ADDRESS_LINES = {
    "the address a computed value": "SEARCH_PATH = compute()",
    "the address read from a setting": 'SEARCH_PATH = environment.get("PATH")',
    "the address a number": "SEARCH_PATH = 5",
    "the address bytes": 'SEARCH_PATH = b"/x"',
    "the address missing": "OTHER = 1",
}
# Setups that ADD one more line after the (still good) address line.
BAD_EXTRA_LINES = {
    "the address bound again": 'SEARCH_PATH = "/other"',
    "the address bound again by a call": "SEARCH_PATH = compute()",
    "the address bound again by an augmented assignment": 'SEARCH_PATH += "x"',
    "the library imported under a name": "import httpx as h",
    "the library imported from": "from httpx import Client",
    "the library imported from, with star": "from httpx import *",
    "star import of anything": "from helpers import *",
    "another web library": "import requests",
    "a raw socket": "import socket",
    "the name httpx bound again": "httpx = other",
    "a different module under the name httpx": "import other as httpx",
    "import httpx dotted": "import httpx.sub",
    "import httpx a second time": "import httpx",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label", sorted(BAD_ADDRESS_LINES))
def test_every_way_the_address_could_stop_being_one_fixed_text_is_caught(label):
    source = lookup(GOOD_CALL).replace(ADDRESS_LINE, BAD_ADDRESS_LINES[label], 1)
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/lookup.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label", sorted(BAD_EXTRA_LINES))
def test_every_way_to_change_the_address_or_the_library_after_the_fact_is_caught(label):
    source = lookup(GOOD_CALL).replace(ADDRESS_LINE, ADDRESS_LINE + "\n" + BAD_EXTRA_LINES[label], 1)
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/lookup.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", ["a computed address", "a keyword address", "unpacked arguments"])
def test_the_same_calls_in_any_other_file_are_caught_too(label):
    body = {"a computed address": 'client.post(job.url)', "a keyword address": "client.stream(url=job.url)", "unpacked arguments": "client.request(*job.args)"}[label]
    source = f"def f(client, job):\n    return {body}\n"
    assert find_unfixed_destinations(source, "app/other.py") != []
    assert find_unfixed_destinations(source, "app/worker.py") != []


@pytest.mark.owasp("A05", 610)
def test_the_one_allowance_stays_narrow():
    good = lookup(GOOD_CALL)
    assert find_unfixed_destinations(good, "app/lookup.py") == []
    assert find_unfixed_destinations(good, "app/other.py") != []  # the same code anywhere else is refused
    assert find_unfixed_destinations(good, "app/lookup.py.txt") != []
    assert find_unfixed_destinations(good, "lookup.py") == []


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
def test_the_one_client_is_built_in_make_client_and_returned_directly():
    good = lookup(GOOD_CALL) + "\n\ndef make_client(environment):\n    return httpx.Client(base_url=environment)\n"
    assert find_unfixed_destinations(good, "app/lookup.py") == []
    kept = lookup(GOOD_CALL) + "\n\ndef make_client(environment):\n    c = httpx.Client(base_url=environment)\n    return c\n"
    assert find_unfixed_destinations(kept, "app/lookup.py") != []  # built in make_client but not handed straight back
    elsewhere = lookup("        if job:\n            return httpx.Client()\n" + GOOD_CALL)
    assert find_unfixed_destinations(elsewhere, "app/lookup.py") != []  # handed straight back, but not built in make_client
    two = good + "\n\ndef make_client2(environment):\n    return httpx.Client(base_url=environment)\n"
    assert find_unfixed_destinations(two, "app/lookup.py") != []  # a second client anywhere
    many = lookup(GOOD_CALL) + "\n\ndef make_client(environment):\n    if environment:\n        return httpx.Client(base_url=environment)\n    return httpx.Client()\n"
    assert find_unfixed_destinations(many, "app/lookup.py") != []  # two clients, both built in make_client and both returned directly


# ---------- Kafka ----------

BAD_PRODUCES = {
    "a computed topic": "    producer.produce(key, key=key, value=value)",
    "a topic from a message": "    producer.produce(value.topic, key=key)",
    "a keyword topic": "    producer.produce(topic=value.topic, value=value)",
    "a keyword topic and a positional one": "    producer.produce(topic, topic=value.topic)",
    "no topic argument": "    producer.produce(key=key, value=value)",
    "unpacked arguments": "    producer.produce(*value)",
    "unpacked keyword arguments": "    producer.produce(topic, **value)",
    "an unknown keyword": "    producer.produce(topic, partition=value.p)",
    "a topic that is rebound first": "    topic = value.topic\n    producer.produce(topic, key=key)",
    "a topic rebound by a loop": "    for topic in value:\n        producer.produce(topic)",
    "a topic rebound by with": "    with value as topic:\n        producer.produce(topic)",
    "a topic rebound by walrus": "    (topic := value.topic)\n    producer.produce(topic)",
    "a topic rebound by except": "    try:\n        pass\n    except ValueError as topic:\n        producer.produce(topic)",
    "a topic rebound by a nested function": "    def topic():\n        pass\n    producer.produce(topic)",
    "two sends": "    producer.produce(topic, key=key)\n    producer.produce(topic, key=value)",
    "assign": "    producer.assign(value.partitions)",
    "seek": "    producer.seek(value.position)",
    "consume": "    producer.consume(1)",
    "getattr on the producer": '    getattr(producer, "produce")(value.topic)',
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label", sorted(BAD_PRODUCES))
def test_every_other_way_to_send_to_kafka_is_caught(label):
    source = worker(BAD_PRODUCES[label])
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != [], f"not caught: {label}"


BAD_WORKER_PARTS = {
    "a second subscribe": "    consumer.subscribe([TOPIC])\n    consumer.subscribe([TOPIC])",
    "subscribe to a computed topic": "    consumer.subscribe([job.topic])",
    "subscribe with a keyword": "    consumer.subscribe(topics=[TOPIC])",
    "subscribe with two topics": "    consumer.subscribe([TOPIC, RESULT_TOPIC])",
    "subscribe with a name that is not a constant": "    t = job.topic\n    consumer.subscribe([t])",
    "send helper called with a computed topic": "    _deliver(producer, job.topic, 1, 2)",
    "send helper called with a keyword topic": "    _deliver(producer, RESULT_TOPIC, 1, 2, topic=job.topic)",
    "send helper called with unpacked arguments": "    _deliver(*job.args)",
    "send helper called with a constant that is not fixed": "    _deliver(producer, TOPIC, 1, 2)",
    "send helper called with too few arguments": "    _deliver(producer)",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label", sorted(BAD_WORKER_PARTS))
def test_every_other_way_to_subscribe_or_call_the_send_helper_is_caught(label):
    source = worker(GOOD_PRODUCE).replace("    consumer.subscribe([TOPIC])\n", BAD_WORKER_PARTS[label] + "\n", 1) if "subscribe" in label else worker(GOOD_PRODUCE) + "\n\ndef extra(consumer, producer, job):\n" + BAD_WORKER_PARTS[label] + "\n"
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
def test_kafka_calls_in_any_other_file_are_caught():
    for call in ("producer.produce(topic)", "consumer.subscribe([TOPIC])", "consumer.seek(x)", "consumer.assign(x)"):
        assert find_unfixed_destinations(f"TOPIC = 'x'\ndef f(producer, consumer, topic, x):\n    {call}\n", "app/other.py") != [], call


# ---------- Simple bans that apply to every file ----------

SIMPLE_BAD = {
    "requests": "import requests\nrequests.get('http://x')\n",
    "requests with a nickname": "import requests as r\n",
    "from requests import": "from requests import get\n",
    "httpx outside the lookup": "import httpx\n",
    "urllib.request": "import urllib.request\n",
    "from urllib import": "from urllib import request\n",
    "http.client": "import http.client\n",
    "socket": "import socket\n",
    "smtplib": "import smtplib\n",
    "aiohttp": "import aiohttp\n",
    "star import": "from os import *\n",
    "getattr": "def f(o, n):\n    return getattr(o, n)\n",
    "getattr with a fixed word": "def f(o):\n    return getattr(o, 'post')\n",
    "setattr": "def f(o):\n    setattr(o, 'x', 1)\n",
    "delattr": "def f(o):\n    delattr(o, 'x')\n",
    "globals": "def f():\n    return globals()\n",
    "locals": "def f():\n    return locals()\n",
    "vars": "def f(o):\n    return vars(o)\n",
    "the dictionary of an object": "def f(o):\n    return o.__dict__\n",
    "the class of an object": "def f(o):\n    return o.__class__\n",
    "the built-ins": "def f(o):\n    return o.__builtins__\n",
    "the globals of a function": "def f(o):\n    return o.__globals__\n",
    "a sending method outside the lookup": "def f(c, u):\n    c.post(u)\n",
    "a sending method with a fixed address outside the lookup": "def f(c):\n    c.post('/x')\n",
}
SIMPLE_GOOD = {
    "the database driver": "import psycopg\n",
    "the kafka client": "from confluent_kafka import Consumer\n",
    "the word in a comment": "# we never import requests or socket here\nx = 1\n",
    "the word in a string": "text = 'import requests'\n",
    "an ordinary dictionary lookup": "def f(d, k):\n    return d.get(k)\n",
    "a settings lookup": "def f(environment):\n    return environment.get('X')\n",
    "an ordinary method named like a verb": "def f(o):\n    return o.close()\n",
    "importing a name that contains star": "from os import path\n",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", sorted(SIMPLE_BAD))
def test_every_banned_construct_is_caught_in_any_file(label):
    assert find_unfixed_destinations(SIMPLE_BAD[label], "app/other.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", sorted(SIMPLE_GOOD))
def test_ordinary_code_is_not_flagged(label):
    assert find_unfixed_destinations(SIMPLE_GOOD[label], "app/other.py") == [], f"wrongly flagged: {label}"


@pytest.mark.owasp("A05", 610)
def test_a_problem_names_the_line():
    problems = find_unfixed_destinations("x = 1\ny = 2\nimport socket\n", "app/x.py")
    assert problems and problems[0].startswith("app/x.py:3:")


# ---------------------------------------------------------------------------
# The "bound exactly once" rule is only as good as the list of ways Python can bind a name. These tests check that list against the
# language itself: a table of every binding form, the language's own list of syntax kinds that carry a name, and Python's own
# symbol table.
# ---------------------------------------------------------------------------

# (label, the binding written inside the function body). NAME is replaced by the name under test.
BINDING_FORMS = [
    ("assignment", "NAME = m.url"),
    ("tuple unpacking", "NAME, other = m.pair"),
    ("parenthesised unpacking", "(NAME, other) = m.pair"),
    ("list unpacking", "[NAME, other] = m.pair"),
    ("starred unpacking", "*NAME, other = m.items"),
    ("nested unpacking", "(other, (NAME, more)) = m.pair"),
    ("chained assignment", "other = NAME = m.url"),
    ("annotated assignment", "NAME: str = m.url"),
    ("augmented assignment", "NAME += m.suffix"),
    ("for loop", "for NAME in items:\n    pass"),
    ("for loop over a tuple", "for (NAME, other) in items:\n    pass"),
    ("with statement", "with m.open() as NAME:\n    pass"),
    ("with statement, tuple", "with m.open() as (NAME, other):\n    pass"),
    ("except handler", "try:\n    m.go()\nexcept ValueError as NAME:\n    pass"),
    ("except-star handler", "try:\n    m.go()\nexcept* ValueError as NAME:\n    pass"),
    ("import", "import NAME"),
    ("import dotted", "import NAME.sub"),
    ("import as", "import os.path as NAME"),
    ("from import", "from os import NAME"),
    ("from import as", "from os import path as NAME"),
    ("def", "def NAME():\n    pass"),
    ("async def", "async def NAME():\n    pass"),
    ("class", "class NAME:\n    pass"),
    ("walrus", "(NAME := m.url)"),
    ("list comprehension target", "[0 for NAME in items]"),
    ("set comprehension target", "{0 for NAME in items}"),
    ("dict comprehension target", "{0: 0 for NAME in items}"),
    ("generator target", "(0 for NAME in items)"),
    ("delete", "del NAME"),
    ("global declaration", "global NAME"),
    ("lambda parameter", "f = lambda NAME: 0"),
    ("lambda star parameter", "f = lambda *NAME: 0"),
    ("lambda double-star parameter", "f = lambda **NAME: 0"),
    ("lambda keyword-only parameter", "f = lambda *, NAME: 0"),
    ("nested def parameter", "def inner(NAME):\n    pass"),
    ("nested def star parameter", "def inner(*NAME):\n    pass"),
    ("nested def double-star parameter", "def inner(**NAME):\n    pass"),
    ("nested def keyword-only parameter", "def inner(*, NAME):\n    pass"),
    ("nested def positional-only parameter", "def inner(NAME, /):\n    pass"),
    ("nested def default value parameter", "def inner(NAME=1):\n    pass"),
    ("match capture", "match m.x:\n    case NAME:\n        pass"),
    ("match as", "match m.x:\n    case str() as NAME:\n        pass"),
    ("match star", "match m.x:\n    case [*NAME]:\n        pass"),
    ("match mapping rest", "match m.x:\n    case {'a': 1, **NAME}:\n        pass"),
    ("match class capture", "match m.x:\n    case str(NAME):\n        pass"),
    ("type alias", "type NAME = int"),
    ("generic def type parameter", "def inner[NAME]():\n    pass"),
    ("generic def paramspec", "def inner[**NAME]():\n    pass"),
    ("generic def typevartuple", "def inner[*NAME]():\n    pass"),
    ("generic class type parameter", "class Inner[NAME]:\n    pass"),
]
SIGNATURE_FORMS = [
    ("parameter", "NAME"),
    ("star parameter", "*NAME"),
    ("double-star parameter", "**NAME"),
    ("keyword-only parameter", "*, NAME"),
    ("positional-only parameter", "NAME, /"),
    ("parameter with a default", "NAME=1"),
]
# `global` for a name that is a parameter is a SyntaxError in Python itself, so that one row cannot apply to a parameter.
PARAMETER_FORMS = [form for form in BINDING_FORMS if form[0] != "global declaration"]


# The lookup file with the binding written into the method that makes the one call, before the call.
def lookup_with_binding(name, binding):
    body = textwrap.indent(binding.replace("NAME", name), "        ")
    return lookup(body + "\n" + GOOD_CALL)


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_the_address_name_is_caught(label, binding):
    caught = lookup_with_binding("SEARCH_PATH", binding)
    compile(caught, label, "exec")
    assert find_unfixed_destinations(caught, "app/lookup.py") != [], f"not caught: {label}"
    assert find_unfixed_destinations(lookup_with_binding("SEARCH_PATH", "pass"), "app/lookup.py") == [], f"the control wrongly fails: {label}"
    # also when the binding sits in a method that makes no call at all
    elsewhere = lookup(GOOD_CALL) + "\n    def other(self, m, items):\n" + textwrap.indent(binding.replace("NAME", "SEARCH_PATH"), "        ") + "\n"
    compile(elsewhere, label, "exec")
    assert find_unfixed_destinations(elsewhere, "app/lookup.py") != [], f"not caught in another method: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_parameter_named_like_the_address_is_caught(label, parameter):
    source = lookup(GOOD_CALL).replace("def __call__(self, job):", f"def __call__(self, {parameter.replace('NAME', 'SEARCH_PATH')}):")
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/lookup.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, binding", PARAMETER_FORMS, ids=[label for label, _ in PARAMETER_FORMS])
def test_every_way_of_binding_the_topic_parameter_is_caught_wherever_it_sits(label, binding):
    def program(body, layout):
        indented = textwrap.indent(body, "    ")
        lines = {
            "before": f"{indented}\n    producer.produce(topic, key=key)\n",
            "after": f"    producer.produce(topic, key=key)\n{indented}\n",
            "middle": f"    first = 1\n{indented}\n    producer.produce(topic, key=key)\n    last = 2\n",
        }[layout]
        return worker(lines.rstrip("\n"))

    for layout in ("before", "after", "middle"):
        caught = program(binding.replace("NAME", "topic"), layout)
        compile(caught, label, "exec")
        assert find_unfixed_destinations(caught, "app/worker.py") != [], f"not caught: {label}, {layout}"
        assert find_unfixed_destinations(program("pass", layout), "app/worker.py") == [], f"the control wrongly fails: {label}, {layout}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_a_topic_constant_is_caught(label, binding):
    source = worker(GOOD_PRODUCE) + "\n\ndef other(m, items):\n" + textwrap.indent(binding.replace("NAME", "RESULT_TOPIC"), "    ") + "\n"
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_nested_function_parameter_with_the_topics_name_is_caught(label, parameter):
    body = f"    def inner({parameter.replace('NAME', 'topic')}):\n        pass\n    producer.produce(topic, key=key)"
    source = worker(body)
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("parameter", ["*topic", "**topic"])
def test_a_star_parameter_is_never_the_topic(parameter):
    source = worker(GOOD_PRODUCE).replace("def _deliver(producer, topic, key, value, headers=None):", f"def _deliver(producer, {parameter}):")
    compile(source, "star", "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != []


# In plain English: the table above must cover EVERY kind of syntax that can carry a name. This lists those kinds from the language
# itself. If a newer Python adds one, or the scanner stops covering one, this fails and says which.
@pytest.mark.owasp("A05", 610)
def test_the_binding_table_covers_every_syntax_kind_that_can_carry_a_name():
    fields = {"name", "asname", "arg", "vararg", "kwarg", "rest", "optional_vars", "target", "targets", "names"}
    in_the_language = {
        cls.__name__
        for cls in vars(ast).values()
        if isinstance(cls, type) and issubclass(cls, ast.AST) and fields & set(getattr(cls, "_fields", ()))
    }
    accounted_for = {
        # each of these binds a name, and has rows in BINDING_FORMS or SIGNATURE_FORMS
        "Assign", "AnnAssign", "AugAssign", "For", "AsyncFor", "comprehension", "withitem", "ExceptHandler", "alias", "Import",
        "ImportFrom", "FunctionDef", "AsyncFunctionDef", "ClassDef", "arguments", "arg", "NamedExpr", "Delete", "Global",
        "Nonlocal", "MatchAs", "MatchStar", "MatchMapping", "TypeAlias", "TypeVar", "ParamSpec", "TypeVarTuple",
        # this one carries a name but binds nothing: it is the name of a keyword argument in a call, f(name=value)
        "keyword",
    }
    assert in_the_language == accounted_for, (in_the_language ^ accounted_for)


# In plain English: names_bound_by must agree with Python's own record of which names a program binds. Python's symbol table lists,
# for every scope, the names that are assigned, are parameters, are imported or are defined as a function or class. The scanner
# must report every one of them.
@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_the_scanner_agrees_with_pythons_own_symbol_table(label, binding):
    import symtable

    body = "def g(m, items):\n" + textwrap.indent(binding.replace("NAME", "NAME"), "    ") + "\n"
    source = "TARGET = 1\n" + body
    scanner_bound = set()
    for node in ast.walk(ast.parse(source)):
        scanner_bound |= names_bound_by(node)

    def python_bound(table):
        names = {
            symbol.get_name()
            for symbol in table.get_symbols()
            if symbol.is_assigned() or symbol.is_parameter() or symbol.is_imported() or symbol.is_namespace() or symbol.is_declared_global()
        }
        for child in table.get_children():
            names |= python_bound(child)
        return names

    assert "NAME" in python_bound(symtable.symtable(source, "<test>", "exec")), f"the row does not really bind the name: {label}"
    assert "NAME" in scanner_bound, f"the scanner misses a binding Python reports: {label}"
