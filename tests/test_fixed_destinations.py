# In plain English: a guardrail that keeps this service from ever reaching a place chosen by someone else. A message or a
# request must never be able to pick the address the service connects to, or the Kafka topic it reads or writes.
#
# HOW IT WORKS. There are only two outbound paths in the whole service, and each is one call:
#   - the knowledge-service lookup:  self.web.stream("POST", SEARCH_PATH, json=..., headers=...)   in app/lookup.py
#   - the Kafka send and read:       producer.produce(topic, ...), consumer.subscribe([TOPIC])    in app/worker.py
# tests/test_allowed_code.py already makes sure only the listed files import the web library or Kafka, that only listed calls exist
# anywhere, and that open, the web call, the web client, produce and subscribe appear only at their listed places, exactly once.
# This test adds what a list of names cannot say, the exact SHAPE of those calls:
#   - the web client lives in one place (self.web) and may be used for one call with one exact shape: the method "POST", the
#     address given by the name SEARCH_PATH, and nothing but json and headers; no keyword address, no *args, no **kwargs, no
#     other method, no copy of the client under another name; the client is built once, in make_client, and handed straight back;
#   - SEARCH_PATH is bound exactly once in the file, by a text written at the top (checked against EVERY way Python can bind a
#     name, from the language's own list of syntax kinds and from Python's own symbol table, see the tests at the bottom);
#   - produce is called with the topic an unchanged parameter; subscribe is called with a list holding one text constant bound
#     once; the send helper _deliver may only be called with the two fixed topic constants. (That produce sits only inside _deliver,
#     that the helper has no alias and that no wrapper such as functools.partial exists is the allowed table's job.)
# Why it matters: if a request or message could pick the address or the topic, an attacker could make the service call an
# internal system, leak data to their own server or read someone else's topic (OWASP A05 CWE-610, and the server-side request
# forgery family in A01).
import ast
import textwrap
from pathlib import Path

import pytest

import allowed_code
from allowed_code import names_bound_by
from allowed_table import TABLE

APP = Path(__file__).resolve().parent.parent / "app"

# The files whose outbound call has a pinned shape.
LOOKUP_FILES = {"lookup.py"}
KAFKA_FILES = {"worker.py"}
# The names that fix where the service reaches: each must be a text written once at the top of its file and never bound again.
FIXED_CONSTANTS = {"lookup.py": ("SEARCH_PATH",), "worker.py": ("TOPIC", "RESULT_TOPIC", "DEAD_LETTER_TOPIC")}


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
    # 1. The name httpx is never re-bound.
    if sum(1 for node in ast.walk(tree) if "httpx" in names_bound_by(node)) != 1:
        problems.append(f"{name}: the name httpx must be bound exactly once, by 'import httpx'")
    # 2. The web client lives in self.web, which is only ever used for the one stream call (never copied, passed on or read by itself).
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and ast.unparse(node) == "self.web":
            holder = parents.get(node)
            if isinstance(node.ctx, ast.Store):
                continue
            if not (isinstance(holder, ast.Attribute) and holder.attr == "stream" and isinstance(parents.get(holder), ast.Call) and parents[holder].func is holder):
                problems.append(f"{name}:{node.lineno}: self.web is used other than for the one pinned stream call")
    # 3. The constructor parameter "client" is read exactly once: to set self.web.
    reads = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "client" and isinstance(node.ctx, ast.Load)]
    if len(reads) > 1:
        problems.append(f"{name}: the client parameter is used more than once")
    # 4. The one web client is built in make_client and handed straight back; no other client exists.
    clients = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "httpx.Client"]
    for call in clients:
        function = call
        while function in parents and not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = parents[function]
        in_make_client = isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name == "make_client"
        if len(clients) != 1 or not in_make_client or not isinstance(parents.get(call), ast.Return):
            problems.append(f"{name}:{call.lineno}: the web client must be built exactly once, in make_client, and returned directly")
    return problems


# In plain English: checks what the exact call texts in tests/allowed_table.py cannot say about the worker's Kafka use: the topic the send
# helper uses is its own unchanged parameter, and the names that hold the topics are texts written once and never bound again.
def kafka_problems(tree, name):
    problems = []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    for call in [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "produce"]:
        function = call
        while function in parents and not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = parents[function]
        topic_is_a_parameter = isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and "topic" in {argument.arg for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs}
        rebound = set()
        if topic_is_a_parameter:
            for statement in function.body:
                for part in ast.walk(statement):
                    rebound |= names_bound_by(part)
        if not (topic_is_a_parameter and "topic" not in rebound):
            problems.append(f"{name}:{call.lineno}: the topic given to produce must be an unchanged parameter of its function")
    return problems


# In plain English: the names that fix where the file reaches must each be a text written once at the top and never bound again.
def constant_problems(tree, name, constants):
    return [f"{name}: {constant} must be a text written once at the top of the file and never bound again" for constant in constants if not is_a_text_constant_bound_once(tree, constant)]


# In plain English: only the shapes of the pinned calls (the list of allowed names is tests/test_allowed_code.py).
def pinned_problems(source, name="<code>"):
    tree = ast.parse(source)
    base = name.rsplit("/", 1)[-1]
    problems = []
    if base in LOOKUP_FILES:
        problems += lookup_problems(tree, name)
    if base in KAFKA_FILES:
        problems += kafka_problems(tree, name)
    problems += constant_problems(tree, name, FIXED_CONSTANTS.get(base, ()))
    return problems


# In plain English: the whole check for one file: the pinned shapes, and everything the allowed table refuses.
def find_unfixed_destinations(source, name="<code>"):
    return pinned_problems(source, name) + allowed_code.compare(source, name, TABLE)[0]


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
    assert LOOKUP_FILES == {"lookup.py"} and KAFKA_FILES == {"worker.py"}


# A good lookup file and a good worker file, written out in full. Every bad program below is one of these with one change.
LOOKUP = """\
import httpx

SEARCH_PATH = "/examples/search"


class KnowledgeLookup:
    def __init__(self, client):
        self.web = client

    def __call__(self, job, body, key):
@BODY@
"""
GOOD_CALL = '        with self.web.stream("POST", SEARCH_PATH, json=body, headers={"Authorization": f"Bearer {key}"}) as reply:\n            return reply'
WORKER = """\
TOPIC = "grading-jobs"
RESULT_TOPIC = "grading-results"
DEAD_LETTER_TOPIC = "grading-jobs.dead-letter"


def _deliver(producer, topic, key, value, headers=None):
@BODY@


def run(consumer, producer, detail, message, reason):
    consumer.subscribe([TOPIC])
    _deliver(producer, RESULT_TOPIC, detail[0], detail[1])
    _deliver(producer, DEAD_LETTER_TOPIC, message.key(), message.value(), headers=[("error", reason.encode("utf-8"))])
"""
GOOD_PRODUCE = "    refused = []\n    producer.produce(topic, key=key, value=value, headers=headers, on_delivery=lambda error, _message: refused.append(error) if error else None)"


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
    assert pinned_problems(good, "app/lookup.py") == []
    kept = lookup(GOOD_CALL) + "\n\ndef make_client(environment):\n    c = httpx.Client(base_url=environment)\n    return c\n"
    assert pinned_problems(kept, "app/lookup.py") != []  # built in make_client but not handed straight back
    elsewhere = lookup("        if job:\n            return httpx.Client()\n" + GOOD_CALL)
    assert pinned_problems(elsewhere, "app/lookup.py") != []  # handed straight back, but not built in make_client
    two = good + "\n\ndef make_client2(environment):\n    return httpx.Client(base_url=environment)\n"
    assert pinned_problems(two, "app/lookup.py") != []  # a second client anywhere
    many = lookup(GOOD_CALL) + "\n\ndef make_client(environment):\n    if environment:\n        return httpx.Client(base_url=environment)\n    return httpx.Client()\n"
    assert pinned_problems(many, "app/lookup.py") != []  # two clients, both built in make_client and both returned directly


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


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label", sorted(SIMPLE_BAD))
def test_every_other_way_to_reach_out_is_refused_in_the_files_that_hold_the_pinned_calls(label):
    for filename in ("app/worker.py", "app/lookup.py"):
        assert find_unfixed_destinations(SIMPLE_BAD[label], filename) != [], f"not caught in {filename}: {label}"


# ---------- Findings from reviews, kept as tests so they can never come back ----------

# Each is the good worker plus one extra function. They were found by reviewers, one by one, while the guardrail still worked by
# listing forbidden things. Now none of them is on the allowed list, so each is refused.
REVIEWED = {
    "a client from make_client used to call any address": "def extra(env, m):\n    return make_client(env).get(m.url)\n",
    "the web library taken from the lookup module": "from app.lookup import httpx\n\n\ndef extra(m):\n    return httpx.get(m.url)\n",
    "the send helper copied to another name": "def extra(producer, m):\n    d = _deliver\n    d(producer, m.topic, 1, 2)\n",
    "the send helper wrapped in functools.partial": "import functools\n\n\ndef extra(producer, m):\n    functools.partial(_deliver, producer, m.topic)()\n",
    "the send helper renamed, with a computed topic": "def _send(producer, topic, key, value, headers=None):\n    producer.produce(topic, key=key, value=value)\n\n\ndef extra(producer, m):\n    _send(producer, m.topic, 1, 2)\n",
    "a socket opened by asyncio": "import asyncio\n\n\nasync def extra(m):\n    return await asyncio.open_connection(m.host, 80)\n",
    "a connection made by anyio": "import anyio\n",
    "a connection made by multiprocessing": "import multiprocessing.connection\n",
    "a module nobody listed": "import nntplib\n",
}


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label", sorted(REVIEWED))
def test_every_gap_a_reviewer_found_is_closed(label):
    source = worker(GOOD_PRODUCE) + "\n\n" + REVIEWED[label]
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/worker.py") != [], f"not caught: {label}"


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
    assert pinned_problems(caught, "app/lookup.py") != [], f"not caught: {label}"
    assert pinned_problems(lookup_with_binding("SEARCH_PATH", "pass"), "app/lookup.py") == [], f"the control wrongly fails: {label}"
    # also when the binding sits in a method that makes no call at all
    elsewhere = lookup(GOOD_CALL) + "\n    def other(self, m, items):\n" + textwrap.indent(binding.replace("NAME", "SEARCH_PATH"), "        ") + "\n"
    compile(elsewhere, label, "exec")
    assert pinned_problems(elsewhere, "app/lookup.py") != [], f"not caught in another method: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_parameter_named_like_the_address_is_caught(label, parameter):
    source = lookup(GOOD_CALL).replace("def __call__(self, job, body, key):", f"def __call__(self, body, key, {parameter.replace('NAME', 'SEARCH_PATH')}):")
    compile(source, label, "exec")
    assert pinned_problems(source, "app/lookup.py") != [], f"not caught: {label}"


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
        assert pinned_problems(caught, "app/worker.py") != [], f"not caught: {label}, {layout}"
        assert pinned_problems(program("pass", layout), "app/worker.py") == [], f"the control wrongly fails: {label}, {layout}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_a_topic_constant_is_caught(label, binding):
    source = worker(GOOD_PRODUCE) + "\n\ndef other(m, items):\n" + textwrap.indent(binding.replace("NAME", "RESULT_TOPIC"), "    ") + "\n"
    compile(source, label, "exec")
    assert pinned_problems(source, "app/worker.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_nested_function_parameter_with_the_topics_name_is_caught(label, parameter):
    body = f"    def inner({parameter.replace('NAME', 'topic')}):\n        pass\n    producer.produce(topic, key=key)"
    source = worker(body)
    compile(source, label, "exec")
    assert pinned_problems(source, "app/worker.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("parameter", ["*topic", "**topic"])
def test_a_star_parameter_is_never_the_topic(parameter):
    source = worker(GOOD_PRODUCE).replace("def _deliver(producer, topic, key, value, headers=None):", f"def _deliver(producer, {parameter}):")
    compile(source, "star", "exec")
    assert pinned_problems(source, "app/worker.py") != []


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
