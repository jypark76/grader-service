# In plain English: a guardrail that keeps this service from ever reaching a place chosen by someone
# else. The service must not open connections to addresses it was handed in a request or a message, and
# the Kafka topics it reads and writes must be fixed names written in the code or taken from settings,
# never built from a message.
#
# Why it matters: if a request or message could pick the address or the topic, an attacker could make
# the service call an internal system, leak data to their own server or read someone else's topic
# (OWASP A05 CWE-610 "externally controlled reference to a resource", and the server-side request
# forgery family in A01).
#
# It reads the program text (it never runs it). Its own tests feed it small bad and good programs, so it
# cannot pass by finding nothing.
import ast
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# Modules that open connections to other machines. This service makes no outbound connection yet. When the Kafka
# reader and the knowledge-service lookup are added, they are added here on purpose.
# Anything else in app/ must be a deliberate decision, so adding it must change this list.
OUTBOUND_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "http", "socket", "aiohttp", "websockets", "ftplib", "smtplib",
    "telnetlib", "xmlrpc", "poplib", "imaplib", "paramiko", "grpc",
}

# The one deliberate exception: the file that is allowed to import an outbound module, and which module. Every other
# file stays banned. The lookup (app/lookup.py) asks the knowledge service for similar examples; its address is a
# deploy-time setting and its path a fixed word (tests/test_lookup.py proves that, and that redirects are not followed).
ALLOWED_OUTBOUND = {"lookup.py": {"httpx"}}

# Calls whose first argument names a Kafka topic.
TOPIC_CALLS = {"produce", "subscribe"}

# Methods of a web client that take the address (or path) to call, and where that argument sits. In an allowed file
# the address must be a fixed word (a text or a named constant), never something computed from a message.
ADDRESS_CALLS = {"get": 0, "post": 0, "put": 0, "patch": 0, "delete": 0, "head": 0, "options": 0, "request": 1, "stream": 1, "send": 0}
# In every OTHER file the rule applies too, but not to "get", "head" and "options": those names are also dictionary and
# settings lookups all over normal code. The sending methods are checked everywhere, so a web client handed to some
# other file cannot be pointed at a computed address either.
ADDRESS_CALLS_EVERYWHERE = {name: place for name, place in ADDRESS_CALLS.items() if name not in ("get", "head", "options")}

# In plain English: reads one program's text and returns plain sentences, one per problem, each with
# its line number.
def find_unfixed_destinations(source, name="<code>"):
    tree = ast.parse(source)
    problems = []
    allowed = ALLOWED_OUTBOUND.get(name.rsplit("/", 1)[-1], set())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in OUTBOUND_MODULES and alias.name.split(".")[0] not in allowed:
                    problems.append(f"{name}:{node.lineno}: imports '{alias.name}', which opens connections to other machines")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in OUTBOUND_MODULES and (node.module or "").split(".")[0] not in allowed:
                problems.append(f"{name}:{node.lineno}: imports from '{node.module}', which opens connections to other machines")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in (ADDRESS_CALLS if allowed else ADDRESS_CALLS_EVERYWHERE) and len(node.args) > ADDRESS_CALLS[node.func.attr]:
            address = node.args[ADDRESS_CALLS[node.func.attr]]
            fixed = isinstance(address, ast.Name) or (isinstance(address, ast.Constant) and isinstance(address.value, str))
            if not fixed:
                problems.append(f"{name}:{node.lineno}: the address given to '{node.func.attr}' is computed, not a fixed word")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in TOPIC_CALLS:
            if not node.args:
                continue
            first = node.args[0]
            options = first.elts if isinstance(first, (ast.List, ast.Tuple)) else [first]
            for option in options:
                fixed = isinstance(option, ast.Name) or (isinstance(option, ast.Constant) and isinstance(option.value, str))
                if not fixed:
                    problems.append(f"{name}:{node.lineno}: the topic given to '{node.func.attr}' is computed, not a fixed name")
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
    assert {"main.py", "errors.py", "secret_files.py", "logsafe.py", "lookup.py"} <= names


# In plain English: the one allowance must still be needed (the file really imports that module) and must stay as narrow
# as written: any other file importing it, or the allowed file importing another outbound module, is still caught.
@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
def test_the_one_allowance_is_still_needed_and_stays_narrow():
    assert ALLOWED_OUTBOUND == {"lookup.py": {"httpx"}}
    text = (APP / "lookup.py").read_text(encoding="utf-8")
    assert "import httpx" in text
    assert find_unfixed_destinations("import httpx\n", "app/lookup.py") == []
    assert find_unfixed_destinations("import httpx\n", "app/other.py") != []
    assert find_unfixed_destinations("import requests\n", "app/lookup.py") != []
    assert find_unfixed_destinations("import socket\n", "app/lookup.py") != []
    assert find_unfixed_destinations("import httpx\n", "lookup.py.txt") != []


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize(
    "source",
    [
        "def f(client, m):\n    client.post(m.url)\n",
        "def f(client, m):\n    client.post(f'/x/{m}')\n",
        "def f(client, m):\n    client.post('/x/' + m)\n",
        "def f(client, m):\n    client.stream('POST', m['path'])\n",
        "def f(client, m):\n    client.request('GET', m.path)\n",
        "def f(client, m):\n    client.get(m.url.lower())\n",
    ],
)
def test_in_the_allowed_file_a_computed_address_is_still_caught(source):
    assert find_unfixed_destinations(source, "app/lookup.py") != []


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize(
    "source",
    [
        "PATH = '/x'\ndef f(client):\n    client.post(PATH)\n",
        "def f(client):\n    client.post('/examples/search')\n",
        "PATH = '/x'\ndef f(client):\n    client.stream('POST', PATH, json={})\n",
        "def f(d):\n    return d.get('key')\n",
    ],
)
def test_in_the_allowed_file_a_fixed_address_passes(source):
    assert find_unfixed_destinations(source, "app/lookup.py") == []


# ---------------------------------------------------------------------------
# Self-tests: the check must complain about each bad program and stay quiet for good ones.
# ---------------------------------------------------------------------------

BAD_PROGRAMS = {
    "requests": "import requests\nrequests.get('http://x')\n",
    "requests with a nickname": "import requests as r\n",
    "from requests import": "from requests import get\n",
    "httpx": "import httpx\n",
    "urllib.request": "import urllib.request\n",
    "from urllib import": "from urllib import request\n",
    "http.client": "import http.client\n",
    "socket": "import socket\n",
    "smtplib": "import smtplib\n",
    "aiohttp": "import aiohttp\n",
    "an f-string topic": "def f(p, m):\n    p.produce(f'topic-{m}', key=b'k')\n",
    "a topic from a function call": "def f(p, m):\n    p.produce(m.topic(), key=b'k')\n",
    "a topic from a dictionary": "def f(p, m):\n    p.produce(m['topic'])\n",
    "a topic joined from text": "def f(p, m):\n    p.produce('a-' + m)\n",
    "a subscribe list with a computed item": "def f(c, m):\n    c.subscribe([m.topic])\n",
}

GOOD_PROGRAMS = {
    "a fixed topic name": "def f(p):\n    p.produce('approved-examples', key=b'k')\n",
    "a named constant": "TOPIC = 'x'\ndef f(c):\n    c.subscribe([TOPIC])\n",
    "a topic given as a parameter name": "def f(p, topic):\n    p.produce(topic, key=b'k')\n",
    "the database driver": "import psycopg\n",
    "the kafka client": "from confluent_kafka import Consumer\n",
    "the word in a comment": "# we never import requests or socket here\nx = 1\n",
    "the word in a string": "text = 'import requests'\n",
}


@pytest.mark.owasp("A05", 610)
def test_every_bad_program_is_caught():
    for label, source in BAD_PROGRAMS.items():
        assert find_unfixed_destinations(source), f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
def test_every_good_program_passes():
    for label, source in GOOD_PROGRAMS.items():
        assert find_unfixed_destinations(source) == [], f"wrongly flagged: {label}: {find_unfixed_destinations(source)}"


# In plain English: in a file that is NOT allowed to use a web client, a call that sends something to a computed address is
# still caught, and ordinary dictionary and settings lookups are not mistaken for one.
@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize(
    "source",
    [
        "def f(client, m):\n    client.post(m.url)\n",
        "def f(client, m):\n    client.put(f'/x/{m}')\n",
        "def f(client, m):\n    client.stream('POST', m['path'])\n",
        "def f(client, m):\n    client.request('GET', m.path)\n",
        "def f(client, m):\n    client.send(m.request)\n",
    ],
)
def test_in_any_file_a_computed_address_for_a_sending_call_is_caught(source):
    assert find_unfixed_destinations(source, "app/other.py") != []


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize(
    "source",
    [
        "def f(d, m):\n    return d.get(m.key)\n",
        "def f(environment):\n    return environment.get('KNOWLEDGE_URL')\n",
        "def f(headers, m):\n    return headers.get(m.name)\n",
        "PATH = '/x'\ndef f(client):\n    client.post(PATH)\n",
    ],
)
def test_in_any_file_ordinary_lookups_and_fixed_addresses_pass(source):
    assert find_unfixed_destinations(source, "app/other.py") == []
