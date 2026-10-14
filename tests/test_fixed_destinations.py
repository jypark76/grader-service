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
# the address must be a fixed word (a text, or a name that is a text constant written once at the top of the file), never
# something computed from a message and never a variable, however it was made.
ADDRESS_CALLS = {"get": 0, "post": 0, "put": 0, "patch": 0, "delete": 0, "head": 0, "options": 0, "request": 1, "stream": 1, "send": 0}
# In every OTHER file the rule applies too, but not to "get", "head" and "options": those names are also dictionary and
# settings lookups all over normal code. The sending methods are checked everywhere, so a web client handed to some
# other file cannot be pointed at a computed address either.
ADDRESS_CALLS_EVERYWHERE = {name: place for name, place in ADDRESS_CALLS.items() if name not in ("get", "head", "options")}

# In plain English: every name that ONE piece of code binds, meaning gives a value to, declares, imports, defines or deletes.
# This list is Python's own: it covers every syntax tree node type that can carry a name (the test below checks the list
# against the language itself, so a new kind of binding added by a future Python makes a test fail instead of slipping by).
def names_bound_by(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return {node.id}  # =, :=, +=, for, with ... as, comprehensions, del, tuple and star unpacking, type X = ...
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


# In plain English: the names in a file that are a fixed word. A name counts only if the file gives it a value in exactly one
# kind of place: a text written straight into the code at the top of the file (`PATH = "/x"` or `PATH: str = "/x"`). If ANY
# other piece of code anywhere in the file binds the same name, in any way at all (see names_bound_by), it is not a fixed word,
# however constant it looks at the call.
def fixed_words(tree):
    plain_targets = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            plain_targets |= {id(target) for target in node.targets if isinstance(target, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            plain_targets.add(id(node.target))
    plain, other = set(), set()
    for node in ast.walk(tree):
        if id(node) in plain_targets:
            plain.add(node.id)
        else:
            other |= names_bound_by(node)
    return plain - other


# In plain English: the ordinary parameters of the function that contains this call (not *args or **kwargs, which are a tuple and
# a dictionary and never one fixed topic), minus every name that function (or anything inside it, nested functions and lambdas
# included) binds again, wherever in the function that happens. A Kafka topic may be such a parameter: the worker passes the fixed
# topic constants into one small helper, and the helper never changes them.
def unchanged_parameters(call, parents):
    function = call
    while function in parents:
        function = parents[function]
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = function.args
            parameters = {argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
            rebound = set()
            for statement in function.body:
                for part in ast.walk(statement):
                    rebound |= names_bound_by(part)
            return parameters - rebound
    return set()


# In plain English: reads one program's text and returns plain sentences, one per problem, each with
# its line number.
def find_unfixed_destinations(source, name="<code>"):
    tree = ast.parse(source)
    problems = []
    words = fixed_words(tree)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
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
            fixed = (isinstance(address, ast.Name) and address.id in words) or (isinstance(address, ast.Constant) and isinstance(address.value, str))
            if not fixed:
                problems.append(f"{name}:{node.lineno}: the address given to '{node.func.attr}' is computed, not a fixed word")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in TOPIC_CALLS:
            if not node.args:
                continue
            first = node.args[0]
            options = first.elts if isinstance(first, (ast.List, ast.Tuple)) else [first]
            for option in options:
                fixed = (isinstance(option, ast.Name) and (option.id in words or option.id in unchanged_parameters(node, parents))) or (isinstance(option, ast.Constant) and isinstance(option.value, str))
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


# In plain English: a plain variable name is NOT automatically a fixed word. Only a name that is a text constant written once
# at the top of the file counts. A variable made from a message (`p = m.url; client.post(p)`), a parameter, or a constant
# that some code later overwrites does not. (For a Kafka topic, a parameter of the enclosing function is also accepted, as long
# as the function never reassigns it, because the worker passes the fixed topic constants into one small helper.)
@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize(
    "label, source",
    [
        ("an alias of a computed value", "def f(client, m):\n    p = m.url\n    client.post(p)\n"),
        ("an alias of an f-string", "def f(client, m):\n    p = f'/x/{m}'\n    client.stream('POST', p)\n"),
        ("an alias made in two steps", "def f(client, m):\n    a = m.url\n    p = a\n    client.request('GET', p)\n"),
        ("an alias of a constant is not the constant", "PATH = '/x'\ndef f(client):\n    p = PATH\n    client.post(p)\n"),
        ("a parameter used as the address", "def f(client, path):\n    client.post(path)\n"),
        ("a constant overwritten inside a function", "PATH = '/x'\ndef f(client, m):\n    global PATH\n    PATH = m.url\n    client.post(PATH)\n"),
        ("a constant changed with +=", "PATH = '/x'\ndef f(client, m):\n    global PATH\n    PATH += m.suffix\n    client.post(PATH)\n"),
        ("a constant assigned twice", "PATH = '/x'\nPATH = compute()\ndef f(client):\n    client.post(PATH)\n"),
        ("a constant that is a computed value from the start", "PATH = compute()\ndef f(client):\n    client.post(PATH)\n"),
        ("a name taken from a loop", "def f(client, items):\n    for p in items:\n        client.post(p)\n"),
        ("a name from the walrus operator", "def f(client, m):\n    if (p := m.url):\n        client.post(p)\n"),
        ("a constant that a loop later re-binds", "PATH = '/x'\ndef f(client, items):\n    for PATH in items:\n        client.post(PATH)\n"),
        ("a constant that the walrus operator later re-binds", "PATH = '/x'\ndef f(client, m):\n    if (PATH := m.url):\n        client.post(PATH)\n"),
        ("a constant that a with-block later re-binds", "PATH = '/x'\ndef f(client, m):\n    with m.open() as PATH:\n        client.post(PATH)\n"),
        ("a constant that a comprehension re-binds", "PATH = '/x'\ndef f(client, items):\n    [client.post(PATH) for PATH in items]\n"),
        ("a text written inside the function", "def f(client):\n    p = '/x'\n    client.post(p)\n"),
        ("a constant that is not a text", "PATH = None\ndef f(client):\n    client.post(PATH)\n"),
        ("a constant that is a number", "PATH = 5\ndef f(client):\n    client.post(PATH)\n"),
        ("an annotated text written inside the function", "def f(client):\n    p: str = '/x'\n    client.post(p)\n"),
        ("an annotated constant that is a number", "PATH: int = 5\ndef f(client):\n    client.post(PATH)\n"),
        ("a constant that is bytes", "PATH = b'/x'\ndef f(client):\n    client.post(PATH)\n"),
        ("an annotated constant that is a call", "PATH: str = compute()\ndef f(client):\n    client.post(PATH)\n"),
        ("an annotated name with no value, then set from a message", "PATH: str\ndef f(client, m):\n    global PATH\n    PATH = m.url\n    client.post(PATH)\n"),
    ],
)
def test_a_variable_that_is_not_a_fixed_constant_is_not_a_fixed_word(label, source):
    assert find_unfixed_destinations(source, "app/other.py") != [], label
    assert find_unfixed_destinations(source, "app/lookup.py") != [], label


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize(
    "label, source",
    [
        ("a topic alias of a computed value", "def f(p, m):\n    t = m.topic\n    p.produce(t)\n"),
        ("a topic parameter that is then overwritten", "def f(p, topic, m):\n    topic = m.topic\n    p.produce(topic)\n"),
        ("a topic that is a name from a loop", "def f(p, items):\n    for t in items:\n        p.produce(t)\n"),
        ("a subscribe list with an alias", "def f(c, m):\n    t = m.topic\n    c.subscribe([t])\n"),
        ("a topic constant overwritten in a function", "TOPIC = 'x'\ndef f(p, m):\n    global TOPIC\n    TOPIC = m.topic\n    p.produce(TOPIC)\n"),
    ],
)
def test_a_topic_that_is_a_variable_made_from_something_else_is_not_a_fixed_name(label, source):
    assert find_unfixed_destinations(source, "app/x.py") != [], label


@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize(
    "source",
    [
        "PATH = '/x'\ndef f(client):\n    client.post(PATH)\n",
        "PATH: str = '/x'\ndef f(client):\n    client.post(PATH)\n",
        "PATH = '/x'\ndef f(client, m):\n    client.stream('POST', PATH, json={'a': m})\n",
        "TOPIC = 'x'\ndef f(p):\n    p.produce(TOPIC)\n",
        "def f(p, topic):\n    p.produce(topic)\n",
        "def f(p, topic, key):\n    p.produce(topic, key=key)\n",
    ],
)
def test_a_text_constant_written_once_and_an_unchanged_topic_parameter_are_fixed(source):
    assert find_unfixed_destinations(source, "app/lookup.py") == []


# ---------------------------------------------------------------------------
# The whole class, not the cases someone thought of. THE RULE: a name is a fixed word only if the file never binds it in any
# way except one text written at the top. Every way Python can bind a name is a row in the table below, written into a small
# program that binds the constant's name that way and then sends to it. Each program must be caught, and each program with the
# binding replaced by `pass` must NOT be (so a catch is really because of the binding). A second test compares the table with
# the list of syntax node types in the language itself.
# ---------------------------------------------------------------------------
import textwrap

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

# The same forms for a Kafka topic that is a parameter of the enclosing function. Python itself refuses `global` for a name that is
# a parameter (a SyntaxError), so that one row cannot apply here.
TOPIC_FORMS = [form for form in BINDING_FORMS if form[0] != "global declaration"]

# Where the name under test is a parameter of the enclosing function itself.
SIGNATURE_FORMS = [
    ("parameter", "NAME"),
    ("star parameter", "*NAME"),
    ("double-star parameter", "**NAME"),
    ("keyword-only parameter", "*, NAME"),
    ("positional-only parameter", "NAME, /"),
    ("parameter with a default", "NAME=1"),
]


def program_with_binding(name, binding, tail):
    body = textwrap.indent(binding.replace("NAME", name), "    ")
    return f"PATH = '/x'\n\ndef g(client, m, items):\n{body}\n    {tail}\n"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_every_way_of_binding_the_constants_name_stops_it_being_a_fixed_address(label, binding):
    caught = program_with_binding("PATH", binding, "client.post(PATH)")
    control = program_with_binding("PATH", "pass", "client.post(PATH)")
    compile(caught, label, "exec")  # the program is real Python, not a typo that fails for the wrong reason
    for name in ("app/lookup.py", "app/other.py"):
        assert find_unfixed_destinations(caught, name) != [], f"not caught: {label}"
        assert find_unfixed_destinations(control, name) == [], f"the control wrongly fails: {label}"
    # the binding may also sit in a different function from the one that sends, or at the top of the file after the constant
    elsewhere = "PATH = '/x'\n\ndef sender(client):\n    client.post(PATH)\n\ndef other(m, items):\n" + textwrap.indent(binding.replace("NAME", "PATH"), "    ") + "\n"
    compile(elsewhere, label, "exec")
    assert find_unfixed_destinations(elsewhere, "app/lookup.py") != [], f"not caught in another function: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_parameter_with_the_constants_name_is_not_the_constant(label, parameter):
    source = f"PATH = '/x'\n\ndef g(client, {parameter.replace('NAME', 'PATH')}):\n    client.post(PATH)\n"
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/lookup.py") != [], f"not caught: {label}"
    assert find_unfixed_destinations(source, "app/other.py") != [], f"not caught: {label}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, binding", TOPIC_FORMS, ids=[label for label, _ in TOPIC_FORMS])
def test_every_way_of_binding_a_topic_parameter_stops_it_being_a_fixed_topic(label, binding):
    def program(body, layout):
        indented = textwrap.indent(body, "    ")
        if layout == "before":
            lines = f"{indented}\n    p.produce(topic)\n"
        elif layout == "after":
            lines = f"    p.produce(topic)\n{indented}\n"
        else:  # in the middle of other statements, not the first and not the last
            lines = f"    first = 1\n{indented}\n    p.produce(topic)\n    last = 2\n"
        return f"def g(p, topic, m, items):\n{lines}"

    for layout in ("before", "after", "middle"):
        caught = program(binding.replace("NAME", "topic"), layout)
        compile(caught, label, "exec")
        assert find_unfixed_destinations(caught, "app/x.py") != [], f"not caught: {label}, {layout}"
        assert find_unfixed_destinations(program("pass", layout), "app/x.py") == [], f"the control wrongly fails: {label}, {layout}"


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("label, parameter", SIGNATURE_FORMS, ids=[label for label, _ in SIGNATURE_FORMS])
def test_a_nested_function_parameter_with_the_topics_name_is_not_the_topic(label, parameter):
    source = f"def g(p, topic):\n    def inner({parameter.replace('NAME', 'topic')}):\n        pass\n    p.produce(topic)\n"
    compile(source, label, "exec")
    assert find_unfixed_destinations(source, "app/x.py") != [], f"not caught: {label}"


# In plain English: the table above must cover EVERY kind of syntax that can carry a name. This lists those kinds from the
# language itself. If a newer Python adds one, or the scanner stops covering one, this fails and says which.
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


# In plain English: names_bound_by must agree with Python's own record of which names a program binds. Python's symbol table
# lists, for every scope, the names that are assigned, are parameters, are imported or are defined as a function or class. The
# names the scanner treats as bound must include all of them.
@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize("label, binding", BINDING_FORMS, ids=[label for label, _ in BINDING_FORMS])
def test_the_scanner_agrees_with_pythons_own_symbol_table(label, binding):
    import symtable

    source = program_with_binding("NAME", binding, "pass")
    tree = ast.parse(source)
    scanner_bound = set()
    for node in ast.walk(tree):
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


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
@pytest.mark.parametrize("parameter", ["*topic", "**topic"])
def test_a_star_parameter_is_never_a_fixed_topic(parameter):
    source = f"def g(p, {parameter}):\n    p.produce(topic)\n"
    compile(source, "star", "exec")
    assert find_unfixed_destinations(source, "app/x.py") != []
