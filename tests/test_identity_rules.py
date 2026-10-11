# In plain English: tests that the service decides who a caller is from ONE thing only: the key in the
# Authorization header (the grader has no inbound keys yet, so this scan keeps it that way). Not from the caller's network address, not from a Referer or Origin header, not from a
# host name or a reverse DNS lookup, and not from how the address was spelled. And a password or key setting
# never has a built-in default, so a missing or empty one stops the service instead of opening it.
#
# Why it matters (OWASP A07, authentication failures): everything other than the key can be forged or changed
# by the caller (CWE-291 reliance on an IP address, CWE-293 the Referer field, CWE-350 reverse DNS), the same
# address can be written many ways to slip past an exact-match check (CWE-288 and 289 alternate path or
# name), and a default or empty password is a password everyone knows (CWE-258, 1392, 1393).
#
# Like the other code scanners, the scan proves itself with deliberately bad and good programs.
import ast
import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent / "app"

# Headers that say something about WHERE or WHO a request claims to come from. None of them may be read: they are
# all set by the caller, or by whatever sits in front of it, and none proves who the caller is.
IDENTITY_HEADERS = {
    "x-forwarded-for", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-user",
    "referer", "referrer", "origin", "host", "cookie", "user-agent", "remote-addr", "remote_addr", "x-caller", "x-service-name",
}
NETWORK_NAMES = {"gethostbyaddr", "gethostbyname", "gethostbyname_ex", "getfqdn", "getnameinfo", "getpeername", "getaddrinfo", "inet_aton", "inet_ntoa"}
SECRET_SETTING = re.compile(r"(?i)(^|[^a-z])(password|passwd|secret|token|keys?|credential)s?($|[^a-z])")


# In plain English: reads one Python file's text and returns a list of (what was found, line).
def find_identity_problems(source):
    tree = ast.parse(source)
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "client":
            problems.append(("reads the caller's network address (.client)", node.lineno))
        if isinstance(node, (ast.Name, ast.Attribute)) and (node.id if isinstance(node, ast.Name) else node.attr) in NETWORK_NAMES:
            problems.append(("looks up a network address or host name", node.lineno))
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
            if text.strip().lower() in IDENTITY_HEADERS:
                problems.append((f"mentions the header {text.strip().lower()}", node.lineno))
        # Every header read must be the Authorization header, spelled as a plain string.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "get" and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "headers":
            first = node.args[0] if node.args else None
            if not (isinstance(first, ast.Constant) and str(first.value).lower() == "authorization"):
                problems.append(("reads a header other than authorization", node.lineno))
        if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute) and node.value.attr == "headers":
            key = node.slice
            if not (isinstance(key, ast.Constant) and str(key.value).lower() == "authorization"):
                problems.append(("reads a header other than authorization", node.lineno))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("items", "keys", "values", "getlist", "raw", "multi_items") and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == "headers":
            problems.append(("lists the request headers", node.lineno))
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in ("headers", "client", "server", "query_string"):
            problems.append(("reaches into the raw request", node.lineno))
        # A password, key, secret or token setting may never have a built-in default.
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "getenv") and node.args:
            name = node.args[0]
            if isinstance(name, ast.Constant) and isinstance(name.value, str) and SECRET_SETTING.search(name.value):
                defaults = list(node.args[1:]) + [k.value for k in node.keywords if k.arg == "default"]
                # An empty default is fine: no value means the service stays closed. Any real value is a built-in secret.
                if any(not (isinstance(d, ast.Constant) and d.value in ("", None)) for d in defaults):
                    problems.append((f"gives {name.value} a default value", node.lineno))
    return sorted(set(problems), key=lambda p: p[1])


def app_files():
    return sorted(APP.glob("*.py"))


# ---------- The real code ----------

@pytest.mark.owasp("A07", 291, 293, 350, 258, 1392, 1393)
@pytest.mark.owasp("A04", 321)
@pytest.mark.owasp("A06", 454, 472, 598, 807)
def test_identity_uses_only_the_key_and_no_secret_setting_has_a_default():
    files = app_files()
    assert files, "no application files were found to check"
    found = {path.name: find_identity_problems(path.read_text(encoding="utf-8")) for path in files}
    assert {name: problems for name, problems in found.items() if problems} == {}


@pytest.mark.owasp("A07", 291, 293, 350)
def test_the_check_covers_the_real_application_files():
    names = {path.name for path in app_files()}
    assert {"main.py", "errors.py", "secret_files.py", "logsafe.py"} <= names


# ---------- The check proves itself ----------

BAD = {
    "the caller's address": "def f(request):\n    return request.client.host\n",
    "the client on any object": "def f(r):\n    return r.client\n",
    "a forwarded address header": "def f(request):\n    return request.headers.get('X-Forwarded-For')\n",
    "the referer": "def f(request):\n    return request.headers.get('referer')\n",
    "the origin": "def f(request):\n    return request.headers['Origin']\n",
    "the host header": "def f(request):\n    return request.headers.get('host')\n",
    "a header spelled by a variable": "def f(request, name):\n    return request.headers.get(name)\n",
    "any other header": "def f(request):\n    return request.headers.get('x-api-user')\n",
    "a cookie": "def f(request):\n    return request.headers.get('cookie')\n",
    "a list of identity header names": "NAMES = ('referer', 'origin', 'user-agent')\n",
    "a header name written as bytes": "def f(scope):\n    return [v for k, v in scope['x'] if k == b'x-forwarded-for']\n",
    "a header subscripted by a variable": "def f(request, name):\n    return request.headers[name]\n",
    "listing every header": "def f(request):\n    return dict(request.headers.items())\n",
    "the raw header list": "def f(request):\n    return request.scope['headers']\n",
    "the raw client pair": "def f(request):\n    return request.scope['client']\n",
    "a reverse lookup": "import socket\n\ndef f(ip):\n    return socket.gethostbyaddr(ip)\n",
    "a host name lookup": "import socket\n\ndef f():\n    return socket.getfqdn()\n",
    "a password with a default": "import os\n\npassword = os.environ.get('DB_PASSWORD', 'changeme')\n",
    "a key with a default": "import os\n\nkeys = os.environ.get('SERVICE_KEYS', 'dev-key')\n",
    "a token with getenv and a default": "import os\n\ntoken = os.getenv('API_TOKEN', 'x')\n",
    "a secret with a default keyword": "import os\n\ns = os.environ.get('MY_SECRET', default='x')\n",
}

GOOD = {
    "reading the authorization header": "def f(request):\n    return request.headers.get('authorization')\n",
    "reading it with another spelling": "def f(request):\n    return request.headers['Authorization']\n",
    "a password with no default": "import os\n\npassword = os.environ.get('DB_PASSWORD')\n",
    "a setting that is not secret may have a default": "import os\n\nport = os.environ.get('DB_PORT', '5432')\n",
    "a word that merely contains key": "def f(item):\n    return item.get('keyboard', 1)\n",
    "an empty default for the key setting": "import os\n\nraw = os.environ.get('SERVICE_KEYS', '')\n",
    "a none default": "import os\n\nraw = os.environ.get('DB_PASSWORD', None)\n",
    "response headers are not request headers": "def f():\n    return {'WWW-Authenticate': 'Bearer'}\n",
}


@pytest.mark.owasp("A07", 291, 293, 350, 258, 1392, 1393)
@pytest.mark.parametrize("label", sorted(BAD))
def test_every_bad_program_is_caught(label):
    assert find_identity_problems(BAD[label]), label


@pytest.mark.owasp("A07", 291, 293, 350, 258, 1392, 1393)
@pytest.mark.parametrize("label", sorted(GOOD))
def test_good_programs_are_not_flagged(label):
    assert find_identity_problems(GOOD[label]) == []
