# In plain English: the main code guardrail. Every file in app/ has an entry in tests/allowed_table.py that lists, completely, what that
# file may use: the packages it imports, the functions and methods it calls, the attributes it reads, the built-in names it touches,
# the keyword names it passes and the errors it catches. This test reads each file, lists what it really uses, and fails when the file
# uses anything its entry does not list. It also fails when an entry lists something the file no longer uses, because a stale
# allowance would quietly permit a future change.
#
# Why it is built this way: a list of forbidden things is an arms race, because whoever writes the next trick only has to think of one
# thing nobody listed. A list of ALLOWED things has no such gap. A new import, a new call, an alias, a function passed around as a
# value, a hidden way to reach a name by text: none of them is on the list, so all of them turn this test red until a pull request
# that someone reads adds them on purpose. The same test therefore covers running commands or code from text, unsafe loading, files and
# redirects, uploads, cryptography, error handling, configuration, who the caller is, and the database (the grader has none).
#
# Besides the file lists, three rules need no table: the whole environment (where passwords live) may only be handed, alone, to the
# settings functions; a hand-written set of headers may only be built in the one file allowed to; and an error handler must do
# something with the error.
#
# The check proves itself in three ways: tests/allowed_bad_programs.py holds deliberately bad programs that must each be refused;
# the "mechanism" tests below add one extra thing of every kind to a small program and show it is refused; and each kind of entry is
# shown to be reported as stale when it is no longer used.
import ast
from pathlib import Path

import pytest

import allowed_code
from allowed_bad_programs import APPENDED, CORPORA
from allowed_table import TABLE

APP = Path(__file__).resolve().parent.parent / "app"
ROOT = APP.parent


def app_sources():
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(APP.glob("*.py"))}


# ---------- The real code ----------

def test_the_table_lists_exactly_the_files_in_app():
    assert set(app_sources()) == set(TABLE) - {"<all files>"}
    assert {"main.py", "errors.py", "secret_files.py", "logsafe.py", "lookup.py", "worker.py"} <= set(app_sources())


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
@pytest.mark.owasp("A02", 15, 489, 526, 611, 776, 942)
@pytest.mark.owasp("A04", 261, 296, 321, 323, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 757, 759, 760, 780, 916, 1240, 1241)
@pytest.mark.owasp("A05", 77, 78, 88, 89, 94, 95, 470, 564)
@pytest.mark.owasp("A06", 73, 434, 454, 472, 598, 646, 676, 807)
@pytest.mark.owasp("A07", 258, 291, 293, 350, 1392, 1393)
@pytest.mark.owasp("A08", 426, 427, 502)
@pytest.mark.owasp("A10", 215, 390, 391, 396, 460)
def test_every_app_file_uses_only_what_its_entry_allows():
    problems = []
    for name, source in app_sources().items():
        problems += allowed_code.compare(source, f"app/{name}", TABLE)[0]
    assert problems == [], "\n".join(problems)


def test_nothing_allowed_is_unused():
    stale = []
    for name, source in app_sources().items():
        stale += allowed_code.compare(source, f"app/{name}", TABLE)[1]
    assert stale == [], "\n".join(stale)


# In plain English: the kinds of code any file may use must all be used somewhere, or the list could hide a permission nobody needs.
def test_every_allowed_kind_of_code_is_used_somewhere():
    used = set()
    for source in app_sources().values():
        used |= allowed_code.facts_of(source)[0]["kinds"]
    assert used == set(TABLE["<all files>"]["kinds"]), used ^ set(TABLE["<all files>"]["kinds"])


def test_the_listed_settings_functions_and_header_file_are_real():
    everywhere = TABLE["<all files>"]
    text = "\n".join(app_sources().values())
    for name in everywhere["environment_receivers"]:
        assert f"def {name}(" in text, name
    assert set(everywhere["header_literal_files"]) <= set(app_sources())


# ---------- The check proves itself: deliberately bad programs ----------

# Every bad program must be refused whichever file it is pretended to sit in (the worker, the lookup, the secret reader, the app itself),
# so a file that happens to allow one thing, such as open, cannot let a different bad thing through.
def assert_refused_everywhere(category, label):
    source = CORPORA[category]["programs"][label]
    ast.parse(source)
    for filename in ("worker.py", "lookup.py", "secret_files.py", "main.py"):
        extra, _ = allowed_code.compare(source, f"app/{filename}", TABLE)
        assert extra, f"not refused in {filename}: {category}: {label}"


@pytest.mark.owasp("A05", 77, 78, 88, 94, 95, 470)
@pytest.mark.owasp("A06", 676)
@pytest.mark.owasp("A08", 426, 427, 502)
@pytest.mark.parametrize("label", sorted(CORPORA['running code from text, commands and unsafe loading']["programs"]))
def test_every_bad_program_about_run_code_is_refused(label):
    assert_refused_everywhere('running code from text, commands and unsafe loading', label)


@pytest.mark.owasp("A04", 261, 296, 323, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 757, 759, 760, 780, 916, 1240, 1241)
@pytest.mark.parametrize("label", sorted(CORPORA['cryptography']["programs"]))
def test_every_bad_program_about_cryptography_is_refused(label):
    assert_refused_everywhere('cryptography', label)


@pytest.mark.owasp("A02", 489)
@pytest.mark.owasp("A10", 215, 390, 391, 396, 460)
@pytest.mark.parametrize("label", sorted(CORPORA['error handling and debug leftovers']["programs"]))
def test_every_bad_program_about_errors_is_refused(label):
    assert_refused_everywhere('error handling and debug leftovers', label)


@pytest.mark.owasp("A02", 15, 526, 611, 776, 942)
@pytest.mark.owasp("A06", 454)
@pytest.mark.parametrize("label", sorted(CORPORA['configuration, cross-domain and XML']["programs"]))
def test_every_bad_program_about_configuration_is_refused(label):
    assert_refused_everywhere('configuration, cross-domain and XML', label)


@pytest.mark.owasp("A04", 321)
@pytest.mark.owasp("A06", 454, 472, 598, 807)
@pytest.mark.owasp("A07", 258, 291, 293, 350, 1392, 1393)
@pytest.mark.parametrize("label", sorted(CORPORA['who the caller is and secret defaults']["programs"]))
def test_every_bad_program_about_identity_is_refused(label):
    assert_refused_everywhere('who the caller is and secret defaults', label)


@pytest.mark.owasp("A01", 22, 23, 36, 59, 61, 65, 219, 377, 379, 548, 552, 601)
@pytest.mark.owasp("A06", 73)
@pytest.mark.parametrize("label", sorted(CORPORA['files, folders, redirects']["programs"]))
def test_every_bad_program_about_files_is_refused(label):
    assert_refused_everywhere('files, folders, redirects', label)


@pytest.mark.owasp("A06", 434, 646)
@pytest.mark.parametrize("label", sorted(CORPORA['uploads and forms']["programs"]))
def test_every_bad_program_about_uploads_is_refused(label):
    assert_refused_everywhere('uploads and forms', label)


@pytest.mark.owasp("A05", 89, 564)
@pytest.mark.parametrize("label", sorted(CORPORA['no database']["programs"]))
def test_every_bad_program_about_database_is_refused(label):
    assert_refused_everywhere('no database', label)


# ---------- The check proves itself: a sneaked capability using only names the file already uses ----------

APPENDED_CASES = [(filename, label) for filename, programs in APPENDED.items() for label in programs]


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A01", 441, 918)
@pytest.mark.owasp("A07", 941)
@pytest.mark.owasp("A02", 15, 526, 942)
@pytest.mark.parametrize("filename, label", APPENDED_CASES)
def test_every_sneaked_capability_is_refused(filename, label):
    source = (APP / filename).read_text(encoding="utf-8") + "\n\n" + APPENDED[filename][label]
    ast.parse(source)
    extra, _ = allowed_code.compare(source, f"app/{filename}", TABLE)
    assert extra, f"not refused in {filename}: {label}"


# ---------- The check proves itself: one extra thing of every kind ----------

BASE = """\
import json


def settings(environment):
    return environment.get("X")


def go(value):
    try:
        return json.loads(value)
    except ValueError:
        return None
"""


SENSITIVE = ("json.loads",)  # in the made-up program below, json.loads stands for a call that reaches outside, like open


# In plain English: a table that allows exactly what the given program uses and nothing more, for one made-up file called a.py.
def exact_table(source, kinds_from=None):
    facts, _ = allowed_code.facts_of(source, SENSITIVE)
    entry = {key: tuple(sorted(facts[key])) for key in ("imports", "calls", "values", "names", "keywords", "handlers", "sites")}
    kinds = allowed_code.facts_of(kinds_from or source)[0]["kinds"]
    return {
        "<all files>": {"kinds": tuple(sorted(kinds)), "environment_receivers": ("settings",), "header_literal_files": ("a.py",), "sensitive_calls": SENSITIVE},
        "a.py": entry,
        "b.py": entry,
    }


def test_a_program_that_uses_exactly_what_is_listed_is_clean():
    assert allowed_code.compare(BASE, "app/a.py", exact_table(BASE)) == ([], [])


EXTRAS = {
    "an import": ("import os\n", "import os"),
    "the pinned call made in another function": ("def more(v):\n    return json.loads(v)\n", "json.loads(v) in more"),
    "a from-import": ("from os import path\n", "from os import path"),
    "an import with a nickname": ("import json as j\n", "import json as j"),
    "a star import": ("from os import *\n", "from os import *"),
    "a call": ("def more(v):\n    return v.strip()\n", "v.strip"),
    "a call on a result": ("def more(v):\n    return json.loads(v).get(1)\n", "json.loads(v).get"),
    "an attribute read": ("def more(v):\n    return v.size\n", "v.size"),
    "a method kept as a value": ("def more(v):\n    f = v.strip\n    return f\n", "v.strip"),
    "a built-in name": ("def more(v):\n    return v is eval\n", "eval"),
    "a built-in called": ("def more(v):\n    return open(v)\n", "open"),
    "a keyword name": ("def more(v):\n    return json.loads(v, strict=False)\n", "strict"),
    "a ** expansion": ("def more(environment, k):\n    return environment.get(**k)\n", "**"),
    "a * expansion": ("def more(environment, k):\n    return environment.get(*k)\n", "*"),
    "another error caught": ("def more(v):\n    try:\n        return json.loads(v)\n    except KeyError:\n        return 1\n", "KeyError"),
    "a bare except": ("def more(v):\n    try:\n        return json.loads(v)\n    except:\n        return 1\n", "BARE"),
    "a kind of code nobody may use": ("f = lambda: 1\n", "Lambda"),
    "a built-in name used for something else": ("def more(id):\n    return 1\n", "id"),
    "an imported name re-bound": ("json = 1\n", "json"),
    "a module used as a value": ("x = json\n", "json"),
}


@pytest.mark.parametrize("label", sorted(EXTRAS))
def test_one_extra_thing_of_every_kind_is_refused(label):
    snippet, mentioned = EXTRAS[label]
    source = BASE + "\n\n" + snippet
    extra, _ = allowed_code.compare(source, "app/a.py", exact_table(BASE))
    assert extra, label
    assert any(mentioned in sentence for sentence in extra), (label, extra)


STRUCTURE = {
    "a handler that only passes": "def more(v):\n    try:\n        json.loads(v)\n    except ValueError:\n        pass\n",
    "a handler that only continues": "def more(v):\n    for i in v:\n        try:\n            json.loads(i)\n        except ValueError:\n            continue\n",
    "a handler with only a string": "def more(v):\n    try:\n        json.loads(v)\n    except ValueError:\n        'ignored'\n",
    "a return in finally": "def more(v):\n    try:\n        json.loads(v)\n    finally:\n        return 1\n",
    "a break in finally": "def more(v):\n    for i in v:\n        try:\n            json.loads(i)\n        finally:\n            break\n",
    "a setting with a default": 'def more(environment):\n    return environment.get("X", "dflt")\n',
    "a setting with a default keyword": 'def more(environment):\n    return environment.get("X", default="d")\n',
    "the whole environment logged": "import os\n\nlog = [os.environ]\n",
    "the whole environment given with another argument": "import os\n\nsettings(os.environ, 1)\n",
    "the whole environment given by keyword": "import os\n\nsettings(environment=os.environ)\n",
    "the whole environment read by key": "import os\n\nvalue = os.environ['X']\n",
    "the whole environment in a text": "import os\n\ntext = f'{os.environ}'\n",
    "the whole environment given to another function": "import os\n\nother(os.environ)\n",
    "a hand-written set of headers": "def more(v):\n    return Response(headers={'a': 'b'})\n",
}


@pytest.mark.parametrize("label", sorted(STRUCTURE))
def test_the_rules_that_need_no_table_refuse_their_cases_even_when_everything_is_listed(label):
    source = BASE + "\n\n" + STRUCTURE[label]
    table = exact_table(source)  # every import, call and name in it is allowed, so only the structural rule can refuse it
    extra, _ = allowed_code.compare(source, "app/b.py", table)
    assert extra, label


GOOD_STRUCTURE = {
    "the environment given alone to a settings function": "import os\n\nsettings(os.environ)\n",
    "a setting read without a default": 'def more(environment):\n    return environment.get("X")\n',
    "a handler that acts": "def more(v):\n    try:\n        json.loads(v)\n    except ValueError:\n        raise\n",
    "a finally that calls": "def more(v):\n    try:\n        json.loads(v)\n    finally:\n        v.close()\n",
}


@pytest.mark.parametrize("label", sorted(GOOD_STRUCTURE))
def test_the_rules_that_need_no_table_allow_their_good_cases(label):
    source = BASE + "\n\n" + GOOD_STRUCTURE[label]
    assert allowed_code.compare(source, "app/b.py", exact_table(source)) == ([], [])


def test_a_set_of_headers_is_allowed_only_in_the_listed_file():
    source = BASE + "\n\n" + "def more(v):\n    return Response(headers={'a': 'b'})\n"
    table = exact_table(source)
    assert allowed_code.compare(source, "app/a.py", table) == ([], [])
    assert allowed_code.compare(source, "app/b.py", table)[0] != []


def test_a_file_that_is_not_in_the_table_is_refused():
    extra, _ = allowed_code.compare("x = 1\n", "app/new_file.py", TABLE)
    assert extra and "not in the allowed table" in extra[0]


def test_the_pinned_call_made_twice_in_its_own_function_is_refused():
    source = BASE.replace("        return json.loads(value)", "        json.loads(value)\n        return json.loads(value)")
    extra, _ = allowed_code.compare(source, "app/a.py", exact_table(BASE))
    assert extra and "json.loads(value) in go x2" in extra[0]


STALE = {
    "a pinned call site": ("sites", "json.loads(v) in elsewhere x1"),
    "an import": ("imports", "import os"),
    "a call": ("calls", "json.dumps"),
    "an attribute": ("values", "v.size"),
    "a built-in name": ("names", "len"),
    "a keyword name": ("keywords", "strict"),
    "an error handler": ("handlers", "go: KeyError"),
}


@pytest.mark.parametrize("label", sorted(STALE))
def test_an_allowance_that_is_no_longer_used_is_reported(label):
    key, item = STALE[label]
    table = exact_table(BASE)
    table["a.py"][key] = table["a.py"][key] + (item,)
    extra, stale = allowed_code.compare(BASE, "app/a.py", table)
    assert extra == [] and stale and item in stale[0], label


# ---------- Things the grader promises that are not about one file ----------

@pytest.mark.owasp("A05", 89, 564)
def test_there_is_no_database_folder_no_sql_file_and_no_database_library_in_the_lock():
    assert not (ROOT / "db").exists()
    skipped = {".git", ".venv", "docs-private", "node_modules"}
    sql_files = [p for p in ROOT.rglob("*.sql") if not (set(p.relative_to(ROOT).parts) & skipped)]
    assert sql_files == []
    for lock in ("requirements.txt", "requirements.in"):
        text = (ROOT / lock).read_text(encoding="utf-8").lower()
        for name in ("psycopg", "sqlalchemy", "asyncpg", "pymysql", "pymongo", "redis"):
            assert name not in text, (lock, name)


# With no SQL file anywhere, no SQL can hash weakly or make predictable identifiers (the SQL checks of the other services come with a database).
@pytest.mark.owasp("A04", 327, 328, 326, 1240, 330, 338, 340, 342, 1241, 916)
def test_there_is_no_sql_so_nothing_in_it_can_use_a_weak_hash_or_a_predictable_identifier():
    assert [p for p in ROOT.rglob("*") if p.suffix in {".sql"} and ".git" not in p.parts and "docs-private" not in p.parts] == []


@pytest.mark.owasp("A10", 215)
@pytest.mark.owasp("A02", 489)
def test_the_running_app_is_not_in_debug_mode():
    from app.main import app

    assert app.debug is False


@pytest.mark.owasp("A02", 547)
def test_the_security_relevant_constants_have_the_agreed_values():
    # These values decide how much is logged and what the fixed replies say. They live in one place each, with a
    # comment, and this test pins them, so changing one is a deliberate decision made in a pull request that also
    # changes this test, never a quiet edit.
    from app import errors, logsafe

    assert logsafe.PATH_LOG_LENGTH == 100
    assert errors.FIXED_PROBLEMS[404] == "Not found" and errors.UNEXPECTED_PROBLEM == "Something went wrong"
    assert errors.PLAIN_PROBLEM == "The request could not be completed"


@pytest.mark.owasp("A02", 547)
def test_the_security_relevant_constants_are_defined_once_in_the_code():
    import re

    definitions = {}
    for name, source in app_sources().items():
        for match in re.finditer(r"(?m)^(PATH_LOG_LENGTH|SECRET_FOLDER)\s*=", source):
            definitions.setdefault(match.group(1), []).append(name)
    assert definitions == {"PATH_LOG_LENGTH": ["logsafe.py"], "SECRET_FOLDER": ["secret_files.py"]}
