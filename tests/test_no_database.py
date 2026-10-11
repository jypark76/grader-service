# In plain English: a guardrail that keeps the grader free of any database. The grader is stateless: grading jobs
# arrive over Kafka and results go back over Kafka, so there is nothing to store. Without a database there is no SQL
# to inject into, no stored student text to leak, and no database login to protect. If a database is ever added,
# this test goes red until the decision is made on purpose in a pull request (and the SQL guardrails from the other
# services are brought over with it).
#
# Why it matters (OWASP A05 and A06): no SQL means no SQL injection (CWE-89, 564), and no stored data means nothing
# at rest to protect for this service (CWE-311, 312, 313; see the coverage notes).
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app"
DATABASE_MODULES = {"psycopg", "psycopg2", "sqlite3", "sqlalchemy", "asyncpg", "pymysql", "mysql", "pymongo", "redis", "peewee", "databases", "tortoise"}


def find_database_use(source):
    problems = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            problems += [alias.name for alias in node.names if alias.name.split(".")[0] in DATABASE_MODULES]
        elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in DATABASE_MODULES:
            problems.append(node.module)
    return problems


@pytest.mark.owasp("A05", 89, 564)
def test_the_application_imports_no_database_library():
    files = sorted(APP.rglob("*.py"))
    assert files
    found = {path.name: find_database_use(path.read_text(encoding="utf-8")) for path in files}
    assert {name: used for name, used in found.items() if used} == {}


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


@pytest.mark.owasp("A05", 89, 564)
@pytest.mark.parametrize(
    "label, source",
    [
        ("psycopg", "import psycopg\n"),
        ("sqlite3", "import sqlite3\n"),
        ("sqlalchemy", "from sqlalchemy import text\n"),
        ("asyncpg with a dot", "import asyncpg.pool\n"),
        ("redis", "import redis\n"),
    ],
)
def test_the_check_catches_every_database_library(label, source):
    assert find_database_use(source), label


@pytest.mark.owasp("A05", 89, 564)
@pytest.mark.parametrize("source", ["import json\n", "from fastapi import FastAPI\n", "# import psycopg\nx = 1\n", "name = 'sqlite3'\n"])
def test_the_check_ignores_everything_else(source):
    assert find_database_use(source) == []
