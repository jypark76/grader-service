# In plain English: shared test setup. It checks every OWASP tag before any test runs and switches on the
# coverage report.
import os

import pytest

import owasp_report
import owasp_tags


# In plain English: before any test runs, check every OWASP tag. A malformed tag (wrong category, a
# CWE number that is not a number, a repeat) stops the whole run with a message naming the test,
# because a wrong tag would show a guardrail as covered when it is not.
def pytest_collection_modifyitems(items):
    try:
        owasp_tags.check_items(items)
    except ValueError as problem:
        raise pytest.UsageError(f"bad owasp tag: {problem}") from None


# In plain English: switches on the coverage report (owasp_report.py) for every run.
def pytest_configure(config):
    config.pluginmanager.register(owasp_report.OwaspReport(config), "owasp-report")
