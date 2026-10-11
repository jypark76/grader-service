# In plain English: a guardrail that keeps the dead-letter reason codes in step with the written contract. The worker
# puts a short reason code in the "error" header of every message it sends to the dead-letter topic. A person reading
# that topic must be able to look every code up in platform/contracts/grading-jobs.md. If someone adds a new reason
# code in the code, this test goes red until the set below is changed on purpose, which is the moment to add the code to
# the contract (and to the contract test in the platform repo) in the same piece of work.
#
# Why it matters: an undocumented code was found in review once (grading_refused), and the same thing happened earlier
# in another service. This turns "remember to update the contract" into a failing test.
import ast
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"

# The reason codes written in platform/contracts/grading-jobs.md. Change this set only together with that file.
AGREED_REASON_CODES = {"invalid_json", "unknown_schema_version", "invalid_field", "key_mismatch", "grading_refused"}


# In plain English: every text that is the second item of a ("dead_letter", "<text>") pair in the code.
def reason_codes_in(source):
    found = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Tuple) and len(node.elts) == 2:
            first, second = node.elts
            if isinstance(first, ast.Constant) and first.value == "dead_letter" and isinstance(second, ast.Constant) and isinstance(second.value, str):
                found.add(second.value)
    return found


def real_codes():
    codes = set()
    for path in sorted(APP.glob("*.py")):
        codes |= reason_codes_in(path.read_text(encoding="utf-8"))
    return codes


def test_the_reason_codes_in_the_code_are_exactly_the_agreed_ones():
    assert real_codes() == AGREED_REASON_CODES


def test_the_scan_finds_a_code_and_ignores_everything_else():
    assert reason_codes_in('def f():\n    return "dead_letter", "new_reason"\n') == {"new_reason"}
    assert reason_codes_in('x = ("dead_letter", reason)\n') == set()
    assert reason_codes_in('x = ("graded", "invalid_json")\n') == set()
    assert reason_codes_in('x = ("dead_letter", "a", "b")\n') == set()
    assert reason_codes_in('# return "dead_letter", "in_a_comment"\ny = "dead_letter, in_a_string"\n') == set()
