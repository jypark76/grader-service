# In plain English: tests that the grader reads every grading job strictly, exactly as the written contract
# (platform/contracts/grading-jobs.md) says, and builds its answer exactly as grading-results.md says. A job the
# contract does not allow is refused with a short reason code, never repaired, and the reason never contains the
# student's text.
#
# Why it matters (OWASP A05, injection and A08, integrity): a job is untrusted input that carries student writing, so
# it is checked at the boundary (CWE-20), read as plain JSON with no code loading (CWE-502), refused when it has a
# field it does not know (CWE-915), and refused when it hides a repeated field or odd text (CWE-115, 116, 159).
import json
import uuid

import pytest

from app import jobs
from app.jobs import build_result, read_job


def good_value(**change):
    data = {
        "schema_version": 1,
        "submission_id": str(uuid.uuid4()),
        "based_on_version": 1,
        "assignment_id": str(uuid.uuid4()),
        "rubric": "Grade for clarity and evidence.",
        "student_work": "Photosynthesis turns light into sugar.",
    }
    data.update(change)
    return data


def encode(data):
    return json.dumps(data).encode("utf-8")


def keyed(data):
    return data["submission_id"].encode(), encode(data)


def _without(field):
    data = good_value()
    key = data["submission_id"].encode()
    del data[field]
    return key, encode(data)


# ---------- A good job ----------

def test_a_good_job_is_accepted():
    data = good_value()
    kind, job = read_job(*keyed(data))
    assert kind == "job"
    assert str(job.submission_id) == data["submission_id"]
    assert job.based_on_version == 1 and job.feedback is None
    assert job.student_work == "Photosynthesis turns light into sugar."


def test_feedback_is_optional_and_kept_exactly():
    data = good_value(feedback="  Please use more evidence.  ")
    kind, job = read_job(*keyed(data))
    assert kind == "job" and job.feedback == "  Please use more evidence.  "


def test_the_texts_are_kept_exactly_as_written_spaces_and_all():
    kind, job = read_job(*keyed(good_value(rubric=" r ", student_work="  w\n")))
    assert kind == "job" and job.rubric == " r " and job.student_work == "  w\n"


def test_the_key_may_be_written_in_capitals():
    data = good_value()
    assert read_job(data["submission_id"].upper().encode(), encode(data))[0] == "job"


# ---------- Every kind of bad message ----------

def bad_cases():
    other_key = str(uuid.uuid4()).encode()
    return {
        "invalid_json": (other_key, b"{not json", "invalid_json"),
        "not_utf8": (other_key, b"\xff\xfe", "invalid_json"),
        "not_an_object": (other_key, b"[1, 2]", "invalid_json"),
        "a_bare_string": (other_key, b'"hello"', "invalid_json"),
        "empty_value": (other_key, None, "invalid_json"),
        "repeated_field": (other_key, b'{"schema_version": 1, "schema_version": 1}', "invalid_json"),
        "nan_number": (other_key, b'{"schema_version": 1, "based_on_version": NaN}', "invalid_json"),
        "infinity_number": (other_key, b'{"schema_version": Infinity}', "invalid_json"),
        "deeply_nested": (other_key, b"[" * 100_000, "invalid_json"),
        "unknown_version": (*keyed(good_value(schema_version=2)), "unknown_schema_version"),
        "missing_version": (*_without("schema_version"), "unknown_schema_version"),
        "version_true_is_not_one": (*keyed(good_value(schema_version=True)), "unknown_schema_version"),
        "version_as_text": (*keyed(good_value(schema_version="1")), "unknown_schema_version"),
        "version_one_point_zero": (*keyed(good_value(schema_version=1.5)), "unknown_schema_version"),
        "missing_submission_id": (*_without("submission_id"), "invalid_field"),
        "missing_rubric": (*_without("rubric"), "invalid_field"),
        "missing_work": (*_without("student_work"), "invalid_field"),
        "bad_uuid": (*keyed(good_value(assignment_id="nope")), "invalid_field"),
        "version_zero": (*keyed(good_value(based_on_version=0)), "invalid_field"),
        "version_as_text_for_based_on": (*keyed(good_value(based_on_version="1")), "invalid_field"),
        "version_as_a_float": (*keyed(good_value(based_on_version=1.0)), "invalid_field"),
        "version_as_true": (*keyed(good_value(based_on_version=True)), "invalid_field"),
        "assignment_id_with_braces": (*keyed(good_value(assignment_id="{" + str(uuid.uuid4()) + "}")), "invalid_field"),
        "assignment_id_without_hyphens": (*keyed(good_value(assignment_id=uuid.uuid4().hex)), "invalid_field"),
        "assignment_id_with_a_newline": (*keyed(good_value(assignment_id=str(uuid.uuid4()) + "\n")), "invalid_field"),
        "assignment_id_as_a_number": (*keyed(good_value(assignment_id=12345)), "invalid_field"),
        "extra_field": (*keyed(good_value(student_name="Ann")), "invalid_field"),
        "extra_field_with_a_scary_name": (*keyed(good_value(**{"__class__": "x"})), "invalid_field"),
        "blank_rubric": (*keyed(good_value(rubric="   ")), "invalid_field"),
        "blank_work": (*keyed(good_value(student_work="")), "invalid_field"),
        "blank_feedback": (*keyed(good_value(feedback="  ")), "invalid_field"),
        "null_character": (*keyed(good_value(student_work="a\x00b")), "invalid_field"),
        "half_a_character": (*keyed(good_value(student_work="a\ud800b")), "invalid_field"),
        "rubric_too_long": (*keyed(good_value(rubric="r" * 10_001)), "invalid_field"),
        "work_too_long": (*keyed(good_value(student_work="w" * 20_001)), "invalid_field"),
        "feedback_too_long": (*keyed(good_value(feedback="f" * 10_001)), "invalid_field"),
        "work_is_a_list": (*keyed(good_value(student_work=["x"])), "invalid_field"),
        "key_mismatch": (other_key, encode(good_value()), "key_mismatch"),
        "key_missing": (None, encode(good_value()), "key_mismatch"),
        "key_not_a_uuid": (b"hello", encode(good_value()), "key_mismatch"),
        "key_not_utf8": (b"\xff", encode(good_value()), "key_mismatch"),
    }


@pytest.mark.owasp("A05", 20, 115, 116, 159)
@pytest.mark.owasp("A08", 502, 915)
@pytest.mark.parametrize("name", sorted(bad_cases()))
def test_a_bad_message_is_refused_with_its_code(name):
    key, value, reason = bad_cases()[name]
    assert read_job(key, value) == ("dead_letter", reason)


# The key must be the submission ID written the normal way. Python's own reader accepts other spellings of the same
# number, and those must not get through, because they could carry a line break into a log line.
@pytest.mark.owasp("A05", 20)
@pytest.mark.owasp("A09", 117)
@pytest.mark.parametrize(
    "spelling",
    [
        lambda i: "{" + i + "}",
        lambda i: i.replace("-", ""),
        lambda i: "urn:uuid:" + i,
        lambda i: " " + i,
        lambda i: i + "\n",
        lambda i: i + "\r\n",
        lambda i: "+" + i,
        lambda i: "0x" + i.replace("-", ""),
    ],
)
def test_a_key_that_is_not_the_normal_spelling_is_refused(spelling):
    data = good_value()
    key = spelling(data["submission_id"]).encode()
    assert read_job(key, encode(data)) == ("dead_letter", "key_mismatch")


# ---------- The limits ----------

def test_the_longest_allowed_job_is_accepted():
    data = good_value(rubric="r" * 10_000, student_work="w" * 20_000, feedback="f" * 10_000)
    assert read_job(*keyed(data))[0] == "job"


@pytest.mark.owasp("A06", 183)
def test_the_limits_equal_the_contract_table():
    # platform/contracts/grading-jobs.md and grading-results.md: change a limit there, in the assessment service and
    # here in the same piece of work. This test fails first if only one side moves.
    assert (jobs.RUBRIC_MAX, jobs.WORK_MAX, jobs.FEEDBACK_MAX) == (10_000, 20_000, 10_000)
    assert (jobs.GRADE_MAX, jobs.REASONING_MAX) == (20, 10_000)


@pytest.mark.owasp("A09", 532)
def test_the_reason_never_contains_the_student_text():
    data = good_value(student_work="STUDENT-MARKER", rubric="")
    assert "STUDENT-MARKER" not in repr(read_job(*keyed(data)))
    assert "STUDENT-MARKER" not in repr(read_job(b"nope", encode(good_value(student_work="STUDENT-MARKER"))))


# ---------- The answer ----------

def good_job():
    return read_job(*keyed(good_value(based_on_version=3)))[1]


def test_the_answer_follows_the_contract_exactly():
    job = good_job()
    key, value = build_result(job, "A", "Clear and correct.")
    assert key == str(job.submission_id).encode()
    assert json.loads(value) == {
        "schema_version": 1,
        "submission_id": str(job.submission_id),
        "based_on_version": 3,
        "ai_grade": "A",
        "ai_reasoning": "Clear and correct.",
    }


def test_the_grade_is_trimmed_and_the_reasoning_is_kept_exactly():
    key, value = build_result(good_job(), "  A  ", "  because\n")
    data = json.loads(value)
    assert data["ai_grade"] == "A" and data["ai_reasoning"] == "  because\n"


def test_the_longest_allowed_answer_is_built():
    build_result(good_job(), "g" * 20, "r" * 10_000)


@pytest.mark.owasp("A05", 20)
@pytest.mark.parametrize(
    "grade, reasoning",
    [("", "ok"), ("   ", "ok"), ("g" * 21, "ok"), ("A", ""), ("A", "   "), ("A", "r" * 10_001), ("A\x00", "ok"), ("A", "x\x00"), ("A", "\ud800")],
)
def test_an_answer_the_contract_would_refuse_is_never_built(grade, reasoning):
    with pytest.raises(ValueError):
        build_result(good_job(), grade, reasoning)


@pytest.mark.owasp("A09", 532)
def test_a_refused_answer_does_not_carry_the_text_in_its_error():
    with pytest.raises(ValueError) as problem:
        build_result(good_job(), "A", "SECRET-MARKER" + "r" * 10_001)
    assert "SECRET-MARKER" not in str(problem.value)
