# In plain English: the rules for one grading job and for the answer sent back, straight from the written contracts
# (platform/contracts/grading-jobs.md and grading-results.md). Nothing in here talks to Kafka: it only decides
# whether a message is acceptable and builds the answer.
#
# Every job is untrusted input: it came from another service over a queue, and its texts are student work, which an
# attacker can write anything into. So each message is read strictly, and a message the contract does not allow is
# refused, never repaired.
import json
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.text_rules import long_text, trimmed

# The limits, written once. A test checks them against the contract table, so a change here fails loudly until the
# contract and the assessment service are changed too.
RUBRIC_MAX = 10_000
WORK_MAX = 20_000
FEEDBACK_MAX = 10_000
GRADE_MAX = 20
REASONING_MAX = 10_000


# In plain English: an identifier in a message must be the normal text form of a UUID (hexadecimal with hyphens). Python's
# own UUID reader also accepts braces, a missing-hyphen form, a "urn:uuid:" prefix, spaces and a trailing newline, none
# of which belong in a message, and a trailing newline could carry a line break into a log line.
NORMAL_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _normal_uuid(value):
    if not isinstance(value, str) or not NORMAL_UUID.fullmatch(value):
        raise ValueError("Must be a UUID written with hyphens")
    return value


# In plain English: the rules for one job. Extra fields are refused. The three texts are kept exactly as written,
# must not be blank, and must fit their limit. Feedback is optional: it is left out of a first-time job.
class GradingJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    submission_id: uuid.UUID
    based_on_version: int = Field(ge=1, strict=True)
    assignment_id: uuid.UUID
    rubric: str
    student_work: str
    feedback: str | None = None

    @field_validator("submission_id", "assignment_id", mode="before")
    @classmethod
    def ids_are_written_normally(cls, value):
        return _normal_uuid(value)

    @field_validator("rubric")
    @classmethod
    def rubric_rules(cls, value):
        return long_text(value, RUBRIC_MAX)

    @field_validator("student_work")
    @classmethod
    def work_rules(cls, value):
        return long_text(value, WORK_MAX)

    @field_validator("feedback")
    @classmethod
    def feedback_rules(cls, value):
        return None if value is None else long_text(value, FEEDBACK_MAX)


# In plain English: the rules for the answer. The grade has its spaces at either end trimmed; the reasoning is kept
# exactly as written. Neither may be blank.
class GradingResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    submission_id: uuid.UUID
    based_on_version: int = Field(ge=1, strict=True)
    ai_grade: str
    ai_reasoning: str

    @field_validator("ai_grade")
    @classmethod
    def grade_rules(cls, value):
        return trimmed(value, GRADE_MAX)

    @field_validator("ai_reasoning")
    @classmethod
    def reasoning_rules(cls, value):
        return long_text(value, REASONING_MAX)


# In plain English: reads a message's JSON strictly. A field named twice is refused, because different programs keep
# different copies (some the first, some the last) and a sender and a reader could then disagree about what the
# message says. NaN and Infinity are refused too: they are not JSON, Python accepts them anyway, and other programs
# do not.
def _no_repeated_fields(pairs):
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ValueError("a field is repeated")
    return dict(pairs)


def _no_special_numbers(token):
    raise ValueError("NaN and Infinity are not JSON")


def _read_json(value):
    return json.loads(value.decode("utf-8"), object_pairs_hook=_no_repeated_fields, parse_constant=_no_special_numbers)


# In plain English: decides whether one message is an acceptable job. It returns ("job", the job) or
# ("dead_letter", a reason code) and never raises for a bad message. The reason codes are the ones in the contract:
# invalid_json, unknown_schema_version, invalid_field and key_mismatch. The reason never contains the student's text.
def read_job(key, value):
    try:
        data = _read_json(value)
    except (AttributeError, UnicodeDecodeError, ValueError, RecursionError):
        return "dead_letter", "invalid_json"
    if not isinstance(data, dict):
        return "dead_letter", "invalid_json"

    version = data.get("schema_version")
    if isinstance(version, bool) or version != 1:
        return "dead_letter", "unknown_schema_version"

    try:
        job = GradingJob.model_validate(data)
    except ValidationError:
        return "dead_letter", "invalid_field"

    # The key must be the submission ID written the normal way (lowercase, with hyphens, or the same in capitals).
    # Python's own UUID reader also accepts odd forms (a trailing newline, spaces, a plus sign, a 0x prefix, braces,
    # no hyphens), which have no business in a key and could carry a line break into a log line.
    try:
        key_text = key.decode("utf-8")
        key_id = uuid.UUID(key_text)
    except (AttributeError, UnicodeDecodeError, ValueError):
        return "dead_letter", "key_mismatch"
    if key_text.lower() != str(key_id) or key_id != job.submission_id:
        return "dead_letter", "key_mismatch"
    return "job", job


# In plain English: builds the key and value of the answer message for one graded job. The key is the submission ID
# as text; the value is the contract's JSON. It raises ValueError if the grade or reasoning would break the contract
# (so a result the assessment service would refuse is never sent). The error never carries the student's text.
def build_result(job, grade, reasoning):
    try:
        result = GradingResult(
            submission_id=job.submission_id,
            based_on_version=job.based_on_version,
            ai_grade=grade,
            ai_reasoning=reasoning,
        )
    except ValidationError:
        # The library's own error text quotes the offending value, which could be the grader's output or the
        # student's words, so it is replaced with fixed wording.
        raise ValueError("The answer does not follow the contract") from None
    value = json.dumps(result.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
    return str(job.submission_id).encode("utf-8"), value
