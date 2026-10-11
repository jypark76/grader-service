# In plain English: before grading a job, the worker asks the knowledge service for the few most similar graded examples
# for the same assignment. This is the ONLY place in the grader that opens a connection to another service, and it is
# deliberately narrow:
#   - it talks to one address, taken from a deploy-time setting (KNOWLEDGE_URL), and one fixed path;
#   - nothing from a message can change where it connects: the job only supplies the assignment ID and the student's
#     work, and both travel in the body, never in the address;
#   - it presents the grader's own key, read from a mounted file every time (so a changed key takes effect without a
#     restart), and never logs it;
#   - it follows no redirects and ignores proxy settings, so a reply can never send it somewhere else;
#   - the reply is untrusted too: its size is capped and every field is checked strictly, and a reply that does not
#     fit is refused, never repaired.
# If the knowledge service is down, slow, or answers with anything but a good reply, the lookup raises LookupUnavailable.
# The worker then stops WITHOUT marking the job done, Kubernetes restarts it, and the job is tried again.
import json

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.jobs import _read_json, _normal_uuid
from app.secret_files import read_secret
from app.text_rules import long_text

SEARCH_PATH = "/examples/search"
EXAMPLE_COUNT = 3  # how many similar examples are asked for, and the most that are accepted back
CONNECT_TIMEOUT_SECONDS = 5.0
TOTAL_TIMEOUT_SECONDS = 30.0
MAX_REPLY_BYTES = 1_000_000
KEY_SETTING = "KNOWLEDGE_KEY"  # read through app/secret_files.py: the file named by KNOWLEDGE_KEY_FILE

# The limits knowledge-service keeps on a saved example (platform/contracts/approved-examples.md). A reply with a longer
# text is not something that service can have produced, so it is refused.
WORK_MAX = 20_000
GRADE_MAX = 100
REASONING_MAX = 10_000


class LookupUnavailable(Exception):
    pass


# In plain English: one similar example as the knowledge service sends it. Extra fields are refused. The texts are kept
# exactly as written and must not be blank. The similarity is a plain number between -1 and 1 (a yes/no is not a number).
class SimilarExample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    example_id: str
    assignment_id: str
    same_assignment: bool = Field(strict=True)
    student_work: str
    grade: str
    reasoning: str
    similarity: float

    @field_validator("example_id", "assignment_id", mode="before")
    @classmethod
    def ids_are_written_normally(cls, value):
        return _normal_uuid(value)

    @field_validator("student_work")
    @classmethod
    def work_rules(cls, value):
        return long_text(value, WORK_MAX)

    @field_validator("grade")
    @classmethod
    def grade_rules(cls, value):
        return long_text(value, GRADE_MAX)

    @field_validator("reasoning")
    @classmethod
    def reasoning_rules(cls, value):
        return long_text(value, REASONING_MAX)

    @field_validator("similarity", mode="before")
    @classmethod
    def similarity_is_a_real_number(cls, value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Must be a number")
        if not -1.0 <= value <= 1.0:
            raise ValueError("Must be between -1 and 1")
        return value


# In plain English: checks the address setting. It must be a plain web address of a service (scheme, host and an optional
# port), with no login, no path, no query and no fragment, so what the worker connects to is exactly what was deployed.
# Returns the address without a trailing slash. The error never repeats the setting.
def checked_base_url(value):
    if not value:
        raise RuntimeError("Missing required setting: KNOWLEDGE_URL")
    try:
        url = httpx.URL(value)
    except httpx.InvalidURL:
        raise RuntimeError("KNOWLEDGE_URL is not a valid address") from None
    if url.port is not None and not 1 <= url.port <= 65535:
        raise RuntimeError("KNOWLEDGE_URL is not a valid address")
    if url.scheme not in ("http", "https") or not url.host or url.userinfo or url.path not in ("", "/") or url.query or url.fragment:
        raise RuntimeError("KNOWLEDGE_URL must be a plain address: scheme, host and optional port only")
    return str(url).rstrip("/")


# In plain English: builds the one HTTP client the worker uses. No redirects, no proxy settings from the environment, and
# fixed time limits. The setting is checked first.
def make_client(environment):
    return httpx.Client(
        base_url=checked_base_url(environment.get("KNOWLEDGE_URL")),
        timeout=httpx.Timeout(TOTAL_TIMEOUT_SECONDS, connect=CONNECT_TIMEOUT_SECONDS),
        follow_redirects=False,
        trust_env=False,
    )


# In plain English: reads the reply's bytes, but never more than the cap, so a huge reply cannot use up the worker's memory.
def _read_capped(reply):
    chunks, size = [], 0
    for chunk in reply.iter_bytes():
        size += len(chunk)
        if size > MAX_REPLY_BYTES:
            raise LookupUnavailable("the lookup reply was too large")
        chunks.append(chunk)
    return b"".join(chunks)


# In plain English: the lookup itself. "client" is a parameter so tests can pass a client with a pretend transport.
class KnowledgeLookup:
    def __init__(self, client):
        self.web = client

    # Returns the list of similar examples (at most EXAMPLE_COUNT, possibly none) for this job.
    def __call__(self, job):
        key = read_secret(KEY_SETTING)  # a missing or unreadable key stops the worker; it never falls back to something open
        if not key:
            raise RuntimeError("Missing required setting: KNOWLEDGE_KEY")
        body = {"assignment_id": str(job.assignment_id), "query_text": job.student_work, "limit": EXAMPLE_COUNT}
        try:
            with self.web.stream("POST", SEARCH_PATH, json=body, headers={"Authorization": f"Bearer {key}"}) as reply:
                if reply.status_code != 200:
                    # Only the number is kept: the reply's own text could repeat what we sent.
                    raise LookupUnavailable(f"the lookup answered with status {reply.status_code}")
                raw = _read_capped(reply)
        except httpx.HTTPError:
            raise LookupUnavailable("the lookup could not be reached") from None
        try:
            data = _read_json(raw)
            if not isinstance(data, list) or len(data) > EXAMPLE_COUNT:
                raise ValueError("not a short list")
            return [SimilarExample.model_validate(item) for item in data]
        except (ValueError, ValidationError, RecursionError, TypeError, json.JSONDecodeError):
            raise LookupUnavailable("the lookup reply did not follow the agreed shape") from None
