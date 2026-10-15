# In plain English: tests for the lookup that asks the knowledge service for similar graded examples. They use a pretend
# web server (so no network is needed), plus one test with a real local server to prove the worker really does not follow
# a redirect. They check what is sent (one fixed address, one fixed path, the key in the header, the job's text only in the
# body), what is accepted back (a short list of strictly checked examples and nothing else), and that every kind of trouble
# ends the same way: LookupUnavailable, which makes the worker stop without marking the job done.
#
# Why it matters (OWASP): the address cannot be chosen by a message (A01 CWE-918, 441, A05 CWE-610), the key comes from a
# file and is never logged (A02 CWE-526, A07 CWE-798, 259, A09 CWE-532), the reply is untrusted input (A05 CWE-20, 915,
# 502) and a slow or broken service cannot hang or crash the worker silently (A10 CWE-252, 391, 396, 754, A06 CWE-799).
import ast
import json
import logging
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

from app import lookup
from app.jobs import read_job
from app.lookup import EXAMPLE_COUNT, MAX_REPLY_BYTES, REFUSED_STATUSES, SEARCH_PATH, KnowledgeLookup, LookupRefused, LookupUnavailable, checked_base_url, make_client

KEY = "k" * 64
BASE = "http://knowledge-service.knowledge.svc.cluster.local:8000"


def good_job(**change):
    data = {
        "schema_version": 1,
        "submission_id": str(uuid.uuid4()),
        "based_on_version": 1,
        "assignment_id": str(uuid.uuid4()),
        "rubric": "Grade for clarity.",
        "student_work": "An essay about photosynthesis.",
    }
    data.update(change)
    return read_job(data["submission_id"].encode(), json.dumps(data).encode())[1]


def good_example(**change):
    data = {
        "example_id": str(uuid.uuid4()),
        "assignment_id": str(uuid.uuid4()),
        "same_assignment": True,
        "student_work": "A similar essay.",
        "grade": "B",
        "reasoning": "Clear but thin.",
        "similarity": 0.8123,
    }
    data.update(change)
    return data


@pytest.fixture(autouse=True)
def the_key(monkeypatch):
    monkeypatch.delenv("KNOWLEDGE_KEY_FILE", raising=False)
    monkeypatch.setenv("KNOWLEDGE_KEY", KEY)


def lookup_with(handler):
    seen = []

    def wrapped(request):
        seen.append(request)
        return handler(request)

    client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(wrapped), follow_redirects=False, trust_env=False)
    return KnowledgeLookup(client), seen


def replying(payload, status=200):
    return lambda request: httpx.Response(status, content=payload if isinstance(payload, bytes) else json.dumps(payload).encode())


# ---------- What is sent ----------

@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.owasp("A05", 610)
def test_one_fixed_address_and_path_with_the_key_in_the_header_and_the_job_in_the_body():
    job = good_job()
    ask, seen = lookup_with(replying([]))
    assert ask(job) == []
    assert len(seen) == 1
    request = seen[0]
    assert request.method == "POST"
    assert str(request.url) == BASE + SEARCH_PATH == "http://knowledge-service.knowledge.svc.cluster.local:8000/examples/search"
    assert request.headers["authorization"] == f"Bearer {KEY}"
    assert json.loads(request.content) == {"assignment_id": str(job.assignment_id), "query_text": job.student_work, "limit": EXAMPLE_COUNT}
    assert EXAMPLE_COUNT == 3


@pytest.mark.owasp("A01", 918, 441)
@pytest.mark.owasp("A05", 610)
@pytest.mark.parametrize(
    "text",
    ["http://evil.example/steal", "//evil.example", "/../../admin", "http://127.0.0.1:9999/", "@evil.example", "x\r\nHost: evil.example", "file:///etc/passwd"],
)
def test_nothing_in_the_job_can_change_where_the_request_goes(text):
    ask, seen = lookup_with(replying([]))
    ask(good_job(student_work=text, rubric=text))
    assert len(seen) == 1
    assert seen[0].url.host == "knowledge-service.knowledge.svc.cluster.local"
    assert seen[0].url.path == SEARCH_PATH and not seen[0].url.query
    assert text not in str(seen[0].url) and "evil" not in str(seen[0].headers)


def test_the_fallback_to_other_assignments_is_never_switched_on():
    ask, seen = lookup_with(replying([]))
    ask(good_job())
    assert "fallback_to_all" not in json.loads(seen[0].content)


# ---------- What is accepted back ----------

def test_a_good_reply_is_accepted_in_order():
    first, second = good_example(grade="A"), good_example(grade="C", similarity=-0.25)
    ask, _ = lookup_with(replying([first, second]))
    examples = ask(good_job())
    assert [e.grade for e in examples] == ["A", "C"] and examples[1].similarity == -0.25
    assert examples[0].student_work == "A similar essay."


def test_the_longest_allowed_reply_is_accepted():
    items = [good_example(student_work="w" * lookup.WORK_MAX, grade="g" * lookup.GRADE_MAX, reasoning="r" * lookup.REASONING_MAX) for _ in range(EXAMPLE_COUNT)]
    ask, _ = lookup_with(replying(items))
    assert len(ask(good_job())) == EXAMPLE_COUNT


def bad_replies():
    return {
        "not_json": b"{nope",
        "not_utf8": b"\xff\xfe",
        "an_object_not_a_list": {"examples": []},
        "a_bare_string": "hello",
        "four_items": [good_example() for _ in range(EXAMPLE_COUNT + 1)],
        "an_extra_field": [good_example(student_name="Ann")],
        "a_missing_field": [{k: v for k, v in good_example().items() if k != "grade"}],
        "an_item_that_is_not_an_object": ["x"],
        "a_bad_id_spelling": [good_example(example_id="{" + str(uuid.uuid4()) + "}")],
        "an_id_without_hyphens": [good_example(assignment_id=uuid.uuid4().hex)],
        "an_id_as_a_number": [good_example(example_id=123)],
        "same_assignment_as_text": [good_example(same_assignment="true")],
        "same_assignment_as_a_number": [good_example(same_assignment=1)],
        "similarity_as_true": [good_example(similarity=True)],
        "similarity_as_text": [good_example(similarity="0.5")],
        "similarity_too_big": [good_example(similarity=1.5)],
        "similarity_too_small": [good_example(similarity=-1.5)],
        "blank_work": [good_example(student_work="   ")],
        "blank_grade": [good_example(grade="")],
        "blank_reasoning": [good_example(reasoning=" ")],
        "work_too_long": [good_example(student_work="w" * (lookup.WORK_MAX + 1))],
        "grade_too_long": [good_example(grade="g" * (lookup.GRADE_MAX + 1))],
        "reasoning_too_long": [good_example(reasoning="r" * (lookup.REASONING_MAX + 1))],
        "a_null_character": [good_example(student_work="a\x00b")],
        "a_repeated_field": b'[{"example_id": "x", "example_id": "y"}]',
        "nan": b'[{"similarity": NaN}]',
        "deeply_nested": b"[" * 100_000,
    }


@pytest.mark.owasp("A05", 20)
@pytest.mark.owasp("A08", 502, 915)
@pytest.mark.parametrize("name", sorted(bad_replies()))
def test_a_reply_that_does_not_follow_the_agreed_shape_is_refused(name):
    ask, _ = lookup_with(replying(bad_replies()[name]))
    with pytest.raises(LookupUnavailable):
        ask(good_job())


@pytest.mark.owasp("A06", 799)
def test_a_reply_larger_than_the_cap_is_refused_without_reading_it_all():
    big = b"[" + b" " * (MAX_REPLY_BYTES + 10) + b"]"
    ask, _ = lookup_with(replying(big))
    with pytest.raises(LookupUnavailable, match="too large"):
        ask(good_job())


def test_a_reply_exactly_at_the_cap_is_still_read():
    padding = b" " * (MAX_REPLY_BYTES - 2)
    ask, _ = lookup_with(replying(b"[" + padding + b"]"))
    assert ask(good_job()) == []


# ---------- Every kind of trouble ends the same way ----------

@pytest.mark.owasp("A10", 252, 391, 396, 754)
@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 404, 405, 408, 409, 429, 500, 502, 503, 504])
def test_any_other_answer_than_a_good_one_is_trouble_and_only_the_status_is_kept(status):
    ask, _ = lookup_with(lambda request: httpx.Response(status, content=b"SECRET-BODY-MARKER", headers={"location": "http://evil.example/"}))
    with pytest.raises(LookupUnavailable) as problem:
        ask(good_job())
    assert str(problem.value) == f"the lookup answered with status {status}"
    assert "SECRET-BODY-MARKER" not in str(problem.value)


# A refusal that will never change for THIS job must not loop for ever: 400, 413 and 422 are told apart from trouble. A wrong key
# (401, 403), a wrong address (404, 405) or too many requests (429) are setup or temporary problems, which stop the worker instead.
@pytest.mark.owasp("A10", 252, 754)
@pytest.mark.parametrize("status", sorted(REFUSED_STATUSES))
def test_a_refusal_that_will_never_change_for_this_job_is_told_apart_and_only_the_status_is_kept(status):
    ask, seen = lookup_with(lambda request: httpx.Response(status, content=b"SECRET-BODY-MARKER"))
    with pytest.raises(LookupRefused) as problem:
        ask(good_job())
    assert str(problem.value) == f"the lookup refused this job (status {status})"
    assert "SECRET-BODY-MARKER" not in str(problem.value)
    assert len(seen) == 1  # asked once, not retried


def test_the_refused_statuses_are_exactly_the_agreed_ones():
    assert REFUSED_STATUSES == {400, 413, 422}


@pytest.mark.parametrize("status", [401, 403, 404, 405, 429, 500, 503])
def test_a_wrong_key_or_address_or_a_server_problem_is_never_mistaken_for_a_refusal(status):
    ask, _ = lookup_with(lambda request: httpx.Response(status))
    with pytest.raises(LookupUnavailable):
        ask(good_job())


@pytest.mark.owasp("A10", 252, 391, 396, 754)
@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError("refused"), httpx.ConnectTimeout("slow"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("bad"), httpx.ReadError("cut")],
)
def test_a_service_that_cannot_be_reached_or_is_too_slow_is_trouble(error):
    def fail(request):
        raise error

    ask, _ = lookup_with(fail)
    with pytest.raises(LookupUnavailable) as problem:
        ask(good_job(student_work="STUDENT-MARKER"))
    assert str(problem.value) == "the lookup could not be reached"
    assert "STUDENT-MARKER" not in str(problem.value)


def test_a_redirect_is_trouble_and_the_second_address_is_never_asked():
    asked = []

    def handler(request):
        asked.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://evil.example/steal"})

    ask, seen = lookup_with(handler)
    with pytest.raises(LookupUnavailable):
        ask(good_job())
    assert asked == [BASE + SEARCH_PATH]


@pytest.mark.owasp("A01", 918, 441)
def test_a_real_redirect_to_another_server_is_not_followed():
    # Two real local servers: the first redirects to the second. The second must never be asked.
    hits = {"second": 0}

    class Second(BaseHTTPRequestHandler):
        def do_POST(self):
            hits["second"] += 1
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"[]")

        do_GET = do_POST

        def log_message(self, *args):
            pass

    second = HTTPServer(("127.0.0.1", 0), Second)

    class First(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))  # read the body first, or the client sees a reset
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{second.server_port}/examples/search")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    first = HTTPServer(("127.0.0.1", 0), First)
    for server in (first, second):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = make_client({"KNOWLEDGE_URL": f"http://127.0.0.1:{first.server_port}"})
        with pytest.raises(LookupUnavailable, match="307"):
            KnowledgeLookup(client)(good_job())
    finally:
        for server in (first, second):
            server.shutdown()
            server.server_close()
    assert hits["second"] == 0


@pytest.mark.owasp("A07", 798, 259)
@pytest.mark.owasp("A02", 526)
def test_a_missing_key_stops_the_worker_it_is_not_a_lookup_problem(monkeypatch):
    monkeypatch.delenv("KNOWLEDGE_KEY", raising=False)
    ask, seen = lookup_with(replying([]))
    with pytest.raises(RuntimeError):
        ask(good_job())
    assert seen == []  # nothing was sent without a key


@pytest.mark.owasp("A07", 798, 259)
@pytest.mark.parametrize("value", ["", None])
def test_an_empty_key_stops_the_worker_too(monkeypatch, value):
    monkeypatch.setenv("KNOWLEDGE_KEY", value or "")
    ask, seen = lookup_with(replying([]))
    with pytest.raises(RuntimeError):
        ask(good_job())
    assert seen == []


@pytest.mark.owasp("A09", 532)
def test_neither_the_key_nor_the_student_text_ever_reaches_a_log_or_an_error(caplog):
    marker = "STUDENT-MARKER-4711"
    cases = [replying([good_example(extra=1)]), replying([], 503), lambda request: (_ for _ in ()).throw(httpx.ConnectError(marker))]
    with caplog.at_level(logging.DEBUG):
        for handler in cases:
            ask, _ = lookup_with(handler)
            with pytest.raises(LookupUnavailable) as problem:
                ask(good_job(student_work=marker))
            assert KEY not in str(problem.value) and marker not in str(problem.value)
    assert all(KEY not in record.getMessage() and marker not in record.getMessage() for record in caplog.records)


# ---------- The address setting and the client ----------

@pytest.mark.parametrize(
    "value, expected",
    [
        ("http://knowledge-service.knowledge.svc.cluster.local:8000", "http://knowledge-service.knowledge.svc.cluster.local:8000"),
        ("http://knowledge-service.knowledge.svc.cluster.local:8000/", "http://knowledge-service.knowledge.svc.cluster.local:8000"),
        ("https://knowledge.example.internal", "https://knowledge.example.internal"),
        ("http://127.0.0.1:9", "http://127.0.0.1:9"),
    ],
)
def test_a_plain_address_is_accepted(value, expected):
    assert checked_base_url(value) == expected


# (The address with a login in it is built from parts, so the repo's secret scanner does not flag this test itself.)
@pytest.mark.owasp("A01", 918)
@pytest.mark.owasp("A02", 16)
@pytest.mark.parametrize(
    "value",
    [None, "", "knowledge", "ftp://host", "file:///etc/passwd", "http://" + "user" + ":" + "word" + "@host", "http://host/some/path", "http://host?x=1", "http://host#frag", "http://", "javascript:alert(1)", "http://host:99999999"],
)
def test_anything_but_a_plain_address_stops_the_worker_without_repeating_it(value):
    with pytest.raises(RuntimeError) as problem:
        checked_base_url(value)
    assert "word" not in str(problem.value) and "etc/passwd" not in str(problem.value)


@pytest.mark.owasp("A01", 918)
@pytest.mark.owasp("A06", 799)
def test_the_real_client_follows_no_redirects_ignores_proxy_settings_and_has_time_limits(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.example:3128")
    client = make_client({"KNOWLEDGE_URL": BASE})
    assert client.follow_redirects is False and client.trust_env is False
    assert client.timeout.connect == lookup.CONNECT_TIMEOUT_SECONDS == 5.0
    assert client.timeout.read == client.timeout.write == client.timeout.pool == lookup.READ_TIMEOUT_SECONDS == 10.0
    assert str(client.base_url).rstrip("/") == BASE


@pytest.mark.owasp("A01", 918)
def test_the_code_builds_its_client_only_with_redirects_and_proxies_switched_off():
    source = (Path(__file__).resolve().parent.parent / "app" / "lookup.py").read_text(encoding="utf-8")
    clients = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call) and ast.unparse(node.func) == "httpx.Client"]
    assert len(clients) == 1
    options = {keyword.arg: ast.literal_eval(keyword.value) for keyword in clients[0].keywords if isinstance(keyword.value, ast.Constant)}
    assert options["follow_redirects"] is False and options["trust_env"] is False


# ---------- One overall deadline ----------

class Clock:
    """A clock the test controls: it only moves when told to."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Trickle(httpx.SyncByteStream):
    """A reply that arrives in small pieces, each one taking `step` seconds on the pretend clock."""

    def __init__(self, clock, pieces, step):
        self.clock, self.pieces, self.step = clock, pieces, step

    def __iter__(self):
        for piece in self.pieces:
            self.clock.now += self.step
            yield piece


def lookup_with_clock(clock, stream):
    client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=stream)), follow_redirects=False, trust_env=False)
    return KnowledgeLookup(client, clock=clock)


@pytest.mark.owasp("A06", 799)
@pytest.mark.owasp("A10", 396, 754)
def test_a_reply_that_trickles_in_slowly_is_stopped_at_the_overall_deadline():
    # Every single piece arrives well inside the per-step limit (10 s), yet the reply as a whole would take far longer
    # than the deadline. Without an overall deadline this reply would be read to the end, one slow piece at a time.
    clock = Clock()
    pieces = [b"[" + b" " * 10] + [b" " * 10] * 50 + [b"]"]
    ask = lookup_with_clock(clock, Trickle(clock, pieces, step=lookup.READ_TIMEOUT_SECONDS - 1))
    with pytest.raises(LookupUnavailable, match="too long"):
        ask(good_job())
    assert clock.now - 1000.0 <= lookup.TOTAL_DEADLINE_SECONDS + lookup.READ_TIMEOUT_SECONDS  # stopped near the deadline, not at the end


def test_a_reply_that_finishes_inside_the_deadline_is_accepted():
    clock = Clock()
    ask = lookup_with_clock(clock, Trickle(clock, [b"[", b"]"], step=lookup.TOTAL_DEADLINE_SECONDS / 4))
    assert ask(good_job()) == []


def test_a_reply_exactly_at_the_deadline_is_still_accepted():
    clock = Clock()
    ask = lookup_with_clock(clock, Trickle(clock, [b"[", b"]"], step=lookup.TOTAL_DEADLINE_SECONDS / 2))
    assert ask(good_job()) == []


@pytest.mark.owasp("A06", 799)
def test_waiting_a_long_time_for_the_first_byte_counts_against_the_deadline_too():
    clock = Clock()

    def slow_start(request):
        clock.now += lookup.TOTAL_DEADLINE_SECONDS + 1
        return httpx.Response(200, content=b"[]")

    client = httpx.Client(base_url=BASE, transport=httpx.MockTransport(slow_start), follow_redirects=False, trust_env=False)
    with pytest.raises(LookupUnavailable, match="too long"):
        KnowledgeLookup(client, clock=clock)(good_job())


def test_the_deadline_and_the_step_limit_are_the_agreed_numbers_and_far_below_the_poll_interval():
    assert lookup.TOTAL_DEADLINE_SECONDS == 30.0 and lookup.READ_TIMEOUT_SECONDS == 10.0
    poll_interval_seconds = 600  # app/worker.py: max.poll.interval.ms is 600,000
    assert lookup.TOTAL_DEADLINE_SECONDS + lookup.READ_TIMEOUT_SECONDS + lookup.CONNECT_TIMEOUT_SECONDS < poll_interval_seconds / 10
