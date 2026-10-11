# In plain English: tests for the worker that takes grading jobs off Kafka. They use fakes (a pretend Kafka and a pretend
# grader), so they need no Kafka. They check the two things that matter most: what happens to each kind of message,
# and that a message is marked "done" only AFTER its answer (or its dead-letter copy) is confirmed delivered.
#
# Why it matters (OWASP A10, mishandling of exceptional conditions): a job must never be lost (CWE-252, 394, 754, 755),
# a failure must stop the worker instead of being swallowed (CWE-390, 391, 396) and the Kafka client must always be
# closed (CWE-460). Repeats must be harmless (A06 CWE-362) and the logs must never carry student text (A09 CWE-532).
import json
import logging
import uuid

import pytest

from app import worker
from app.jobs import read_job
from app.lookup import LookupUnavailable
from app.provider import FakeProvider, Grade, ProviderRefused, ProviderUnavailable
from app.worker import DEAD_LETTER_TOPIC, RESULT_TOPIC, TOPIC


def good_value(**change):
    data = {
        "schema_version": 1,
        "submission_id": str(uuid.uuid4()),
        "based_on_version": 2,
        "assignment_id": str(uuid.uuid4()),
        "rubric": "Grade for clarity and evidence.",
        "student_work": "An essay.",
    }
    data.update(change)
    return data


def keyed(data):
    return data["submission_id"].encode(), json.dumps(data).encode("utf-8")


def no_examples(job):
    return []


# The tests below were written before the lookup existed; these two helpers hand the worker a lookup that finds nothing,
# unless a test gives its own.
def handle_message(key, value, provider, lookup=no_examples):
    return worker.handle_message(key, value, provider, lookup)


def run(consumer, producer, provider, should_stop=lambda: False, lookup=no_examples):
    return worker.run(consumer, producer, provider, lookup, should_stop=should_stop)


class Provider:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.seen, self.examples = result or Grade("A", "Correct."), error, [], []

    def grade(self, job, examples=()):
        self.seen.append(job)
        self.examples.append(list(examples))
        if self.error:
            raise self.error
        return self.result


def never_grade():
    return Provider(error=AssertionError("a bad message must never reach the grader"))


# ---------- handle_message: what happens to each kind of message ----------

def test_a_good_job_is_graded_and_the_answer_is_built_from_the_grade():
    data = good_value()
    provider = Provider(Grade("B+", "Good use of evidence."))
    outcome, answer = handle_message(*keyed(data), provider)
    assert outcome == "graded"
    key, value = answer
    assert key == data["submission_id"].encode()
    assert json.loads(value) == {
        "schema_version": 1,
        "submission_id": data["submission_id"],
        "based_on_version": 2,
        "ai_grade": "B+",
        "ai_reasoning": "Good use of evidence.",
    }
    assert str(provider.seen[0].submission_id) == data["submission_id"]
    assert provider.seen[0].student_work == "An essay."


@pytest.mark.owasp("A05", 20)
@pytest.mark.parametrize(
    "key, value, reason",
    [
        (b"k", b"{not json", "invalid_json"),
        (b"k", json.dumps(good_value(schema_version=2)).encode(), "unknown_schema_version"),
        (b"k", json.dumps(good_value(rubric="")).encode(), "invalid_field"),
        (b"k", json.dumps(good_value(student_name="Ann")).encode(), "invalid_field"),
        (b"not-the-id", json.dumps(good_value()).encode(), "key_mismatch"),
    ],
)
def test_a_bad_message_is_dead_lettered_and_never_reaches_the_grader(key, value, reason):
    assert handle_message(key, value, never_grade()) == ("dead_letter", reason)


def test_a_job_the_grader_refuses_is_dead_lettered():
    assert handle_message(*keyed(good_value()), Provider(error=ProviderRefused())) == ("dead_letter", "grading_refused")


@pytest.mark.owasp("A05", 20)
@pytest.mark.parametrize("grade, reasoning", [("", "ok"), ("g" * 21, "ok"), ("A", ""), ("A", "r" * 10_001), ("A\x00", "ok")])
def test_an_answer_the_contract_would_refuse_dead_letters_the_job(grade, reasoning):
    assert handle_message(*keyed(good_value()), Provider(Grade(grade, reasoning))) == ("dead_letter", "grading_refused")


@pytest.mark.owasp("A10", 252, 394)
def test_the_grader_being_unavailable_is_not_swallowed():
    with pytest.raises(ProviderUnavailable):
        handle_message(*keyed(good_value()), Provider(error=ProviderUnavailable()))


@pytest.mark.owasp("A10", 252, 394)
def test_any_other_grader_failure_is_not_swallowed_either():
    with pytest.raises(RuntimeError):
        handle_message(*keyed(good_value()), Provider(error=RuntimeError("bug")))


@pytest.mark.owasp("A09", 532)
def test_the_reason_never_contains_the_student_text():
    outcome = handle_message(*keyed(good_value(student_work="STUDENT-MARKER", rubric="")), never_grade())
    assert "STUDENT-MARKER" not in repr(outcome)


def test_the_fake_provider_always_gives_the_same_answer_and_never_reads_the_text():
    job = read_job(*keyed(good_value(student_work="STUDENT-MARKER")))[1]
    grade = FakeProvider().grade(job, [])
    assert grade == FakeProvider().grade(job, []) == Grade("B", "Graded by the fake provider: no AI was used.")
    assert "STUDENT-MARKER" not in grade.reasoning


@pytest.mark.owasp("A06", 362)
def test_the_same_job_twice_gives_the_same_answer():
    message = keyed(good_value())
    assert handle_message(*message, FakeProvider()) == handle_message(*message, FakeProvider())


# ---------- run: the loop and the order of "done" ----------

class FakeMessage:
    def __init__(self, key, value, offset=0, error=None):
        self._key, self._value, self._offset, self._error = key, value, offset, error

    def key(self):
        return self._key

    def value(self):
        return self._value

    def offset(self):
        return self._offset

    def error(self):
        return self._error


class FakeConsumer:
    def __init__(self, messages, log):
        self.messages = list(messages)
        self.log = log
        self.subscribed = None
        self.closed = False

    def subscribe(self, topics):
        self.subscribed = topics

    def poll(self, timeout):
        # A loop that keeps polling after the messages ran out would hang a test forever.
        assert self.messages, "polled after the messages ran out"
        return self.messages.pop(0)

    def commit(self, message=None, asynchronous=True):
        assert asynchronous is False
        self.log.append(("commit", message.offset()))

    def close(self):
        self.closed = True


class FakeProducer:
    # "rejected" pretends the broker refused the copy: the delivery callback gets an error, yet flush() still reports
    # nothing left in the queue, as real Kafka does.
    def __init__(self, log, left_over=0, rejected=False):
        self.log = log
        self.left_over = left_over
        self.rejected = rejected
        self.callbacks = []

    def produce(self, topic, key=None, value=None, headers=None, on_delivery=None):
        self.log.append(("produce", topic, key, value, headers))
        self.callbacks.append(on_delivery)

    def flush(self, timeout=None):
        self.log.append(("flush",))
        for callback in self.callbacks:
            if callback is not None:
                callback("broker said no" if self.rejected else None, None)
        return self.left_over


# Runs the loop until the fake has handed over all its messages.
def run_with(messages, provider, left_over=0):
    log = []
    fake = FakeConsumer(messages, log)
    run(fake, FakeProducer(log, left_over), provider, should_stop=lambda: not fake.messages)
    return fake, log


@pytest.mark.owasp("A05", 610)
@pytest.mark.owasp("A07", 941)
def test_the_loop_subscribes_to_the_agreed_topic_and_the_topics_are_the_agreed_words():
    fake, _ = run_with([], Provider())
    assert fake.subscribed == [TOPIC] == ["grading-jobs"]
    assert DEAD_LETTER_TOPIC == "grading-jobs.dead-letter" and RESULT_TOPIC == "grading-results"
    assert fake.closed


def test_a_good_job_sends_its_answer_to_the_results_topic_before_the_commit():
    data = good_value()
    _, log = run_with([FakeMessage(*keyed(data), 7)], Provider())
    assert [entry[0] for entry in log] == ["produce", "flush", "commit"]
    _, topic, key, value, headers = log[0]
    assert topic == RESULT_TOPIC and key == data["submission_id"].encode() and headers is None
    assert json.loads(value)["based_on_version"] == 2
    assert log[2] == ("commit", 7)


def test_a_bad_message_is_copied_to_the_dead_letter_topic_before_the_commit():
    _, log = run_with([FakeMessage(b"k", b"{oops", 5)], never_grade())
    assert [entry[0] for entry in log] == ["produce", "flush", "commit"]
    _, topic, key, value, headers = log[0]
    assert topic == DEAD_LETTER_TOPIC and key == b"k" and value == b"{oops"
    assert dict(headers)["error"] == b"invalid_json"
    assert log[2] == ("commit", 5)


@pytest.mark.owasp("A10", 252, 394)
def test_an_answer_that_is_not_delivered_is_not_committed():
    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 5)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log, left_over=1), Provider(), should_stop=lambda: False)
    assert ("commit", 5) not in log
    assert fake.closed


# flush() only says how many copies are still queued. A refused copy is reported through the delivery callback, so a
# refusal must stop the worker before the commit.
@pytest.mark.owasp("A10", 252, 394)
def test_an_answer_the_broker_refused_is_not_committed():
    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 5)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log, rejected=True), Provider(), should_stop=lambda: False)
    assert ("commit", 5) not in log


@pytest.mark.owasp("A10", 252, 394)
def test_a_dead_letter_the_broker_refused_is_not_committed():
    log = []
    fake = FakeConsumer([FakeMessage(b"k", b"{oops", 5)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log, rejected=True), never_grade(), should_stop=lambda: False)
    assert ("commit", 5) not in log


@pytest.mark.owasp("A10", 252, 394, 754)
def test_the_grader_being_unavailable_means_no_commit_no_answer_and_the_loop_stops():
    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 3)], log)
    with pytest.raises(ProviderUnavailable):
        run(fake, FakeProducer(log), Provider(error=ProviderUnavailable()), should_stop=lambda: False)
    assert log == []
    assert fake.closed


@pytest.mark.owasp("A10", 460)
def test_the_consumer_is_closed_even_when_the_loop_fails():
    log = []
    fake = FakeConsumer([FakeMessage(None, None, 9, error="broker gone")], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log), never_grade(), should_stop=lambda: False)
    assert fake.closed and log == []


def test_messages_are_handled_in_order_each_committed_in_turn():
    _, log = run_with(
        [FakeMessage(*keyed(good_value()), 1), FakeMessage(b"bad", b"{", 2), FakeMessage(*keyed(good_value()), 3)],
        Provider(),
    )
    assert [entry for entry in log if entry[0] == "commit"] == [("commit", 1), ("commit", 2), ("commit", 3)]


@pytest.mark.owasp("A09", 532)
@pytest.mark.owasp("A09", 117)
def test_the_log_carries_only_the_outcome_and_the_offset(caplog):
    marker = "STUDENT-MARKER-4711"
    messages = [
        FakeMessage(*keyed(good_value(student_work=marker, rubric=marker)), 1),
        FakeMessage(b"k\nforged line", ("{" + marker).encode(), 2),
    ]
    with caplog.at_level(logging.DEBUG):
        run_with(messages, Provider(Grade("A", marker)))
    lines = [record.getMessage() for record in caplog.records]
    assert lines == ["offset 1: graded", "offset 2: dead_letter (invalid_json)"]
    assert all(marker not in line and "\n" not in line for line in lines)


# ---------- the settings ----------

@pytest.mark.owasp("A02", 16)
def test_the_group_and_manual_commit_settings():
    settings = worker.consumer_settings({"KAFKA_BOOTSTRAP": "kafka:9092"})
    assert settings["group.id"] == "grader-service-jobs"
    assert settings["enable.auto.commit"] is False
    assert settings["auto.offset.reset"] == "earliest"
    assert settings["bootstrap.servers"] == "kafka:9092"
    assert settings["max.poll.interval.ms"] >= 300_000


@pytest.mark.owasp("A02", 16)
def test_the_producer_settings_wait_for_every_copy_and_never_duplicate():
    settings = worker.producer_settings({"KAFKA_BOOTSTRAP": "kafka:9092"})
    assert settings == {"bootstrap.servers": "kafka:9092", "acks": "all", "enable.idempotence": True}


@pytest.mark.owasp("A02", 16)
@pytest.mark.parametrize("environment", [{}, {"KAFKA_BOOTSTRAP": ""}])
def test_a_missing_bootstrap_setting_stops_early(environment):
    with pytest.raises(RuntimeError):
        worker.consumer_settings(environment)
    with pytest.raises(RuntimeError):
        worker.producer_settings(environment)


# ---------- The knowledge-service lookup inside the worker ----------

class Lookup:
    def __init__(self, examples=(), error=None):
        self.examples, self.error, self.calls = list(examples), error, []

    def __call__(self, job):
        self.calls.append(job)
        if self.error:
            raise self.error
        return self.examples


def never_lookup():
    return Lookup(error=AssertionError("a bad message must never reach the lookup"))


def test_a_good_job_is_looked_up_once_and_the_examples_go_to_the_grader():
    data = good_value()
    lookup, provider = Lookup(["example-1", "example-2"]), Provider()
    assert handle_message(*keyed(data), provider, lookup)[0] == "graded"
    assert len(lookup.calls) == 1 and str(lookup.calls[0].submission_id) == data["submission_id"]
    assert provider.examples == [["example-1", "example-2"]]


@pytest.mark.owasp("A05", 20)
@pytest.mark.parametrize("value", [b"{not json", json.dumps(good_value(rubric="")).encode(), json.dumps(good_value(student_name="Ann")).encode()])
def test_a_bad_message_never_reaches_the_lookup(value):
    assert handle_message(b"k", value, never_grade(), never_lookup())[0] == "dead_letter"


@pytest.mark.owasp("A10", 252, 394, 754)
def test_the_lookup_being_unavailable_is_not_swallowed_and_the_grader_is_never_asked():
    provider = Provider()
    with pytest.raises(LookupUnavailable):
        handle_message(*keyed(good_value()), provider, Lookup(error=LookupUnavailable("down")))
    assert provider.seen == []


@pytest.mark.owasp("A10", 252, 394, 754)
def test_the_lookup_being_unavailable_means_no_commit_no_answer_and_the_loop_stops():
    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 3)], log)
    with pytest.raises(LookupUnavailable):
        run(fake, FakeProducer(log), Provider(), should_stop=lambda: False, lookup=Lookup(error=LookupUnavailable("down")))
    assert log == []
    assert fake.closed


@pytest.mark.owasp("A02", 526)
@pytest.mark.owasp("A07", 798)
def test_a_missing_lookup_key_stops_the_worker_without_a_commit():
    log = []
    fake = FakeConsumer([FakeMessage(*keyed(good_value()), 3)], log)
    with pytest.raises(RuntimeError):
        run(fake, FakeProducer(log), Provider(), should_stop=lambda: False, lookup=Lookup(error=RuntimeError("Missing required setting: KNOWLEDGE_KEY")))
    assert log == [] and fake.closed
