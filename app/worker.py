# In plain English: the grading worker. It takes grading jobs off the Kafka topic "grading-jobs", grades each one
# and sends the answer to the topic "grading-results". The message formats are the shared contracts in
# platform/contracts (grading-jobs.md and grading-results.md).
#
# The promise it keeps: a message is marked "done" (committed) only AFTER it has been dealt with, so a crash can
# never lose one. Dealt with means one of:
#   graded       a good job was graded and the answer was delivered to "grading-results" (the delivery is confirmed).
#   dead_letter  a message that can never succeed (not JSON, unknown version, a broken rule, a key that is not the
#                submission ID, a job the grader refuses, or a job the knowledge service refuses for good). It is copied to "grading-jobs.dead-letter" with the
#                reason in a header, and that copy is confirmed delivered, so it cannot block its lane and a person
#                can look at it.
# Temporary trouble (the grader unavailable, Kafka down) is NOT dealt with: nothing is committed, the worker stops
# with an error, Kubernetes restarts it and the message is tried again. Sending a job twice is harmless: the
# assessment service keeps the first grade it records for a version.
#
# Nothing the student wrote is ever logged. Logs carry only the outcome and the offset.
import logging
import os
import signal

from app.jobs import build_result, read_job
from app.lookup import KnowledgeLookup, LookupRefused, make_client
from app.provider import FakeProvider, ProviderRefused

TOPIC = "grading-jobs"
DEAD_LETTER_TOPIC = "grading-jobs.dead-letter"
RESULT_TOPIC = "grading-results"
GROUP_ID = "grader-service-jobs"

log = logging.getLogger("grader-worker")


# In plain English: decides what to do with one message and reports the outcome as a pair: ("graded", (key, value))
# with the answer to send, or ("dead_letter", a reason code). It raises for temporary trouble (such as the grader
# being unavailable or the knowledge service not answering) so the caller does not commit. "provider" and "lookup" are
# parameters so tests can pass pretend ones.
def handle_message(key, value, provider, lookup):
    kind, found = read_job(key, value)
    if kind == "dead_letter":
        return "dead_letter", found
    try:
        examples = lookup(found)  # raises LookupUnavailable on trouble, which must reach the caller: nothing is committed
    except LookupRefused:
        # The knowledge service refuses this job for good (a bad request, too large, text it will not take). Trying
        # again can never help, so the job is dead-lettered and cannot block the jobs behind it.
        return "dead_letter", "lookup_refused"
    try:
        grade = provider.grade(found, examples)
    except ProviderRefused:
        return "dead_letter", "grading_refused"
    try:
        answer = build_result(found, grade.grade, grade.reasoning)
    except ValueError:
        # The grader produced something the contract does not allow (a blank grade, a grade that is too long). It
        # would do the same every time for this job, so the job must not block its lane. The reason is fixed
        # wording: the error text is not used, because it could carry the grader's own output.
        return "dead_letter", "grading_refused"
    return "graded", answer


# In plain English: sends one message to a topic and waits until Kafka CONFIRMS it was delivered. flush() only says
# how many copies are still queued; a copy the broker refuses is reported through the delivery callback, so the
# callback records it. If the copy is not confirmed, this raises, and the caller does not commit.
def _deliver(producer, topic, key, value, headers=None):
    refused = []
    producer.produce(
        topic,
        key=key,
        value=value,
        headers=headers,
        on_delivery=lambda error, _message: refused.append(error) if error else None,
    )
    if producer.flush(30) != 0 or refused:
        raise RuntimeError(f"a copy for {topic} was not delivered")


# In plain English: the loop. It asks Kafka for one message at a time, deals with it, and only then commits.
# "consumer", "producer" and "provider" are parameters so tests can pass pretend ones. The loop ends when
# should_stop() says so. Any error ends it too, after closing the consumer, and the error goes up to the caller.
def run(consumer, producer, provider, lookup, should_stop=lambda: False):
    consumer.subscribe([TOPIC])
    try:
        while not should_stop():
            message = consumer.poll(1.0)
            if message is None:
                continue
            if message.error():
                raise RuntimeError(f"Kafka error: {message.error()}")
            outcome, detail = handle_message(message.key(), message.value(), provider, lookup)
            if outcome == "graded":
                _deliver(producer, RESULT_TOPIC, detail[0], detail[1])
                reason = None
            else:
                reason = detail
                _deliver(producer, DEAD_LETTER_TOPIC, message.key(), message.value(), headers=[("error", reason.encode("utf-8"))])
            consumer.commit(message=message, asynchronous=False)
            log.info("offset %s: %s%s", message.offset(), outcome, f" ({reason})" if reason else "")
    finally:
        consumer.close()


# In plain English: the Kafka settings. Commits are manual (the worker decides when a message is done), a brand-new
# group starts from the oldest message, and the generous poll interval allows for a slow grader.
def consumer_settings(environment):
    bootstrap = environment.get("KAFKA_BOOTSTRAP")
    if not bootstrap:
        raise RuntimeError("Missing required setting: KAFKA_BOOTSTRAP")
    return {
        "bootstrap.servers": bootstrap,
        "group.id": GROUP_ID,
        "enable.auto.commit": False,
        "auto.offset.reset": "earliest",
        "max.poll.interval.ms": 600_000,
    }


# In plain English: the settings for sending. "acks=all" means Kafka confirms only when every copy is safe, and
# idempotence means a retry inside Kafka cannot create a duplicate.
def producer_settings(environment):
    return {
        "bootstrap.servers": consumer_settings(environment)["bootstrap.servers"],
        "acks": "all",
        "enable.idempotence": True,
    }


# In plain English: starts the real worker. It stops cleanly when Kubernetes asks it to (SIGTERM), after finishing the
# message in hand.
def main():
    from confluent_kafka import Consumer, Producer

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(True))
    signal.signal(signal.SIGINT, lambda *_: stopping.append(True))
    run(
        Consumer(consumer_settings(os.environ)),
        Producer(producer_settings(os.environ)),
        FakeProvider(),
        KnowledgeLookup(make_client(os.environ)),
        should_stop=lambda: bool(stopping),
    )


if __name__ == "__main__":
    main()
