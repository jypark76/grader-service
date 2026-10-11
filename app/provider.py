# In plain English: whatever decides a grade sits behind one small door, so the rest of the worker never knows (or
# cares) who is grading. Today the only grader is a FAKE one that returns a fixed answer and uses no AI, so the whole
# flow (Kafka in, grade, Kafka out) can be built and proven for free. The real model replaces it in a later step, and
# it will have to follow the same two rules about failure:
#
#   ProviderUnavailable   temporary trouble (the model service is down or slow). The job is NOT marked done, the worker
#                         stops, Kubernetes restarts it and the job is tried again.
#   ProviderRefused       this job can never be graded (for example the model refuses it). The job is copied to the
#                         dead-letter topic so it cannot block its lane.
from typing import NamedTuple


class Grade(NamedTuple):
    grade: str
    reasoning: str


class ProviderUnavailable(Exception):
    pass


class ProviderRefused(Exception):
    pass


# In plain English: the fake grader. It always answers the same thing and never looks at the student's text, so it
# cannot leak it and costs nothing.
class FakeProvider:
    def grade(self, job):
        return Grade("B", "Graded by the fake provider: no AI was used.")
