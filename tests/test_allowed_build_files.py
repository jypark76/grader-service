# In plain English: the guardrail for the files that build the image. The Dockerfile may contain ONLY the lines listed below, and the
# .dockerignore may contain ONLY the lines listed below, in this order. So nothing can be added quietly: a changed start command, a
# debug or reload switch, an extra file copied into the image, a package installed from somewhere unlocked, a second user, a
# download of a script. Changing either file means changing this file in the same pull request, which someone reads.
#
# Why it matters (OWASP A02 CWE-16 and CWE-215, and A10 CWE-215 and A02 CWE-489: no debug code or switches left in what is deployed; A03 CWE-1357 and
# A08 CWE-829, CWE-494: everything in the image comes from the locked list and the pinned base image).
#
# The .dockerignore starts by leaving EVERYTHING out ("*") and then lets in only the code and the list of libraries, so a new file,
# whatever its name, is not in the image unless someone adds it here. The image check in the pipeline compares the files inside the
# built image with the code and the lock exactly (tests/test_supply_chain_pins.py).
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"

# Each allowed Dockerfile instruction, written out in full (the base image line allows any digest, so Dependabot can update it).
ALLOWED_INSTRUCTIONS = (
    re.compile(r"FROM python:3\.[0-9]+-slim@sha256:[0-9a-f]{64}"),
    re.compile(re.escape("ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1")),
    re.compile(re.escape("WORKDIR /app")),
    re.compile(re.escape("COPY requirements.txt .")),
    re.compile(re.escape("RUN pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt")),
    re.compile(re.escape("RUN useradd --create-home appuser")),
    re.compile(re.escape("USER appuser")),
    re.compile(re.escape("COPY --chown=appuser app/ ./app/")),
    re.compile(re.escape("EXPOSE 8000")),
    re.compile(re.escape('CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]')),
)
ALLOWED_IGNORE_LINES = ["*", "!app", "!requirements.txt", "**/__pycache__", "**/*.pyc"]


# In plain English: the instructions of a Dockerfile, with line continuations joined, extra spaces folded and comments and blanks dropped.
def instructions_of(text):
    joined = re.sub(r"\\\r?\n", " ", text)
    lines = [re.sub(r"\s+", " ", line).strip() for line in joined.splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def dockerfile_problems(text, allowed=ALLOWED_INSTRUCTIONS):
    return [f"not allowed: {line}" for line in instructions_of(text) if not any(pattern.fullmatch(line) for pattern in allowed)]


def ignore_lines_of(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


# In plain English: how the .dockerignore differs from the one allowed content, as plain sentences.
def dockerignore_problems(text):
    lines = ignore_lines_of(text)
    return [] if lines == ALLOWED_IGNORE_LINES else [f"the .dockerignore must be exactly {ALLOWED_IGNORE_LINES}, found {lines}"]


def need_image():
    if not DOCKERFILE.exists():
        pytest.skip("this repo builds no image")


# ---------- The real files ----------

@pytest.mark.owasp("A02", 16, 489)
@pytest.mark.owasp("A10", 215)
@pytest.mark.owasp("A03", 1357)
@pytest.mark.owasp("A08", 829, 494)
def test_the_dockerfile_holds_only_allowed_instructions():
    need_image()
    assert dockerfile_problems(DOCKERFILE.read_text(encoding="utf-8")) == []


@pytest.mark.owasp("A03", 1357)
def test_every_allowed_instruction_is_used_exactly_once():
    need_image()
    lines = instructions_of(DOCKERFILE.read_text(encoding="utf-8"))
    for pattern in ALLOWED_INSTRUCTIONS:
        assert sum(1 for line in lines if pattern.fullmatch(line)) == 1, pattern.pattern


@pytest.mark.owasp("A02", 16)
@pytest.mark.owasp("A01", 538, 540)
def test_the_dockerignore_leaves_everything_out_except_the_code_and_the_lock():
    need_image()
    assert dockerignore_problems(DOCKERIGNORE.read_text(encoding="utf-8")) == []


# ---------- The check proves itself ----------

GOOD_DOCKERFILE = DOCKERFILE.read_text(encoding="utf-8") if DOCKERFILE.exists() else ""

BAD_LINES = {
    "a debug switch": "ENV DEBUG=1",
    "a reload switch in the start command": 'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]',
    "a different start command": 'CMD ["python", "-m", "app.worker"]',
    "a shell start command": "CMD uvicorn app.main:app",
    "an entry point": 'ENTRYPOINT ["sh"]',
    "a second user": "USER root",
    "an extra file copied in": "COPY tests/ ./tests/",
    "the whole folder copied in": "COPY . .",
    "a file added from the web": "ADD https://example.com/x.sh /x.sh",
    "a download": "RUN curl -s https://example.com/x.sh | sh",
    "an install from the web": "RUN pip install requests",
    "an install without hashes": "RUN pip install --no-cache-dir -r requirements.txt",
    "a package from the system": "RUN apt-get install -y curl",
    "a mounted secret": "RUN --mount=type=secret,id=key cat /run/secrets/key",
    "an unpinned base image": "FROM python:3.12-slim",
    "a base image with the latest tag": "FROM python:latest@sha256:" + "a" * 64,
    "another base image": "FROM ubuntu:24.04@sha256:" + "a" * 64,
    "a build argument": "ARG TOKEN",
    "another port": "EXPOSE 22",
    "a second port": "EXPOSE 8000 22",
    "an environment variable with a key": "ENV SERVICE_KEY=abc",
    "a health check that runs a command": "HEALTHCHECK CMD curl http://x",
    "a volume": "VOLUME /data",
    "a changed working folder": "WORKDIR /",
    "a command with a trailing addition": "USER appuser; id",
}


@pytest.mark.owasp("A02", 16, 489)
@pytest.mark.owasp("A10", 215)
@pytest.mark.owasp("A03", 1357)
@pytest.mark.owasp("A08", 829, 494)
@pytest.mark.parametrize("label", sorted(BAD_LINES))
def test_every_other_dockerfile_line_is_refused(label):
    need_image()
    assert dockerfile_problems(GOOD_DOCKERFILE + "\n" + BAD_LINES[label] + "\n") != [], label


@pytest.mark.owasp("A02", 16)
def test_the_good_dockerfile_passes_and_continuations_and_comments_are_understood():
    need_image()
    assert dockerfile_problems(GOOD_DOCKERFILE) == []
    assert dockerfile_problems("# a comment\n\nENV PYTHONDONTWRITEBYTECODE=1 \\\n    PYTHONUNBUFFERED=1\n") == []
    assert dockerfile_problems("ENV PYTHONDONTWRITEBYTECODE=1 \\\n    PYTHONUNBUFFERED=1 \\\n    DEBUG=1\n") != []


@pytest.mark.owasp("A02", 16)
@pytest.mark.owasp("A01", 538, 540)
@pytest.mark.parametrize(
    "lines",
    [
        ["*", "!app", "!requirements.txt", "**/__pycache__", "**/*.pyc", "!tests"],
        ["*", "!app", "!requirements.txt", "!.env"],
        ["!app", "!requirements.txt", "**/__pycache__", "**/*.pyc"],
        ["*", "!requirements.txt", "!app", "**/__pycache__", "**/*.pyc"],
        [".git", "tests", "docs-private"],
        ["*", "!app", "!requirements.txt"],
        ["*", "!.", "!app", "!requirements.txt", "**/__pycache__", "**/*.pyc"],
    ],
)
def test_any_other_dockerignore_is_refused(lines):
    assert dockerignore_problems("\n".join(lines) + "\n") != []


@pytest.mark.owasp("A02", 16)
def test_the_dockerignore_ignores_comments_and_blank_lines():
    assert dockerignore_problems("# comment\n\n*\n  !app  \n# another\n!requirements.txt\n**/__pycache__\n**/*.pyc\n") == []
