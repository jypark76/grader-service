# In plain English: the helpers behind the "nothing secret in the repo" guardrail (tests/test_no_secrets_in_the_repo.py). The repo is
# public, so a key that gets saved in any file is seen by everyone. Instead of a list of key shapes to look for (an arms race), this
# works from what is ALLOWED:
#   - every file in the repo must be on the list in tests/allowed_files.py, so a new file, whatever its name, is a decision made in a
#     pull request that someone reads;
#   - every long run of letters, digits, dashes, underscores, slashes, plus signs and equals signs (20 or more) must have the look of a
#     NAME (words joined with underscores, dashes, slashes or capital letters, such as test_every_bad_program or
#     readOnlyRootFilesystem), or be a digest after "sha256:", or a commit pin after "@" in a workflow, or be written out on the list
#     in tests/allowed_strings.py. A real key is random letters and digits, which has none of those looks, so it is refused;
#   - every "://" must be followed by a plain host name and a port, never by a name and password.
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Folders that are not part of the repo's own files (tools, caches, private notes that are never committed).
SKIPPED_FOLDERS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", "node_modules", ".model_cache", "model_cache", "docs-private"}
MAX_BYTES = 1_000_000
# The only files whose lines may start with a bare 64-character digest (a checksum file).
DIGEST_FILES = ("model/model.sha256",)

LONG_TOKEN = re.compile(r"[A-Za-z0-9_+/=-]{20,}")
MAX_WORD = 24
SPLIT = re.compile(r"[_/+=-]")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")
# A word is a run of two or more lowercase letters, a Capitalised word, or a run of capitals not followed by a lowercase letter (an
# acronym). A part of a name is one or more words, then up to four digits (sha256, api03, v2), or just up to four digits, or a single
# letter, or anything of four characters or fewer (k8s, s3, ec2). Random mixed-case letters break into one-letter pieces and fail.
WORD = r"(?:[A-Z]+(?![a-z])|[A-Z]?[a-z]{2,})"
PART = re.compile(rf"(?:{WORD})+[0-9]{{0,4}}|[0-9]{{1,4}}|[A-Za-z]|[A-Za-z0-9]{{2,4}}")
AUTHORITY = re.compile(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?=[/\s'\")\]>}`,;]|$)")


# In plain English: true when a long token reads like a name: parts joined by underscores or dashes, each part made of words.
def looks_like_a_name(token):
    for part in SPLIT.split(token):
        if not part:
            continue
        # A name is built from words, and a word is short: a run of more than 24 letters of one case is not a word.
        if (re.fullmatch(r"[a-z]+|[A-Z]+", part) and len(part) > MAX_WORD) or not PART.fullmatch(part):
            return False
    return True


def repo_files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in SKIPPED_FOLDERS for part in relative.parts):
            continue
        if path.is_file():
            yield path, relative.as_posix()


def readable_text_files():
    for path, relative in repo_files():
        if path.stat().st_size > MAX_BYTES:
            continue
        try:
            yield relative, path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # a binary file: nothing to read as text


# In plain English: every long token in the text that is not explained, as (line number, token).
def unexplained_tokens(relative, text, allowed_strings=()):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in LONG_TOKEN.finditer(line):
            token = match.group(0)
            before = line[max(0, match.start() - 7):match.start()]
            if HEX64.fullmatch(token) and (before.endswith("sha256:") or (relative in DIGEST_FILES and match.start() == 0)):
                continue
            if HEX40.fullmatch(token) and before.endswith("@") and "uses:" in line:
                continue
            if looks_like_a_name(token) or token in allowed_strings:
                continue
            found.append((number, token))
    return found


# In plain English: every "://" in the text that is not followed by a plain host name (and port), as a line number.
def unexplained_addresses(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in re.finditer("://", line):
            if not AUTHORITY.match(line[match.end():]):
                found.append(number)
    return found


# In plain English: the files present that are not on the allowed list, and the listed files that are gone.
def files_not_on_the_list(present, allowed):
    return sorted(set(present) - set(allowed))


def listed_files_that_are_gone(present, allowed):
    return sorted(set(allowed) - set(present))
