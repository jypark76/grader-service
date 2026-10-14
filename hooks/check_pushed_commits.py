#!/usr/bin/env python3
# In plain English: the check that runs on your own computer just BEFORE anything is pushed to GitHub (see hooks/pre-push). The repo is
# public, so a key that reaches GitHub, even in a commit that a later commit removes, has already been seen by everyone. GitHub's
# own push protection is a second line of defence, but it is a setting that can be switched off; this check lives in the repo.
#
# It reads every commit that is about to be pushed and applies the same allowed lists as tests/test_no_secrets_in_the_repo.py:
#   - a file added by a pushed commit must be on tests/allowed_files.py;
#   - every long string on an added line must read like a name, be a digest or a commit pin, or be on tests/allowed_strings.py;
#   - an added quoted value next to a word such as password, secret, token or api_key must read like a joined name;
#   - an added web address must have a plain host name, never a name and password in front of it (outside the tests folder).
# It uses only what Python ships with, so it needs nothing installed. Install it once with:   git config core.hooksPath hooks
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import allowed_text  # noqa: E402
from allowed_files import ALLOWED_FILES  # noqa: E402
from allowed_strings import ALLOWED_STRINGS  # noqa: E402

NOTHING = "0" * 40


# In plain English: the lines a patch adds, as (file, text), and the files it adds, from the text of `git log -p` or `git diff`.
# Inside a hunk every line starts with a space, + or -, so a added line that itself starts with "++ " (it shows as "+++ ") is still an
# added line and not a file header. A file header can only appear before the first hunk of a file.
def added_in(patch_text):
    lines, files, current = [], [], None
    new_file = in_hunk = False
    for raw in patch_text.splitlines():
        if raw.startswith("diff --git "):
            current, new_file, in_hunk = None, False, False
        elif in_hunk:
            if raw.startswith("+") and current is not None:
                lines.append((current, raw[1:]))
        elif raw.startswith("new file mode"):
            new_file = True
        elif raw.startswith("+++ "):
            name = raw[4:]
            current = name[2:] if name.startswith("b/") else name
            if current and new_file:
                files.append(current)
        elif raw.startswith("@@"):
            in_hunk = True
    return lines, files


# In plain English: everything wrong with the added lines and files of a patch, as plain sentences.
def patch_problems(patch_text, allowed_files=None, allowed_strings=None):
    allowed_files = ALLOWED_FILES if allowed_files is None else allowed_files
    allowed_strings = ALLOWED_STRINGS if allowed_strings is None else allowed_strings
    lines, files = added_in(patch_text)
    problems = [f"{name}: a new file that is not on tests/allowed_files.py" for name in allowed_text.files_not_on_the_list(files, allowed_files)]
    for name, text in lines:
        for _, token in allowed_text.unexplained_tokens(name, text + "\n", allowed_strings):
            problems.append(f"{name}: an added {len(token)}-character string that does not read like a name")
        for _, value in allowed_text.unexplained_secret_values(name, text + "\n", allowed_strings):
            problems.append(f"{name}: an added {len(value)}-character value after a secret-sounding name")
        if not name.startswith("tests/") and allowed_text.unexplained_addresses(text + "\n"):
            problems.append(f"{name}: an added address that carries a name or password")
    return problems


def git(*arguments):
    return subprocess.run(["git", *arguments], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout


# In plain English: the patch text of the commits a push would send, for one line of the hook's input.
def patch_of_push(local_ref_sha, remote_ref_sha):
    if set(local_ref_sha) == {"0"}:
        return ""  # a branch being deleted sends no commits
    if set(remote_ref_sha) == {"0"}:
        revisions = git("rev-list", local_ref_sha, "--not", "--remotes").split()  # a new branch: every commit GitHub has not seen
        return "".join(git("show", "--format=", "--no-color", "-U0", revision) for revision in reversed(revisions))
    return git("log", "--format=", "-p", "--no-color", "-U0", f"{remote_ref_sha}..{local_ref_sha}")


def main(standard_input):
    problems = []
    for line in standard_input.read().splitlines():
        parts = line.split()
        if len(parts) != 4:
            problems.append("git sent a line this check does not understand, so nothing is pushed")
            continue
        problems += patch_problems(patch_of_push(parts[1], parts[3]))
    if problems:
        print("Nothing was pushed. These commits hold something that is not allowed in a public repo:", file=sys.stderr)
        for problem in sorted(set(problems)):
            print("  " + problem, file=sys.stderr)
        print("If it is a made-up test value, add it with a reason to tests/allowed_strings.py or the file to tests/allowed_files.py, commit, and push again.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.stdin))
