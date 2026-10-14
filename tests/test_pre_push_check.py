# In plain English: tests for the check that runs on your own computer just before a push (hooks/check_pushed_commits.py). The repo is
# public, so a key that reaches GitHub, even inside a commit that a later commit removes, has already been seen by everyone. The check
# reads every commit about to be pushed and refuses the push when one holds something not on the allowed lists. These tests show it
# refuses each kind of secret, still refuses one that a later commit removes, leaves honest changes alone, and really refuses a push when
# run against a real git repository.
#
# Why it matters (OWASP A01 CWE-540, 615, 538: secrets in source, comments and files that outsiders can reach; A07 CWE-259, 798: hard-coded
# passwords and keys).
import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

import check_pushed_commits as hook  # noqa: E402


def made(*pieces):
    return "".join(pieces)


SECRETS = {
    "an AWS access key id": made("AKIA", "IOSFODNN7EXAMPLE"),
    "a 64-character hex key": made("9f86d081884c7d65", "9a2feaa0c55ad015", "a3bf4f1b2b0b822c", "d15d6c15b0f00a08"),
    "a base64 password": made("Zm9vYmFy", "Qm9iU2VjcmV0", "UGFzc3dvcmQx", "MjM0NTY3ODkw"),
    "an Anthropic API key": made("sk-", "ant-", "api03-", "Xk3pQ9vL2mNz8R", "tYb5WcHd7J4qF"),
}
ADDRESS_WITH_PASSWORD = made("postgresql", "://user:", "hunter2pw", "@db.example")


# In plain English: the text git shows for a commit that adds one file with the given lines (or changes one with `+` lines).
def patch(path, lines, new=True, removed=()):
    head = f"diff --git a/{path} b/{path}\n" + ("new file mode 100644\n--- /dev/null\n" if new else f"--- a/{path}\n") + f"+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n"
    return head + "".join(f"-{line}\n" for line in removed) + "".join(f"+{line}\n" for line in lines)


@pytest.mark.owasp("A01", 540, 615, 538)
def test_the_lines_and_the_new_files_of_a_patch_are_found():
    text = patch("app/x.py", ["one", "two"]) + patch("README.md", ["three"], new=False, removed=["old"])
    lines, files = hook.added_in(text)
    assert lines == [("app/x.py", "one"), ("app/x.py", "two"), ("README.md", "three")]
    assert files == ["app/x.py"]


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_deleted_file_adds_nothing():
    text = "diff --git a/app/x.py b/app/x.py\ndeleted file mode 100644\n--- a/app/x.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-secret = 1\n"
    assert hook.added_in(text) == ([], [])


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.parametrize("label", sorted(SECRETS))
def test_a_secret_on_an_added_line_refuses_the_push(label):
    problems = hook.patch_problems(patch("app/x.py", [f"value = {SECRETS[label]}"], new=False))
    assert problems and "does not read like a name" in problems[0], label


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
def test_a_secret_that_a_later_commit_removes_still_refuses_the_push():
    first = patch("app/x.py", [f"value = {SECRETS['a 64-character hex key']}"], new=False)
    second = patch("app/x.py", ["value = None"], new=False, removed=[f"value = {SECRETS['a 64-character hex key']}"])
    assert hook.patch_problems(first + second) != []


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
def test_a_password_next_to_its_name_on_an_added_line_refuses_the_push():
    line = made("password = \"", "hunter2", "pw\"")
    problems = hook.patch_problems(patch("app/x.py", [line], new=False))
    assert problems and "after a secret-sounding name" in problems[0]
    assert hook.patch_problems(patch("app/x.py", [made("api_key: \"", "Zq8vK3", "mTx\"")], new=False)) != []
    assert hook.patch_problems(patch("app/x.py", ['password = os.environ.get("DB_PASSWORD")'], new=False)) == []


@pytest.mark.owasp("A01", 540, 615, 538)
def test_removing_a_secret_is_not_refused():
    removal = patch("app/x.py", ["value = None"], new=False, removed=[f"value = {SECRETS['a base64 password']}"])
    assert hook.patch_problems(removal) == []


@pytest.mark.owasp("A01", 538, 540)
def test_a_new_file_must_be_on_the_allowed_list():
    assert hook.patch_problems(patch("server.pem", ["x"])) != []
    assert hook.patch_problems(patch(".env", ["x"])) != []
    assert hook.patch_problems(patch("k8s/base/secret.yaml", ["x"])) != []
    assert hook.patch_problems(patch("README.md", ["x"]), allowed_files=("README.md",)) == []
    assert hook.patch_problems(patch("README.md", ["x"]), allowed_files=()) != []


@pytest.mark.owasp("A01", 540, 615)
def test_an_address_with_a_name_and_password_is_refused_outside_the_tests_folder_only():
    line = f"url = '{ADDRESS_WITH_PASSWORD}'"
    assert hook.patch_problems(patch("app/x.py", [line], new=False)) != []
    assert hook.patch_problems(patch("tests/x.py", [line], new=False)) == []


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_string_on_the_allowed_list_is_not_refused():
    secret = SECRETS["a 64-character hex key"]
    assert hook.patch_problems(patch("tests/x.py", [f"v = '{secret}'"], new=False)) != []
    assert hook.patch_problems(patch("tests/x.py", [f"v = '{secret}'"], new=False), allowed_strings={secret: "made up"}) == []


@pytest.mark.owasp("A01", 540, 615, 538)
def test_honest_changes_pass():
    lines = ["def test_every_bad_program_about_run_code_is_refused(label):", "    readOnlyRootFilesystem: true", "url = 'http://knowledge-service.knowledge.svc.cluster.local:8000'"]
    assert hook.patch_problems(patch("app/x.py", lines, new=False)) == []


# ---------- Against a real git repository ----------

def git(folder, *arguments):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *arguments], cwd=folder, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repository(tmp_path, monkeypatch):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "first")
    monkeypatch.setattr(hook, "ROOT", tmp_path)
    monkeypatch.setattr(hook, "ALLOWED_FILES", ("app/x.py",))
    return tmp_path


def push_of(folder, remote_sha="0" * 40):
    return io.StringIO(f"refs/heads/main {git(folder, 'rev-parse', 'HEAD')} refs/heads/main {remote_sha}\n")


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_real_push_with_a_secret_is_refused_and_one_without_is_allowed(repository, monkeypatch, capsys):
    assert hook.main(push_of(repository)) == 0  # a new branch whose only commit is honest
    base = git(repository, "rev-parse", "HEAD")
    (repository / "app" / "x.py").write_text(f"x = '{SECRETS['a 64-character hex key']}'\n", encoding="utf-8")
    git(repository, "commit", "-q", "-am", "oops")
    assert hook.main(push_of(repository, base)) == 1
    assert "does not read like a name" in capsys.readouterr().err
    (repository / "app" / "x.py").write_text("x = 2\n", encoding="utf-8")
    git(repository, "commit", "-q", "-am", "removed again")
    assert hook.main(push_of(repository, base)) == 1  # the secret is still in the history that would be pushed
    assert hook.main(push_of(repository, git(repository, "rev-parse", "HEAD"))) == 0  # nothing new to push


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_new_branch_is_checked_commit_by_commit_not_only_by_its_last_commit(repository):
    (repository / "app" / "x.py").write_text(f"x = '{SECRETS['a 64-character hex key']}'\n", encoding="utf-8")
    git(repository, "commit", "-q", "-am", "oops")
    (repository / "app" / "x.py").write_text("x = 2\n", encoding="utf-8")
    git(repository, "commit", "-q", "-am", "removed again")
    assert hook.main(push_of(repository)) == 1  # the new branch holds three commits, and the middle one holds the key


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize("line", ["garbage", "refs/heads/main abc", "a b c d e", "   "])
def test_input_from_git_that_is_not_understood_stops_the_push(line):
    assert hook.main(io.StringIO(line + "\n")) == 1


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_branch_that_is_deleted_sends_nothing(repository):
    assert hook.main(io.StringIO(f"(delete) {'0' * 40} refs/heads/main {git(repository, 'rev-parse', 'HEAD')}\n")) == 0


@pytest.mark.owasp("A01", 540, 615, 538)
def test_an_empty_input_is_fine():
    assert hook.main(io.StringIO("")) == 0


# ---------- The hook itself, as git runs it ----------

def real_git(folder, *arguments, check=True):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *arguments], cwd=folder, capture_output=True, text=True, check=check)


@pytest.mark.owasp("A01", 540, 615, 538)
def test_git_will_run_the_hook_because_it_is_marked_executable_in_the_repo():
    # Git silently ignores a hook that is not marked executable, so a hook with mode 100644 protects nothing.
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    listing = real_git(ROOT, "ls-files", "-s", "hooks/pre-push", "hooks/check_pushed_commits.py").stdout.splitlines()
    assert sorted(line.split()[0] for line in listing) == ["100755", "100755"], listing


@pytest.mark.owasp("A01", 540, 615, 538)
def test_the_hook_files_keep_unix_line_endings_on_every_computer():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    assert "hooks/pre-push text eol=lf" in attributes and "hooks/*.py text eol=lf" in attributes


@pytest.fixture
def pushing_repository(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    real_git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    real_git(tmp_path, "init", "-q", "-b", "main", str(work))
    (work / "hooks").mkdir()
    (work / "tests").mkdir()
    (work / "app").mkdir()
    for name in ("pre-push", "check_pushed_commits.py"):
        shutil.copy2(ROOT / "hooks" / name, work / "hooks" / name)
    for name in ("allowed_text.py", "allowed_strings.py"):
        shutil.copy2(ROOT / "tests" / name, work / "tests" / name)
    (work / "tests" / "allowed_files.py").write_text(
        'ALLOWED_FILES = ("app/x.py", "hooks/check_pushed_commits.py", "hooks/pre-push", "tests/allowed_files.py", "tests/allowed_strings.py", "tests/allowed_text.py")\n',
        encoding="utf-8",
    )
    (work / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    real_git(work, "add", "-A")
    real_git(work, "update-index", "--chmod=+x", "hooks/pre-push", "hooks/check_pushed_commits.py")  # as committed in the real repo
    real_git(work, "commit", "-q", "-m", "first")
    real_git(work, "remote", "add", "origin", str(remote))
    real_git(work, "config", "core.hooksPath", "hooks")
    return work, remote


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
def test_a_real_git_push_runs_the_hook_and_is_refused_for_a_key_but_not_for_honest_work(pushing_repository):
    work, remote = pushing_repository
    honest = real_git(work, "push", "origin", "main", check=False)
    assert honest.returncode == 0, honest.stderr
    (work / "app" / "x.py").write_text(f"x = '{SECRETS['a 64-character hex key']}'\n", encoding="utf-8")
    (work / "leaked.env").write_text("TOKEN=1\n", encoding="utf-8")
    real_git(work, "add", "-A")
    real_git(work, "commit", "-q", "-m", "oops")
    leaked = real_git(work, "push", "origin", "main", check=False)
    assert leaked.returncode != 0 and "Nothing was pushed" in leaked.stderr, leaked.stderr
    assert "leaked.env" in leaked.stderr
    on_remote = real_git(remote, "rev-parse", "main").stdout.strip()
    assert on_remote != real_git(work, "rev-parse", "HEAD").stdout.strip()  # the remote never received the bad commit


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_real_git_push_is_not_waved_through_when_the_hook_is_not_executable(pushing_repository):
    # This proves why the executable mark matters: with it removed git runs nothing and the same bad push goes through.
    work, remote = pushing_repository
    (work / "leaked.env").write_text("TOKEN=1\n", encoding="utf-8")
    real_git(work, "add", "-A")
    real_git(work, "update-index", "--chmod=-x", "hooks/pre-push")
    real_git(work, "commit", "-q", "-m", "oops")
    (work / "hooks" / "pre-push").chmod(0o644)
    assert real_git(work, "push", "origin", "main", check=False).returncode == 0


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_line_that_starts_with_two_plus_signs_is_still_scanned():
    key = SECRETS["a 64-character hex key"]
    text = "diff --git a/app/x.py b/app/x.py\n--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1,2 @@\n-x\n+++ " + key + "\n"
    assert hook.added_in(text) == ([("app/x.py", "++ " + key)], [])
    assert hook.patch_problems(text) != []
    # and a removed line that starts with two minus signs does not confuse the file header either
    text = "diff --git a/app/x.py b/app/x.py\n--- a/app/x.py\n+++ b/app/x.py\n@@ -1,2 +1,2 @@\n--- old\n+++ " + key + "\n"
    assert hook.patch_problems(text) != []


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize("name", ["python", "python3"])
def test_the_hook_works_with_either_python_name(pushing_repository, tmp_path, monkeypatch, name):
    import os

    if os.name != "posix":
        pytest.skip("this test shapes PATH the way a Unix computer has it")
    work, remote = pushing_repository
    bin_folder = tmp_path / "only-one-python"
    bin_folder.mkdir()
    (bin_folder / name).symlink_to(sys.executable)
    git_folder = str(Path(shutil.which("git")).parent)
    monkeypatch.setenv("PATH", f"{bin_folder}:{git_folder}:/bin")
    honest = real_git(work, "push", "origin", "main", check=False)
    assert honest.returncode == 0, honest.stderr
    (work / "app" / "x.py").write_text(f"x = '{SECRETS['a 64-character hex key']}'\n", encoding="utf-8")
    real_git(work, "commit", "-q", "-am", "oops")
    leaked = real_git(work, "push", "origin", "main", check=False)
    assert leaked.returncode != 0 and "Nothing was pushed" in leaked.stderr, leaked.stderr
