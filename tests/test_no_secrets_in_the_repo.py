# In plain English: tests that nothing secret is saved in this repo. The repo is PUBLIC, so a key, a password or a private key committed
# by mistake is visible to the whole world and stays in the history even after it is deleted.
#
# These tests work from what is ALLOWED, not from a list of key shapes to hunt for (whoever invents the next key format would
# slip past such a list):
#   - every file must be on the list in tests/allowed_files.py, so a key file, a .env file, a Kubernetes Secret or any new file is a
#     decision made in a pull request that someone reads;
#   - every long run of letters, digits, dashes and underscores (20 or more) must read like a name, be a digest or a commit pin, or
#     be written out in tests/allowed_strings.py with its reason; a real key is random and reads like none of those;
#   - every "://" outside the tests folder must be followed by a plain host name, never by a name and password;
#   - (the kinds and settings a Kubernetes file may use are checked in tests/test_allowed_manifests.py; a Secret is not allowed there).
# Everything is read from the file text, comments included.
#
# Why it matters (OWASP A01): sensitive information in source code (CWE-540), in comments (CWE-615) and in files that outsiders can
# reach (CWE-538). GitHub's push protection catches many keys, but it is a setting somebody can switch off; this test lives in the
# repo and runs on every pull request. (A local pre-push check runs the same test before anything leaves the laptop.)
#
# The checker proves itself: every kind of planted secret must be refused. The planted values are built from short pieces below, so
# this file does not contain a complete secret that it would then flag in itself.
from pathlib import Path

import pytest

import allowed_text
from allowed_files import ALLOWED_FILES
from allowed_strings import ALLOWED_STRINGS

ROOT = allowed_text.ROOT
# The lines .gitignore must keep, so a secret file is never saved by accident.
REQUIRED_IGNORES = [".env", "*.pem", "*.key", "*secret*.yaml", "kubeconfig*"]


# ---------- The real repo ----------

@pytest.mark.owasp("A01", 538, 540)
def test_every_file_in_the_repo_is_on_the_allowed_list():
    present = {relative for _, relative in allowed_text.repo_files()}
    assert allowed_text.files_not_on_the_list(present, ALLOWED_FILES) == [], "not on the allowed list (tests/allowed_files.py)"


@pytest.mark.owasp("A01", 538, 540)
def test_every_file_on_the_allowed_list_still_exists():
    present = {relative for _, relative in allowed_text.repo_files()}
    assert allowed_text.listed_files_that_are_gone(present, ALLOWED_FILES) == [], "listed but gone: remove it from tests/allowed_files.py"


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260)
@pytest.mark.owasp("A04", 321)
def test_no_long_string_in_the_repo_looks_like_a_key():
    problems = []
    for relative, text in allowed_text.readable_text_files():
        for line, token in allowed_text.unexplained_tokens(relative, text, ALLOWED_STRINGS):
            problems.append(f"{relative}:{line}: a {len(token)}-character string that does not read like a name")
    assert problems == []


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260)
def test_no_address_in_the_repo_carries_a_name_and_password():
    # The tests folder is left out on purpose: it holds the bad addresses these checks are proved with, and its long strings are still checked above.
    problems = [f"{relative}:{line}" for relative, text in allowed_text.readable_text_files() if not relative.startswith("tests/") for line in allowed_text.unexplained_addresses(text)]
    assert problems == []


@pytest.mark.owasp("A01", 540, 615)
def test_every_allowed_string_is_still_needed():
    found = set()
    for relative, text in allowed_text.readable_text_files():
        found |= {token for _, token in allowed_text.unexplained_tokens(relative, text)}
    assert sorted(set(ALLOWED_STRINGS) - found) == [], "listed in tests/allowed_strings.py but no file contains it: remove it"


@pytest.mark.owasp("A01", 540, 615, 538)
def test_the_scan_really_reads_the_repo():
    names = {relative for relative, _ in allowed_text.readable_text_files()}
    assert "pytest.ini" in names
    assert len(names) >= 8, names


@pytest.mark.owasp("A01", 538, 540)
def test_gitignore_still_blocks_secret_files():
    lines = {line.strip() for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}
    assert set(REQUIRED_IGNORES) <= lines, sorted(set(REQUIRED_IGNORES) - lines)


# ---------- The check proves itself ----------

def made(*pieces):
    return "".join(pieces)


# Real-looking secrets of the usual kinds, each built from pieces shorter than the limit. Every one must be refused.
PLANTED = {
    "the body of a private key": made("MIIEvQIBADANBgkq", "hkiG9w0BAQEFAASC", "BKcwggSjAgEAAoIB"),
    "an AWS access key id": made("AKIA", "IOSFODNN7EXAMPLE"),
    "an Anthropic API key": made("sk-", "ant-", "api03-", "Xk3pQ9vL2mNz8R", "tYb5WcHd7J4qF"),
    "an OpenAI-style API key": made("sk-", "proj-", "T3BlbkFJx9Qw", "7Lm2Zp8Rk4Vn", "Cd6Hs1Yt5Bf0"),
    "a GitHub token": made("ghp", "_", "R4nd0mT0kenValu3", "Xy9Qw7Lm2Zp8Rk4Vn"),
    "a Slack token": made("xox", "b-", "1234567890-", "AbCdEfGhIjKlMnOp"),
    "a Google API key": made("AI", "zaSyA-", "9QwXy7Lm2Zp8", "Rk4Vn3Bf0Cd6", "Hs1Yt5"),
    "a live payment key": made("sk", "_live_", "4eC39HqLyjWD", "arjtT1zdp7dc"),
    "a signed token (JWT)": made("ey", "JhbGciOiJIUzI1NiJ9", ".ey", "JzdWIiOiIxMjM0", "NTY3ODkwIn0", ".SflKxwRJSMeKKF2QT4"),
    "a long bearer token": made("Authorization: Bearer ", "q7Zr3Wv8Tn1Kc5Yb", "Hd2Lm9Xs4Pf6Gj0A"),
    "a 64-character hex key": made("9f86d081884c7d65", "9a2feaa0c55ad015", "a3bf4f1b2b0b822c", "d15d6c15b0f00a08"),
    "a 48-character hex key": made("9f86d081884c7d65", "9a2feaa0c55ad015", "a3bf4f1b2b0b822c"),
    "a base64 password": made("Zm9vYmFy", "Qm9iU2VjcmV0", "UGFzc3dvcmQx", "MjM0NTY3ODkw"),
    "a key made of lowercase letters and digits": made("x7k2q9m4v8", "b3n6c1z5l0", "p9o8i7u6y5"),
    "a random identifier used as a key": made("3f2b8c1e", "-9d4a-4b7e-", "8a1c-6e5f0d2b9a73"),
    "a long run of digits": made("12345678901234", "567890123456"),
    "the AWS documentation example secret key": made("wJalrXUtnFEMI/", "K7MDENG/bPxRfiCY", "EXAMPLEKEY"),
    "a random base64 key with a slash and a plus": made("Zk3q9XvL2mNz8R", "tYb5WcHd7J4qF/", "x+Pa0Sg1"),
    "a random key of mixed-case letters only": made("kQzXvBnMwLpRtY", "hGjFdSaPoIuYtR", "eWqAzX"),
    "a base64 key broken up by plus signs": made("Zk3q9XvL2mNz8Rt", "+", "Yb5WcHd7J4qFx9P", "+", "a0Sg1Lk7Qw3Er5T"),
    "a key broken up by equals signs": made("Zk3q9XvL2mNz8Rt", "=", "Yb5WcHd7J4qFx9P", "=", "a0Sg1Lk7Qw3Er5T"),
    "a key broken into short pieces": made("Zk3q9X", "-vL2mN", "z8-RtY", "b5-cHd", "7J4-qF", "x9Pa0S"),
    "a lowercase key of 32 letters": made("qzxvbnmwlprtyhgj", "fdsapoiuytrewqkl"),
    "a lowercase key of 40 letters in one run": made("qzxvbnmwlprtyhgjfdsa", "poiuytrewqklmnbvcxzs"),
    "an uppercase key of 30 letters": made("QZXVBNMWLPRTYHG", "JFDSAPOIUYTREWQ"),
    "a base64 key ending in padding": made("Zm9vYmFyQm9iU2Vj", "cmV0UGFzc3dv", "cmQxMjM0NTY3ODk=="),
}


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260)
@pytest.mark.owasp("A04", 321)
@pytest.mark.parametrize("label", sorted(PLANTED))
def test_every_kind_of_planted_secret_is_refused(label):
    assert allowed_text.unexplained_tokens("app/x.py", f"value = {PLANTED[label]}\n"), label


@pytest.mark.owasp("A01", 615)
def test_a_secret_hidden_in_a_comment_is_refused():
    source = "def f():\n    # old key, remove later: " + PLANTED["an AWS access key id"] + "\n    return 1\n"
    assert [token for _, token in allowed_text.unexplained_tokens("app/x.py", source)] == [PLANTED["an AWS access key id"]]


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_secret_is_allowed_only_when_it_is_written_on_the_list():
    secret = PLANTED["a 64-character hex key"]
    assert allowed_text.unexplained_tokens("app/x.py", secret + "\n")
    assert allowed_text.unexplained_tokens("app/x.py", secret + "\n", {secret: "a made-up value"}) == []
    assert allowed_text.unexplained_tokens("app/x.py", secret + "x\n", {secret: "a made-up value"})  # the whole string must match


@pytest.mark.owasp("A01", 540, 615, 538)
def test_a_digest_is_allowed_only_in_the_places_digests_belong():
    digest = PLANTED["a 64-character hex key"]
    commit = digest[:40]
    assert allowed_text.unexplained_tokens("Dockerfile", f"FROM python@sha256:{digest}\n") == []
    assert allowed_text.unexplained_tokens("requirements.txt", f"    --hash=sha256:{digest} \\\n") == []
    assert allowed_text.unexplained_tokens("model/model.sha256", f"{digest}  model.onnx\n") == []
    assert allowed_text.unexplained_tokens("app/x.py", f"{digest}  model.onnx\n")  # a bare digest at the start of a line, in any other file
    assert allowed_text.unexplained_tokens("app/x.py", f"key = {digest}\n")
    assert allowed_text.unexplained_tokens(".github/workflows/tests.yml", f"      - uses: actions/checkout@{commit} # v7\n") == []
    assert allowed_text.unexplained_tokens("app/x.py", f"key = '{commit}'\n")
    assert allowed_text.unexplained_tokens(".github/workflows/tests.yml", f"      - run: echo {commit}\n")
    assert allowed_text.unexplained_tokens(".github/workflows/tests.yml", f"      - run: echo me@{commit}\n")  # an @ alone is not enough, the line must be a "uses:" line


@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize(
    "ordinary",
    [
        "def test_every_bad_program_about_run_code_is_refused(label):",
        "readOnlyRootFilesystem: true",
        "allowPrivilegeEscalation: false",
        "KNOWLEDGE_URL_FILE = os.environ.get('SOMETHING_ELSE')",
        "image: knowledge-service.knowledge.svc.cluster.local",
        "topic grading-jobs.dead-letter is written by the worker",
        "tests/test_every_app_file_uses_only_what_its_entry_allows",
        "HTTPError and ParseConstantObjectPairsHook are names",
        "a sentence with many ordinary words that goes on and on without any run of twenty characters",
        "a_name_with_a_long_but_real_word_internationalization_support",
        "ELEVEN_UPPER_CASE_WORDS_JOINED_BY_UNDERSCORES_IS_FINE",
    ],
)
def test_ordinary_text_is_not_refused(ordinary):
    assert allowed_text.unexplained_tokens("app/x.py", ordinary + "\n") == []


@pytest.mark.owasp("A01", 538, 540)
@pytest.mark.parametrize("name", [".env", ".env.local", "server.pem", "signing.key", "keystore.p12", "id_rsa", "kubeconfig", "db-secret.yaml", "notes.txt", "k8s/base/secret.yaml", "tests/new_test.py"])
def test_a_new_file_is_refused_until_it_is_listed(name):
    assert name not in ALLOWED_FILES
    assert allowed_text.files_not_on_the_list([*ALLOWED_FILES, name], ALLOWED_FILES) == [name]


@pytest.mark.owasp("A01", 538, 540)
def test_a_listed_file_that_is_gone_is_reported():
    assert allowed_text.listed_files_that_are_gone(ALLOWED_FILES[1:], ALLOWED_FILES) == [ALLOWED_FILES[0]]
    assert allowed_text.listed_files_that_are_gone(ALLOWED_FILES, ALLOWED_FILES) == []


@pytest.mark.owasp("A01", 540, 615)
@pytest.mark.parametrize(
    "address",
    [
        made("postgresql", "://user:", "hunter2pw", "@db.example"),
        made("https", "://admin:", "pw", "@host"),
        made("redis", "://:", "pw", "@host:6379/0"),
        made("http", "://", "user@host"),
        made("http", "://$", "HOST:80"),
    ],
)
def test_an_address_carrying_a_name_or_password_is_refused(address):
    assert allowed_text.unexplained_addresses(f"url = '{address}'\n")


@pytest.mark.owasp("A01", 540, 615)
@pytest.mark.parametrize(
    "address",
    [
        made("http", "://knowledge-service.knowledge.svc.cluster.local:8000"),
        made("https", "://github.com/jypark76/grader-service"),
        made("http", "://localhost:8000/health"),
        made("postgresql", "://db.example:5432/app"),
    ],
)
def test_a_plain_address_is_not_refused(address):
    assert allowed_text.unexplained_addresses(f"url = '{address}'\n") == []


@pytest.mark.owasp("A01", 538, 540)
def test_the_required_ignore_list_names_the_essentials():
    assert {".env", "*.pem", "*.key", "*secret*.yaml", "kubeconfig*"} <= set(REQUIRED_IGNORES)
