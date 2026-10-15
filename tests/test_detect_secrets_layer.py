# In plain English: the second layer of the secrets check. The allowed lists (tests/test_no_secrets_in_the_repo.py) cannot judge a SHORT value
# such as a typed password, so a detector, detect-secrets from Yelp, also reads every file. Everything it finds must be written on
# tests/allowed_detections.py with a reason, otherwise this test fails. It is a detector, not an allow list, so it is only an extra layer;
# the allowed lists stay the main guarantee. (Denny accepted the detector as a second layer on 2026-10-14.)
#
# Why it matters (OWASP A07 CWE-259 and CWE-798, hard-coded password and credentials; A02 CWE-260, password in a configuration file;
# A01 CWE-540, 615 and 538, secrets in source, comments and files; A04 CWE-321, hard-coded key).
#
# The layer proves itself: planted passwords and keys of the kinds the allowed lists cannot judge must each be found, in every kind of
# file, even with the detector's own "pragma: allowlist secret" comment next to them. The planted values are built from short pieces, so
# this file does not contain a complete secret.
import sys

import pytest

import allowed_text
import detect_layer
from allowed_detections import ALLOWED_DETECTIONS


def made(*pieces):
    return "".join(pieces)


# ---------- The real repo ----------

@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260)
@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.owasp("A04", 321)
def test_the_detector_finds_nothing_in_the_repo_that_is_not_listed():
    problems = []
    for relative, text in allowed_text.readable_text_files():
        for line, kind in detect_layer.unlisted_detections(relative, text, ALLOWED_DETECTIONS):
            problems.append(f"{relative}:{line}: the detector found a {kind}")
    assert problems == [], "\n".join(problems)


@pytest.mark.owasp("A01", 540, 615)
def test_every_listed_find_is_still_made():
    made_now = set()
    for relative, text in allowed_text.readable_text_files():
        made_now |= {(relative, value) for _, _, value in detect_layer.detections_in_text(relative, text)}
    assert detect_layer.stale_listed_finds(made_now, ALLOWED_DETECTIONS) == [], "listed in tests/allowed_detections.py but the detector no longer finds it: remove it"


@pytest.mark.owasp("A01", 540, 615)
def test_every_listed_find_has_a_real_reason():
    assert detect_layer.short_reasons(ALLOWED_DETECTIONS) == []


@pytest.mark.owasp("A01", 540, 615)
def test_a_listed_find_that_is_no_longer_made_is_reported():
    now = {("app/x.py", "one")}
    assert detect_layer.stale_listed_finds(now, {("app/x.py", "one"): "r", ("app/x.py", "two"): "r"}) == [("app/x.py", "two")]
    assert detect_layer.stale_listed_finds(now, {("app/x.py", "one"): "r"}) == []


@pytest.mark.owasp("A01", 540, 615)
def test_a_reason_that_is_too_short_is_reported():
    assert detect_layer.short_reasons({("a", "b"): "ok", ("c", "d"): "a real reason that explains it"}) == [("a", "b")]
    assert detect_layer.short_reasons({("a", "b"): ""}) == [("a", "b")]


# ---------- The layer proves itself ----------

PASSWORD = made("hunter2", "pw")
API_KEY = made("Zq8vK3", "mTx")
LOWERCASE_KEY = made("qzxvbnmwlprt", "yhgjfdsapoiu")
AWS_KEY = made("AKIA", "IOSFODNN7EXAMPLE")

PLANTED = {
    "a password in a python file": ("app/x.py", made("password = \"", PASSWORD, "\"\n")),
    "an api key in a python file": ("app/x.py", made("api_key = \"", API_KEY, "\"\n")),
    "a password with symbols": ("app/x.py", made("PASSWORD = \"P@ss", "w0rd!\"\n")),
    "a password in a yaml file": ("k8s/base/x.yaml", made("password: ", PASSWORD, "\n")),
    "an api key in a yaml file": ("k8s/base/x.yaml", made("api_key: ", API_KEY, "\n")),
    "a word password in a yaml file": ("k8s/base/x.yaml", made("secret: ", "change", "me\n")),
    "a password in an env file": ("x.env", made("PASSWORD=", PASSWORD, "\n")),
    "an api key in an env file": ("x.env", made("API_KEY=", API_KEY, "\n")),
    "a password exported in a shell script": ("k8s/x.sh", made("export PASSWORD=", PASSWORD, "\n")),
    "a password in a markdown file": ("README.md", made("password: ", PASSWORD, "\n")),
    "a lowercase key of 24 letters": ("app/x.py", made("key = \"", LOWERCASE_KEY, "\"\n")),
    "a lowercase key in a text file": ("notes.txt", made("key = ", LOWERCASE_KEY, "\n")),
    "an AWS access key id": ("notes.txt", AWS_KEY + "\n"),
    "a password with the detector's own silencing comment": ("app/x.py", made("password = \"", PASSWORD, "\"  # pragma: allowlist ", "secret\n")),
    "a password with a silencing comment on the line above": ("app/x.py", made("# pragma: allowlist ", "nextline secret\n", "password = \"", PASSWORD, "\"\n")),
}


@pytest.mark.owasp("A07", 259, 798)
@pytest.mark.owasp("A02", 260)
@pytest.mark.owasp("A01", 540, 615, 538)
@pytest.mark.parametrize("label", sorted(PLANTED))
def test_every_planted_secret_is_found(label):
    relative, text = PLANTED[label]
    assert detect_layer.unlisted_detections(relative, text, {}), label


@pytest.mark.owasp("A07", 259, 798)
def test_a_find_is_accepted_only_when_the_file_and_the_exact_value_are_listed():
    relative, text = PLANTED["a password in a python file"]
    assert detect_layer.unlisted_detections(relative, text, {}) != []
    assert detect_layer.unlisted_detections(relative, text, {(relative, PASSWORD): "a made-up example"}) == []
    assert detect_layer.unlisted_detections(relative, text, {("app/other.py", PASSWORD): "a made-up example"}) != []  # another file
    assert detect_layer.unlisted_detections(relative, text, {(relative, PASSWORD + "x"): "a made-up example"}) != []  # another value


@pytest.mark.owasp("A07", 259, 798)
def test_ordinary_text_is_not_a_find():
    text = "KEY_SETTING = \"KNOWLEDGE_KEY\"\nname = \"a sentence of ordinary words\"\nversion = \"0.3.0\"\nimport os\nvalue = os.environ.get(\"X\")\n"
    assert detect_layer.unlisted_detections("app/x.py", text, {}) == []


@pytest.mark.owasp("A01", 540, 615)
def test_text_outside_plain_ascii_does_not_stop_the_scan_or_hide_a_secret():
    relative, text = PLANTED["a password in a python file"]
    assert detect_layer.unlisted_detections(relative, "# café ✓ \U0001f511\n" + text, {}) != []
    assert detect_layer.unlisted_detections("app/x.py", "# café ✓\nx = 1\n", {}) == []


@pytest.mark.owasp("A01", 540, 615)
def test_the_detector_not_being_installed_is_an_error_with_the_install_command_and_never_a_pass(monkeypatch):
    for name in [name for name in sys.modules if name == "detect_secrets" or name.startswith("detect_secrets.")]:
        monkeypatch.setitem(sys.modules, name, None)  # None in sys.modules makes an import of that name fail, as if it were not installed
    with pytest.raises(detect_layer.DetectorMissing) as error:
        detect_layer.detections_in_text("app/x.py", "x = 1\n")
    assert detect_layer.INSTALL_COMMAND in str(error.value)


@pytest.mark.owasp("A01", 540, 615)
def test_the_detectors_own_silencing_comment_is_switched_off():
    names = [entry["path"] for entry in detect_layer.detector_settings()["filters_used"]]
    assert names and not any("allowlist" in name for name in names)
    assert len(detect_layer.detector_settings()["plugins_used"]) >= 20
