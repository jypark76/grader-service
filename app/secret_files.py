# In plain English: reads a secret (the service keys, the database password) either from a file that Kubernetes
# mounts, or from a plain setting. A setting called NAME_FILE names the file; if it is not set, the setting NAME
# is used, which keeps local runs and tests simple. Kubernetes keeps a mounted Secret up to date, so a changed
# Secret reaches the file without restarting the pod.
#
# This is the only place in app/ that opens a file, and it is strict:
#   - the path must be inside /etc/secrets (where the Secrets are mounted) and every name below it may only use letters,
#     digits, dot, dash and underscore and must start with a letter or digit, so a wrong or tampered setting ("..",
#     a null character, a space, a newline) can never make the service read some other file;
#   - if the file cannot be read the service stops (RuntimeError), it never falls back to something open;
#   - only the final line break is removed from the text, nothing else;
#   - the text is returned, never logged, and never put in an error message.
import os
import re
from pathlib import PurePosixPath

SECRET_FOLDER = ("/", "etc", "secrets")
# The only kind of name a folder or file below /etc/secrets may have: starts with a letter or digit, then letters, digits, dot, dash or underscore.
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


# In plain English: the one place a file is opened. Tests replace it so they need no real files.
def _read_text(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


# In plain English: true only for a path with at least one name below /etc/secrets where every name is made of the
# allowed characters. A path that does not start with "/etc/secrets" (a relative path, another folder, a look-alike such
# as /etc/secretsX) fails the first test, and PurePosixPath has already folded any "." parts away. Anything else, such as
# "..", a null character, a space or a line break, is not in the allowed kind of name.
def _is_allowed(path_text):
    parts = PurePosixPath(path_text).parts
    return parts[:3] == SECRET_FOLDER and len(parts) > 3 and all(SAFE_NAME.fullmatch(part) for part in parts[3:])


# In plain English: returns the secret called NAME, from the file named by NAME_FILE if that is set, otherwise from
# the setting NAME (or None if neither is set).
def read_secret(name):
    path_text = os.environ.get(f"{name}_FILE")
    if not path_text:
        return os.environ.get(name)
    if not _is_allowed(path_text):
        raise RuntimeError(f"{name}_FILE must name a file inside /etc/secrets")
    try:
        text = _read_text(path_text)
    except OSError:
        raise RuntimeError(f"The secret file for {name} could not be read") from None
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text
