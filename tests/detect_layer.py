# In plain English: the second layer of the secrets check. The first layer is the allowed lists (tests/allowed_text.py): they refuse every
# file and every long random-looking string that nobody listed, but they cannot judge a SHORT value such as a typed password. This layer
# asks a detector, detect-secrets from Yelp, to look at the text. It is a detector, not an allow list, so it is only an extra layer: the
# allowed lists stay the main guarantee.
#
# Two choices keep it honest. The detector is told to ignore its own "pragma: allowlist secret" comment, because that comment would let
# anyone silence it from inside the file. And everything it finds must be written on tests/allowed_detections.py with a reason (the file
# and the exact value), so a finding is either fixed or visibly accepted in a pull request.
import pathlib
import tempfile

INSTALL_COMMAND = "python -m pip install --require-hashes -r requirements-dev.txt"


class DetectorMissing(Exception):
    pass


def _tools():
    try:
        from detect_secrets.core.scan import scan_file
        from detect_secrets.settings import default_settings, get_settings, transient_settings
    except ImportError:
        raise DetectorMissing(f"the secret detector (detect-secrets) is not installed; install it once with:  {INSTALL_COMMAND}") from None
    return scan_file, default_settings, get_settings, transient_settings


# In plain English: the detector's own default plugins and default filters, except the one that honours "pragma: allowlist secret".
def detector_settings():
    _, default_settings, get_settings, _ = _tools()
    with default_settings():
        configured = get_settings().json()
    filters = [entry for entry in configured["filters_used"] if "allowlist" not in entry["path"]]
    return {"plugins_used": configured["plugins_used"], "filters_used": filters}


# In plain English: everything the detector finds in this text, as (line number, kind of find, the value). The text is written to a
# temporary file with the same name, so the detector treats a .yaml, .env or .py file the way it should. Characters outside plain ASCII
# are replaced first, so the result is the same on every computer.
def detections_in_text(relative, text):
    scan_file, _, _, transient_settings = _tools()
    configured = detector_settings()
    with tempfile.TemporaryDirectory() as folder:
        path = pathlib.Path(folder) / pathlib.PurePosixPath(relative).name
        path.write_bytes(text.encode("ascii", "replace"))
        with transient_settings(configured):
            return [(secret.line_number, secret.type, secret.secret_value) for secret in scan_file(str(path))]


# In plain English: the finds in this text that are not written on the allowed list for this file.
def unlisted_detections(relative, text, allowed):
    return [(line, kind) for line, kind, value in detections_in_text(relative, text) if (relative, value) not in allowed]


# In plain English: the listed finds that the detector no longer makes (a stale entry would quietly accept a future find).
def stale_listed_finds(found_now, allowed):
    return sorted(set(allowed) - set(found_now))


# In plain English: the listed finds whose reason is too short to be a real reason.
def short_reasons(allowed):
    return sorted(key for key, reason in allowed.items() if len(str(reason)) < 20)
