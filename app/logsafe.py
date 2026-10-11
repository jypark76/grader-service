# In plain English: makes text safe to put in a log line. Anything a caller could send (a route, a method) is
# cleaned first, so a caller can never forge or split a log line (OWASP A09: CWE-117).
import re

# The most characters of a route that are written to a log line.
PATH_LOG_LENGTH = 100


# In plain English: keeps only letters, digits and a few harmless marks; every other character becomes "?"; and the
# text is cut to the given length.
def _safe_text(text, longest):
    return re.sub(r"[^A-Za-z0-9/_.~%\-]", "?", text)[:longest]
