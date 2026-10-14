# In plain English: the long strings (20 or more letters, digits, dashes and underscores) that are allowed in this repo even though
# they do not read like a name. Each is written out in full with the reason. They are all made-up values or public identifiers; a
# real key must never be added here. A string listed here that no file contains any more also fails, so the list cannot grow stale.
ALLOWED_STRINGS = {
    'marker-value-0123456789abcdef': 'a made-up marker used only in tests/test_secret_files.py',
}
