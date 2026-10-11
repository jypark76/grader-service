# In plain English: tests that every reply the grader gives is labelled JSON that decodes exactly, and that no
# line break from a request can ever reach a reply header (header splitting, response splitting).
#
# Why it matters (OWASP A05, injection): a reply with the wrong content type or a header built from caller text
# can be read as something else, such as HTML or a second reply (CWE-93, 113, 115, 116, 159).
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ATTACK = "x\r\nSet-Cookie: pwned=1\r\nX-Injected: 1"


def assert_headers_clean(response):
    for name, value in response.headers.items():
        assert "\r" not in value and "\n" not in value, (name, value)
        assert "pwned" not in value, (name, value)
    assert "set-cookie" not in response.headers
    assert "x-injected" not in response.headers


@pytest.mark.owasp("A05", 93, 113)
def test_line_breaks_in_requests_never_reach_reply_headers():
    replies = [
        client.get("/health", params={"x": ATTACK}),
        client.get("/ready", params={"x": ATTACK}),
        client.get("/" + quote(ATTACK)),
        client.get("/health", headers={"X-Test": "plain"}),
        client.post("/health", content=ATTACK),
    ]
    for reply in replies:
        assert_headers_clean(reply)
    assert [r.status_code for r in replies] == [200, 200, 404, 200, 405]


@pytest.mark.owasp("A05", 115, 116, 159)
@pytest.mark.parametrize("request_args", [("get", "/health"), ("get", "/ready"), ("get", "/nothing"), ("post", "/health")])
def test_every_reply_is_labelled_json_and_decodes(request_args):
    method, path = request_args
    reply = getattr(client, method)(path)
    assert reply.headers["content-type"].startswith("application/json")
    assert isinstance(reply.json(), dict)
    assert reply.headers.get("x-content-type-options") in (None, "nosniff")


@pytest.mark.owasp("A05", 115, 116, 159)
def test_html_like_text_in_a_request_comes_back_only_as_data_or_not_at_all():
    reply = client.get("/<script>alert(1)</script>")
    assert reply.status_code == 404
    assert "<script>" not in reply.text
    assert reply.headers["content-type"].startswith("application/json")
