# In plain English: tests that the grader's web side stays tiny. It has exactly two addresses, /health and /ready,
# both read-only, and nothing else: no business routes, no documentation pages, no way for a caller to ask the
# grader to do anything. If a new route is ever added, this test goes red until the route is written down here
# on purpose, with its protection decided in the same pull request.
#
# Why it matters (OWASP A01 and A06): fewer routes means less attack surface (CWE-1125), nothing is open that was
# not meant to be (CWE-419, 656), and an address spelled in an odd way cannot reach anything the plain spelling
# cannot (CWE-288, 289).
import pytest
from fastapi.testclient import TestClient
from starlette.routing import Route

from app.main import app

client = TestClient(app)

# Every route of the service, written out. A new route must be added here AND given a decision about who may call it.
EXPECTED_ROUTES = {"GET /health", "GET /ready"}
OPEN_PATHS = {"/health", "/ready"}


def real_route_keys():
    found = set()
    for route in app.routes:
        if isinstance(route, Route) or hasattr(route, "methods"):
            for method in route.methods:
                found.add(f"{method} {route.path}")
    return found


@pytest.mark.owasp("A06", 1125, 419, 656)
@pytest.mark.owasp("A01", 497)
def test_the_routes_that_exist_are_exactly_the_routes_these_tests_know_about():
    assert real_route_keys() == EXPECTED_ROUTES


@pytest.mark.owasp("A06", 1125, 419, 656)
@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_the_documentation_pages_are_closed(path):
    reply = client.get(path)
    assert reply.status_code == 404 and reply.json() == {"problem": "Not found"}


@pytest.mark.owasp("A06", 1125)
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete", "head"])
@pytest.mark.parametrize("path", sorted(OPEN_PATHS))
def test_the_two_routes_accept_nothing_but_reading(method, path):
    reply = client.request(method.upper(), path)
    assert reply.status_code == 405
    if method != "head":  # a HEAD reply has no body by definition
        assert reply.json() == {"problem": "Method not allowed"}


# In plain English: many ways of writing an address, or an address that merely looks like a real one.
def spellings(path):
    return [
        path.upper(),
        path.title(),
        path + "/",
        "/" + path,
        "/." + path,
        path + "%20",
        path + "%2f",
        path + "%00",
        path + ";x=1",
        "/health/.." + "/admin",
        "/%2e" + path,
        "/health%2f.." + path,
    ]


@pytest.mark.owasp("A07", 288, 289)
@pytest.mark.owasp("A06", 419, 656)
@pytest.mark.parametrize("path", sorted(OPEN_PATHS))
def test_an_odd_spelling_of_an_address_reaches_nothing_the_plain_spelling_does_not(path):
    for variant in spellings(path):
        reply = client.get(variant)
        # Either it is the real, harmless route or it is a plain fixed refusal. Nothing else exists to reach.
        assert reply.status_code in (200, 404, 405, 307, 308), (variant, reply.status_code)
        if reply.status_code != 200:
            assert reply.headers.get("content-type", "").startswith("application/json") or reply.status_code in (307, 308)
        assert "detail" not in reply.text


@pytest.mark.owasp("A06", 1125, 419)
def test_the_health_checks_say_nothing_about_the_inside():
    for path in sorted(OPEN_PATHS):
        reply = client.get(path)
        assert reply.status_code == 200 and reply.json() == {"ok": True}
