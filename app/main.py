# In plain English: this is the front door of the grader service. The grader does its real work by taking grading
# jobs off Kafka (added in a later step), so its web side is deliberately tiny: it answers "are you alive?" and
# "are you ready to work?" for Kubernetes, and nothing else. There are no other routes, so there is nothing for
# a caller to ask the grader to do, and the automatic documentation pages are switched off.
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.errors import catch_everything, fixed_http_error

# Create the web application. The documentation, schema and redoc pages are switched off on purpose: they would
# list the service's insides, and they are routes too (tests/test_routes.py pins the exact list of routes).
app = FastAPI(title="Grader service", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)

# In plain English: every failure ends in a short, fixed reply (see app/errors.py). The catch-all wraps every
# request, so it also catches an error anywhere inside.
app.middleware("http")(catch_everything)
# The framework declares its handler type wider than what it really passes for this error, so the one check below is switched off.
app.add_exception_handler(StarletteHTTPException, fixed_http_error)  # type: ignore[arg-type]


# In plain English: a simple "are you alive?" check. If this address answers {"ok": true}, the service process is
# up. Kubernetes uses it to decide whether to restart the service.
@app.get("/health")
def health():
    return {"ok": True}


# In plain English: decides whether the grader is ready to work. For now it needs nothing outside itself, so it is
# ready whenever it is alive. When the Kafka reader is added, this answers ready only if that is working too.
def work_is_ready():
    return True


# In plain English: an "are you ready to work?" check. It answers {"ok": true} when the grader is ready, and a plain
# 503 with no details when it is not. Kubernetes uses it to decide whether to send work to this copy.
@app.get("/ready")
def ready():
    if work_is_ready():
        return {"ok": True}
    return JSONResponse(status_code=503, content={"ok": False})
