# Grader service

The AI Assessment Grader's grading worker, rebuilt as one small Python microservice. It will take
grading jobs off Kafka, look up similar graded examples from the knowledge service, ask a grading
model for a grade, and put the result back on Kafka. **Right now it is only the secure baseline:**
no Kafka, no model, no grading yet. Those arrive in later steps, each with its own tests.

## What it does today

| Address | Answer |
|---|---|
| `GET /health` | `{"ok": true}` while the process is alive |
| `GET /ready` | `{"ok": true}` when the grader is ready to work, otherwise a plain 503 |

There are no other routes. The automatic documentation pages are switched off. Nothing in the
cluster can ask the grader to do anything over HTTP, because it does its work from Kafka.

## Decisions that shape this service

- **No database.** The grader is stateless: jobs and results travel over Kafka. A test fails if a
  database library, a SQL file or a `db/` folder ever appears (`tests/test_no_database.py`).
- **No AI and no AWS yet.** The first model call will be to a fake provider. Bedrock comes after
  that, through one AWS role that may call only `InvokeModel` on one model in one region, with a
  monthly spending alarm, and its credentials mounted as a file.
- **No outbound connections yet.** When the knowledge-service lookup and Kafka are added they are
  added to the reviewed list in `tests/test_fixed_destinations.py` on purpose.

## Security guardrails

Every guardrail is a test that runs on every pull request. Each test is tagged with the OWASP
Top 10:2025 weaknesses (CWEs) it proves, and `expected-coverage.txt` lists the weaknesses this repo
claims. The pipeline fails if a claimed weakness has no passing test, or a test is tagged with a
weakness that is not claimed. The written design rules, each tied to a named test, are in
[`docs/design-rules.md`](docs/design-rules.md).

| Guardrail | Test file |
|---|---|
| The exact list of routes, docs closed, odd address spellings | `tests/test_routes.py` |
| Fixed error replies and safe log lines | `tests/test_error_handling.py`, `tests/test_error_handling_rules.py` |
| Replies labelled JSON, no request text in reply headers | `tests/test_replies.py` |
| No shell, eval or object loading; no file access; no uploads | `tests/test_forbidden_calls.py`, `tests/test_no_file_access.py`, `tests/test_no_file_uploads.py` |
| Only reviewed cryptography | `tests/test_cryptography_rules.py` |
| Settings fixed at deploy time, nothing identifies a caller except a key | `tests/test_configuration_rules.py`, `tests/test_identity_rules.py` |
| Secrets read only from mounted files under `/etc/secrets` | `tests/test_secret_files.py` |
| No secret in any repo file | `tests/test_no_secrets_in_the_repo.py` |
| Locked, hash-checked libraries, pinned base image and Actions | `tests/test_dependency_lock.py`, `tests/test_supply_chain_pins.py`, `tests/test_image_pins.py` |
| Hardened, internal-only pods | `tests/test_pod_hardening.py`, `tests/test_internal_only.py`, `tests/test_k8s_manifests.py` |
| Wrong arguments caught before the program runs (mypy) | `tests/test_type_checking.py` |

Dependency and image scanning run in `.github/workflows/dependency-audit.yml` and
`.github/workflows/image-scan.yml`, and Dependabot proposes updates (`.github/dependabot.yml`).

## Running it

```
docker build -t grader-service .
docker run --rm -p 8000:8000 grader-service
```

On the laptop cluster: `bash k8s/deploy.sh` (it looks at which cluster `kubectl` points at and
refuses anything it does not recognise). `bash k8s/deploy.sh --preview` only prints what it would
deploy.

## Tests

```
pip install --require-hashes -r requirements-dev.txt
pytest -v --ignore=tests/test_k8s_manifests.py
```

The Kubernetes file checks (`tests/test_k8s_manifests.py`) need `kubectl` and run in their own
pipeline job. To regenerate a lock file after editing its `.in` file, use the command written at the
top of the `.in` file (it needs Docker).

## Known limits

- No Kafka, no knowledge-service lookup, no model: the service does not grade anything yet.
- No inbound keys: with no business routes there is nothing to protect with a key. The first inbound
  route, if one is ever added, must come with its own key check and permission tests.
- TLS, encryption of stored data and Kafka login wait for the AWS step, the same as the other
  services.
