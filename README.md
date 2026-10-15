# Grader service

The AI Assessment Grader's grading worker, rebuilt as one small Python microservice. It will take
grading jobs off Kafka, look up similar graded examples from the knowledge service, ask a grading
model for a grade, and put the result back on Kafka. **Right now it reads jobs, looks up
similar examples and sends results, but the grade comes from a FAKE provider:** there is no AI yet. The model arrives in a later
step, with its own guardrails and tests.

## What it does today

| Address | Answer |
|---|---|
| `GET /health` | `{"ok": true}` while the process is alive |
| `GET /ready` | `{"ok": true}` when the grader is ready to work, otherwise a plain 503 |

There are no other routes. The automatic documentation pages are switched off. Nothing in the
cluster can ask the grader to do anything over HTTP, because it does its work from Kafka.

## Decisions that shape this service

- **No database.** The grader is stateless: jobs and results travel over Kafka. A test fails if a
  database library, a SQL file or a `db/` folder ever appears (`tests/test_allowed_code.py`).
- **No AI and no AWS yet.** The first model call will be to a fake provider. Bedrock comes after
  that, through one AWS role that may call only `InvokeModel` on one model in one region, with a
  monthly spending alarm, and its credentials mounted as a file.
- **One outbound web call.** The lookup (`app/lookup.py`) asks the knowledge service for similar graded examples with the
  grader's own key. Its address is a deploy-time setting, its path is fixed, redirects and proxy settings are ignored, and the
  reply is size-capped and checked strictly. It is the only file allowed to use a web client, written down on purpose in
  `tests/test_fixed_destinations.py`.

## Security guardrails

Every guardrail is a test that runs on every pull request. Each test is tagged with the OWASP
Top 10:2025 weaknesses (CWEs) it proves, and `expected-coverage.txt` lists the weaknesses this repo
claims. The pipeline fails if a claimed weakness has no passing test, or a test is tagged with a
weakness that is not claimed. The written design rules, each tied to a named test, are in
[`docs/design-rules.md`](docs/design-rules.md).

| Guardrail | Test file |
|---|---|
| The exact list of routes, docs closed, odd address spellings | `tests/test_routes.py` |
| Fixed error replies and safe log lines | `tests/test_error_handling.py`, `tests/test_allowed_code.py` |
| Replies labelled JSON, no request text in reply headers | `tests/test_replies.py` |
| No shell, eval or object loading; no file access; no uploads | `tests/test_allowed_code.py` |
| Only reviewed cryptography | `tests/test_allowed_code.py` |
| Settings fixed at deploy time, nothing identifies a caller except a key | `tests/test_allowed_code.py` |
| Secrets read only from mounted files under `/etc/secrets` | `tests/test_secret_files.py` |
| The lookup: one fixed address, no redirects, strict reply, failures stop the worker | `tests/test_lookup.py`, `tests/test_worker.py` |
| Strict job and result messages, contract limits | `tests/test_jobs.py`, `tests/test_reason_codes.py` |
| No secret in any repo file | `tests/test_no_secrets_in_the_repo.py` |
| Only listed imports, calls and names in each code file | `tests/test_allowed_code.py`, `tests/allowed_table.py` |
| Only listed Dockerfile and .dockerignore lines | `tests/test_allowed_build_files.py` |
| Only listed settings in each Kubernetes file | `tests/test_allowed_manifests.py`, `tests/allowed_paths.py` |
| A short password or a lowercase key is also found (a detector, as an extra layer) | `tests/detect_layer.py`, `tests/test_detect_secrets_layer.py`, `tests/allowed_detections.py` |
| A key cannot be pushed, even in a commit that is later removed | `hooks/check_pushed_commits.py`, `tests/test_pre_push_check.py` |
| Locked, hash-checked libraries, pinned base image and Actions | `tests/test_dependency_lock.py`, `tests/test_supply_chain_pins.py`, `tests/test_image_pins.py` |
| Hardened, internal-only pods | `tests/test_pod_hardening.py`, `tests/test_allowed_manifests.py`, `tests/test_k8s_manifests.py` |
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

- No model: the grade is a fixed fake answer. The similar examples are fetched and checked but not yet used.
- No inbound keys: with no business routes there is nothing to protect with a key. The first inbound
  route, if one is ever added, must come with its own key check and permission tests.
- TLS, encryption of stored data and Kafka login wait for the AWS step, the same as the other
  services. Until then the call to the knowledge service travels in plain text inside the cluster and its reply is not
  signed.
- The key for the knowledge service is a Secret made by hand (`knowledge-lookup-key`); the deploy script checks it exists
  and never creates it.

## Install the pre-push check (once, on your computer)

```bash
git config core.hooksPath hooks
python -m pip install --require-hashes -r requirements-dev.txt
```

The second line installs the secret detector the check uses. Without it every push is refused with this same command, because a check that cannot run must never look like a check that passed.

From then on every `git push` first runs `hooks/check_pushed_commits.py`, which refuses the push if any commit about to leave holds a key,
a password in an address or a file that is not on `tests/allowed_files.py`.
