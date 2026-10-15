# In plain English: what the secret detector (tests/detect_layer.py) finds in this repo that is NOT a secret, each written out with the
# file, the exact value and the reason. A find that is not here fails tests/test_detect_secrets_layer.py (and the pre-push check), so a new
# find is either fixed or accepted here in a pull request that someone reads. A listed find that the detector no longer makes also
# fails, so the list cannot grow stale. Never list a real secret.
ALLOWED_DETECTIONS = {
    ('k8s/base/worker-deployment.yaml', 'knowledge-lookup-key'): 'the NAME of the Secret object that holds the key (secretName), not the key itself',
    ('tests/allowed_bad_programs.py', 'def read_secret2(name):\\n    return read_secret(name)\\n'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
    ('tests/test_allowed_build_files.py', 'RUN --mount=type=secret,id=key cat /run/secrets/key'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
    ('tests/test_k8s_manifests.py', 'kubectl create secret generic x -n grader --from-literal=key=1'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
    ('tests/test_k8s_manifests.py', 'kubectl get secret knowledge-lookup-key -n grader -o yaml'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
    ('tests/test_no_secrets_in_the_repo.py', 'a made-up value'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
    ('tests/test_pre_push_check.py', 'made up'): 'text inside a test about secrets: a made-up example or a command the test shows is refused, not a secret',
}
