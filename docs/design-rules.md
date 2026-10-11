# Design rules

The secure-design rules this service follows, each with the test that proves it. A test
(`tests/test_design_rules.py`) fails if a named test is renamed or deleted, so this page cannot
claim a rule that nothing checks. To add a rule, add the test first, then a row here.

| Rule | In plain words | Proof |
|---|---|---|
| Minimal surface | The web side has exactly two routes, health and ready, and nothing else. | `tests/test_routes.py::test_the_routes_that_exist_are_exactly_the_routes_these_tests_know_about` |
| Documentation closed | The documentation and schema pages are switched off. | `tests/test_routes.py::test_the_documentation_pages_are_closed` |
| Labelled replies | Every reply is labelled JSON and no request text reaches a reply header. | `tests/test_replies.py::test_every_reply_is_labelled_json_and_decodes` |
| No default secrets | A password or key setting never has a built-in default. | `tests/test_identity_rules.py::test_identity_uses_only_the_key_and_no_secret_setting_has_a_default` |
| Secrets as files | A secret is read from a read-only mounted file, never from the environment. | `tests/test_secret_files.py::test_the_file_is_used_when_it_is_named_and_wins_over_the_plain_setting` |
| Reveal nothing | An unexpected error gets one fixed reply with nothing from inside. | `tests/test_error_handling.py::test_an_unexpected_error_gets_a_fixed_reply_with_nothing_from_inside` |
| Internal only | Nothing this repo deploys can be reached from outside the cluster. | `tests/test_internal_only.py::test_nothing_this_repo_deploys_can_be_reached_from_outside_the_cluster` |
| Hardened pods | Every pod is locked down: no Kubernetes token, default seccomp, read-only filesystem. | `tests/test_pod_hardening.py::test_every_pod_this_repo_deploys_is_locked_down` |
| Pinned supply chain | Every Python library is pinned exactly and checked by hash. | `tests/test_dependency_lock.py::test_every_library_in_a_lock_is_pinned_exactly_and_has_hashes` |
| Pinned images | Every ready-made image is pinned to an exact digest. | `tests/test_image_pins.py::test_every_ready_made_image_in_the_real_files_is_pinned_to_a_digest` |
| Reviewed cryptography | The only cryptography is the reviewed set; anything new is a deliberate change. | `tests/test_cryptography_rules.py::test_application_code_uses_no_unreviewed_cryptography` |
| No dangerous functions | No shell commands, code evaluation or object loading. | `tests/test_forbidden_calls.py::test_application_code_contains_no_forbidden_calls` |
| Checked calls | The type checker finds wrong arguments before the program runs. | `tests/test_type_checking.py::test_the_application_passes_the_type_checker` |
| Settings fixed at deploy | The code cannot change its own settings, and opens no cross-domain or XML door. | `tests/test_configuration_rules.py::test_the_application_code_keeps_its_configuration_fixed_and_opens_no_cross_domain_or_xml_doors` |
| No uploads | The application accepts no uploaded files or forms. | `tests/test_no_file_uploads.py::test_application_code_accepts_no_uploaded_files_or_forms` |
| No file access | The application opens no file except the reviewed secret-file reader. | `tests/test_no_file_access.py::test_application_code_never_touches_the_file_system_or_redirects` |
| No database | The grader is stateless: no database library, no SQL file. | `tests/test_no_database.py::test_the_application_imports_no_database_library` |
| Fixed destinations | The application opens no outbound connection to an address a caller could choose. | `tests/test_fixed_destinations.py::test_application_code_reaches_only_fixed_destinations` |
| Strict messages | Every job is read strictly against the contract; anything else is refused with a reason code. | `tests/test_jobs.py::test_a_bad_message_is_refused_with_its_code` |
| Done only after delivery | A message is committed only after its answer or dead-letter copy is confirmed delivered. | `tests/test_worker.py::test_a_good_job_sends_its_answer_to_the_results_topic_before_the_commit` |
| Never lose a job | If an answer cannot be delivered, nothing is committed and the worker stops. | `tests/test_worker.py::test_an_answer_that_is_not_delivered_is_not_committed` |
| No student text in logs | The log carries only the outcome and the offset. | `tests/test_worker.py::test_the_log_carries_only_the_outcome_and_the_offset` |
| One fixed destination | The only outbound web call goes to one deploy-time address and one fixed path; nothing in a message can change it. | `tests/test_lookup.py::test_nothing_in_the_job_can_change_where_the_request_goes` |
| No redirects | A redirect is never followed, so a reply cannot send the worker somewhere else. | `tests/test_lookup.py::test_a_real_redirect_to_another_server_is_not_followed` |
| Untrusted replies | A reply from another service is size-capped and checked strictly; anything that does not fit is refused. | `tests/test_lookup.py::test_a_reply_that_does_not_follow_the_agreed_shape_is_refused` |
| Lookup failure stops the worker | If the lookup fails, nothing is committed and the worker stops, so the job is retried. | `tests/test_worker.py::test_the_lookup_being_unavailable_means_no_commit_no_answer_and_the_loop_stops` |
| Key never logged | Neither the key nor the student text reaches a log or an error. | `tests/test_lookup.py::test_neither_the_key_nor_the_student_text_ever_reaches_a_log_or_an_error` |
