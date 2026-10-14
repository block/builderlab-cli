# Blox client

This crate contains Blox orchestrator protocol messages and a synchronous
Connect JSON client. Its client methods list, retrieve, and create workstations,
and discover the caller's available compute SKUs.
Durable process execution uses `execute_process`, followed by
`stream_command_output` to deliver typed stdout/stderr messages and exit codes.
Lifecycle methods request suspension, resumption, and deletion once and return
the server's typed response. Callers must inspect lifecycle status and deletion
success; an accepted request does not imply that asynchronous teardown or startup
has finished.
Callers supply the endpoint and credentials; the crate does not perform login
or select a deployment.

Unary requests time out after 30 seconds, except lifecycle operations, which
allow up to 12 minutes for snapshot creation and provider teardown. Responses
are limited to 2 MiB, and requests do not
follow redirects or retry requests. Error messages redact reflected session
credentials. Creation has no idempotency key: after a transport error or an
invalid response, inspect existing workstations before attempting another create.

Output streaming uses Connect JSON envelopes with a 2 MiB per-envelope limit
and no overall time limit. It requires a successful protocol end-stream message;
transport EOF is an error. Stream callbacks can stop reading without stopping
the remote process. The caller must capture a process exit code before reporting
success, and must not relaunch execution after an uncertain result.

For BuilderLab ingress, `with_session_credential` sends an existing shared
login session using `Authorization: BBIdentity <credential>`. The caller must
select an ingress configured to accept this authentication scheme.

## Protocol source

`protos/xyz/block/blox/orchestrator/v1/orchestrator.proto` is an unchanged copy
of `open/protos/xyz/block/blox/orchestrator/v1/orchestrator.proto` from the Blox
repository (`squareup/blox`) at revision
`57bc2e40b162b43e1d1b2d0b860bd67e0a3ce3e7`.

To sync the protocol, replace that file with the complete source file from the
chosen Blox revision and update this revision note in the same change. Run
`cargo test -p blox` in the Hermit environment to regenerate the Rust messages
and check binary and protobuf JSON encoding. Generated files stay in Cargo's
build output. The `go_package` option is retained as source metadata.

JSON decoding ignores new fields from newer servers. Unknown enum variants
decode to their unspecified default; refresh the copied protocol to recognize
new workstation statuses. Known enum values retain their protobuf names.
