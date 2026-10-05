# Apps operation correlation

`bl apps` forwards valid inherited `TRACEPARENT` as a
[W3C `traceparent`](https://www.w3.org/TR/trace-context/#traceparent-header)
header on Compose requests, including uploads. It preserves sampling flags,
ignores malformed context, and adds no trace headers to authentication requests.
The CLI doesn't create spans or generate fallback IDs.

## Returned IDs

The server's valid `X-Hotpod-Trace-Id` header takes precedence over structured
`trace_id` (top-level or `error.trace_id`). IDs must be nonzero 32-character
hexadecimal values and are normalized to lowercase. Missing response IDs are
never replaced with the inherited ID: the server may have started another trace.

Successful JSON objects expose `trace_id`. Failures include `trace_id=<id>` in
text and `error.trace_id` with `--json`. Header IDs survive unreadable or
oversized bodies and CLI validation/recovery errors. Body-only IDs require
complete JSON within the existing 2 MiB limit. Responses must be JSON objects.
Authentication, exit codes, and retry behavior are unchanged.

Use `deployment_trace_id` to investigate the original deployment. Later `ready`
or `debug` requests have their own `trace_id`, which identifies the inspection
request rather than the deployment.

Create preserves IDs within its `plan`, `reservation`, and `initialize` results.
For a reconciled reservation, `reservation.trace_id` identifies the confirming
inspection; `reservation.reserve_trace_id` retains the original reserve response
ID when available. Unknown-outcome errors prefer the reserve ID, falling back to
the inspection ID.

## Rollout and remaining work

This needs Compose to return IDs and persist deployment context through
asynchronous work. Ingress must preserve the tracing headers. End-to-end log
correlation and restart recovery still need staging verification.

`bl apps deploy` uploads a prebuilt artifact. Blox builds that fail before deploy
have no Compose deployment trace. BuilderLab's command runner still needs to
persist operation context, export `TRACEPARENT` into local and remote commands,
return failure IDs, and provide references to saved stdout/stderr. Keep task,
command, and deployment selectors alongside the ID when an operation spans
multiple commands.

## Staging verification

After the Compose dependency is deployed, authenticate with `bl auth` and read
`bl apps contract --base-url <staging-control-plane> --json`. Follow the current
contract and command help, and test each staging environment separately.

1. Run `bl apps get <missing-test-app> --base-url <staging-control-plane> --json`
   with `TRACEPARENT=00-1234567890abcdef1234567890abcdef-1234567890abcdef-00`.
   Confirm `error.trace_id` matches the admitted trace and is searchable in
   ingress/Compose logs even when APM doesn't retain the unsampled trace.
2. Deploy a freshly built artifact to an approved disposable app using fixed
   version and deployment IDs. Save its correlation IDs and confirm validation,
   reconciliation, and runtime events share the deployment trace.
3. Request `ready` and `debug` for that exact version under a different trace.
   Confirm the request ID changes while `deployment_trace_id` stays the same.
   Repeat after an approved restart test resumes asynchronous work.
4. Repeat with sampled (`01`) and malformed context. Malformed context must not
   break the command; the server should return its own ID.

Once runner support exists, separately fail a pre-deploy Blox build and follow
its ID to command logs and saved output. A deploy that never ran should have no
Compose deployment event.
