# Apps operation correlation

`bl apps` forwards a valid inherited `TRACEPARENT` environment variable as the
[W3C `traceparent`](https://www.w3.org/TR/trace-context/#traceparent-header)
header on Compose control-plane requests, including artifact
uploads. It preserves the parent ID and flags, including unsampled context.
The CLI does not create spans or generate a fallback trace ID. Missing or
malformed context is ignored, so interactive use still works without a tracing
environment. Version `00` must have exactly 55 lowercase hexadecimal characters
and separators, with nonzero trace and parent IDs. Higher versions preserve the
known prefix and an optional opaque suffix; `ff` and values over 512 bytes are
rejected. No trace header is added to login or session-verification requests.

The server owns the response correlation ID. A valid `X-Hotpod-Trace-Id` header
takes precedence over structured `trace_id` (top-level or `error.trace_id`).
IDs must be nonzero 32-character hexadecimal values and are normalized to
lowercase. Invalid IDs are ignored. The inherited context is never substituted
for a missing response ID: ingress or Compose may have started a different trace.

Failures include `trace_id=<id>` in their message and, with `--json`,
`error.trace_id`. The header is captured before reading the bounded response
body, so it survives oversized, incomplete, non-UTF-8, and malformed JSON
responses. Body-only IDs require a complete valid JSON response within the
existing 2 MiB limit. Responses must be JSON objects. Create identity/plan
validation, sharing validation, reservation recovery, and delete's
`delete_outcome_unknown` guidance retain the relevant response ID. Exit codes,
authentication, origin restrictions, redirects, and retry behavior are unchanged.

Successful JSON objects expose the response `trace_id` too. This lets callers
save the correlation ID when admission succeeds and a failure occurs later.
The CLI preserves Compose's separate `deployment_trace_id` without deriving or
overwriting it. A later `ready` or `debug` request has its own `trace_id`; use
`deployment_trace_id` to investigate the original deployment. Create returns
individual response IDs inside its `plan`, `reservation`, and `initialize`
objects rather than assigning one ID to several HTTP requests. A server that
does not return correlation metadata produces the existing output shape.

## Boundaries and rollout

This CLI integration needs a Compose rollout that returns the response header
and structured IDs and retains deployment context through asynchronous work.
Forwarding a header alone does not prove end-to-end log correlation, tracing
export, or restart recovery. Ingress must also preserve the request and response
headers. Check each BuilderLab staging environment separately.

`bl apps deploy` uploads a prebuilt artifact. A Blox build that fails before the
deploy command runs has no Compose admission or deployment trace. Separate work
in the BuilderLab command runner must establish and persist the operation
context, export `TRACEPARENT` into the command environment (including remote
execution), return command-failure IDs, and record authorized references to
saved stdout/stderr. Task, command, and deployment selectors are still needed
when several commands share one trace. This change neither instruments Blox
builds nor stores command output.

## Staging verification

After the server dependency is deployed, use the supported `bl auth` flow and
`bl apps contract --base-url <staging-control-plane> --json` for the selected
environment. Use the current contract and command help for runtime and artifact
requirements. Do not send staging credentials to a different origin.

1. Run a failing inspection under a known unsampled context, for example
   `TRACEPARENT=00-1234567890abcdef1234567890abcdef-1234567890abcdef-00` with
   `bl apps get <missing-test-app> --base-url <staging-control-plane> --json`.
   Confirm `error.trace_id` matches the server's admitted trace and is searchable
   in ingress/Compose logs even when APM did not retain a sampled trace.
2. With an approved disposable staging app and freshly built artifact, deploy
   under the same known context using fixed version and deployment IDs. Save
   the returned `trace_id`, `deployment_trace_id`, and deployment selectors.
   Confirm deployment, validation, reconciliation, and runtime events correlate.
3. Run `ready` and `debug` for that exact version under a different traceparent.
   Confirm their request `trace_id` changes while `deployment_trace_id` still
   identifies the original operation. With an approved staging restart test,
   verify this also holds after asynchronous work resumes.
4. Repeat with sampled context (`01`) and malformed context. Malformed context
   must not break the command, and the server should return its own ID.

Validate command-output correlation separately once the BuilderLab runner
supports it: deliberately fail a pre-deploy Blox build, then follow its returned
ID to command-stage logs and saved output. There should be no Compose deployment
event for a deploy that was never issued.
