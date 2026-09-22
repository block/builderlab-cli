# BuilderLab Local Auth Testing

This covers local CLI auth testing for BuilderLab identity.

The important invariant is that the browser must hit `/v1/auth/login` and `/v1/auth/callback`
on the same host that Auth0 redirects to. kgoose uses an HttpOnly state cookie between
those two requests before it redirects back to the CLI with a short-lived exchange code.

While BuilderLab staging is only reachable from a laptop through a Kubernetes
port-forward, keep the backend Auth0 redirect URI as:

```text
http://localhost:5173/cash-app/goose/v1/auth/callback
```

Then point the CLI at the same local host.

For the target login sequence, see [BuilderLab Auth Flow](bl-auth-flow.md).

## Build

From this repository root:

```bash
source ./bin/activate-hermit
cargo build --bin bl
```

## Test Against A Port-Forward

Find the running pod and dynamic Java app port:

```bash
kubectl -n kgoose-builderlab get pods -o wide

kubectl -n kgoose-builderlab exec <pod-name> -c kgoose-builderlab -- \
  sh -c "ss -ltnp | awk '/java/ {print \$4}' | tr '\n' ' '"
```

Forward local `5173` to the dynamic app port, not the declared `8080` health/admin port:

```bash
kubectl -n kgoose-builderlab port-forward pod/<pod-name> 5173:<dynamic-java-port>
```

In another terminal, run the CLI login command through the port-forward:

```bash
./target/debug/bl config set org test

BL_AUTH_STORAGE=file \
BL_AUTH_STORAGE_FILE="$(pwd)/target/bl-auth-sessions.json" \
KGOOSE_BASE_URL="http://localhost:5173" \
KGOOSE_SERVICE_PATH="/cash-app/goose" \
  ./target/debug/bl auth login
```

Expected result:

- the browser opens `http://localhost:5173/cash-app/goose/v1/auth/login`
- kgoose redirects to Auth0 with `redirect_uri=http://localhost:5173/cash-app/goose/v1/auth/callback`
- Auth0 redirects the browser back through the same port-forward
- kgoose validates the state cookie, exchanges the Auth0 code server-side, and redirects to the CLI loopback callback with a one-time exchange code
- the CLI exchanges that code through kgoose and stores the returned session credential

By default, the CLI stores browser auth sessions in the OS keyring. For local debugging without touching keyring state, use the `BL_AUTH_STORAGE=file` command above.

## Test In Staging

Point the CLI at the real staging URL:

```bash
./target/debug/bl config set org test

KGOOSE_BASE_URL="https://blockstaging.build" \
  ./target/debug/bl auth login
```

The staging command uses BuilderLab's public `/api/goose` BFF prefix by
default. Set `KGOOSE_SERVICE_PATH=/cash-app/goose` only when calling kgoose
directly, such as through the local port-forward above.

## Test Against A Playpen

Set `BL_KGOOSE_PLAYPEN` when you need to route backend auth requests to a playpen. Replace `<playpen-route>` with your full kgoose playpen route value.
The Chrome extension must be enabled for playpen login so browser requests route through the playpen.

```bash
BL_AUTH_STORAGE=file \
BL_AUTH_STORAGE_FILE="$(pwd)/target/bl-auth-sessions.json" \
BL_KGOOSE_PLAYPEN="jsiblison--cash-usw2" \
KGOOSE_BASE_URL="https://blockstaging.build" \
  ./target/debug/bl auth login
```

## Notes

- For port-forward testing, use `localhost:5173`, not `127.0.0.1:5173`, so the browser host matches the registered Auth0 callback URL.
- The dynamic Java app port is the port that serves `/cash-app/goose`; `8080` is the health/admin listener.
- Non-local-dev `bl` commands require `org`; set it with `bl config set org <org>` or let interactive `bl auth login` prompt for it.
- `KGOOSE_BASE_URL` is the pure base URL. For non-local commands, the CLI derives the org-routed host and uses the public `/api/goose` BFF prefix; set `KGOOSE_SERVICE_PATH=/cash-app/goose` when calling kgoose directly.
- `BL_KGOOSE_PLAYPEN` routes bl backend requests with `Baggage: kgoose-builderlab-playpen=<playpen-route>`.
- Do not log callback query strings, cookies, or returned session credentials.
