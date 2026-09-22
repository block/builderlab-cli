#!/bin/sh
set -eu

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

assert_isolated_path() {
  case "$1" in
    "$HOME"|"$HOME"/*) ;;
    *) fail "acceptance path escapes isolated HOME: $1" ;;
  esac
}

[ "$(id -u)" -ne 0 ] || fail "acceptance runner must not execute as root"

RUN_ROOT="$(mktemp -d /tmp/bl-acceptance.XXXXXX)"
trap 'rm -rf "$RUN_ROOT"' EXIT HUP INT TERM
export HOME="$RUN_ROOT/home"
export BL_HOME="$HOME/.bl"
export BL_SKILLS_HOME="$BL_HOME/skills"
export BL_SKILLS_PACKAGES_DIR="$HOME/.agents/skills"
export BL_SKILLS_CONFIG="$BL_HOME/skills.yaml"
export BL_AUTH_STORAGE=file
export BL_AUTH_STORAGE_FILE="$BL_HOME/auth-sessions.json"
PROFILE=docker-acceptance
BL_COMMAND="${BL_ACCEPTANCE_BL_PATH:-bl}"
MOCK_MARKETPLACE="${BL_ACCEPTANCE_MOCK_MARKETPLACE:-/opt/bl-acceptance/mock-marketplace.py}"
MOCK_PORT="${BL_ACCEPTANCE_MOCK_PORT:-18080}"

for path in "$HOME" "$BL_HOME" "$BL_SKILLS_HOME" "$BL_SKILLS_PACKAGES_DIR" "$BL_SKILLS_CONFIG" "$BL_AUTH_STORAGE_FILE"; do
  assert_isolated_path "$path"
done
mkdir -p "$BL_HOME" "$BL_SKILLS_HOME" "$BL_SKILLS_PACKAGES_DIR/unmanaged"
printf '%s\n' 'unmanaged files must survive' > "$BL_SKILLS_PACKAGES_DIR/unmanaged/sentinel.txt"
printf '%s\n' "current_profile: $PROFILE" 'profiles:' "  $PROFILE: {}" > "$HOME/bl-local-dev-config.yaml"
cd "$HOME"

write_runtime_credential() {
  PROFILE="$PROFILE" python3 - "$BL_AUTH_STORAGE_FILE" "$1" <<'PY'
import hashlib
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
server_url = sys.argv[2].rstrip("/")
key = hashlib.sha256(os.environ["PROFILE"].encode() + b"\0" + server_url.encode()).hexdigest()
path.write_text(json.dumps({key: {"sessionCredential": os.environ["BL_SESSION_CREDENTIAL"]}}))
PY
  unset BL_SESSION_CREDENTIAL
}

write_report() {
  if [ -z "${BL_ACCEPTANCE_REPORT_PATH:-}" ]; then
    return 0
  fi
  python3 - "$BL_ACCEPTANCE_REPORT_PATH" "$HOME" "$BL_HOME" "$BL_SKILLS_HOME" "$BL_SKILLS_PACKAGES_DIR" "$BL_AUTH_STORAGE_FILE" "${BL_ACCEPTANCE_MODE:-mock}" <<'PY'
import json
import os
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "home": sys.argv[2],
    "bl_home": sys.argv[3],
    "skills_home": sys.argv[4],
    "packages_dir": sys.argv[5],
    "auth_storage_file": sys.argv[6],
    "mode": sys.argv[7],
    "uid": os.getuid(),
}))
PY
}

assert_mock_result() {
  package="$BL_SKILLS_PACKAGES_DIR/docker-harness"
  test -f "$package/SKILL.md" || fail "mock install did not create the skills-only package"
  test -f "$package/.bl-skills-meta.json" || fail "mock install did not create BL metadata"
  grep -q 'bl-skills-install/v1' "$package/.bl-skills-meta.json" || fail "mock metadata has unexpected schema"
  grep -q 'bundle:default' "$package/.bl-skills-meta.json" || fail "mock metadata lacks bundle provenance"
  test -f "$BL_SKILLS_PACKAGES_DIR/unmanaged/sentinel.txt" || fail "mock install removed unmanaged sentinel"
  assert_idempotent_result "$RUN_ROOT/repeat-install.json" "repeat install"
  assert_idempotent_result "$RUN_ROOT/update.json" "update"
}

assert_idempotent_result() {
  python3 - "$1" "$2" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text())
operation = sys.argv[2]
if result.get("installed") != []:
    raise SystemExit(f"{operation} reinstalled marketplace content")
if "docker-harness" not in result.get("up_to_date", []):
    raise SystemExit(f"{operation} did not report docker-harness as up to date")
PY
}

run_mock() {
  export KGOOSE_BASE_URL="http://127.0.0.1:$MOCK_PORT"
  export KGOOSE_SERVICE_PATH=/api/goose
  unset BL_KGOOSE_PLAYPEN KGOOSE_PLAYPEN
  python3 "$MOCK_MARKETPLACE" --port "$MOCK_PORT" --expect-bundle default >"$RUN_ROOT/mock.log" 2>&1 &
  mock_pid=$!
  trap 'kill "$mock_pid" 2>/dev/null || true; rm -rf "$RUN_ROOT"' EXIT HUP INT TERM
  startup_attempts="${BL_ACCEPTANCE_MOCK_START_ATTEMPTS:-30}"
  attempt=1
  while ! python3 -c "import socket; socket.create_connection(('127.0.0.1', $MOCK_PORT), 1).close()" 2>/dev/null; do
    if ! kill -0 "$mock_pid" 2>/dev/null; then
      cat "$RUN_ROOT/mock.log" >&2
      fail "mock marketplace exited before becoming ready"
    fi
    if [ "$attempt" -ge "$startup_attempts" ]; then
      cat "$RUN_ROOT/mock.log" >&2
      fail "mock marketplace did not become ready after $startup_attempts attempts"
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  "$BL_COMMAND" --local-dev skills install --bundle default --yes --json >"$RUN_ROOT/first-install.json"
  "$BL_COMMAND" --local-dev skills install --bundle default --yes --json >"$RUN_ROOT/repeat-install.json"
  "$BL_COMMAND" --local-dev skills update --yes --json >"$RUN_ROOT/update.json"
  assert_mock_result
  write_report
  printf '%s\n' 'Docker mock acceptance passed.'
}

run_live() {
  [ -n "${BL_MARKETPLACE_BASE_URL:-}" ] || fail 'live mode requires BL_MARKETPLACE_BASE_URL at docker run time'
  [ -n "${BL_SESSION_CREDENTIAL:-}" ] || fail 'live mode requires BL_SESSION_CREDENTIAL at docker run time'
  export KGOOSE_BASE_URL="$BL_MARKETPLACE_BASE_URL"
  credential_service_path="${KGOOSE_SERVICE_PATH:-/cash-app/goose}"
  case "$credential_service_path" in
    /*) ;;
    *) credential_service_path="/$credential_service_path" ;;
  esac
  if [ -n "${KGOOSE_PLAYPEN:-}" ]; then
    export BL_KGOOSE_PLAYPEN="$KGOOSE_PLAYPEN"
  fi
  write_runtime_credential "${KGOOSE_BASE_URL%/}$credential_service_path"
  "$BL_COMMAND" --local-dev skills install --bundle "${BL_ACCEPTANCE_BUNDLE:-default}" --yes --json
  "$BL_COMMAND" --local-dev skills update --yes --json
  write_report
}

case "${BL_ACCEPTANCE_MODE:-mock}" in
  mock) run_mock ;;
  live) run_live ;;
  *) fail 'BL_ACCEPTANCE_MODE must be mock or live' ;;
esac
