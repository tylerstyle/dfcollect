#!/usr/bin/env bash
#
# run-local.sh: Spin up local test mocks (IMAP, Microsoft Graph, Gmail)
# on 127.0.0.1 with ephemeral TLS certificates for manual TUI testing.
#
# Usage:
#   ./tests/mocks/run-local.sh [--approve] [--keep]
#
# Options:
#   --approve  Gate Microsoft Graph device code sign-in until <requests.jsonl>.approve exists
#   --keep     Preserve temporary certificates and logs directory on exit
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

APPROVE_FLAG=""
KEEP_TEMP=0

for arg in "$@"; do
  case "$arg" in
    --approve)
      APPROVE_FLAG="--approve"
      ;;
    --keep)
      KEEP_TEMP=1
      ;;
    -h|--help)
      echo "Usage: $0 [--approve] [--keep]"
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 1
      ;;
  esac
done

WORKDIR="$(mktemp -d -t dfcollect-mocks-XXXXXX)"
echo "[*] Working directory: $WORKDIR"

cleanup() {
  echo ""
  echo "[*] Shutting down mock servers..."
  # Terminate background jobs started by this script
  jobs -p | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
  if [ "$KEEP_TEMP" -eq 0 ]; then
    echo "[*] Cleaning up $WORKDIR..."
    rm -rf "$WORKDIR"
  else
    echo "[*] Kept temp directory: $WORKDIR"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# 1. Generate local test CA and certificate for localhost / 127.0.0.1
echo "[*] Generating ephemeral TLS CA and localhost certificate..."
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=dfcollect-local-ca" \
  -keyout "$WORKDIR/ca-key.pem" -out "$WORKDIR/ca.pem" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" \
  -keyout "$WORKDIR/key.pem" -out "$WORKDIR/server.csr" 2>/dev/null

cat << 'EOF' > "$WORKDIR/ext.cnf"
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in "$WORKDIR/server.csr" -CA "$WORKDIR/ca.pem" -CAkey "$WORKDIR/ca-key.pem" \
  -CAcreateserial -days 1 -extfile "$WORKDIR/ext.cnf" -out "$WORKDIR/leaf.pem" 2>/dev/null

cat "$WORKDIR/leaf.pem" "$WORKDIR/ca.pem" > "$WORKDIR/cert.pem"

# Service account key for Gmail mock
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORKDIR/sa-key.pem" 2>/dev/null
openssl rsa -in "$WORKDIR/sa-key.pem" -pubout -out "$WORKDIR/sa-pub.pem" 2>/dev/null
python3 - <<PY
import json
with open("$WORKDIR/sa-key.pem") as f:
    priv = f.read()
with open("$WORKDIR/sa.json", "w") as f:
    json.dump({
        "type": "service_account",
        "project_id": "dfnix-test",
        "private_key_id": "kid-1",
        "private_key": priv,
        "client_email": "dfcollect-sa@dfnix-test.iam.gserviceaccount.com",
    }, f)
PY

# Graph mock bodies
python3 - <<PY
import base64, json
def msg(n, subject):
    return (f"From: a@example.org\r\nTo: alice@contoso.test\r\nSubject: {subject}\r\n"
            f"Message-ID: <{n}@example.org>\r\nMIME-Version: 1.0\r\n\r\nBody {n}\r\n").encode()
bodies = {f"m{i}": base64.b64encode(msg(i, f"m{i}")).decode() for i in range(1, 8)}
with open("$WORKDIR/graph-bodies.json", "w") as f:
    json.dump(bodies, f)
PY

# 2. Start IMAP mock
IMAP_PORT_FILE="$WORKDIR/imap.port"
IMAP_ERR="$WORKDIR/imap.err"
python3 "$REPO_ROOT/tests/imap-mock.py" 0 "$WORKDIR/cert.pem" "$WORKDIR/key.pem" "$WORKDIR/imap-requests.log" \
  --bind 127.0.0.1 --port-file "$IMAP_PORT_FILE" 2>"$IMAP_ERR" &
IMAP_PID=$!

# 3. Start Graph mock
GRAPH_PORT_FILE="$WORKDIR/graph.port"
GRAPH_ERR="$WORKDIR/graph.err"
# shellcheck disable=SC2086
python3 "$REPO_ROOT/tests/graph-mock.py" 0 "$WORKDIR/cert.pem" "$WORKDIR/key.pem" "$WORKDIR/graph-requests.jsonl" "$WORKDIR/graph-bodies.json" \
  --bind 127.0.0.1 --host localhost --port-file "$GRAPH_PORT_FILE" $APPROVE_FLAG 2>"$GRAPH_ERR" &
GRAPH_PID=$!

# 4. Start Gmail mock
GMAIL_PORT_FILE="$WORKDIR/gmail.port"
GMAIL_ERR="$WORKDIR/gmail.err"
python3 "$REPO_ROOT/tests/gmail-mock.py" 0 "$WORKDIR/cert.pem" "$WORKDIR/key.pem" "$WORKDIR/sa-pub.pem" "$WORKDIR/gmail-requests.jsonl" "$WORKDIR/gmail-bodies.json" \
  --bind 127.0.0.1 --host localhost --port-file "$GMAIL_PORT_FILE" 2>"$GMAIL_ERR" &
GMAIL_PID=$!

# Wait for all mocks to bind and write port files (max 10s timeout with liveness check)
MOCKS=(
  "IMAP:$IMAP_PORT_FILE:$IMAP_PID:$IMAP_ERR"
  "Graph:$GRAPH_PORT_FILE:$GRAPH_PID:$GRAPH_ERR"
  "Gmail:$GMAIL_PORT_FILE:$GMAIL_PID:$GMAIL_ERR"
)

for entry in "${MOCKS[@]}"; do
  IFS=":" read -r name port_file pid err_file <<< "$entry"
  elapsed=0
  while [ ! -s "$port_file" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "[-] Mock $name (PID $pid) died unexpectedly! Stderr:" >&2
      cat "$err_file" >&2
      exit 1
    fi
    sleep 0.1
    elapsed=$((elapsed + 1))
    if [ "$elapsed" -ge 100 ]; then
      echo "[-] Timed out waiting for $name mock to write port file ($port_file) after 10s. Stderr:" >&2
      cat "$err_file" >&2
      exit 1
    fi
  done
done

IMAP_PORT="$(cat "$IMAP_PORT_FILE")"
GRAPH_PORT="$(cat "$GRAPH_PORT_FILE")"
GMAIL_PORT="$(cat "$GMAIL_PORT_FILE")"

echo ""
echo "================================================================================"
echo " dfcollect Local Mocks Ready (TLS on 127.0.0.1)"
echo "================================================================================"
echo ""
echo "Before launching the TUI or running CLI commands, set these environment variables:"
echo ""
echo "  export SSL_CERT_FILE=\"$WORKDIR/ca.pem\""
echo "  export HOME=\"\$(mktemp -d -t dfcollect-home-XXXXXX)\""
echo ""
echo "Values for TUI Forms & CLI dry-runs:"
echo ""
echo "1. IMAP (press 'm' from Home):"
echo "   Server   : 127.0.0.1:$IMAP_PORT"
echo "   User     : alice@example.org"
echo "   Password : invented-imap-pw"
echo "   CLI test : dfcollect imap 127.0.0.1:$IMAP_PORT --user alice@example.org --password-file <(echo invented-imap-pw) -o /tmp/imap-out -C CASE -E ev01 -e tester --dry-run"
echo ""
echo "2. Microsoft 365 (Graph) (press 'g' from Home):"
echo "   Tenant   : tenant1"
echo "   Client ID: test-client"
echo "   Mailbox  : alice@contoso.test"
echo "   Endpoints: (press Tab to Cloud preset -> cycle to custom)"
echo "     Graph Endpoint: https://localhost:$GRAPH_PORT"
echo "     Login Endpoint: https://localhost:$GRAPH_PORT"
echo "   CLI test : dfcollect graph --tenant tenant1 --client-id test-client --mailbox alice@contoso.test --graph-endpoint https://localhost:$GRAPH_PORT --login-endpoint https://localhost:$GRAPH_PORT -o /tmp/graph-out -C CASE -E ev01 -e tester --dry-run"
if [ -n "$APPROVE_FLAG" ]; then
echo "   Note     : Device-code poll is gated. Run in another terminal to approve:"
echo "              touch \"$WORKDIR/graph-requests.jsonl.approve\""
fi
echo ""
echo "3. Gmail / Google Workspace (press 'w' from Home):"
echo "   Auth     : Service Account (cycle Authentication to service-account)"
echo "   Mailbox  : alice@workspace.test"
echo "   SA Key   : $WORKDIR/sa.json"
echo "   Endpoints: (press Tab to Gmail Endpoint / Token Endpoint)"
echo "     Gmail Endpoint: https://localhost:$GMAIL_PORT"
echo "     Token Endpoint: https://localhost:$GMAIL_PORT/token"
echo "   Window   : 2026-02-01T00:00:00Z .. 2026-06-01T00:00:00Z"
echo "   CLI test : dfcollect gmail --auth service-account --key-file $WORKDIR/sa.json --mailbox alice@workspace.test --gmail-endpoint https://localhost:$GMAIL_PORT --token-endpoint https://localhost:$GMAIL_PORT/token --not-before 2026-02-01T00:00:00Z --not-after 2026-06-01T00:00:00Z -o /tmp/gmail-out -C CASE -E ev01 -e tester --dry-run"
echo ""
echo "Logs & Evidence:"
echo "   IMAP log : $WORKDIR/imap-requests.log"
echo "   Graph log: $WORKDIR/graph-requests.jsonl"
echo "   Gmail log: $WORKDIR/gmail-requests.jsonl"
echo ""
echo "Press Ctrl+C to terminate all mocks."
echo "================================================================================"

wait
