#!/usr/bin/env bash
# Upgrade test: writes data with the first committed worker (schema v1), restarts the current
# worker on the same local storage, and checks that keys, ACLs and messages survive.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/test/lib.sh"
trap 'stop_relay; rm -rf "$TMP"' EXIT

ADMIN="migration-admin-$RANDOM$RANDOM"
PORT=${PORT:-$((20000 + RANDOM % 2000))}
REV=$(git -C "$ROOT" log --diff-filter=A --format=%H -- src/worker.js | tail -1)
OLD="$TMP/old"; mkdir -p "$OLD/src"
git -C "$ROOT" show "$REV:src/worker.js" > "$OLD/src/worker.js"
git -C "$ROOT" show "$REV:src/page.html" > "$OLD/src/page.html"
cp "$ROOT/wrangler.example.toml" "$OLD/wrangler.toml"

echo "== schema v1 (commit ${REV:0:7})"
start_relay "$OLD" wrangler.toml "$TMP/state" "$PORT" "$ADMIN" || exit 1
expect "v1 join" 200 POST /v2/join "$ADMIN" '{"agent":"old-a"}'; KA=$(field .key)
expect "v1 join" 200 POST /v2/join "$ADMIN" '{"agent":"old-b"}'; KB=$(field .key)
expect "v1 acl" 200 POST /v2/acl "$ADMIN" '{"from":"old-a","to":"old-b","kind":"msg"}'
expect "v1 send" 200 POST /v2/messages "$KA" '{"to":"old-b","text":"written before upgrade","idem_key":"m1"}'; MID=$(field .msg.id); SEQ=$(field .msg.seq)
stop_relay; sleep 1

echo "== current worker on the same storage"
start_relay "$ROOT" wrangler.example.toml "$TMP/state" "$PORT" "$ADMIN" || exit 1
expect "v1 keys still authenticate" 200 GET /v2/inbox "$KB"
eq "v1 message survives" "$(field '.messages[0].body')" "written before upgrade"
expect "v1 ACL still allows" 200 POST /v2/messages "$KA" '{"to":"old-b","text":"written after upgrade"}'
expect "v1 ACL still denies the reverse" 403 POST /v2/messages "$KB" '{"to":"old-a","text":"nope"}'
expect "v1 idem_key still dedupes" 200 POST /v2/messages "$KA" '{"to":"old-b","text":"written before upgrade","idem_key":"m1"}'; eq "  same id" "$(field .msg.id)" "$MID"
expect "ack and receipts still work" 200 POST /v2/ack "$KB" "{\"seq\":$SEQ}"
api GET "/v2/receipts?id=$MID" "$KA"; eq "  read=true" "$(field .read)" true
api GET /v2/task-types "$KA"; eq "migration seeded github.invite" "$(jq -r '.task_types[0].name' <<<"$out")" github.invite
expect "v2 tables are usable" 200 POST /v2/invites "$ADMIN" '{"agent":"new-a"}'
expect "redact works on a v1 row" 200 POST /v2/redact "$KA" "{\"id\":\"$MID\"}"
stop_relay; sleep 1

echo "== restart is a no-op"
start_relay "$ROOT" wrangler.example.toml "$TMP/state" "$PORT" "$ADMIN" || exit 1
expect "second boot does not re-run the migration" 200 GET /v2/inbox "$KB"
api GET /v2/task-types "$KA"; eq "  one seeded type" "$(jq '.task_types | length' <<<"$out")" 1

summary "migration"
