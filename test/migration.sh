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
api GET /v2/wiki "$KA"; eq "wiki is empty and usable after the v1 upgrade" "$(field .quota.pages)" 0
expect "agents can write the wiki" 200 PUT /v2/wiki/after-upgrade "$KA" '{"title":"t","body":"b"}'
expect "context stays closed without a grant" 403 PUT /v2/wiki/ctx "$KA" '{"title":"t","kind":"context","body":"b"}'
stop_relay; sleep 1

echo "== restart is a no-op"
start_relay "$ROOT" wrangler.example.toml "$TMP/state" "$PORT" "$ADMIN" || exit 1
expect "second boot does not re-run the migration" 200 GET /v2/inbox "$KB"
api GET /v2/task-types "$KA"; eq "  one seeded type" "$(jq '.task_types | length' <<<"$out")" 1
api GET /v2/wiki/after-upgrade "$KA"; eq "  wiki page survives" "$(field .body)" b
api GET /v2/wiki "$KA"; eq "  counters survive" "$(field .quota.pages)" 1
stop_relay; sleep 1

# The deployed relay was at schema v2 when the wiki shipped. a37c13e is the last v2 commit.
echo "== schema v2 (a37c13e) to the wiki, with WIKI_CONTEXT_WRITERS"
OLD2="$TMP/old2"; mkdir -p "$OLD2/src"
git -C "$ROOT" show a37c13e:src/worker.js > "$OLD2/src/worker.js"
git -C "$ROOT" show a37c13e:src/page.html > "$OLD2/src/page.html"
cp "$ROOT/wrangler.example.toml" "$OLD2/wrangler.toml"
start_relay "$OLD2" wrangler.toml "$TMP/state2" "$PORT" "$ADMIN" || exit 1
expect "v2 join" 200 POST /v2/join "$ADMIN" '{"agent":"keeper"}'; KK=$(field .key)
expect "v2 join" 200 POST /v2/join "$ADMIN" '{"agent":"plain"}'; KP=$(field .key)
expect "v2 acl" 200 POST /v2/acl "$ADMIN" '{"from":"keeper","to":"plain","kind":"msg"}'
expect "v2 send" 200 POST /v2/messages "$KK" '{"to":"plain","text":"before the wiki"}'
expect "v2 invite" 200 POST /v2/invites "$ADMIN" '{"agent":"later"}'; ICODE=$(field .invite_code)
expect "v2 task type" 200 POST /v2/task-types "$ADMIN" '{"name":"mig.keep","schema":{"type":"object"},"risk":"low"}'
expect "v2 task acl" 200 POST /v2/acl "$ADMIN" '{"from":"keeper","to":"plain","kind":"task:mig.keep"}'
expect "v2 open task" 200 POST /v2/tasks "$KK" '{"type":"mig.keep","to":"plain","params":{}}'; TID=$(field .task.id)
api GET /v2/acl "$ADMIN"; ROWS=$(field '.acl | length')
stop_relay; sleep 1
start_relay "$ROOT" wrangler.example.toml "$TMP/state2" "$PORT" "$ADMIN" "" "WIKI_CONTEXT_WRITERS:keeper, __wiki__,Bad Name"  || exit 1
expect "v2 keys still authenticate" 200 GET /v2/inbox "$KP"; eq "  message survives" "$(field '.messages[0].body')" "before the wiki"
expect "v2 invite still redeems" 200 POST /v2/join '' "{\"invite_code\":\"$ICODE\"}"
expect "v2 task is still open" 200 POST "/v2/tasks/$TID/claim" "$KP"
expect "named writer gets context on upgrade" 200 PUT /v2/wiki/ctx "$KK" '{"title":"t","kind":"context","body":"b"}'
expect "others do not" 403 PUT /v2/wiki/ctx2 "$KP" '{"title":"t","kind":"context","body":"b"}'
api GET /v2/acl "$ADMIN"; eq "exactly one ACL row was added, bad names skipped" "$(field '.acl | length')" "$((ROWS + 1))"
eq "  that row is the grant" "$(jq -c '[.acl[] | select(.kind=="wiki:context") | [.from_agent,.to_agent]]' <<<"$out")" '[["keeper","__wiki__"]]'
expect "the grant is removable like any other" 200 POST /v2/acl "$ADMIN" '{"from":"keeper","to":"__wiki__","kind":"wiki:context","allow":false}'
expect "  and takes effect" 403 PUT /v2/wiki/ctx "$KK" '{"body":"c"}'
stop_relay; sleep 1
start_relay "$ROOT" wrangler.example.toml "$TMP/state2" "$PORT" "$ADMIN" "" "WIKI_CONTEXT_WRITERS:keeper" || exit 1
expect "a later boot does not grant it back" 403 PUT /v2/wiki/ctx "$KK" '{"body":"c"}'

summary "migration"
