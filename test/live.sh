#!/usr/bin/env bash
# Post-deploy check against a real relay. Runs the chain on throwaway agents that it revokes afterwards,
# so real agents receive nothing unless you opt in with LIVE_PING_A and LIVE_PING_B.
#
#   RELAY_URL=... RELAY_ADMIN_KEY=... bash test/live.sh
#   AGENT_KEYS_FILE=path   name=key lines. Checks each key still authenticates, without touching its cursors.
#   LIVE_PING_A, LIVE_PING_B  agent names in that file. Exchanges one labelled message between them.
#
# Agent keys only, no admin key. Reads and refused requests, plus throwaway wiki pages it deletes afterwards:
#   RELAY_URL=... AGENT_KEYS_FILE=path LIVE_WIKI_AGENT=name LIVE_WIKI_CONTEXT_AGENT=name bash test/live.sh wiki
#   LIVE_WIKI_AGENT is an ordinary agent and spends its whole hourly wiki write quota on the rate limit check.
#   LIVE_WIKI_CONTEXT_AGENT holds the wiki:context grant.
#   The 5MB and 200 page limits are not filled here, because that would block real writers. test/smoke.sh covers them.
#
# It also leaves one task holding a lease. Run the printed command after the lease has lapsed (5 minutes):
#   bash test/live.sh lease TASK_ID TYPE
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/test/lib.sh"
: "${RELAY_URL:?set RELAY_URL}"
BASE=${RELAY_URL%/}
trap 'rm -rf "$TMP"' EXIT

# wiki_chain WRITER_KEY WRITER_NAME CONTEXT_KEY CONTEXT_NAME: W is an ordinary agent, P may write context.
wiki_chain() {
  local W=$1 WN=$2 P=$3 PN=$4 R="lt-$RANDOM$RANDOM"
  local S1="$R-note" S2="$R-ctx" S3="$R-rate" S4="$R-big"
  page() { jq -cn --arg title "$1" --arg kind "$2" --arg body "$3" --argjson tags "${4:-[]}" '{title:$title,kind:$kind,body:$body,tags:$tags}'; }
  slugs() { jq -c '[.pages[].slug | select(startswith("'"$R"'"))] | sort' <<<"$out"; }

  echo "== wiki: versions"
  expect "no key is 401" 401 GET /v2/wiki ''
  expect "invalid slug is 400" 400 PUT /v2/wiki/Bad_Slug "$W" "$(page t note b)"
  expect "create" 200 PUT "/v2/wiki/$S1" "$W" "$(page "فحص النشر $R" note "قائمة مهام $R للفحص" '["Live-Check","QA"]')"; eq "  version 1" "$(field .version)" 1
  expect "another agent reads it" 200 GET "/v2/wiki/$S1" "$P"; eq "  body" "$(field .body)" "قائمة مهام $R للفحص"; eq "  author" "$(field .updated_by)" "$WN"; eq "  tags normalized" "$(jq -c .tags <<<"$out")" '["live-check","qa"]'
  expect "update" 200 PUT "/v2/wiki/$S1" "$P" "{\"body\":\"نسخة ثانية $R\"}"; eq "  version 2" "$(field .version)" 2
  expect "repeat of the same write" 200 PUT "/v2/wiki/$S1" "$W" "{\"body\":\"نسخة ثانية $R\"}"; eq "  adds no version" "$(field .version)" 2
  expect "history" 200 GET "/v2/wiki/$S1/history" "$W"; eq "  lists the old version" "$(jq -c '[.versions[].version]' <<<"$out")" '[1]'; eq "  without its body" "$(jq '.versions[0] | has("body")' <<<"$out")" false
  expect "old version in full" 200 GET "/v2/wiki/$S1/history/1" "$W"; eq "  body" "$(field .body)" "قائمة مهام $R للفحص"

  echo "== wiki: search and filters"
  expect "arabic search" 200 GET "/v2/wiki?q=$(uri "نسخة ثانية $R")" "$W"; eq "  finds the page" "$(slugs)" "[\"$S1\"]"
  api GET "/v2/wiki?q=$(uri "فحص النشر $R")" "$W"; eq "  searches the title too" "$(slugs)" "[\"$S1\"]"
  api GET "/v2/wiki?kind=note&tag=QA" "$W"; eq "kind and tag filters" "$(slugs)" "[\"$S1\"]"
  api GET "/v2/wiki?kind=skill&tag=qa" "$W"; eq "  exclude other kinds" "$(slugs)" '[]'
  api GET "/v2/wiki?tag=live" "$W"; eq "  tags match whole" "$(slugs)" '[]'
  expect "unknown kind is 400" 400 GET "/v2/wiki?kind=x" "$W"

  echo "== wiki: refused writes"
  expect "secret in body is 422" 422 PUT "/v2/wiki/$S1" "$W" '{"body":"ghp_abcdefghijklmnopqrstuvwxyz123456"}'
  expect "secret in title is 422" 422 PUT "/v2/wiki/$S1" "$W" '{"title":"ghp_abcdefghijklmnopqrstuvwxyz123456","body":"b"}'
  expect "HTML body is 415" 415 PUT "/v2/wiki/$S1" "$W" '{"body":"  <SCRIPT>x</script>"}'
  expect "9 tags is 400" 400 PUT "/v2/wiki/$S1" "$W" '{"body":"b","tags":["a","b","c","d","e","f","g","h","i"]}'
  { printf '{"title":"big","body":"'; head -c 102401 /dev/zero | tr '\0' w; printf '"}'; } > "$TMP/wiki.json"
  api_file PUT "/v2/wiki/$S4" "$W" "$TMP/wiki.json"; eq "100KB + 1 byte is 413" "$code" 413
  { printf '{"title":"big","body":"'; head -c 102400 /dev/zero | tr '\0' w; printf '"}'; } > "$TMP/wiki.json"
  api_file PUT "/v2/wiki/$S4" "$W" "$TMP/wiki.json"; eq "exactly 100KB is accepted" "$code" 200

  echo "== wiki: context"
  expect "ordinary agent cannot create context" 403 PUT "/v2/wiki/$S2" "$W" "$(page t context b)"
  expect "context writer can" 200 PUT "/v2/wiki/$S2" "$P" "$(page t context b)"
  expect "ordinary agent reads it" 200 GET "/v2/wiki/$S2" "$W"
  expect "but cannot edit it" 403 PUT "/v2/wiki/$S2" "$W" '{"body":"x"}'
  expect "nor relabel it as a note" 403 PUT "/v2/wiki/$S2" "$W" '{"kind":"note","body":"x"}'
  expect "nor delete it" 403 DELETE "/v2/wiki/$S2" "$W"
  expect "nor purge" 403 DELETE "/v2/wiki/$S2?purge=1" "$W"
  expect "nor grant itself" 404 POST /v2/acl "$W" "{\"from\":\"$WN\",\"to\":\"__wiki__\",\"kind\":\"wiki:context\"}"

  echo "== wiki: delete"
  expect "an earlier author cannot delete" 403 DELETE "/v2/wiki/$S1" "$W"
  expect "the last editor can" 200 DELETE "/v2/wiki/$S1" "$P"
  expect "deleted page is 404" 404 GET "/v2/wiki/$S1" "$W"
  expect "history survives" 200 GET "/v2/wiki/$S1/history" "$W"; eq "  ends in a tombstone" "$(field '.versions[0].deleted')" true
  expect "last body is recoverable" 200 GET "/v2/wiki/$S1/history/2" "$W"
  expect "context writer deletes context" 200 DELETE "/v2/wiki/$S2" "$P"
  expect "big page deleted" 200 DELETE "/v2/wiki/$S4" "$W"

  echo "== wiki: rate limit"
  rl=''; n=0; for i in $(seq 1 70); do api PUT "/v2/wiki/$S3" "$W" "$(page r note "rate $i")"; rl=$code; [ "$code" = 200 ] && n=$i; [ "$code" = 200 ] || break; done
  eq "writes stop at 429" "$rl" 429; [ "$n" -le 60 ] && ok "  after at most 60 writes ($n)" || no "  after at most 60 writes ($n)"
  expect "the limited agent can still read" 200 GET "/v2/wiki/$S3" "$W"
  expect "and can delete its own page" 200 DELETE "/v2/wiki/$S3" "$W"

  api GET /v2/wiki "$W"; eq "quota is reported" "$(jq -c '[.quota.max_pages,.quota.max_bytes]' <<<"$out")" '[200,5242880]'; echo "  pages: $(field .quota.pages), bytes: $(field .quota.bytes)"
  api GET "/v2/wiki?q=$(uri "$R")" "$W"; eq "no test page is left in the list" "$(slugs)" '[]'
  # Only the admin can erase history. With agent keys, these rows expire 14 days after the delete.
  if [ "$PN" = __admin__ ]; then for s in "$S1" "$S2" "$S3" "$S4"; do expect "purge $s" 200 DELETE "/v2/wiki/$s?purge=1" "$P"; done; fi
}

if [ "${1:-}" = wiki ]; then
  : "${AGENT_KEYS_FILE:?set AGENT_KEYS_FILE}" "${LIVE_WIKI_AGENT:?set LIVE_WIKI_AGENT}" "${LIVE_WIKI_CONTEXT_AGENT:?set LIVE_WIKI_CONTEXT_AGENT}"
  key_of() { sed -n "s/^$1=//p" "$AGENT_KEYS_FILE"; }
  WK=$(key_of "$LIVE_WIKI_AGENT"); PK=$(key_of "$LIVE_WIKI_CONTEXT_AGENT")

  echo "== page"
  code=$(curl -sS -D "$TMP/hdr" -o "$TMP/page.html" -w '%{http_code}' "$BASE/"); eq "page serves" "$code" 200
  grep -qi "^content-security-policy: default-src 'none'" "$TMP/hdr" && ok "  CSP header" || no "  CSP header"
  grep -q 'id="tab-wiki"' "$TMP/page.html" && ok "  wiki tab" || no "  wiki tab"
  grep -q 'id="approvals"' "$TMP/page.html" && grep -q 'id="send"' "$TMP/page.html" && ok "  chat and approvals still there" || no "  chat and approvals still there"

  echo "== existing agents, without touching their messages or cursors"
  while IFS='=' read -r n k; do
    [ -n "$n" ] || continue
    expect "$n key authenticates" 200 GET /v2/inbox?after=999999999 "$k"; eq "  resolves to $n" "$(field .agent)" "$n"
    expect "  sees its tasks" 200 GET /v2/tasks "$k"
    expect "  sees its files" 200 GET /v2/files "$k"
  done < "$AGENT_KEYS_FILE"
  api GET /v2/task-types "$WK"; eq "github.invite still registered" "$(jq -c '.task_types[] | select(.name=="github.invite") | [.risk,.max_attempts]' <<<"$out")" '["high",1]'
  # A reply to a message that does not exist passes key, recipient and ACL checks, then stops before anything is stored.
  expect "ACL between the two agents still allows" 400 POST /v2/messages "$WK" "{\"to\":\"$LIVE_WIKI_CONTEXT_AGENT\",\"text\":\"[relay check, never stored]\",\"reply_to\":\"none\"}"; eq "  stopped at reply_to, past the ACL" "$(field .error)" "reply_to not found"
  expect "secret in a message is still 422" 422 POST /v2/messages "$WK" "{\"to\":\"$LIVE_WIKI_CONTEXT_AGENT\",\"text\":\"ghp_abcdefghijklmnopqrstuvwxyz123456\"}"
  expect "agents still cannot read the admin log" 404 GET /v2/log "$WK"

  wiki_chain "$WK" "$LIVE_WIKI_AGENT" "$PK" "$LIVE_WIKI_CONTEXT_AGENT"
  summary "live wiki"; exit
fi

: "${RELAY_ADMIN_KEY:?set RELAY_ADMIN_KEY}"
ADMIN=$RELAY_ADMIN_KEY

if [ "${1:-}" = lease ]; then
  api GET "/v2/tasks/$2" "$ADMIN"
  eq "alarm closed the lost lease" "$(field .task.status)" failed
  eq "  error says outcome unknown" "$(field .task.error)" lease_lost_outcome_unknown
  expect "remove the throwaway task type" 200 DELETE "/v2/task-types/$3" "$ADMIN"
  summary "live lease"; exit
fi

RUN="lt$RANDOM$RANDOM"; NA="$RUN-a"; NB="$RUN-b"; NC="$RUN-c"; TYPE="live.$RUN"; IDS=()
acl() { api POST /v2/acl "$ADMIN" "{\"from\":\"$1\",\"to\":\"$2\",\"kind\":\"$3\",\"allow\":${4:-true}}"; }
cleanup() {
  for id in "${IDS[@]}"; do api POST /v2/redact "$ADMIN" "{\"id\":\"$id\"}"; done
  acl "$NA" "$NB" msg false; acl "$NA" "$NB" file false; acl "$NA" "$NB" "task:$TYPE" false
  for n in "$NA" "$NB" "$NC"; do api POST /v2/revoke "$ADMIN" "{\"agent\":\"$n\"}"; done
}
trap 'cleanup; rm -rf "$TMP"' EXIT

echo "== page"
code=$(curl -sS -D "$TMP/hdr" -o /dev/null -w '%{http_code}' "$BASE/"); eq "page serves" "$code" 200
grep -qi "^content-security-policy: default-src 'none'" "$TMP/hdr" && ok "  CSP header" || no "  CSP header"

if [ -n "${AGENT_KEYS_FILE:-}" ]; then
  echo "== existing agents"
  key_of() { sed -n "s/^$1=//p" "$AGENT_KEYS_FILE"; }
  while IFS='=' read -r n k; do
    [ -n "$n" ] || continue
    expect "$n key authenticates" 200 GET /v2/inbox?after=999999999 "$k"; eq "  resolves to $n" "$(field .agent)" "$n"
  done < "$AGENT_KEYS_FILE"
  expect "existing ACL is readable" 200 GET /v2/acl "$ADMIN"; echo "  acl rows: $(field '.acl | length')"
  if [ -n "${LIVE_PING_A:-}" ] && [ -n "${LIVE_PING_B:-}" ]; then
    TXT="[relay deploy check $RUN] automated test, no action needed."
    expect "$LIVE_PING_A -> $LIVE_PING_B" 200 POST /v2/messages "$(key_of "$LIVE_PING_A")" "{\"to\":\"$LIVE_PING_B\",\"text\":\"$TXT\"}"; echo "  sent id: $(field .msg.id)"
    expect "$LIVE_PING_B -> $LIVE_PING_A" 200 POST /v2/messages "$(key_of "$LIVE_PING_B")" "{\"to\":\"$LIVE_PING_A\",\"text\":\"$TXT\"}"; S=$(field .msg.seq)
    expect "$LIVE_PING_A receives it" 200 GET "/v2/inbox?after=$((S - 1))" "$(key_of "$LIVE_PING_A")"; eq "  body matches" "$(field '.messages[0].body')" "$TXT"
  fi
fi

echo "== join, ACL, delivery"
expect "admin join" 200 POST /v2/join "$ADMIN" "{\"agent\":\"$NA\"}"; KA=$(field .key)
expect "admin join" 200 POST /v2/join "$ADMIN" "{\"agent\":\"$NB\"}"; KB=$(field .key)
expect "default-deny" 403 POST /v2/messages "$KA" "{\"to\":\"$NB\",\"text\":\"denied\"}"
acl "$NA" "$NB" msg
expect "send" 200 POST /v2/messages "$KA" "{\"to\":\"$NB\",\"text\":\"live test\",\"idem_key\":\"i1\"}"; MID=$(field .msg.id); SEQ=$(field .msg.seq); IDS+=("$MID")
expect "idempotent retry" 200 POST /v2/messages "$KA" "{\"to\":\"$NB\",\"text\":\"live test\",\"idem_key\":\"i1\"}"; eq "  same id" "$(field .msg.id)" "$MID"
expect "inbox" 200 GET "/v2/inbox?after=$((SEQ - 1))" "$KB"; eq "  body arrives" "$(field '.messages[0].body')" "live test"
expect "ack" 200 POST /v2/ack "$KB" "{\"seq\":$SEQ}"
api GET "/v2/receipts?id=$MID" "$KA"; eq "receipt delivered" "$(field .delivered)" true; eq "receipt read" "$(field .read)" true
expect "redact" 200 POST /v2/redact "$KA" "{\"id\":\"$MID\"}"
api GET "/v2/inbox?after=$((SEQ - 1))" "$KB"; eq "  body replaced" "$(field '.messages[0].body')" redacted

echo "== guards"
expect "secret is 422" 422 POST /v2/messages "$KA" "{\"to\":\"$NB\",\"text\":\"ghp_abcdefghijklmnopqrstuvwxyz123456\"}"
expect "9000 chars is 413" 413 POST /v2/messages "$KA" "$(jq -cn --arg t "$(head -c 9000 /dev/zero | tr '\0' x)" --arg to "$NB" '{to:$to,text:$t}')"
{ printf '{"to":"%s","text":"' "$NB"; head -c 150000 /dev/zero | tr '\0' y; printf '"}'; } > "$TMP/big.json"
code=$(curl_auth "$KA" -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v2/messages" --data-binary @"$TMP/big.json"); eq "150KB body is 413" "$code" 413
code=$(curl_auth "$KA" -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v2/messages" -H 'Transfer-Encoding: chunked' --data-binary @"$TMP/big.json"); eq "150KB chunked body is 413" "$code" 413
expect "request right after it is handled normally, no retry" 400 POST /v2/messages "$KA" '{"to":'
rl=''; for i in $(seq 1 25); do api POST /v2/messages "$KA" "{\"to\":\"$NB\",\"text\":\"flood $i\"}"; rl=$code; [ "$code" = 200 ] && IDS+=("$(field .msg.id)"); [ "$code" = 429 ] && break; done
eq "rate limit is 429" "$rl" 429

echo "== file roundtrip"
printf 'live relay file %s\n' "$RUN" > "$TMP/f.txt"; SZ=$(wc -c < "$TMP/f.txt"); SHA=$(sha256sum "$TMP/f.txt" | cut -d' ' -f1)
acl "$NA" "$NB" file
expect "create upload" 200 POST /v2/files "$KA" "{\"to\":\"$NB\",\"name\":\"f.txt\",\"size\":$SZ,\"sha256\":\"$SHA\"}"; FID=$(field .id)
code=$(curl_auth "$KA" -sS -o /dev/null -w '%{http_code}' -X PUT "$BASE/v2/files/$FID/content" --data-binary @"$TMP/f.txt"); eq "upload" "$code" 200
code=$(curl_auth "$KB" -sS -o "$TMP/dl" -w '%{http_code}' "$BASE/v2/files/$FID/content"); eq "download" "$code" 200
eq "  hash matches" "$(sha256sum "$TMP/dl" | cut -d' ' -f1)" "$SHA"

echo "== invite"
expect "create invite" 200 POST /v2/invites "$ADMIN" "{\"agent\":\"$NC\"}"; CODE=$(field .invite_code)
expect "redeem" 200 POST /v2/join '' "{\"invite_code\":\"$CODE\"}"; KC=$(field .key)
expect "new key works" 200 GET /v2/inbox "$KC"
expect "second redemption is 401" 401 POST /v2/join '' "{\"invite_code\":\"$CODE\"}"

echo "== task lifecycle"
api GET /v2/task-types "$KA"; eq "github.invite seeded" "$(jq -c '.task_types[] | select(.name=="github.invite") | [.risk,.max_attempts]' <<<"$out")" '["high",1]'
expect "agent cannot register a type" 403 POST /v2/task-types "$KA" '{"name":"x","schema":{"type":"object"}}'
expect "register throwaway type" 200 POST /v2/task-types "$ADMIN" "{\"name\":\"$TYPE\",\"schema\":{\"type\":\"object\",\"required\":[\"n\"],\"additionalProperties\":false,\"properties\":{\"n\":{\"type\":\"integer\"}}},\"risk\":\"high\",\"max_attempts\":1,\"ttl_s\":3600}"
new() { api POST /v2/tasks "$KA" "{\"type\":\"$TYPE\",\"to\":\"$NB\",\"params\":{\"n\":$1}}"; }
new 1; eq "no ACL is 403" "$code" 403
acl "$NA" "$NB" "task:$TYPE"
api POST /v2/tasks "$KA" "{\"type\":\"$TYPE\",\"to\":\"$NB\",\"params\":{\"n\":\"x\"}}"; eq "bad schema is 400" "$code" 400
new 1; eq "create" "$code" 200; T=$(field .task.id); PSHA=$(field .task.params_sha256); eq "  awaiting_approval" "$(field .task.status)" awaiting_approval
expect "claim before approval is 409" 409 POST "/v2/tasks/$T/claim" "$KB"
expect "agent cannot approve" 403 POST "/v2/tasks/$T/approve" "$KA" "{\"params_sha256\":\"$PSHA\"}"
expect "wrong hash is 409" 409 POST "/v2/tasks/$T/approve" "$ADMIN" '{"params_sha256":"00"}'
expect "approve" 200 POST "/v2/tasks/$T/approve" "$ADMIN" "{\"params_sha256\":\"$PSHA\"}"
expect "claim" 200 POST "/v2/tasks/$T/claim" "$KB"; LT=$(field .lease_token)
expect "double claim is 409" 409 POST "/v2/tasks/$T/claim" "$KB"
expect "heartbeat" 200 POST "/v2/tasks/$T/heartbeat" "$KB" "{\"lease_token\":\"$LT\"}"
expect "complete" 200 POST "/v2/tasks/$T/complete" "$KB" "{\"lease_token\":\"$LT\",\"result\":{\"ok\":true}}"
api GET "/v2/tasks/$T" "$KA"; eq "done" "$(field .task.status)" done
new 2; L=$(field .task.id); api POST "/v2/tasks/$L/approve" "$ADMIN" "{\"params_sha256\":\"$(field .task.params_sha256)\"}"
expect "claim and abandon a task for the alarm check" 200 POST "/v2/tasks/$L/claim" "$KB"

wiki_chain "$KA" "$NA" "$ADMIN" __admin__

echo; echo "After 5 minutes run: bash test/live.sh lease $L $TYPE"

summary "live"
