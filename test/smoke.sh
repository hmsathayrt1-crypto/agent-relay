#!/usr/bin/env bash
# End-to-end scenarios against a throwaway local relay (wrangler dev --local).
# Touches nothing remote. State lives in a temp dir that is removed on exit.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/test/lib.sh"
trap 'stop_relay; rm -rf "$TMP"' EXIT

ADMIN="smoke-admin-$RANDOM$RANDOM"
PORT=${PORT:-$((18000 + RANDOM % 2000))}
start_relay "$ROOT" wrangler.example.toml "$TMP/state" "$PORT" "$ADMIN" 2000 WIKI_AGENT_DAILY_BYTES:10485760 || exit 1

join() { api POST /v2/join "$ADMIN" "{\"agent\":\"$1\"}"; field .key; }
acl() { api POST /v2/acl "$ADMIN" "{\"from\":\"$1\",\"to\":\"$2\",\"kind\":\"$3\"}"; }
wait_status() { # wait_status TASK WANT: polls without mutating, so only the alarm can move the task
  local s=''
  for _ in $(seq 1 30); do api GET "/v2/tasks/$1" "$ADMIN"; s=$(field .task.status); [ "$s" = "$2" ] && break; sleep 0.5; done
  printf '%s' "$s"
}

echo "== join and auth"
A=$(join alice); B=$(join bob); C=$(join carol); D=$(join dave); E=$(join erin); GH=$(join github-bot)
[ "${A:0:4}" = ark_ ] && [ "${B:0:4}" = ark_ ] && ok "admin join returns server-generated keys" || no "admin join returns server-generated keys"
expect "duplicate join is 409" 409 POST /v2/join "$ADMIN" '{"agent":"alice"}'
expect "invalid name is 400" 400 POST /v2/join "$ADMIN" '{"agent":"Bad Name!"}'
expect "no token is 401" 401 GET /v2/inbox ''
expect "wrong token is 401" 401 GET /v2/inbox 'ark_wrong'
expect "agent cannot list agents" 404 GET /v2/agents "$A"

echo "== ACL deny and messaging"
expect "default-deny blocks a message" 403 POST /v2/messages "$A" '{"to":"bob","text":"no acl yet"}'
acl alice bob msg; acl bob alice msg; acl carol dave msg; acl dave carol msg; acl erin alice msg
expect "acl listing visible to admin" 200 GET /v2/acl "$ADMIN"
expect "send after ACL grant" 200 POST /v2/messages "$A" '{"to":"bob","text":"hello bob"}'
MID=$(field .msg.id); SEQ=$(field .msg.seq)
expect "receipt before delivery" 200 GET "/v2/receipts?id=$MID" "$A"; eq "  delivered=false" "$(field .delivered)" false
expect "recipient inbox" 200 GET /v2/inbox "$B"
eq "  message body arrives" "$(field '.messages[-1].body')" "hello bob"
api GET /v2/inbox "$C"; eq "third agent cannot read the DM" "$(field '.messages | length')" 0
expect "receipt after delivery" 200 GET "/v2/receipts?id=$MID" "$A"; eq "  delivered=true" "$(field .delivered)" true; eq "  read=false" "$(field .read)" false
expect "ack" 200 POST /v2/ack "$B" "{\"seq\":$SEQ}"
api GET "/v2/receipts?id=$MID" "$A"; eq "  read=true after ack" "$(field .read)" true
expect "receipts are private to the sender" 404 GET "/v2/receipts?id=$MID" "$C"

echo "== idempotency"
expect "first send with idem_key" 200 POST /v2/messages "$A" '{"to":"bob","text":"idem body","idem_key":"k1"}'; IDEM=$(field .msg.id)
for i in 1 2 3 4; do api POST /v2/messages "$A" '{"to":"bob","text":"idem body","idem_key":"k1"}'; done
eq "4 retries stay 200 (no duplicate-flood 429)" "$code" 200; eq "  same id returned" "$(field .msg.id)" "$IDEM"; eq "  flagged deduplicated" "$(field .deduplicated)" true
expect "idem_key with different text is 409" 409 POST /v2/messages "$A" '{"to":"bob","text":"other","idem_key":"k1"}'

echo "== secret blocking and size caps"
expect "GitHub token is 422" 422 POST /v2/messages "$A" '{"to":"bob","text":"ghp_abcdefghijklmnopqrstuvwxyz123456"}'
expect "relay key is 422" 422 POST /v2/messages "$A" "{\"to\":\"bob\",\"text\":\"$A\"}"
expect "private key header is 422" 422 POST /v2/messages "$A" '{"to":"bob","text":"-----BEGIN RSA PRIVATE KEY-----"}'
expect "admin key is 422" 422 POST /v2/messages "$A" "{\"to\":\"bob\",\"text\":\"key is $ADMIN\"}"
expect "'task-...' is not mistaken for sk-" 200 POST /v2/messages "$A" '{"to":"bob","text":"see task-management-workflow-notes"}'
expect "9000 char message is 413" 413 POST /v2/messages "$A" "$(jq -cn --arg t "$(head -c 9000 /dev/zero | tr '\0' x)" '{to:"bob",text:$t}')"
{ printf '{"to":"bob","text":"'; head -c 150000 /dev/zero | tr '\0' y; printf '"}'; } > "$TMP/big.json"
code=$(curl_auth "$A" -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v2/messages" --data-binary @"$TMP/big.json"); eq "150KB body with Content-Length is 413" "$code" 413
code=$(curl_auth "$A" -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v2/messages" -H 'Transfer-Encoding: chunked' --data-binary @"$TMP/big.json"); eq "150KB chunked body is 413" "$code" 413
# The Worker refuses this body without draining it, so the connection between wrangler's dev proxy and
# workerd cannot be reused. The proxy reports that one network error as a 503 with Retry-After: 0. Only that
# exact proxy response gets a retry here. test/live.sh runs the same sequence on a real deployment with no retry.
api POST /v2/messages "$A" '{"to":'
if [ "$code" = 503 ] && grep -q 'restarted mid-request' <<<"$out"; then echo "  (local dev proxy dropped its connection; retrying once)"; api POST /v2/messages "$A" '{"to":'; fi
eq "request after an oversize body is handled normally" "$code" 400

echo "== loop guard and rate limits"
expect "root of a reply chain" 200 POST /v2/messages "$C" '{"to":"dave","text":"hop 0"}'; PARENT=$(field .msg.id)
hop_code=''; for i in 1 2 3 4 5 6 7; do
  if [ $((i % 2)) = 1 ]; then t=$D; to=carol; else t=$C; to=dave; fi
  api POST /v2/messages "$t" "{\"to\":\"$to\",\"text\":\"hop $i\",\"reply_to\":\"$PARENT\"}"; hop_code=$code
  [ "$code" = 200 ] && PARENT=$(field .msg.id)
done
eq "reply chain past hop 6 is 429" "$hop_code" 429
expect "reply to unseen message is 403" 403 POST /v2/messages "$E" "{\"to\":\"alice\",\"text\":\"peek\",\"reply_to\":\"$MID\"}"
rl=''; for i in $(seq 1 25); do api POST /v2/messages "$E" "{\"to\":\"alice\",\"text\":\"flood $i\"}"; rl=$code; [ "$code" = 429 ] && break; done
eq "pair rate limit is 429" "$rl" 429
dup=''; for i in 1 2 3; do api POST /v2/messages "$B" '{"to":"alice","text":"same text again"}'; dup=$code; done
eq "third identical text is 429" "$dup" 429

echo "== redact"
CANARY="CANARY-$RANDOM$RANDOM"
expect "send message to redact" 200 POST /v2/messages "$A" "{\"to\":\"bob\",\"text\":\"$CANARY\",\"idem_key\":\"redact1\"}"; RID=$(field .msg.id)
expect "recipient cannot redact" 403 POST /v2/redact "$B" "{\"id\":\"$RID\"}"
expect "sender can redact" 200 POST /v2/redact "$A" "{\"id\":\"$RID\"}"
api GET /v2/log "$ADMIN"; eq "  body replaced with placeholder" "$(jq -r --arg i "$RID" '.messages[] | select(.id==$i) | .body' <<<"$out")" redacted
expect "  idem retry after redact still dedupes" 200 POST /v2/messages "$A" "{\"to\":\"bob\",\"text\":\"$CANARY\",\"idem_key\":\"redact1\"}"
expect "admin can redact" 200 POST /v2/redact "$ADMIN" "{\"id\":\"$MID\"}"
expect "unknown id is 404" 404 POST /v2/redact "$A" '{"id":"nope"}'

echo "== files"
printf 'hello relay file %s\n' "$RANDOM" > "$TMP/f.txt"; FSZ=$(wc -c < "$TMP/f.txt"); FSHA=$(sha256sum "$TMP/f.txt" | cut -d' ' -f1)
fmeta() { printf '{"to":"bob","name":"%s","size":%s,"sha256":"%s"}' "$1" "$2" "$3"; }
put() { curl_auth "$1" -sS -o "$TMP/out" -w '%{http_code}' -X PUT "$BASE/v2/files/$2/content" --data-binary @"$3"; }
expect "file without ACL is 403" 403 POST /v2/files "$A" "$(fmeta f.txt "$FSZ" "$FSHA")"
acl alice bob file
expect "disallowed extension is 415" 415 POST /v2/files "$A" "$(fmeta run.exe "$FSZ" "$FSHA")"
expect "over 10MB is 413" 413 POST /v2/files "$A" "$(fmeta f.txt 10485761 "$FSHA")"
expect "create upload" 200 POST /v2/files "$A" "$(fmeta 'تقرير f.txt' "$FSZ" "$FSHA")"; FID=$(field .id)
printf 'tampered bytes!!!!!!!!!!!!!' | head -c "$FSZ" > "$TMP/bad.txt"
eq "wrong content fails the hash check" "$(put "$A" "$FID" "$TMP/bad.txt")" 400
head -c $((FSZ + 500)) /dev/urandom > "$TMP/long.txt"
eq "more bytes than declared is 413" "$(put "$A" "$FID" "$TMP/long.txt")" 413
expect "request right after a refused upload is unaffected" 400 POST /v2/messages "$A" '{"to":'
head -c 90000 /dev/zero | tr '\0' z > "$TMP/90k.bin"
code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$BASE/v2/messages" -H 'Authorization: Bearer wrong' --data-binary @"$TMP/90k.bin"); eq "large unauthenticated body is 401" "$code" 401
expect "request right after a refused large body is unaffected" 400 POST /v2/messages "$A" '{"to":'
expect "download before upload is 409" 409 GET "/v2/files/$FID/content" "$B"
eq "upload" "$(put "$A" "$FID" "$TMP/f.txt")" 200
code=$(curl_auth "$B" -sS -D "$TMP/hdr" -o "$TMP/dl.txt" -w '%{http_code}' "$BASE/v2/files/$FID/content"); eq "recipient download (non-ASCII name)" "$code" 200
eq "  roundtrip hash matches" "$(sha256sum "$TMP/dl.txt" | cut -d' ' -f1)" "$FSHA"
grep -qi '^content-disposition: attachment' "$TMP/hdr" && ok "  served as attachment" || no "  served as attachment"
expect "third agent cannot download" 403 GET "/v2/files/$FID/content" "$C"
printf '\x7fELF-not-really' > "$TMP/elf.txt"; ESZ=$(wc -c < "$TMP/elf.txt"); ESHA=$(sha256sum "$TMP/elf.txt" | cut -d' ' -f1)
api POST /v2/files "$A" "$(fmeta elf.txt "$ESZ" "$ESHA")"; eq "ELF magic bytes are 415" "$(put "$A" "$(field .id)" "$TMP/elf.txt")" 415
printf '  <html><script>x</script>' > "$TMP/h.txt"; HSZ=$(wc -c < "$TMP/h.txt"); HSHA=$(sha256sum "$TMP/h.txt" | cut -d' ' -f1)
api POST /v2/files "$A" "$(fmeta h.txt "$HSZ" "$HSHA")"; eq "HTML after whitespace is 415" "$(put "$A" "$(field .id)" "$TMP/h.txt")" 415

echo "== github.invite lifecycle with approval"
INV='{"repo":"acme/widgets","username":"octocat","permission":"pull"}'
INV_SHA=$(printf '%s' "$INV" | sha256sum | cut -d' ' -f1)
task() { printf '{"type":"github.invite","params":%s%s}' "$1" "${2:-}"; }
api GET /v2/task-types "$A"; eq "github.invite is seeded high risk, one attempt" "$(jq -c '.task_types[] | select(.name=="github.invite") | [.risk,.max_attempts]' <<<"$out")" '["high",1]'
expect "no ACL is 403" 403 POST /v2/tasks "$A" "$(task "$INV")"
acl alice github-bot task:github.invite
expect "unknown type is 400" 400 POST /v2/tasks "$A" '{"type":"nope","params":{}}'
expect "missing field fails schema" 400 POST /v2/tasks "$A" "$(task '{"repo":"acme/widgets","username":"octocat"}')"
expect "extra field fails schema" 400 POST /v2/tasks "$A" "$(task '{"repo":"acme/widgets","username":"octocat","permission":"pull","note":"x"}')"
expect "admin permission fails schema" 400 POST /v2/tasks "$A" "$(task '{"repo":"acme/widgets","username":"octocat","permission":"admin"}')"
expect "bad repo format fails schema" 400 POST /v2/tasks "$A" "$(task '{"repo":"../../etc","username":"octocat","permission":"pull"}')"
expect "valid task is accepted" 200 POST /v2/tasks "$A" "$(task "$INV" ',"idem_key":"t1"')"
T=$(field .task.id); eq "  starts awaiting_approval" "$(field .task.status)" awaiting_approval; eq "  params_sha256 is over the stored JSON" "$(field .task.params_sha256)" "$INV_SHA"
expect "idempotent create returns same task" 200 POST /v2/tasks "$A" "$(task "$INV" ',"idem_key":"t1"')"; eq "  same id" "$(field .task.id)" "$T"
expect "same idem_key, new params is 409" 409 POST /v2/tasks "$A" "$(task '{"repo":"acme/secret","username":"mallory","permission":"push"}' ',"idem_key":"t1"')"
expect "no endpoint can edit a task" 404 POST "/v2/tasks/$T" "$A" '{"params":{"repo":"acme/secret"}}'
expect "executor cannot see an unapproved task" 403 GET "/v2/tasks/$T" "$GH"
expect "claim before approval is 409" 409 POST "/v2/tasks/$T/claim" "$GH"
expect "agent cannot approve" 403 POST "/v2/tasks/$T/approve" "$A" "{\"params_sha256\":\"$INV_SHA\"}"
expect "approve with wrong hash is 409" 409 POST "/v2/tasks/$T/approve" "$ADMIN" '{"params_sha256":"0000"}'
expect "approver sees original params" 200 GET "/v2/tasks?status=awaiting_approval" "$ADMIN"; eq "  params_json from storage" "$(jq -r --arg i "$T" '.tasks[] | select(.id==$i) | .params_json' <<<"$out")" "$INV"
expect "approve with stored hash" 200 POST "/v2/tasks/$T/approve" "$ADMIN" "{\"params_sha256\":\"$INV_SHA\"}"
expect "double approve is 409" 409 POST "/v2/tasks/$T/approve" "$ADMIN" "{\"params_sha256\":\"$INV_SHA\"}"
expect "wrong agent cannot claim" 403 POST "/v2/tasks/$T/claim" "$A"
expect "executor claims" 200 POST "/v2/tasks/$T/claim" "$GH"; LT=$(field .lease_token); eq "  gets the original params" "$(field '.task.params.repo')" acme/widgets
expect "second claim loses the CAS" 409 POST "/v2/tasks/$T/claim" "$GH"
expect "heartbeat with wrong token is 409" 409 POST "/v2/tasks/$T/heartbeat" "$GH" '{"lease_token":"wrong"}'
expect "heartbeat" 200 POST "/v2/tasks/$T/heartbeat" "$GH" "{\"lease_token\":\"$LT\"}"
expect "complete with wrong token is 409" 409 POST "/v2/tasks/$T/complete" "$GH" '{"lease_token":"wrong","result":{}}'
expect "secret in result is 422" 422 POST "/v2/tasks/$T/complete" "$GH" "{\"lease_token\":\"$LT\",\"result\":{\"t\":\"ghp_abcdefghijklmnopqrstuvwxyz123456\"}}"
expect "complete" 200 POST "/v2/tasks/$T/complete" "$GH" "{\"lease_token\":\"$LT\",\"result\":{\"invited\":true}}"
expect "repeated complete is deduplicated" 200 POST "/v2/tasks/$T/complete" "$GH" "{\"lease_token\":\"$LT\",\"result\":{\"invited\":true}}"
api GET "/v2/tasks/$T" "$A"; eq "creator sees done" "$(field .task.status)" done; eq "  result stored" "$(field .task.result_json)" '{"invited":true}'; eq "  no lease token exposed" "$(field .task.lease_token)" null
expect "secret in params is 422" 422 POST /v2/tasks "$A" "$(task '{"repo":"acme/ghp_abcdefghijklmnopqrstuvwxyz123456","username":"octocat","permission":"pull"}')"
expect "new task for rejection" 200 POST /v2/tasks "$A" "$(task "$INV")"; T2=$(field .task.id)
expect "requester cannot reject" 403 POST "/v2/tasks/$T2/reject" "$A" '{"reason":"x"}'
expect "admin rejects" 200 POST "/v2/tasks/$T2/reject" "$ADMIN" '{"reason":"no"}'
expect "rejected task cannot be approved" 409 POST "/v2/tasks/$T2/approve" "$ADMIN" "{\"params_sha256\":\"$INV_SHA\"}"
expect "rejected task cannot be claimed" 409 POST "/v2/tasks/$T2/claim" "$GH"

echo "== leases and alarms (LEASE_MS=2000 in this run)"
reg() { api POST /v2/task-types "$ADMIN" "{\"name\":\"$1\",\"schema\":{\"type\":\"object\",\"properties\":{\"n\":{\"type\":\"integer\"}}},\"risk\":\"low\",\"max_attempts\":$2,\"ttl_s\":$3}"; }
reg smoke.once 1 3600; reg smoke.retry 2 3600; reg smoke.low 3 3600; reg smoke.ttl 3 1
for k in smoke.once smoke.retry smoke.low smoke.ttl; do acl alice bob "task:$k"; done
expect "agent cannot register task types" 403 POST /v2/task-types "$A" '{"name":"x","schema":{"type":"object"}}'
new() { api POST /v2/tasks "$A" "{\"type\":\"$1\",\"to\":\"bob\",\"params\":{\"n\":1}}"; field .task.id; }
T3=$(new smoke.once); api POST "/v2/tasks/$T3/claim" "$B"; LT3=$(field .lease_token)
eq "lost lease on max_attempts=1 fails, no retry" "$(wait_status "$T3" failed)" failed
api GET "/v2/tasks/$T3" "$A"; eq "  error says outcome unknown" "$(field .task.error)" lease_lost_outcome_unknown
expect "  late complete is refused" 409 POST "/v2/tasks/$T3/complete" "$B" "{\"lease_token\":\"$LT3\",\"result\":{}}"
expect "  late heartbeat is refused" 409 POST "/v2/tasks/$T3/heartbeat" "$B" "{\"lease_token\":\"$LT3\"}"
T4=$(new smoke.retry); api POST "/v2/tasks/$T4/claim" "$B"
eq "lost lease retries while attempts remain" "$(wait_status "$T4" pending)" pending
expect "  can be claimed again" 200 POST "/v2/tasks/$T4/claim" "$B"; eq "  attempt 2" "$(field .attempt)" 2
eq "attempts exhausted goes dead" "$(wait_status "$T4" dead)" dead
T5=$(new smoke.ttl); sleep 2
expect "expired task cannot be claimed" 409 POST "/v2/tasks/$T5/claim" "$B"
T6=$(new smoke.low); expect "executor can reject a pending task" 200 POST "/v2/tasks/$T6/reject" "$B" '{"reason":"cannot do this"}'

echo "== depth and cycle guards"
reg smoke.chain 1 3600
acl alice bob task:smoke.chain; acl bob carol task:smoke.chain; acl carol dave task:smoke.chain; acl dave erin task:smoke.chain; acl carol alice task:smoke.chain; acl alice alice task:smoke.chain
spawn() { api POST /v2/tasks "$1" "{\"type\":\"smoke.chain\",\"to\":\"$2\",\"params\":{\"n\":1}${3:+,\"parent_task_id\":\"$3\"}}"; }
expect "agent cannot task itself" 409 POST /v2/tasks "$A" '{"type":"smoke.chain","to":"alice","params":{}}'
spawn "$A" bob; R0=$(field .task.id)
spawn "$B" carol "$R0"; eq "parent must be in progress" "$code" 409
api POST "/v2/tasks/$R0/claim" "$B"
spawn "$C" dave "$R0"; eq "only the parent's executor can spawn" "$code" 403
spawn "$B" carol "$R0"; eq "depth 1 allowed" "$code" 200; R1=$(field .task.id)
api POST "/v2/tasks/$R0/heartbeat" "$B" '{}'
api POST "/v2/tasks/$R1/claim" "$C"
spawn "$C" alice "$R1"; eq "cycle back to the origin is 409" "$code" 409
spawn "$C" dave "$R1"; eq "depth 2 allowed" "$code" 200; R2=$(field .task.id)
api POST "/v2/tasks/$R2/claim" "$D"
spawn "$D" erin "$R2"; eq "depth 3 is refused" "$code" 422

echo "== invites"
expect "agent cannot create invites" 403 POST /v2/invites "$A" '{"agent":"newbie"}'
expect "invite for existing agent is 409" 409 POST /v2/invites "$ADMIN" '{"agent":"alice"}'
expect "template must involve the agent" 400 POST /v2/invites "$ADMIN" '{"agent":"newbie","acl_template":[{"from":"alice","to":"bob","kind":"msg"}]}'
expect "create invite" 200 POST /v2/invites "$ADMIN" '{"agent":"newbie"}'; CODE=$(field .invite_code)
expect "invite code in a message is 422" 422 POST /v2/messages "$A" "{\"to\":\"bob\",\"text\":\"$CODE\"}"
expect "bad code is 401" 401 POST /v2/join '' '{"invite_code":"inv_wrong"}'
expect "redeem without token" 200 POST /v2/join '' "{\"invite_code\":\"$CODE\"}"; NK=$(field .key); eq "  key is shown" "${NK:0:4}" ark_
expect "new key works" 200 GET /v2/inbox "$NK"
expect "new agent starts with empty ACL" 403 POST /v2/messages "$NK" '{"to":"bob","text":"hi"}'
expect "second redemption is 401" 401 POST /v2/join '' "{\"invite_code\":\"$CODE\"}"
expect "invite with template" 200 POST /v2/invites "$ADMIN" '{"agent":"temp1","acl_template":[{"from":"temp1","to":"bob","kind":"msg"}]}'; CODE2=$(field .invite_code)
api POST /v2/join '' "{\"invite_code\":\"$CODE2\"}"; TK=$(field .key)
expect "template grants exactly its ACL" 200 POST /v2/messages "$TK" '{"to":"bob","text":"hi from temp1"}'
expect "  and nothing else" 403 POST /v2/messages "$TK" '{"to":"alice","text":"hi"}'
expect "short-lived invite" 200 POST /v2/invites "$ADMIN" '{"agent":"late1","ttl_s":1}'; CODE3=$(field .invite_code); sleep 2
expect "expired invite is 401" 401 POST /v2/join '' "{\"invite_code\":\"$CODE3\"}"
expect "invite template can grant wiki:context" 200 POST /v2/invites "$ADMIN" '{"agent":"ctxbot","acl_template":[{"from":"ctxbot","to":"__wiki__","kind":"wiki:context"}]}'; CODE4=$(field .invite_code)
api POST /v2/join '' "{\"invite_code\":\"$CODE4\"}"; CTXK=$(field .key)
expect "  and it works" 200 PUT /v2/wiki/invited-ctx "$CTXK" '{"title":"t","kind":"context","body":"from an invite"}'
expect "invite template cannot point wiki:context elsewhere" 400 POST /v2/invites "$ADMIN" '{"agent":"ctxbot2","acl_template":[{"from":"ctxbot2","to":"bob","kind":"wiki:context"}]}'
jc=''; for i in $(seq 1 12); do api POST /v2/join '' '{"invite_code":"inv_guess"}'; jc=$code; [ "$code" = 429 ] && break; done
eq "join attempts are throttled" "$jc" 429

echo "== wiki: create, update, versions"
page() { jq -cn --arg title "$1" --arg kind "$2" --arg body "$3" --argjson tags "${4:-[]}" '{title:$title,kind:$kind,body:$body,tags:$tags}'; }
expect "wiki needs a key" 401 GET /v2/wiki ''
expect "wiki rejects a bad key" 401 PUT /v2/wiki/x 'ark_wrong' "$(page t note b)"
for bad in Upper -dash _under "$(head -c 65 /dev/zero | tr '\0' a)" "$(uri 'مهام')"; do
  expect "slug [${bad:0:12}] is 400" 400 PUT "/v2/wiki/$bad" "$A" "$(page t note b)"
done
expect "unknown page is 404" 404 GET /v2/wiki/nope "$A"
expect "create a note" 200 PUT /v2/wiki/tasks-guide "$A" "$(page 'دليل المهام' note 'كيف تستخدم المهام في القناة' '["Ops","ops"," Daily "]')"; eq "  starts at version 1" "$(field .version)" 1
expect "any active agent reads it" 200 GET /v2/wiki/tasks-guide "$C"
eq "  title" "$(field .title)" 'دليل المهام'; eq "  body" "$(field .body)" 'كيف تستخدم المهام في القناة'; eq "  kind" "$(field .kind)" note
eq "  tags normalized and deduped" "$(jq -c .tags <<<"$out")" '["ops","daily"]'; eq "  updated_by is the caller" "$(field .updated_by)" alice
eq "  response has exactly the documented fields" "$(jq -c 'keys' <<<"$out")" '["body","kind","slug","tags","title","updated_at","updated_by","version"]'
expect "the caller cannot claim another author" 200 PUT /v2/wiki/tasks-guide "$B" '{"body":"نسخة ثانية","updated_by":"mallory","version":99}'
eq "  version increments" "$(field .version)" 2; eq "  author comes from the key" "$(field .updated_by)" bob
api GET /v2/wiki/tasks-guide "$A"; eq "  title, kind and tags survive a body-only update" "$(jq -c '[.title,.kind,.tags]' <<<"$out")" '["دليل المهام","note",["ops","daily"]]'
expect "retry of the same write" 200 PUT /v2/wiki/tasks-guide "$C" '{"body":"نسخة ثانية"}'; eq "  adds no version" "$(field .version)" 2; eq "  flagged unchanged" "$(field .unchanged)" true
api GET /v2/wiki/tasks-guide "$A"; eq "  does not take over the page" "$(field .updated_by)" bob
expect "history list" 200 GET /v2/wiki/tasks-guide/history "$C"; eq "  one old version" "$(field '.versions | length')" 1; eq "  current_version" "$(field .current_version)" 2
eq "  entry has version, author, time, size only" "$(jq -c '.versions[0] | keys' <<<"$out")" '["deleted","size","updated_at","updated_by","version"]'
eq "  size is in bytes" "$(field '.versions[0].size')" "$(printf '%s' 'كيف تستخدم المهام في القناة' | wc -c)"; eq "  author of the old version" "$(field '.versions[0].updated_by')" alice
expect "old version in full" 200 GET /v2/wiki/tasks-guide/history/1 "$C"; eq "  old body" "$(field .body)" 'كيف تستخدم المهام في القناة'
expect "missing version is 404" 404 GET /v2/wiki/tasks-guide/history/99 "$A"
expect "bad version is 400" 400 GET /v2/wiki/tasks-guide/history/0x1 "$A"
expect "slug named content is a normal page" 200 PUT /v2/wiki/content "$A" "$(page 'c' note 'not a file upload')"; api GET /v2/wiki/content "$A"; eq "  reads back" "$(field .body)" 'not a file upload'
expect "slug named history is a normal page" 200 PUT /v2/wiki/history "$A" "$(page 'h' note 'also fine')"
expect "  with its own history" 200 GET /v2/wiki/history/history "$A"
for i in $(seq 1 24); do api PUT /v2/wiki/busy "$ADMIN" "$(page busy note "rev $i")"; done
api GET /v2/wiki/busy/history "$A"; eq "history lists the latest 20" "$(field '.versions | length')" 20; eq "  newest first" "$(field '.versions[0].version')" 23; eq "  older versions are pruned" "$(field .total)" 20
expect "  pruned version is gone" 404 GET /v2/wiki/busy/history/1 "$A"; expect "  kept version loads" 200 GET /v2/wiki/busy/history/4 "$A"; eq "    with the right body" "$(field .body)" 'rev 4'

echo "== wiki: list and search"
acl alice __wiki__ wiki:skill
expect "english page" 200 PUT /v2/wiki/deploy-steps "$A" "$(page 'Deploy Steps' skill 'run wrangler deploy, then 100% check' '["DevOps","release"]')"
slugs() { jq -c '[.pages[].slug] | sort' <<<"$out"; }
expect "arabic search in the body, percent-encoded" 200 GET "/v2/wiki?q=$(uri 'نسخة')" "$A"; eq "  finds it" "$(slugs)" '["tasks-guide"]'
api GET "/v2/wiki?q=$(uri 'مهام')" "$A"; eq "arabic search q=مهام in the title" "$(slugs)" '["tasks-guide"]'
api GET "/v2/wiki?q=مهام" "$A"; eq "  also with raw UTF-8 in the URL" "$(slugs)" '["tasks-guide"]'
api GET "/v2/wiki?q=WRANGLER" "$A"; eq "english search ignores case" "$(slugs)" '["deploy-steps"]'
api GET "/v2/wiki?q=$(uri '%')" "$A"; eq "% is literal, not a wildcard" "$(slugs)" '["deploy-steps"]'
api GET "/v2/wiki?q=$(uri '_')" "$A"; eq "_ is literal, not a wildcard" "$(slugs)" '[]'
api GET "/v2/wiki?q=$(uri "' OR 1=1 --")" "$A"; eq "SQL in q is just text" "$(slugs)" '[]'
expect "very long q is 400" 400 GET "/v2/wiki?q=$(head -c 201 /dev/zero | tr '\0' a)" "$A"
api GET "/v2/wiki?kind=skill" "$A"; eq "kind filter" "$(slugs)" '["deploy-steps"]'
expect "unknown kind is 400" 400 GET "/v2/wiki?kind=secret" "$A"
api GET "/v2/wiki?tag=devops" "$A"; eq "tag filter" "$(slugs)" '["deploy-steps"]'
api GET "/v2/wiki?tag=DevOps" "$A"; eq "  normalizes the query" "$(slugs)" '["deploy-steps"]'
api GET "/v2/wiki?tag=ops" "$A"; eq "  matches whole tags, not substrings" "$(slugs)" '["tasks-guide"]'
api GET "/v2/wiki?kind=skill&tag=ops" "$A"; eq "filters combine" "$(slugs)" '[]'
api GET /v2/wiki "$A"; eq "list omits bodies" "$(jq -c '[.pages[] | has("body")] | any' <<<"$out")" false; eq "  tags are arrays" "$(jq -r '.pages[] | select(.slug=="deploy-steps") | .tags[0]' <<<"$out")" devops

echo "== wiki: secrets and content rules"
GHT=ghp_abcdefghijklmnopqrstuvwxyz123456
expect "secret in body is 422" 422 PUT /v2/wiki/leak "$A" "$(page t note "token is $GHT")"
expect "relay key in body is 422" 422 PUT /v2/wiki/leak "$A" "$(page t note "$A")"
expect "admin key in body is 422" 422 PUT /v2/wiki/leak "$A" "$(page t note "key is $ADMIN")"
expect "secret in title is 422" 422 PUT /v2/wiki/leak "$A" "$(page "$GHT" note ok)"
expect "secret in a tag is 422" 422 PUT /v2/wiki/leak "$A" "$(page t note ok '["ghp_abcdefghijklmnopqrstuvwxyz"]')"
expect "secret as the slug is 422" 422 PUT "/v2/wiki/ark_$(printf 'a%.0s' $(seq 1 32))" "$A" "$(page t note ok)"
expect "secret on update is 422" 422 PUT /v2/wiki/tasks-guide "$A" "{\"body\":\"$GHT\"}"
expect "  and nothing was stored" 404 GET /v2/wiki/leak "$A"
api GET /v2/wiki/tasks-guide "$A"; eq "  page stays as it was" "$(field .version)" 2
for h in '<!DOCTYPE html><p>' '<html>' '<script>x</script>' '<SCRIPT src=x>' '  <html>'; do
  expect "body starting [${h:0:10}] is 415" 415 PUT /v2/wiki/htmlx "$A" "$(page t note "$h")"
done
expect "BOM before <script is 415" 415 PUT /v2/wiki/htmlx "$A" "$(page t note "$(printf '\xef\xbb\xbf<script>')")"
expect "newlines before <html is 415" 415 PUT /v2/wiki/htmlx "$A" '{"title":"t","body":"\n\n<html>"}'
expect "markup later in the text is fine" 200 PUT /v2/wiki/htmlx "$A" "$(page t note 'use <script> carefully')"
expect "9 tags is 400" 400 PUT /v2/wiki/tagsx "$A" "$(page t note ok '["a","b","c","d","e","f","g","h","i"]')"
expect "8 tags is fine" 200 PUT /v2/wiki/tagsx "$A" "$(page t note ok '["a","b","c","d","e","f","g","h"]')"
expect "31 char tag is 400" 400 PUT /v2/wiki/tagsx "$A" "$(page t note ok "[\"$(head -c 31 /dev/zero | tr '\0' a)\"]")"
expect "30 char tag is fine" 200 PUT /v2/wiki/tagsx "$A" "$(page t note ok2 "[\"$(head -c 30 /dev/zero | tr '\0' a)\"]")"
expect "non-string tag is 400" 400 PUT /v2/wiki/tagsx "$A" "$(page t note ok '[1]')"
expect "tags must be a list" 400 PUT /v2/wiki/tagsx "$A" '{"title":"t","body":"b","tags":"a,b"}'
expect "empty tag is 400" 400 PUT /v2/wiki/tagsx "$A" "$(page t note ok '["  "]')"
expect "unknown kind on write is 400" 400 PUT /v2/wiki/kindx "$A" "$(page t secret ok)"
expect "new page needs a title" 400 PUT /v2/wiki/kindx "$A" '{"body":"b"}'
expect "blank title is 400" 400 PUT /v2/wiki/kindx "$A" '{"title":"   ","body":"b"}'
expect "missing body is 400" 400 PUT /v2/wiki/kindx "$A" '{"title":"t"}'
expect "blank body is 400" 400 PUT /v2/wiki/kindx "$A" '{"title":"t","body":"   "}'
expect "NUL in body is 400" 400 PUT /v2/wiki/kindx "$A" '{"title":"t","body":"a\u0000b"}'
expect "non-text body is 400" 400 PUT /v2/wiki/kindx "$A" '{"title":"t","body":{"a":1}}'
wbody() { { printf '{"title":"big","body":"'; cat; printf '"}'; } > "$TMP/wiki.json"; }
head -c 102400 /dev/zero | tr '\0' w | wbody; api_file PUT /v2/wiki/sized "$A" "$TMP/wiki.json"; eq "exactly 100KB is accepted" "$code" 200
head -c 102401 /dev/zero | tr '\0' w | wbody; api_file PUT /v2/wiki/sized "$A" "$TMP/wiki.json"; eq "100KB + 1 byte is 413" "$code" 413
for _ in $(seq 1 50000); do printf '\\u0645'; done | wbody; api_file PUT /v2/wiki/arabic-big "$A" "$TMP/wiki.json"; eq "100KB of Arabic sent as \\uXXXX escapes (300KB request) is accepted" "$code" 200
expect "  stored at its real size" 200 GET /v2/wiki/arabic-big/history "$A"; api GET "/v2/wiki?q=$(uri 'م')&kind=note" "$A"; eq "    100000 bytes" "$(jq -r '.pages[] | select(.slug=="arabic-big") | .size' <<<"$out")" 100000
head -c 400000 /dev/zero | tr '\0' w | wbody; api_file PUT /v2/wiki/sized "$A" "$TMP/wiki.json"; eq "400KB request is 413 before the Durable Object" "$code" 413
expect "request right after it is handled normally" 200 GET /v2/wiki/sized "$A"
api_file POST /v2/messages "$A" "$TMP/wiki.json"; eq "other routes keep the 100KB cap" "$code" 413

echo "== wiki: who can write context"
expect "ordinary agent cannot create context" 403 PUT /v2/wiki/ctx "$A" "$(page t context ok)"
expect "  nor is it stored" 404 GET /v2/wiki/ctx "$A"
expect "admin can" 200 PUT /v2/wiki/ctx "$ADMIN" "$(page 'سياق' context 'نص السياق')"; eq "  by __admin__" "$(field .updated_by)" __admin__
expect "any agent can read context" 200 GET /v2/wiki/ctx "$C"
expect "ordinary agent cannot edit context" 403 PUT /v2/wiki/ctx "$A" '{"body":"changed"}'
expect "nor relabel it as a note to edit it" 403 PUT /v2/wiki/ctx "$A" "$(page t note changed)"
api GET /v2/wiki/ctx "$A"; eq "  page is untouched" "$(jq -c '[.kind,.body,.version]' <<<"$out")" '["context","نص السياق",1]'
expect "nor turn a note into context" 403 PUT /v2/wiki/tasks-guide "$A" '{"kind":"context","body":"x"}'
expect "wrong acl target is 400" 400 POST /v2/acl "$ADMIN" '{"from":"alice","to":"bob","kind":"wiki:context"}'
expect "agent cannot grant itself" 404 POST /v2/acl "$A" '{"from":"alice","to":"__wiki__","kind":"wiki:context"}'
expect "reserved name cannot join" 400 POST /v2/join "$ADMIN" '{"agent":"__wiki__"}'
expect "reserved name cannot be invited" 400 POST /v2/invites "$ADMIN" '{"agent":"__wiki__"}'
expect "grant wiki:context" 200 POST /v2/acl "$ADMIN" '{"from":"alice","to":"__wiki__","kind":"wiki:context"}'
expect "granted agent can edit context" 200 PUT /v2/wiki/ctx "$A" '{"body":"نص محدث"}'
expect "granted agent can create context" 200 PUT /v2/wiki/ctx2 "$A" "$(page t context ok)"
expect "other agents still cannot" 403 PUT /v2/wiki/ctx "$B" '{"body":"x"}'
expect "other agents cannot delete context" 403 DELETE /v2/wiki/ctx "$B"
expect "remove the grant" 200 POST /v2/acl "$ADMIN" '{"from":"alice","to":"__wiki__","kind":"wiki:context","allow":false}'
expect "revoked grant stops edits" 403 PUT /v2/wiki/ctx "$A" '{"body":"y"}'
expect "  and stops deletes, even by the last editor" 403 DELETE /v2/wiki/ctx "$A"

echo "== wiki: delete"
quota() { api GET /v2/wiki "$A"; field "$1"; }
expect "page to delete" 200 PUT /v2/wiki/gone "$A" "$(page 'g' note 'first')"
expect "second version" 200 PUT /v2/wiki/gone "$B" '{"body":"second"}'
expect "earlier author cannot delete" 403 DELETE /v2/wiki/gone "$A"
expect "stranger cannot delete" 403 DELETE /v2/wiki/gone "$C"
expect "last editor deletes" 200 DELETE /v2/wiki/gone "$B"; eq "  tombstone version" "$(field .version)" 3
expect "deleted page is 404" 404 GET /v2/wiki/gone "$A"
expect "second delete is 404" 404 DELETE /v2/wiki/gone "$B"
api GET "/v2/wiki?q=second" "$A"; eq "deleted page leaves the list" "$(slugs)" '[]'
expect "history survives the delete" 200 GET /v2/wiki/gone/history "$A"; eq "  current_version is null" "$(field .current_version)" null; eq "  tombstone first" "$(field '.versions[0].deleted')" true; eq "  by the deleter" "$(field '.versions[0].updated_by')" bob
expect "the last body can be recovered" 200 GET /v2/wiki/gone/history/2 "$A"; eq "  body" "$(field .body)" second
expect "tombstone has no body to load" 404 GET /v2/wiki/gone/history/3 "$A"
expect "slug can be reused" 200 PUT /v2/wiki/gone "$C" "$(page 'g2' note 'third')"; eq "  version keeps counting" "$(field .version)" 4
expect "  and updated again" 200 PUT /v2/wiki/gone "$C" '{"body":"fourth"}'; eq "  version 5" "$(field .version)" 5
expect "admin can delete any page" 200 DELETE /v2/wiki/gone "$ADMIN"
expect "agent cannot purge" 403 DELETE "/v2/wiki/gone?purge=1" "$C"
expect "admin purge erases the history" 200 DELETE "/v2/wiki/gone?purge=1" "$ADMIN"
expect "  history is gone" 404 GET /v2/wiki/gone/history "$A"
expect "  second purge is 404" 404 DELETE "/v2/wiki/gone?purge=1" "$ADMIN"

echo "== wiki: quotas and rate limit"
expect "fresh agent for the rate limit" 200 POST /v2/join "$ADMIN" '{"agent":"wikirate"}'; WR=$(field .key)
for i in $(seq 1 60); do api PUT /v2/wiki/rate-page "$WR" "$(page r note "rate $i")"; [ "$code" = 200 ] || break; done
eq "60 writes in an hour pass" "$code:$i" 200:60
expect "61st write is 429" 429 PUT /v2/wiki/rate-page "$WR" "$(page r note 'rate 61')"
expect "  the same content again is still a no-op" 200 PUT /v2/wiki/rate-page "$WR" "$(page r note 'rate 60')"
expect "  reads are unaffected" 200 GET /v2/wiki/rate-page "$WR"
expect "  another agent is unaffected" 200 PUT /v2/wiki/rate-other "$C" "$(page r note 'x')"
expect "  the limited agent can still delete its page" 200 DELETE /v2/wiki/rate-page "$WR"

# Throwaway bodies fill the rest. The admin is exempt from the rate limit, which keeps this fast.
expect "start from an empty wiki" 200 GET /v2/wiki "$ADMIN"
for s in $(jq -r '.pages[].slug' <<<"$out"); do api DELETE "/v2/wiki/$s?purge=1" "$ADMIN"; done
for s in gone rate-page; do api DELETE "/v2/wiki/$s?purge=1" "$ADMIN"; done
api GET /v2/wiki "$ADMIN"; eq "counters return to zero" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" '[0,0]'; eq "  limits are reported" "$(jq -c '[.quota.max_pages,.quota.max_bytes]' <<<"$out")" '[200,5242880]'
expect "counted page" 200 PUT /v2/wiki/count "$ADMIN" "$(page c note 'خمسة')"; expect "counted update" 200 PUT /v2/wiki/count "$ADMIN" '{"body":"abc"}'
api GET /v2/wiki "$ADMIN"; eq "bytes count both versions" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" "[1,$(($(printf 'خمسة' | wc -c) + 3))]"
expect "delete keeps the bytes for recovery" 200 DELETE /v2/wiki/count "$ADMIN"
api GET /v2/wiki "$ADMIN"; eq "  page count drops, bytes stay" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" "[0,$(($(printf 'خمسة' | wc -c) + 3))]"
expect "purge frees them" 200 DELETE "/v2/wiki/count?purge=1" "$ADMIN"
api GET /v2/wiki "$ADMIN"; eq "  back to zero" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" '[0,0]'

head -c 102400 /dev/zero | tr '\0' q | wbody
qc=''; for i in $(seq 1 60); do api_file PUT "/v2/wiki/fill-$i" "$ADMIN" "$TMP/wiki.json"; qc=$code; [ "$code" = 200 ] || break; done
eq "5MB quota refuses the next write" "$qc" 413; eq "  after 51 pages of 100KB" "$i" 52
api GET /v2/wiki "$A"; eq "  stays within 5MB" "$(jq '.quota.bytes <= 5242880' <<<"$out")" true
expect "  an update that still fits is accepted" 200 PUT /v2/wiki/fill-1 "$A" '{"body":"tiny"}'
head -c 90000 /dev/zero | tr '\0' r | wbody; api_file PUT /v2/wiki/fill-2 "$ADMIN" "$TMP/wiki.json"; eq "  update that would pass 5MB is 413" "$code" 413
expect "  reads still work when full" 200 GET /v2/wiki/fill-1 "$A"
expect "  purge makes room" 200 DELETE "/v2/wiki/fill-3?purge=1" "$ADMIN"
api_file PUT /v2/wiki/fill-2 "$ADMIN" "$TMP/wiki.json"; eq "  and writes resume" "$code" 200
for i in $(seq 1 60); do api DELETE "/v2/wiki/fill-$i?purge=1" "$ADMIN"; done
api GET /v2/wiki "$A"; eq "  counters are exact after all of that" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" '[0,0]'
pc=''; for i in $(seq 1 201); do api PUT "/v2/wiki/p-$i" "$ADMIN" "$(page p note x)"; pc=$code; [ "$code" = 200 ] || break; done
eq "201st page is 413" "$pc:$i" 413:201
expect "  existing pages can still be updated" 200 PUT /v2/wiki/p-1 "$A" '{"body":"y"}'
expect "  deleting frees a page slot" 200 DELETE /v2/wiki/p-200 "$ADMIN"; expect "  so a new page fits" 200 PUT /v2/wiki/p-201 "$A" "$(page p note x)"
expect "revoked agent cannot read the wiki" 200 POST /v2/revoke "$ADMIN" '{"agent":"wikirate"}'; expect "  401" 401 GET /v2/wiki "$WR"

echo "== revoke"
expect "revoke" 200 POST /v2/revoke "$ADMIN" '{"agent":"erin"}'
expect "revoked key is 401" 401 GET /v2/inbox "$E"

echo "== public page"
code=$(curl -sS -D "$TMP/hdr" -o "$TMP/page.html" -w '%{http_code}' "$BASE/"); eq "page serves" "$code" 200
grep -qi "^content-security-policy: default-src 'none'; script-src 'nonce-" "$TMP/hdr" && ok "  strict CSP header" || no "  strict CSP header"
! grep -q '__CSP_NONCE__' "$TMP/page.html" && ok "  nonce is filled in" || no "  nonce is filled in"
! grep -qE 'innerHTML|outerHTML|insertAdjacentHTML|document\.write|\son[a-z]+=' "$ROOT/src/page.html" && ok "  no HTML sinks or inline handlers" || no "  no HTML sinks or inline handlers"
pc=''; for i in $(seq 1 130); do pc=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/"); [ "$pc" = 429 ] && break; done
eq "page flood is 429" "$pc" 429

echo "== page in jsdom against hostile data"
node "$ROOT/test/page-check.mjs" && ok "page script passes" || no "page script passes"

echo "== wiki: deleted history expires (WIKI_AGENT_DAILY_BYTES=10485760 WIKI_TOMBSTONE_MS=1000 in this relay)"
stop_relay; sleep 1
start_relay "$ROOT" wrangler.example.toml "$TMP/state2" "$PORT" "$ADMIN" 1000 WIKI_TOMBSTONE_MS:1000 || exit 1
A2=$(join sweeper); B2=$(join sweep-exec)
expect "page to expire" 200 PUT /v2/wiki/old "$A2" "$(page o note 'expiring body')"; expect "live page" 200 PUT /v2/wiki/keep "$A2" "$(page k note 'keep')"; expect "update it" 200 PUT /v2/wiki/keep "$A2" '{"body":"keep2"}'
expect "delete" 200 DELETE /v2/wiki/old "$A2"; sleep 2
api POST /v2/task-types "$ADMIN" '{"name":"sweep.tick","schema":{"type":"object"},"risk":"low","max_attempts":1}'; acl sweeper sweep-exec task:sweep.tick
api POST /v2/tasks "$A2" '{"type":"sweep.tick","to":"sweep-exec","params":{}}'; ST=$(field .task.id); api POST "/v2/tasks/$ST/claim" "$B2"
eq "an alarm runs" "$(wait_status "$ST" failed)" failed
expect "expired history is removed" 404 GET /v2/wiki/old/history "$A2"
expect "live page keeps its history" 200 GET /v2/wiki/keep/history "$A2"; eq "  one old version" "$(field .total)" 1
api GET /v2/wiki "$A2"; eq "  bytes are released" "$(jq -c '[.quota.pages,.quota.bytes]' <<<"$out")" "[1,$((4 + 5))]"

echo "== page endpoints"
UA=$(join ui-a); UB=$(join ui-b); UC=$(join ui-c); UD=$(join ui-d)
acl ui-a ui-b msg; acl ui-a ui-c msg; acl ui-a ui-b file; acl ui-a __all__ broadcast
api GET /v2/me "$UA"; eq "me names the agent" "$(jq -c '[.agent,.is_admin,.can_broadcast,.can_write_context]' <<<"$out")" '["ui-a",false,true,false]'; eq "  lists who it may message" "$(jq -c .peers <<<"$out")" '["ui-b","ui-c"]'
api POST /v2/revoke "$ADMIN" '{"agent":"ui-c"}'; api GET /v2/me "$UA"; eq "  a revoked peer leaves the list" "$(jq -c .peers <<<"$out")" '["ui-b"]'
api GET /v2/me "$UB"; eq "  no grants means an empty list" "$(jq -c '[.peers,.can_broadcast]' <<<"$out")" '[[],false]'
api GET /v2/me "$ADMIN"; eq "  admin sees active agents and every grant" "$(jq -c '[.agent,.is_admin,(.peers|index("ui-b")!=null),(.peers|index("ui-c")!=null),.can_broadcast,.can_write_context]' <<<"$out")" '["__admin__",true,true,false,true,true]'
expect "no key stops at the Worker" 401 GET /v2/me ''; expect "wrong key is refused" 401 GET /v2/me ark_wrong
expect "unknown route with no key is 401 too" 401 GET /v2/nope ''
api POST /v2/messages "$UA" '{"to":"ui-b","text":"from a to b"}'; SEQ=$(field .msg.seq)
api POST /v2/messages "$UA" '{"to":"__all__","text":"a to everyone"}'
acl ui-b ui-a msg; api POST /v2/messages "$UB" '{"to":"ui-a","text":"from b to a"}'
bodies() { jq -c '[.messages[].body]' <<<"$out"; }
api GET "/v2/inbox?after=$((SEQ - 1))" "$UA"; eq "inbox alone leaves out your own messages" "$(bodies)" '["from b to a"]'
api GET "/v2/inbox?after=$((SEQ - 1))&sent=1" "$UA"; eq "sent=1 adds them, once and in order" "$(bodies)" '["from a to b","a to everyone","from b to a"]'
api GET "/v2/inbox?after=$((SEQ - 1))&sent=1" "$UD"; eq "sent=1 shows no one else's direct messages" "$(bodies)" '["a to everyone"]'
api GET "/v2/inbox?after=999999999&sent=1" "$UA"; eq "a cursor past the end returns nothing" "$(bodies)" '[]'; eq "  and keeps a poll hint" "$(field .suggested_poll_ms)" 5000
expect "a bad cursor reads from the start" 200 GET "/v2/inbox?after=abc" "$UD"; eq "  next_after is a number" "$(jq '.next_after|type' <<<"$out")" '"number"'
api GET "/v2/log?after=$SEQ" "$ADMIN"; eq "log reports where to continue" "$(jq -c '[(.next_after-.messages[-1].seq),.suggested_poll_ms]' <<<"$out")" '[0,5000]'
expect "agents still cannot read the log" 404 GET /v2/log "$UA"
expect "an object as thread_id is not a 500" 200 POST /v2/messages "$UA" '{"to":"ui-b","text":"thread object","thread_id":{"a":1}}'
api GET /v2/agents "$ADMIN"; T1=$(jq '.agents[]|select(.name=="ui-a").last_seen' <<<"$out"); sleep 1; api GET /v2/me "$UA"; api GET /v2/agents "$ADMIN"
eq "last_seen is written at most once a minute" "$(jq '.agents[]|select(.name=="ui-a").last_seen' <<<"$out")" "$T1"

echo "== wiki: if_version"
guard() { jq -cn --arg body "$1" --argjson v "$2" '{title:"g",kind:"note",body:$body,if_version:$v}'; }
expect "if_version 0 creates a new page" 200 PUT /v2/wiki/guard "$UA" "$(guard one 0)"
expect "  and refuses a slug in use" 409 PUT /v2/wiki/guard "$UB" "$(guard two 0)"; eq "    reports the current version" "$(field .current_version)" 1
expect "the right version saves" 200 PUT /v2/wiki/guard "$UA" "$(guard two 1)"; eq "  as version 2" "$(field .version)" 2
expect "a stale version is refused" 409 PUT /v2/wiki/guard "$UB" "$(guard three 1)"
api GET /v2/wiki/guard "$UB"; eq "  the newer text survives" "$(jq -c '[.body,.version,.updated_by]' <<<"$out")" '["two",2,"ui-a"]'
expect "a retry of a save that landed is still fine" 200 PUT /v2/wiki/guard "$UA" "$(guard two 1)"; eq "  unchanged" "$(field .unchanged)" true
expect "no if_version keeps last write wins" 200 PUT /v2/wiki/guard "$UB" '{"body":"four"}'
expect "a non-number version is refused" 409 PUT /v2/wiki/guard "$UB" '{"body":"five","if_version":"3"}'
expect "editing a deleted page is refused" 200 DELETE /v2/wiki/guard "$UB"; expect "  with no current version" 409 PUT /v2/wiki/guard "$UA" "$(guard six 3)"; eq "    null" "$(field .current_version)" null
expect "if_version 0 can reuse a deleted slug" 200 PUT /v2/wiki/guard "$UA" "$(guard seven 0)"

echo "== small fixes"
LONG=$(head -c 197 /dev/zero | tr '\0' a).md
expect "file name over 200 characters is 400" 400 POST /v2/files "$UA" "$(jq -cn --arg n "x$LONG" '{to:"ui-b",name:$n,size:1,sha256:"'"$(printf 'a%.0s' $(seq 1 64))"'"}')"
expect "fractional file size is 413" 413 POST /v2/files "$UA" "$(jq -cn '{to:"ui-b",name:"a.txt",size:1.5,sha256:"'"$(printf 'a%.0s' $(seq 1 64))"'"}')"
api POST /v2/task-types "$ADMIN" '{"name":"ui.echo","schema":{"type":"object"},"risk":"low","max_attempts":2}'; acl ui-a ui-b task:ui.echo
expect "admin key in task params is 422" 422 POST /v2/tasks "$UA" "$(jq -cn --arg k "$ADMIN" '{type:"ui.echo",to:"ui-b",params:{note:$k}}')"
api POST /v2/tasks "$UA" '{"type":"ui.echo","to":"ui-b","params":{"n":1}}'; UT=$(field .task.id)
expect "admin key in a reject reason is 422" 422 POST "/v2/tasks/$UT/reject" "$UB" "$(jq -cn --arg k "$ADMIN" '{reason:$k}')"
api POST "/v2/tasks/$UT/claim" "$UB"; UL=$(field .lease_token)
expect "admin key in a task result is 422" 422 POST "/v2/tasks/$UT/complete" "$UB" "$(jq -cn --arg k "$ADMIN" --arg l "$UL" '{lease_token:$l,result:{x:$k}}')"

echo "== logging"
! grep -q 'Uncaught' "$TMP/wrangler.log" && ok "no uncaught runtime errors" || no "no uncaught runtime errors" "$(grep -m1 'Uncaught' "$TMP/wrangler.log")"
! grep -q 'console\.log' "$ROOT/src/worker.js" && ok "no console.log in the worker" || no "no console.log in the worker"
! grep -q "$CANARY" "$TMP/wrangler.log" && ok "message content absent from runtime logs" || no "message content absent from runtime logs"

summary "smoke"
