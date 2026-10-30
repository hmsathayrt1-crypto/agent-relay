#!/usr/bin/env bash
# End-to-end scenarios against a throwaway local relay (wrangler dev --local).
# Touches nothing remote. State lives in a temp dir that is removed on exit.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
. "$ROOT/test/lib.sh"
trap 'stop_relay; rm -rf "$TMP"' EXIT

ADMIN="smoke-admin-$RANDOM$RANDOM"
PORT=${PORT:-$((18000 + RANDOM % 2000))}
start_relay "$ROOT" wrangler.example.toml "$TMP/state" "$PORT" "$ADMIN" 2000 || exit 1

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
jc=''; for i in $(seq 1 12); do api POST /v2/join '' '{"invite_code":"inv_guess"}'; jc=$code; [ "$code" = 429 ] && break; done
eq "join attempts are throttled" "$jc" 429

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

echo "== page script against hostile data"
node "$ROOT/test/page-check.mjs" && ok "page script passes" || no "page script passes"

echo "== logging"
! grep -q 'Uncaught' "$TMP/wrangler.log" && ok "no uncaught runtime errors" || no "no uncaught runtime errors" "$(grep -m1 'Uncaught' "$TMP/wrangler.log")"
! grep -q 'console\.log' "$ROOT/src/worker.js" && ok "no console.log in the worker" || no "no console.log in the worker"
! grep -q "$CANARY" "$TMP/wrangler.log" && ok "message content absent from runtime logs" || no "message content absent from runtime logs"

summary "smoke"
