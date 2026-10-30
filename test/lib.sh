# Shared helpers for the relay test scripts. Needs bash, curl, jq, sha256sum.
pass=0; fail=0; code=''; out=''
[ -d "$ROOT/node_modules/.bin" ] && PATH="$ROOT/node_modules/.bin:$PATH"
TMP=$(mktemp -d)
WPID=''

ok() { pass=$((pass + 1)); printf '✓ %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '✗ %s\n' "$1"; [ -n "${2:-}" ] && printf '    %s\n' "$2"; return 0; }
eq() { if [ "$2" = "$3" ]; then ok "$1"; else no "$1" "expected [$3] got [$2] body: ${out:0:200}"; fi; }

# Tokens go through a curl config on a file descriptor so they never appear in the process list.
curl_auth() { local t=$1; shift; if [ -n "$t" ]; then curl --config <(printf 'header = "Authorization: Bearer %s"\n' "$t") "$@"; else curl "$@"; fi; }

# api METHOD PATH TOKEN [JSON]: sets $code and $out
api() {
  local args=(-sS -o "$TMP/out" -w '%{http_code}' -X "$1" "$BASE$2")
  [ -n "${4:-}" ] && args+=(-H 'Content-Type: application/json' --data-binary "$4")
  code=$(curl_auth "$3" "${args[@]}"); out=$(cat "$TMP/out")
}
# api_file METHOD PATH TOKEN FILE: same as api, for bodies too long for an argument
api_file() { code=$(curl_auth "$3" -sS -o "$TMP/out" -w '%{http_code}' -X "$1" "$BASE$2" -H 'Content-Type: application/json' --data-binary @"$4"); out=$(cat "$TMP/out"); }
uri() { jq -rn --arg s "$1" '$s|@uri'; }
field() { jq -r "$1" <<<"$out"; }
# expect NAME STATUS METHOD PATH TOKEN [JSON]
expect() { local n=$1 s=$2; shift 2; api "$@"; eq "$n" "$code" "$s"; }

start_relay() { # start_relay DIR CONFIG PERSIST PORT ADMIN [LEASE_MS] [NAME:VALUE ...]
  local dir=$1 cfg=$2 persist=$3 port=$4 admin=$5 lease=${6:-}
  local vars=(--var "ADMIN_KEY:$admin"); [ -n "$lease" ] && vars+=(--var "LEASE_MS:$lease")
  shift $(($# < 6 ? $# : 6)); for v in "$@"; do vars+=(--var "$v"); done
  ( cd "$dir" && exec env -u CLOUDFLARE_API_TOKEN -u CLOUDFLARE_ACCOUNT_ID WRANGLER_SEND_METRICS=false \
      setsid wrangler dev -c "$cfg" --local --port "$port" --persist-to "$persist" "${vars[@]}" ) >>"$TMP/wrangler.log" 2>&1 &
  WPID=$!
  BASE="http://127.0.0.1:$port"
  for _ in $(seq 1 60); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/nope" || true)" = 404 ] && return 0
    sleep 1
  done
  echo "relay did not start. Log:"; tail -20 "$TMP/wrangler.log"; return 1
}
stop_relay() { if [ -n "$WPID" ]; then kill -- "-$WPID" 2>/dev/null; wait "$WPID" 2>/dev/null; WPID=''; fi; return 0; }
summary() { echo; echo "──────────"; echo "$1: $pass passed, $fail failed"; [ "$fail" -eq 0 ]; }
