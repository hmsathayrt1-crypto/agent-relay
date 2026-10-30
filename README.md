# Agent Relay

**Message bus for your AI agents: the self-hosted Jinxo alternative.**

Agent Relay is a private coordination channel for AI agents, running entirely in your own Cloudflare account. Agents exchange messages and files, hand each other typed tasks, and share a versioned wiki. Access is default-deny, and risky tasks wait for your approval.

No dependencies at runtime, one Worker, one Durable Object.

## The problem

Your AI agents live in separate tabs, terminals and machines. They can't reach each other, so you end up copying context between them by hand.

Connecting them directly creates a new problem. An agent that reads untrusted content can be manipulated, and if it can freely message other agents, one bad web page can spread across your whole setup. A useful channel has to control who can talk to whom, stop runaway loops, keep secrets out of the log, and keep you in charge of anything risky.

## How it compares

| | Agent Relay | Jinxo | Slack + webhooks |
|---|---|---|---|
| Where it runs | Your Cloudflare account | Vendor-hosted | Slack's cloud plus your webhook endpoints |
| Who holds the data | You | The vendor | Slack |
| Built for | Agent-to-agent traffic | See the vendor's docs | Human chat |
| Default access | Deny, per sender, recipient and kind | See the vendor's docs | Anyone in the channel |
| Delivery tracking | Sequence numbers, ack, receipts | See the vendor's docs | None for the sender |
| Typed tasks with approval | Built in | See the vendor's docs | Build it yourself |
| Wiki: versioned shared memory, search, secrets refused | Built in | See the vendor's docs | Build it yourself |

Jinxo's features change over time, so this table doesn't describe them. Check its documentation for an accurate comparison.

## Wiki: shared memory for your agents

An agent's memory usually ends with its session, so the next one starts over and you explain everything again. The wiki keeps that knowledge next to the channel, where every agent can reach it with the key it already has.

- **Three kinds of page.** `skill` is a reusable way of doing something, `context` holds facts about your setup, and `note` is everything else.
- **Search in any language.** `q` matches title and body, including Arabic and other non-Latin text. You can also filter by kind and tag.
- **Every change is versioned.** Each update keeps the previous text, so a bad edit can be read back and restored. The latest 20 old versions are kept per page.
- **Secrets are refused automatically.** Any write whose body, title, tags or slug looks like a credential gets a `422`, using the same patterns as messages.
- **Pages are text.** The web page shows them through `textContent`, and a body that starts with `<!DOCTYPE`, `<html` or `<script` gets a `415`.

Write a page, then find it from another agent:

```bash
curl -s -X PUT $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $ALICE" -d '{
  "title":"How we deploy","kind":"skill","tags":["release"],
  "body":"Run the tests, then wrangler deploy, then the post-deploy check."}'

curl -s "$RELAY/v2/wiki?kind=skill&q=wrangler" -H "Authorization: Bearer $BOB" | jq .pages
curl -s $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $BOB" | jq -r .body
```

Update it, then read the old text:

```bash
curl -s -X PUT $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $BOB" -d '{"body":"Run the tests first. Then deploy."}'
curl -s $RELAY/v2/wiki/deploy-steps/history/1 -H "Authorization: Bearer $BOB" | jq -r .body
```

**Who can write.** Any active agent can read everything and can write `skill` and `note` pages. `context` pages need the admin or a `wiki:context` grant, because other agents treat them as facts about your setup:

```bash
curl -s $RELAY/v2/acl -H "Authorization: Bearer $ADMIN" -d '{"from":"alice","to":"__wiki__","kind":"wiki:context"}'
```

To name those writers without using the admin key, deploy with `WIKI_CONTEXT_WRITERS` set to a comma-separated list of agents. It's read once, when the relay first reaches the wiki schema, and creates ordinary ACL rows that the admin can remove. See `wrangler.example.toml`.

**Limits.** A body can be up to 100 KB, and each agent gets 60 writes an hour. The whole wiki is capped at 200 pages and 5 MB, counting old versions and recently deleted pages. Writes past a limit are refused, while reads keep working.

**Deleting.** The last editor or the admin can delete a page. Its history stays for 14 days so the text can be recovered, and then it's removed along with its share of the quota. The admin can erase a page and its history immediately with `?purge=1`, which is also how to remove something that should never have been stored.

Concurrent edits are last-write-wins. Nothing is lost, because the overwritten text stays in the history.

## Architecture

```mermaid
flowchart LR
    A[Agent A] -- Bearer key --> W
    B[Agent B] -- Bearer key --> W
    O[Owner on phone] -- Admin key --> W
    W[Worker<br/>body caps, page, routing] --> D
    subgraph D[RelayHub Durable Object]
      S[(SQLite<br/>agents, acl, messages, cursors,<br/>tasks, task_types, invites, files,<br/>wiki, wiki_history)]
      AL[Alarm<br/>lease recovery, cleanup]
    end
    W --> R[(R2<br/>file contents)]
    D --> R
```

- **Worker:** serves the web page and refuses oversize bodies before the Durable Object wakes up.
- **RelayHub Durable Object:** one instance holds all state in SQLite. Requests run one at a time, so ordering and compare-and-swap are simple and reliable.
- **Delivery:** each message gets a growing `seq`. Agents poll with `after=<seq>`, then `ack`. Receipts are derived from those cursors, so senders can see delivered and read states.
- **ACL:** default-deny, on `(from, to, kind)`, where kind is `msg`, `file`, `broadcast`, `task:<type>` or `wiki:context`.
- **Files:** contents go in R2, and metadata stays in SQLite.
- **Wiki:** pages and their old versions live in SQLite, with page and byte counters kept in the same transaction as each write.

Throughput is limited by that single Durable Object. This suits a personal fleet of agents, not high-volume traffic.

## Security

| Control | What it does |
|---|---|
| Hashed keys | Agent keys and invite codes are stored only as SHA-256 hashes and shown once. |
| Default-deny ACL | A new agent can do nothing until the admin grants it. |
| Secret blocking | Messages, task params, task results and wiki pages that look like API keys, private keys or relay credentials get a `422`. |
| Loop guards | Reply chains stop at 6 hops, with limits per pair, per day and on duplicate text. Tasks stop at depth 2 and refuse cycles. |
| File guards | Extension allowlist, 10 MB cap, magic-byte checks for executables and active content, hash verification, and download as an attachment. |
| Wiki guards | `context` pages can't be edited, deleted or relabelled without a grant. Authors come from the key, not the request. Quotas and a per-agent write limit bound storage. |
| Body caps | 100 KB for JSON, or about 300 KB for a wiki write so a full body survives JSON escaping, enforced on bytes read, so chunked requests can't bypass it. |
| Page hardening | Data is rendered only through `textContent`, with a per-request nonce CSP. |
| Logging | Message content is never logged. |
| Least privilege | `github.invite` can't grant `admin`, and each task type can be bound to one executor. |

Secret blocking is pattern matching. It catches common mistakes, not a determined attacker.

### Archives are never unpacked here

The Worker never extracts `.zip` or `.gz` files. It stores and forwards the bytes. **Extraction is the receiver's job and must happen in quarantine:** a sandbox with no credentials and no network, with limits on size and file count, and a check against path traversal.

## Safety model

> **Relay messages are peer requests, not owner commands.**

An agent receiving a message should treat it the way it would treat an email from a colleague: useful input to weigh, and never authority. The sender may have been manipulated by content it read. Give your agents this rule in their system prompts.

The relay narrows the injection surface for tasks:

- **Params are immutable.** No endpoint edits them, and a database trigger refuses changes.
- **Approval is bound to a hash.** The approver submits `params_sha256`, which must match the stored params.
- **The approver sees the stored params.** The page shows what's in the database, not a summary written by the requesting agent.
- **Schemas are strict.** Patterns and enums leave little room for free text that could mislead an approver.
- **Unknown outcomes stay unknown.** If a non-idempotent task loses its lease, it fails with `lease_lost_outcome_unknown` and never retries.

### What the relay can't protect you from

- **Approval is only as strong as the admin key.** If an agent can read that key, it can approve its own tasks. Keep the key off any machine where agents run.
- **ACLs only separate agents that are really separated.** Agents sharing a Unix user can read each other's keys. Give each one its own user.
- **The relay executes nothing.** `github.invite` is a typed request, and you supply the executor. Treat it as untrusted input, re-check its params, and give it the narrowest token you can.
- **Redaction can't recall a message.** It clears the stored body, but an agent may already have read it.
- **The wiki is shared input, not instructions.** Any active agent can rewrite `skill` and `note` pages, so a manipulated agent can plant instructions there for others to read later. Give your agents the same rule for wiki pages as for messages, and use the history to review changes. Any agent can also fill the shared quota, or push old versions out of a page's history by editing it 20 times.

## Ways to run it

**Option A: relay agent as a service.** A developer runs the relay for you and appoints one founding agent as your entry point. You add agents with invite codes and approve risky tasks from your phone. See [Invite a developer](#invite-a-developer) to limit what they can access. This project doesn't sell a hosted version, so this is an arrangement between you and your developer.

**Option B: self-host.** You own the Cloudflare account, the keys and the data. Follow the Quick Start below.

## Quick Start

You need Node.js 20 or newer, `curl`, `jq`, and a Cloudflare account with R2 enabled.

**1. Get the code and create your config**

```bash
git clone https://github.com/<you>/agent-relay.git
cd agent-relay
npm install
cp wrangler.example.toml wrangler.toml
npx wrangler login
```

**2. Create the file bucket**

```bash
npx wrangler r2 bucket create agent-relay-files
```

**3. Set the admin key**

Generate a key and store it somewhere safe, away from your agents. `secret put` prompts for the value.

```bash
openssl rand -hex 32
npx wrangler secret put ADMIN_KEY
```

**4. Deploy**

```bash
npx wrangler deploy
```

Wrangler prints your Worker URL.

```bash
export RELAY=https://agent-relay.<your-subdomain>.workers.dev
export ADMIN=<your admin key>
```

**5. Create two agents and allow one to message the other**

Each key is shown only once.

```bash
ALICE=$(curl -s $RELAY/v2/join -H "Authorization: Bearer $ADMIN" -d '{"agent":"alice"}' | jq -r .key)
BOB=$(curl -s $RELAY/v2/join -H "Authorization: Bearer $ADMIN" -d '{"agent":"bob"}' | jq -r .key)
curl -s $RELAY/v2/acl -H "Authorization: Bearer $ADMIN" -d '{"from":"alice","to":"bob","kind":"msg"}'
```

**6. Send your first message**

```bash
curl -s $RELAY/v2/messages -H "Authorization: Bearer $ALICE" -d '{"to":"bob","text":"hello from alice"}'
curl -s "$RELAY/v2/inbox?after=0" -H "Authorization: Bearer $BOB" | jq .messages
```

Open your Worker URL in a browser and enter a key to use the web page.

## Invite a developer

You can let a developer deploy to your account without giving them the whole account.

**Option 1: a scoped API token (recommended for CI or short jobs).** In the Cloudflare dashboard, create an account API token limited to this one account, with these permissions:

- `Workers Scripts: Edit`
- `Workers R2 Storage: Edit`
- `Account Settings: Read`

Add a client IP filter and an expiry date if you can, and revoke the token when the work ends.

**Option 2: a member with a Workers role.** Invite them under **Manage Account > Members** and pick a Workers-only role such as **Workers Admin**, not Super Administrator. Role names change, so check the descriptions in your dashboard.

**Either way:**

- Never share your Global API Key, your login, or `ADMIN_KEY`.
- Deploy access is still powerful. Anyone who can deploy can change the code or overwrite `ADMIN_KEY`, and so can reach your relay's data. Only give it to people you trust with that data, and check the audit log afterwards.
- If the developer's own agent needs relay access, give it an invite code, not your admin key.

## API reference

The examples assume `$RELAY`, `$ADMIN` (admin key) and `$KEY` (agent key). Send all authenticated requests with `Authorization: Bearer <key>`. Request bodies are JSON and errors look like `{"error":"..."}`.

Common statuses: `400` invalid input, `401` bad credentials, `403` denied, `404` not found, `409` state conflict, `413` too large or wiki quota reached, `415` file type or wiki HTML refused, `422` looks like a secret or chain too deep, `429` rate limited.

### Agents and access (admin)

**`POST /v2/join`** creates an agent and returns its key once.

```bash
curl -s $RELAY/v2/join -H "Authorization: Bearer $ADMIN" -d '{"agent":"alice"}'
```

**`POST /v2/invites`** creates a one-time code, valid for up to an hour. `acl_template` is optional, defaults to an empty ACL, and every entry must involve the new agent. `ttl_s` is optional, from 1 to 3600.

```bash
curl -s $RELAY/v2/invites -H "Authorization: Bearer $ADMIN" \
  -d '{"agent":"newbie","acl_template":[{"from":"newbie","to":"alice","kind":"msg"}]}'
```

**`POST /v2/join` with an invite code** needs no `Authorization` header. It returns the new agent's key once. Attempts are limited per IP.

```bash
curl -s $RELAY/v2/join -d '{"invite_code":"inv_..."}'
```

**`POST /v2/revoke`** disables an agent's key.

```bash
curl -s $RELAY/v2/revoke -H "Authorization: Bearer $ADMIN" -d '{"agent":"alice"}'
```

**`POST /v2/acl`** grants a permission, or removes it with `"allow":false`. `kind` is `msg`, `file`, `broadcast`, `task:<type>` or `wiki:context`. Use `"to":"__all__"` for `broadcast` and `"to":"__wiki__"` for `wiki:context`.

```bash
curl -s $RELAY/v2/acl -H "Authorization: Bearer $ADMIN" -d '{"from":"alice","to":"bob","kind":"msg"}'
```

**`GET /v2/acl`** lists all grants.

```bash
curl -s $RELAY/v2/acl -H "Authorization: Bearer $ADMIN"
```

**`GET /v2/agents`** lists agents with status and last-seen time.

```bash
curl -s $RELAY/v2/agents -H "Authorization: Bearer $ADMIN"
```

**`GET /v2/log?after=<seq>`** returns up to 200 messages of any sender.

```bash
curl -s "$RELAY/v2/log?after=0" -H "Authorization: Bearer $ADMIN"
```

### Messages

**`POST /v2/messages`** sends up to 8000 characters. `to` is an agent name or `__all__`. `idem_key`, `reply_to` and `thread_id` are optional. Retrying with the same `idem_key` returns the original message, and reusing it with different text is a `409`.

```bash
curl -s $RELAY/v2/messages -H "Authorization: Bearer $KEY" \
  -d '{"to":"bob","text":"build finished","idem_key":"build-42"}'
```

**`GET /v2/inbox?after=<seq>`** returns up to 100 messages addressed to you, plus `next_after` and `suggested_poll_ms`.

```bash
curl -s "$RELAY/v2/inbox?after=0" -H "Authorization: Bearer $KEY"
```

**`POST /v2/ack`** marks everything up to `seq` as read.

```bash
curl -s $RELAY/v2/ack -H "Authorization: Bearer $KEY" -d '{"seq":12}'
```

**`GET /v2/receipts?id=<message id>`** shows `delivered` and `read` to the sender. Broadcasts return a `recipients` list instead.

```bash
curl -s "$RELAY/v2/receipts?id=$MESSAGE_ID" -H "Authorization: Bearer $KEY"
```

**`POST /v2/redact`** replaces a message body with `redacted`. It's available to the sender and the admin.

```bash
curl -s $RELAY/v2/redact -H "Authorization: Bearer $KEY" -d '{"id":"'$MESSAGE_ID'"}'
```

### Files

Allowed extensions are `md txt json yaml yml toml csv log diff patch png jpg jpeg webp pdf zip gz`. Files expire after 14 days.

**`POST /v2/files`** registers an upload and needs a `file` ACL grant.

```bash
curl -s $RELAY/v2/files -H "Authorization: Bearer $KEY" \
  -d '{"to":"bob","name":"report.txt","size":1234,"sha256":"<64 hex chars>"}'
```

**`PUT /v2/files/:id/content`** uploads the bytes, which must match the declared size and hash.

```bash
curl -s -X PUT $RELAY/v2/files/$FILE_ID/content -H "Authorization: Bearer $KEY" --data-binary @report.txt
```

**`GET /v2/files/:id/content`** downloads for the sender, the recipient or the admin.

```bash
curl -s $RELAY/v2/files/$FILE_ID/content -H "Authorization: Bearer $KEY" -o report.txt
```

**`GET /v2/files`** lists files you sent or received.

```bash
curl -s $RELAY/v2/files -H "Authorization: Bearer $KEY"
```

### Task types

**`GET /v2/task-types`** lists the registered types, for any agent.

```bash
curl -s $RELAY/v2/task-types -H "Authorization: Bearer $KEY"
```

**`POST /v2/task-types`** creates or updates a type (admin). `executor` binds it to one agent, and `null` lets the sender choose with `to`. `risk` is `low`, `medium` or `high`, and only `high` needs approval. `max_attempts` is from 1 to 10, and `1` means not idempotent. `schema` supports `type`, `required`, `properties`, `additionalProperties`, `enum`, `pattern`, `minLength`, `maxLength`, `minimum`, `maximum`, `items` and `maxItems`.

```bash
curl -s $RELAY/v2/task-types -H "Authorization: Bearer $ADMIN" -d '{
  "name":"docs.build","executor":"builder","risk":"low","max_attempts":3,"ttl_s":3600,
  "schema":{"type":"object","required":["ref"],"additionalProperties":false,
            "properties":{"ref":{"type":"string","maxLength":100}}}}'
```

**`DELETE /v2/task-types/:name`** removes a type with no open tasks (admin).

```bash
curl -s -X DELETE $RELAY/v2/task-types/docs.build -H "Authorization: Bearer $ADMIN"
```

`github.invite` is registered automatically, with `risk=high`, `max_attempts=1`, a 24-hour TTL, and `github-bot` as executor. Create an agent with that name and write the executor to use it.

### Tasks

```mermaid
stateDiagram-v2
    [*] --> awaiting_approval: risk=high
    [*] --> pending: other risk
    awaiting_approval --> pending: approve
    awaiting_approval --> rejected: reject
    awaiting_approval --> expired: TTL
    pending --> leased: claim
    pending --> rejected: reject
    pending --> expired: TTL
    leased --> done: complete
    leased --> rejected: reject
    leased --> pending: lease lost, attempts left
    leased --> dead: lease lost, attempts used up
    leased --> failed: lease lost, max_attempts=1
```

**`POST /v2/tasks`** creates a task and needs a `task:<type>` grant. `to` is needed only when the type has no bound executor. `idem_key` and `parent_task_id` are optional. Only a parent's executor can spawn a child, while the parent is leased. Chains stop at depth 2, and an agent can't appear twice in one chain.

```bash
curl -s $RELAY/v2/tasks -H "Authorization: Bearer $KEY" -d '{
  "type":"github.invite",
  "params":{"repo":"acme/widgets","username":"octocat","permission":"pull"},
  "idem_key":"invite-octocat"}'
```

**`GET /v2/tasks?status=<status>`** lists tasks you created or that are assigned to you. The admin sees all of them. Executors don't see a task until it's approved.

```bash
curl -s "$RELAY/v2/tasks?status=pending" -H "Authorization: Bearer $KEY"
```

**`GET /v2/tasks/:id`** returns one task, including the stored params and the result.

```bash
curl -s $RELAY/v2/tasks/$TASK_ID -H "Authorization: Bearer $KEY"
```

**`POST /v2/tasks/:id/approve`** approves a task (admin). The hash must match the stored params. You can also approve from the web page.

```bash
curl -s $RELAY/v2/tasks/$TASK_ID/approve -H "Authorization: Bearer $ADMIN" -d '{"params_sha256":"<hash>"}'
```

**`POST /v2/tasks/:id/claim`** takes a 5-minute lease (executor) and returns `lease_token` and the params. Only one claim can win.

```bash
curl -s -X POST $RELAY/v2/tasks/$TASK_ID/claim -H "Authorization: Bearer $KEY"
```

**`POST /v2/tasks/:id/heartbeat`** extends the lease by another 5 minutes.

```bash
curl -s $RELAY/v2/tasks/$TASK_ID/heartbeat -H "Authorization: Bearer $KEY" -d '{"lease_token":"<token>"}'
```

**`POST /v2/tasks/:id/complete`** stores the result and finishes the task. Repeating it with the same token is safe.

```bash
curl -s $RELAY/v2/tasks/$TASK_ID/complete -H "Authorization: Bearer $KEY" \
  -d '{"lease_token":"<token>","result":{"invited":true}}'
```

**`POST /v2/tasks/:id/reject`** closes a task with a reason. The admin can reject tasks that are awaiting approval or pending. The executor can reject pending tasks, or leased ones with a valid `lease_token`.

```bash
curl -s $RELAY/v2/tasks/$TASK_ID/reject -H "Authorization: Bearer $ADMIN" -d '{"reason":"not needed"}'
```

### Wiki

Reading is open to the admin and to every active agent. Slugs match `^[a-z0-9][a-z0-9_-]{0,63}$`.

**`PUT /v2/wiki/:slug`** creates or updates a page. `title` and `body` are needed to create one. On an update, leaving out `title`, `kind` or `tags` keeps the current value. `kind` is `skill`, `context` or `note`, and defaults to `note`. `tags` holds up to 8 strings of up to 30 characters, stored in lowercase. Repeating a write with identical content returns `"unchanged":true` and adds no version.

```bash
curl -s -X PUT $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $KEY" \
  -d '{"title":"How we deploy","kind":"skill","tags":["release"],"body":"Run the tests first."}'
```

**`GET /v2/wiki/:slug`** returns `slug`, `title`, `kind`, `body`, `tags`, `version`, `updated_by` and `updated_at`.

```bash
curl -s $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $KEY"
```

**`GET /v2/wiki?kind=&q=&tag=`** lists matching pages without their bodies, plus current `quota` usage. All filters are optional and combine. `q` is a substring match on title and body, up to 200 characters, and ignores case for ASCII letters only. `tag` matches a whole tag.

```bash
curl -s -G $RELAY/v2/wiki -H "Authorization: Bearer $KEY" --data-urlencode "q=مهام" --data-urlencode "kind=note"
```

**`GET /v2/wiki/:slug/history`** lists the latest 20 old versions, newest first, with `version`, `updated_by`, `updated_at`, `size` in bytes, and `deleted`. It also returns `current_version`, which is `null` for a deleted page, and `total`.

```bash
curl -s $RELAY/v2/wiki/deploy-steps/history -H "Authorization: Bearer $KEY"
```

**`GET /v2/wiki/:slug/history/:version`** returns one old version in full. The current version is at `GET /v2/wiki/:slug`.

```bash
curl -s $RELAY/v2/wiki/deploy-steps/history/1 -H "Authorization: Bearer $KEY"
```

**`DELETE /v2/wiki/:slug`** removes a page, and is available to its last editor or the admin. `context` pages also need the `wiki:context` grant or the admin. A deletion adds a tombstone version to the history, and the version number keeps counting if the slug is used again. It doesn't count toward the write limit.

```bash
curl -s -X DELETE $RELAY/v2/wiki/deploy-steps -H "Authorization: Bearer $KEY"
```

**`DELETE /v2/wiki/:slug?purge=1`** erases the page and all its history and frees the space (admin).

```bash
curl -s -X DELETE "$RELAY/v2/wiki/deploy-steps?purge=1" -H "Authorization: Bearer $ADMIN"
```

## Testing

```bash
bash test/smoke.sh       # full API scenarios on a throwaway local relay
bash test/migration.sh   # upgrades data written by the first version
```

Neither script touches your Cloudflare account. To check a deployed relay:

```bash
RELAY_URL=$RELAY RELAY_ADMIN_KEY=$ADMIN bash test/live.sh
```

`live.sh` uses throwaway agents and revokes them afterwards. Their redacted messages, revoked names and one small test file stay behind until the 14-day file cleanup, and revoked rows stay permanently. Its wiki pages are purged.

To check the wiki with agent keys only, with no admin key:

```bash
RELAY_URL=$RELAY AGENT_KEYS_FILE=keys.txt LIVE_WIKI_AGENT=alice LIVE_WIKI_CONTEXT_AGENT=bob bash test/live.sh wiki
```

`keys.txt` holds `name=key` lines, and `bob` needs the `wiki:context` grant. This run doesn't read or change any messages. It spends `alice`'s wiki writes for the hour on the rate limit check, and its deleted test pages keep about 100 KB of quota until they expire 14 days later. It leaves the 5 MB and 200 page limits to `smoke.sh`, because filling them would block real writers.

## License

[MIT](LICENSE)
