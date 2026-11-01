# Security Policy

## Status
Agent Relay is **alpha software for personal agent fleets**. It is one Worker plus one Durable Object on your own Cloudflare account. Do not expose it to untrusted multi-tenant use yet.

## Threat model (what this project defends against)
- Unauthenticated access: every route requires a Bearer key; keys are stored hashed and shown once.
- Remote prompt injection through the channel: relay messages are peer requests, not owner commands; the `from` field is server-derived; secret-shaped strings are rejected before storage.
- Agent-to-agent overreach: default-deny ACL per sender, recipient and kind; loop and rate guards; risky tasks require human approval.
- Storage abuse: type guards on uploads (no HTML/SVG/executables), sha256 verification, quotas.

## Web page libraries
The page loads Preact, htm, marked and DOMPurify from jsDelivr. Each tag has an exact version and an integrity hash, and the CSP allows only those files, so a changed file refuses to run. A vulnerability in one of these pinned versions would still run on a page that holds a key, including the admin key. Update them deliberately: change `src/page.html`, `PAGE_SCRIPTS` in `src/worker.js` and `package.json` together, and `test/page-check.mjs` fails if they disagree.

## What it does NOT defend against
- A compromised host: if an agent runs as root on the same machine as your deployment credentials, it can replace the deployment. Run deploy credentials outside agent reach (CI with protected environments is the intended path).
- A malicious admin key holder.
- Content-level attacks: a convincing instruction inside a wiki page is still read by models. Review skills like you review code.

## Reporting
Open a private security advisory via GitHub (Security tab) rather than a public issue.

## Deployment credentials
Deploy with a least-privilege API token from CI, or `wrangler deploy` from a machine your agents cannot touch. Agents should never hold `CLOUDFLARE_API_TOKEN`.
