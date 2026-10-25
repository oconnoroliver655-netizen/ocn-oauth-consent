# OCN Threads social module

This module is integrated into the **existing** Render-hosted OCN MCP server,
`canary/mcp/server.mjs`, at its owner-protected `/mcp-oauth` route. It adds 18
`threads_*` tools and does not create another service or a publicly writeable
MCP endpoint. `/mcp` remains ping-only.

## Authentication and configuration

- All 18 tools first require a successful **OCN owner** OAuth verification from
  the existing signed Supabase validator. The Meta token is a separate access
  token, unrelated to the OCN bearer.
- Configure the secret environment variable `OCN_THREADS_ACCESS_TOKEN` on the
  existing Render service using a Meta-authorized Threads user token. It is not
  set automatically by installing this module and must never be committed.
- `OCN_THREADS_WRITES_ENABLED=true` separately enables publication, reply,
  repost, moderation, and deletion. Default unset/false is read-only.
- Every write also requires `confirm: true`, tied to the exact post text/media
  URL/target ID approved by the owner. For deletion, approve the exact ID.
- No passwords, browser cookies, scraping endpoints, or Meta app secrets are
  needed by this server module. Meta app registration, required permissions,
  review, and issuance/renewal of tokens are independent prerequisites.

Use Meta's [Threads API documentation](https://developers.facebook.com/documentation/threads/)
and [getting-started guide](https://developers.facebook.com/documentation/threads/get-started)
to provision a Threads app and user token. Enabling a new capability does not
imply Meta granted its required permissions. Expect third-party discovery to be
incomplete without advanced permissions or when the target is inaccessible.

## Public share links

`threads_read_shared_url` accepts official `https://threads.com/share/...`
and canonical `https://threads.com/@name/post/...` URLs. It follows redirects
only if they stay within recognized Threads domains, then searches the first
100 discoverable profile posts for a matching shortcode. A failure to find a
match is **not** evidence that the post doesn't exist.

## Verification and operations

Run `node canary/mcp/tests/threads-tools.test.mjs` to verify API and safety
rules, plus `node canary/mcp/tests/threads-registration.test.mjs` for MCP route
and unauthenticated access checks. Existing OCN server tests must also pass.

Deployment sequence: feature branch -> tests -> reviewed merge into the exact
Render-linked branch -> manually trigger deployment (auto-deploy is off) ->
confirm Render live status and `/healthz` -> verify tool listing -> verify
owner OAuth and configuration status -> perform a genuine Meta API read test.
No live publication or destructive social action is part of the smoke test.

Known limits: no automated Meta OAuth callback, token refresh scheduler,
pagination across all results, webhook ingestion, or real-time autonomous
posting is installed by this change. Those require further integration and
credentials; this module makes no claim they are operational.
