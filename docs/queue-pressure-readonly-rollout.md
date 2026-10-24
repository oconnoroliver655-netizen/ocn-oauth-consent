# OCN owner OAuth queue-pressure endpoint — staged, NOT deployed

**Change:** Add a read-only, metadata-only `queue_pressure_status` tool to the existing Render MCP server and Supabase Edge function. This is a diagnostic/advisory tool; it **does not currently throttle or reject any normal Windows submissions**.

## Source of truth and preflight (2026-10-25)
- Render service `ocn-mcp-ping-canary` (service ID `srv-db685vqd0e5s739oppbg`) is pinned to `feature/render-mcp-ping-canary-20261012` and has `autoDeploy=no`; deployed commit was `3f8d98fdd8f001aba182cb93076019dc1b5a9fbc` when inspected. Live `canary/mcp/server.mjs` matched the branch source exactly.
- Supabase project `ouxniljtjxnrkwakkvbv`, Edge `ocn-owner-health-dispatch` version **6** on inspection; its source exactly matched the repository branch version.
- User identity and queue authority remain enforced by the existing signed owner OAuth validator; client never sees a Supabase service key.

## Design
1. Edge action requires existing owner bearer authentication **before request processing**. Input is strictly `{"action":"queue_pressure_status"}` — no arbitrary table, host, owner, device, SQL or URL arguments.
2. Supabase PostgREST reads up to **2001** active command *metadata* rows (status and timestamps) and at most one device-agent state row. If over 2000 active rows, `active_queue_complete=false` and optional diagnostic admission is **denied**.
3. Pure evaluator derives queued/claimed/running counts, max queue/claim age, near-expiry, agent heartbeat age, claim flag, lane-busy and clock skew. No payload, request body, stdout, credential or command nonce enters telemetry.
4. Render tool uses the existing `/mcp-oauth` challenge and the same Edge owner validation. It **allowlists every result field**. It never writes to Supabase or invokes Windows.
5. Heartbeat/receipt/owner recovery are never blocked. Existing `submit_windows_operation`, `submit_routed_windows_operation`, `submit_admin_powershell` and `poll_windows_operation` are unchanged.

## Validation and deployment gates
- Run `node --test tests/queue-pressure-edge.test.mjs` and existing MCP/OAuth tests; run `node --check canary/mcp/server.mjs`.
- Confirm Edge code compiles with its relative MJS module and exact imported paths.
- Confirm live deployed Render/Edge versions still match the recorded known-good base.
- Deploy **Supabase Edge first**, preserving `verify_jwt=false` because this function performs its own signed owner OAuth check; smoke-test existing owner health, submit/poll unchanged. Only then trigger the existing Render service deployment if GitHub CI passes.
- Verify new read-only MCP tool: signed owner sees bounded summary; no bearer is rejected; call does not create `local_control_commands` rows.
- Compare unchanged old submit/poll behavior, queue depth, and heartbeat freshness; rollback Edge version 6 and Render commit `3f8d98fdd8f001aba182cb93076019dc1b5a9fbc` immediately if regression.
- Do not enable any enforcement, duplicate cancellation, new workers or task expiry logic under this PR.

## Known limitations
This is an **advisory-only** endpoint. It cannot reduce actual command execution latency until a separately reviewed producer admission policy is introduced. State from the Supabase Agent may temporarily omit `claims_enabled` during completion; unknown readiness intentionally fails closed for *nonessential* submissions.

Related engineering tracker: `oconnoroliver655-netizen/chatgpt-local-bridge#533`.
