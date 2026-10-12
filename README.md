# OCN OAuth Consent — public static frontend

**Published URL:** https://oconnoroliver655-netizen.github.io/ocn-oauth-consent/

**Consent page:** https://oconnoroliver655-netizen.github.io/ocn-oauth-consent/oauth/consent/

**State:** GitHub Pages deployed; real OAuth sign-in is deliberately **inactive** until an owner account, registered OAuth app, exact callback and protected resource are verified.

This repository contains only public static files: HTML, CSS, vanilla JS, and a **publishable** Supabase browser key. It contains **no** Windows controller source, administrator interface, database credentials, service-role key, Runtime API Key or passwords.

## Identity and control boundaries

Supabase Auth is the OAuth 2.1 authorization server. This website only presents the owner's email sign-in and OAuth consent UI.

The site **fails closed** until `assets/config.mjs` contains an owner-reviewed `ownerUserId`, `approvedOAuthClientId` and `approvedRedirectUri`. The displayed client/owner and redirect must match the data supplied by Supabase Auth. The OAuth SDK's default browser redirect is disabled; the returned callback is checked before navigation.

Even after real OAuth consent succeeds, it **does not** grant Windows administrator, file, terminal or GUI control. Those remain behind a separate private, owner-bound MCP resource server and local Windows consent policies.

### Activation prerequisites

1. Create and verify the project owner's Supabase Auth user using the project's official Dashboard (not by inserting directly into `auth.users`). There were no Auth users when this website was first published.
2. Deploy and verify the independent, **authenticated** MCP resource server and its HTTPS resource metadata. Test live owner, client, device, audience, revocation and expired-token handling.
3. Register the actual OAuth client with its exact legitimate callback URI. Do not invent a ChatGPT redirect URI or enable arbitrary dynamic OAuth clients merely to make a test pass.
4. Add the exact website login redirect to Supabase Auth URL Configuration. Set the Site URL to the HTTPS GitHub Pages origin/path, and the Authorization Path to `/oauth/consent`, only after the owner identity and OAuth client setup have been verified.
5. Fill in the remaining **public** configuration and run the end-to-end sign-in, consent, denial and revocation tests.
6. Route machine commands only through a server-side verified owner, device and tool-scope policy. Keep the separate existing diagnostic/Ping tunnels unchanged.

## CI

`.github/workflows/validate.yml` checks syntax, authorizations, identity/callback restrictions and absence of embedded privileged credentials. Run locally with:

```bash
node --check assets/guards.mjs
node --check assets/consent.mjs
node --test tests/policy.test.mjs
```

Production operations must not rely on public JavaScript checks as an authentication or authorization boundary.
