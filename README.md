# OCN OAuth Consent — public static frontend

**Published URL:** https://oconnoroliver655-netizen.github.io/ocn-oauth-consent/

**Consent page:** https://oconnoroliver655-netizen.github.io/ocn-oauth-consent/oauth/consent/

**State (2026-10-13):** GitHub Pages frontend and public owner/client/callback pins are configured and matched to the active Supabase Auth OAuth client. The private Render MCP auth probe now checks a separate Supabase owner-session validator; however, the resource-audience hook binding remains **disabled**, the Supabase Dashboard Custom Access Token Hook is not yet confirmed configured, and real OAuth positive E2E is not complete. Windows file/desktop tools are **not** available through this frontend.

This repository contains only public static files: HTML, CSS, vanilla JS, and a **publishable** Supabase browser key. It contains **no** Windows controller source, administrator interface, database credentials, service-role key, Runtime API Key or passwords.

## Identity and control boundaries

Supabase Auth is the OAuth 2.1 authorization server. This website only presents the owner's email sign-in and OAuth consent UI.

The site **fails closed** until `assets/config.mjs` contains an owner-reviewed `ownerUserId`, `approvedOAuthClientId` and `approvedRedirectUri`. The owner ID, manually registered PUBLIC OAuth client ID and exact ChatGPT callback are pinned and have been checked against Supabase Auth. The resource hook activation and live user login test remain pending. The displayed client/owner and redirect must match the data supplied by Supabase Auth. The OAuth SDK's default browser redirect is disabled; the returned callback is checked before navigation.

Even after real OAuth consent succeeds, it **does not** grant Windows administrator, file, terminal or GUI control. Those remain behind a separate private, owner-bound MCP resource server and local Windows consent policies.

### Activation prerequisites

1. **Completed:** Project owner's Supabase Auth user exists, email is confirmed, and the public frontend has pinned that owner's UUID. Owner UUID is an identifier, not a credential; server-side OAuth validation remains mandatory.
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

## Same-browser OTP rollout (2026-11-05)

The consent UI now verifies an **email code in the same browser tab**, avoiding a Gmail → other browser → ChatGPT app hop during Supabase sign-in. This does not change the pinned owner, registered callback, OAuth scopes or Windows security boundary.

**DEPLOYMENT GATE:** Supabase `signInWithOtp` sends Magic Links by default. Before merging the UI into GitHub Pages, open the **Supabase Dashboard → Authentication → Email Templates → Magic Link** template and replace the existing one-click link with a numeric code. Do not include `{{ .ConfirmationURL }}`.

```html
<h2>OCN owner sign-in code</h2>
<p>Enter this one-time code into the OCN authorization page:</p>
<p><strong>{{ .Token }}</strong></p>
<p>If you did not request this code, ignore this email.</p>
```

The UI calls `verifyOtp({ email, token, type: "email" })`, accepts 6–8 digits, verifies the owner UUID from a fresh `getUser()`, and resumes the original `authorization_id`. Email sends are restricted to one per page and code checks to three attempts per page. Never record an OTP, Magic Link, OAuth code or token in a repo or diagnostic log.

**Acceptance before release:** check the project email template actually delivers numeric codes without an actionable one-click link; run `node --check assets/consent.mjs && node --check assets/guards.mjs && node --test tests/policy.test.mjs`; validate wrong-code, wrong-owner, missing-code and duplicate-state rejection; then perform one authorized real login in a single browser context and independently verify ChatGPT reports Connected and the OAuth code was exchanged. A server-side `owner_verified=true` probe alone is not proof of ChatGPT's new grant.

Missing or malformed OAuth callbacks now fail closed instead of silently redirecting. Mobile browser-to-app token-state handoff problems can still occur after a valid callback; they require a separate ChatGPT client session check.
