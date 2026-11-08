-- ISOLATED CI DATABASE FIXTURE. NOT A PRODUCTION MIGRATION.
-- Recreates only the relevant shapes of auth + OCN tables in disposable PostgreSQL.
-- No production account IDs, database credentials, client secrets or Windows tools.
\set ON_ERROR_STOP on
BEGIN;
CREATE ROLE service_role NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;
CREATE SCHEMA auth;
CREATE SCHEMA ocn_private;

CREATE TABLE auth.oauth_clients (
  id uuid PRIMARY KEY,
  deleted_at timestamptz
);
CREATE TABLE auth.sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  oauth_client_id uuid,
  not_after timestamptz
);
CREATE TABLE auth.oauth_consents (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  client_id uuid NOT NULL,
  revoked_at timestamptz,
  scopes text NOT NULL,
  UNIQUE (user_id, client_id)
);

-- Production-shaped legacy singleton and RPC/hook, reproduced ONLY in CI.
-- Live Supabase still has binding_id=1, UNIQUE text client_id, no v2 map.
CREATE TABLE ocn_private.oauth_resource_binding (
  binding_id smallint PRIMARY KEY CHECK (binding_id = 1),
  client_id text NOT NULL UNIQUE CHECK (length(client_id) BETWEEN 1 AND 200),
  resource_audience text NOT NULL CHECK (
    length(resource_audience) BETWEEN 9 AND 250
    AND resource_audience ~ '^https://[^/?#]+[^?#]*$'
  ),
  enabled boolean NOT NULL DEFAULT false
);
INSERT INTO ocn_private.oauth_resource_binding
  (binding_id, client_id, resource_audience, enabled) VALUES
  (1, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
   'https://ocn-mcp-ping-canary.onrender.com', true);

-- Exact material behavior of the existing three-argument production RPC.
CREATE FUNCTION public.ocn_owner_oauth_session_active(
  p_owner uuid, p_session uuid, p_client uuid
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
AS $legacy$
SELECT EXISTS (
  SELECT 1 FROM auth.sessions s
  JOIN auth.oauth_consents c ON c.user_id=s.user_id AND c.client_id=s.oauth_client_id
  JOIN auth.oauth_clients app ON app.id=c.client_id
  JOIN ocn_private.oauth_resource_binding b
    ON b.binding_id=1 AND b.client_id=c.client_id::text
  WHERE s.user_id=p_owner AND s.id=p_session AND s.oauth_client_id=p_client
    AND app.deleted_at IS NULL AND c.revoked_at IS NULL
    AND (s.not_after IS NULL OR s.not_after > now()) AND b.enabled IS TRUE
);
$legacy$;
REVOKE ALL ON FUNCTION public.ocn_owner_oauth_session_active(uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ocn_owner_oauth_session_active(uuid,uuid,uuid) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ocn_owner_oauth_session_active(uuid,uuid,uuid) TO service_role;

-- Production's current audience hook only changes the OLD pinned client's aud.
CREATE FUNCTION ocn_private.set_ocn_access_token_audience(event jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path = ''
AS $hook$
DECLARE claims jsonb; pinned_client text; pinned_resource text;
BEGIN
  claims := event -> 'claims';
  IF claims IS NULL OR pg_catalog.jsonb_typeof(claims) <> 'object'
    THEN RAISE EXCEPTION 'Invalid claims'; END IF;
  SELECT client_id,resource_audience INTO pinned_client,pinned_resource
    FROM ocn_private.oauth_resource_binding WHERE binding_id=1 AND enabled IS TRUE;
  IF pinned_client IS NOT NULL AND claims->>'client_id'=pinned_client
    THEN claims := pg_catalog.jsonb_set(
      claims,'{aud}',pg_catalog.to_jsonb(pinned_resource),true);
  END IF;
  RETURN pg_catalog.jsonb_build_object('claims',claims);
END;
$hook$;

-- A V2 resource map that permits old and new resource entries to coexist.
-- Current production oauth_resource_binding is intentionally a singleton
-- (binding_id CHECK = 1, PK binding_id); DO NOT replace it in production.
CREATE TABLE ocn_private.oauth_resource_bindings_v2 (
  client_id uuid NOT NULL,
  resource_audience text NOT NULL CHECK (
    length(resource_audience) BETWEEN 9 AND 250
    AND resource_audience ~ '^https://[^/?#]+[^?#]*$'
  ),
  enabled boolean NOT NULL DEFAULT false,
  PRIMARY KEY (client_id, resource_audience)
);
-- OAuth JWT issuance derives audience from verified client_id alone.
-- Permit multiple mapped resources per client over time, but only ONE enabled.
CREATE UNIQUE INDEX oauth_review_one_enabled_resource_per_client
  ON ocn_private.oauth_resource_bindings_v2(client_id) WHERE enabled;

-- Proposed future RPC, in review CI ONLY. Definer needs access to auth tables.
-- Name is intentionally different from existing production RPC.
-- Service-role-only grant is mandatory: no PUBLIC/anon/authenticated execution.
CREATE FUNCTION public.ocn_owner_oauth_resource_session_active(
  p_owner uuid, p_session uuid, p_client uuid, p_resource text
) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = ''
AS $$
SELECT EXISTS (
  SELECT 1
  FROM auth.sessions s
  JOIN auth.oauth_consents c
    ON c.user_id = s.user_id AND c.client_id = s.oauth_client_id
  JOIN auth.oauth_clients app ON app.id = c.client_id
  JOIN ocn_private.oauth_resource_bindings_v2 b
    ON b.client_id = c.client_id
   AND b.resource_audience = p_resource
   AND b.enabled IS TRUE
  WHERE s.user_id = p_owner
    AND s.id = p_session
    AND s.oauth_client_id = p_client
    AND app.deleted_at IS NULL
    AND c.revoked_at IS NULL
    -- OAuth access JWTs do not promise a scope claim. Enforce the specific
    -- private-tool scopes using the trusted, server-side consent record.
    AND pg_catalog.regexp_split_to_array(pg_catalog.btrim(c.scopes),
      '[[:space:]]+') @> ARRAY['openid', 'email']::text[]
    AND (s.not_after IS NULL OR s.not_after > now())
    AND p_resource IS NOT NULL
    AND length(p_resource) BETWEEN 9 AND 250
);
$$;
REVOKE ALL ON FUNCTION public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text) FROM anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text) TO service_role;

INSERT INTO auth.oauth_clients(id) VALUES
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc');
INSERT INTO auth.sessions(id,user_id,oauth_client_id,not_after) VALUES
  ('dddddddd-dddd-4ddd-8ddd-dddddddddddd','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',now()+interval '1 hour'),
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','cccccccc-cccc-4ccc-8ccc-cccccccccccc',now()+interval '1 hour');
INSERT INTO auth.oauth_consents(id,user_id,client_id,scopes) VALUES
  ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','openid email'),
  ('22222222-2222-4222-8222-222222222222','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','cccccccc-cccc-4ccc-8ccc-cccccccccccc','openid email');
INSERT INTO ocn_private.oauth_resource_bindings_v2(client_id,resource_audience,enabled) VALUES
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','https://ocn-mcp-ping-canary.onrender.com',true),
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc','https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review',true);

-- REVIEW-ONLY candidate audience hook. This is NOT installed in live Auth.
-- Simulates a future controlled hook migration while preserving the old singleton.
CREATE FUNCTION ocn_private.set_ocn_access_token_audience_review_v2(event jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path = ''
AS $hook2$
DECLARE claims jsonb; mapped_resource text;
BEGIN
  claims := event -> 'claims';
  IF claims IS NULL OR pg_catalog.jsonb_typeof(claims) <> 'object'
    THEN RAISE EXCEPTION 'Invalid claims'; END IF;
  SELECT resource_audience INTO mapped_resource
    FROM ocn_private.oauth_resource_bindings_v2
   WHERE client_id::text = claims->>'client_id' AND enabled IS TRUE;
  IF mapped_resource IS NOT NULL
    THEN claims := pg_catalog.jsonb_set(
      claims,'{aud}',pg_catalog.to_jsonb(mapped_resource),true);
  END IF;
  RETURN pg_catalog.jsonb_build_object('claims',claims);
END;
$hook2$;

-- Exercise the same SQL function that a future trusted server-side endpoint would use.
DO $test$
DECLARE
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  old_client uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  edge_client uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  old_session uuid := 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  edge_session uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  old_resource text := 'https://ocn-mcp-ping-canary.onrender.com';
  edge_resource text := 'https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review';
  old_claims jsonb;
  edge_claims jsonb;
  new_claims jsonb;
BEGIN
  -- The original single-resource function/hook MUST remain unchanged by
  -- creating a parallel v2 table. No Edge privilege from old OAuth logic.
  IF NOT public.ocn_owner_oauth_session_active(owner_id, old_session, old_client)
    THEN RAISE EXCEPTION 'legacy RPC lost old client after v2 table added'; END IF;
  IF public.ocn_owner_oauth_session_active(owner_id, edge_session, edge_client)
    THEN RAISE EXCEPTION 'legacy RPC accepted new Edge client'; END IF;

  SELECT ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',old_client::text,'aud','authenticated'))
  ) INTO old_claims;
  IF old_claims->'claims'->>'aud' <> old_resource
    THEN RAISE EXCEPTION 'production-shaped audience hook lost Render mapping'; END IF;
  SELECT ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',edge_client::text,'aud','authenticated'))
  ) INTO edge_claims;
  IF edge_claims->'claims'->>'aud' <> 'authenticated'
    THEN RAISE EXCEPTION 'old hook silently authorized Edge audience'; END IF;

  -- The proposed hook (NOT deployed) binds both clients to separate audiences.
  SELECT ocn_private.set_ocn_access_token_audience_review_v2(
    jsonb_build_object('claims',jsonb_build_object('client_id',old_client::text,'aud','authenticated'))
  ) INTO new_claims;
  IF new_claims->'claims'->>'aud' <> old_resource
    THEN RAISE EXCEPTION 'candidate hook changed old Render audience'; END IF;
  SELECT ocn_private.set_ocn_access_token_audience_review_v2(
    jsonb_build_object('claims',jsonb_build_object('client_id',edge_client::text,'aud','authenticated'))
  ) INTO new_claims;
  IF new_claims->'claims'->>'aud' <> edge_resource
    THEN RAISE EXCEPTION 'candidate hook failed Edge audience mapping'; END IF;
  SELECT ocn_private.set_ocn_access_token_audience_review_v2(
    jsonb_build_object('claims',jsonb_build_object(
      'client_id','ffffffff-ffff-4fff-8fff-ffffffffffff','aud','authenticated'))
  ) INTO new_claims;
  IF new_claims->'claims'->>'aud' <> 'authenticated'
    THEN RAISE EXCEPTION 'unknown client unexpectedly received resource audience'; END IF;

  -- A second active resource for the same client MUST be rejected rather
  -- than creating nondeterministic JWT aud issuance. Failed substatement rolls back.
  BEGIN
    INSERT INTO ocn_private.oauth_resource_bindings_v2(client_id,resource_audience,enabled)
      VALUES(old_client,'https://second.invalid',true);
    RAISE EXCEPTION 'missing active-client uniqueness fence';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;

  IF NOT public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'valid Edge session unexpectedly denied'; END IF;
  IF NOT public.ocn_owner_oauth_resource_session_active(owner_id, old_session, old_client, old_resource)
    THEN RAISE EXCEPTION 'old Render session broken by side-by-side binding'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, old_resource)
    THEN RAISE EXCEPTION 'Edge client crossed into old resource'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, old_session, old_client, edge_resource)
    THEN RAISE EXCEPTION 'old session crossed into Edge resource'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, old_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'session/client mismatch'; END IF;
  IF public.ocn_owner_oauth_resource_session_active('ffffffff-ffff-4fff-8fff-ffffffffffff', edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'wrong owner accepted'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, 'https://evil.invalid')
    THEN RAISE EXCEPTION 'unregistered resource accepted'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, NULL)
    THEN RAISE EXCEPTION 'NULL resource accepted'; END IF;

  UPDATE ocn_private.oauth_resource_bindings_v2 SET enabled=false WHERE client_id=edge_client;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'disabled Edge binding accepted'; END IF;
  UPDATE ocn_private.oauth_resource_bindings_v2 SET enabled=true WHERE client_id=edge_client;

  -- Grant scopes are checked from authoritative consent rows, not from
  -- an optional JWT "scope" claim. Match full scope tokens, not substrings.
  UPDATE auth.oauth_consents SET scopes='email' WHERE client_id=edge_client;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'consent without openid scope accepted'; END IF;
  UPDATE auth.oauth_consents SET scopes='openid email-other' WHERE client_id=edge_client;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'substring email scope accepted'; END IF;
  UPDATE auth.oauth_consents SET scopes='email  openid' WHERE client_id=edge_client;
  IF NOT public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'valid whitespace-separated scopes unexpectedly denied'; END IF;
  UPDATE auth.oauth_consents SET scopes='openid email' WHERE client_id=edge_client;

  UPDATE auth.oauth_consents SET revoked_at=now() WHERE client_id=edge_client;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'revoked Edge consent accepted'; END IF;
  UPDATE auth.oauth_consents SET revoked_at=NULL WHERE client_id=edge_client;

  UPDATE auth.sessions SET not_after=now()-interval '1 second' WHERE id=edge_session;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'expired Edge session accepted'; END IF;
  UPDATE auth.sessions SET not_after=now()+interval '1 hour' WHERE id=edge_session;

  UPDATE auth.oauth_clients SET deleted_at=now() WHERE id=edge_client;
  IF public.ocn_owner_oauth_resource_session_active(owner_id, edge_session, edge_client, edge_resource)
    THEN RAISE EXCEPTION 'deleted Edge client accepted'; END IF;
  UPDATE auth.oauth_clients SET deleted_at=NULL WHERE id=edge_client;

  IF has_function_privilege('anon','public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text)','EXECUTE')
    OR has_function_privilege('authenticated','public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text)','EXECUTE')
    OR NOT has_function_privilege('service_role','public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text)','EXECUTE')
    THEN RAISE EXCEPTION 'unsafe RPC EXECUTE grant'; END IF;
  RAISE NOTICE 'OCN_RESOURCE_CONTRACT_PASS: legacy hook/RPC preserved, v2 audience hook preview, active-client uniqueness, dual resource, owner/client/session, revocation, role grants';
END $test$;
-- STAGED, REVERSIBLE CUTOVER EXERCISE (disposable CI transaction ONLY).
-- Stage v2 resources + 4-argument service-only RPC without modifying the
-- legacy JWT audience hook. Edge fails closed until its mapping is enabled.
CREATE TEMP TABLE ocn_review_rollback_baseline AS
  SELECT md5(pg_get_functiondef(
    'ocn_private.set_ocn_access_token_audience(jsonb)'::regprocedure
  )) AS legacy_hook_digest;

UPDATE ocn_private.oauth_resource_bindings_v2
   SET enabled=false
 WHERE client_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc';

DO $pre_cutover$
DECLARE
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  old_client uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  edge_client uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  old_session uuid := 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  edge_session uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  edge_resource text := 'https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review';
BEGIN
  IF NOT public.ocn_owner_oauth_session_active(owner_id,old_session,old_client)
    THEN RAISE EXCEPTION 'legacy RPC failed during staged rollout'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(
    owner_id,edge_session,edge_client,edge_resource)
    THEN RAISE EXCEPTION 'staged disabled Edge binding allowed access'; END IF;
  IF (ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object(
      'client_id',edge_client::text,'aud','authenticated'))
  )->'claims'->>'aud') <> 'authenticated'
    THEN RAISE EXCEPTION 'legacy token hook changed before cutover'; END IF;
END $pre_cutover$;

SAVEPOINT ocn_review_before_cutover;
-- Both the new audience mapping and Auth hook replacement are ONE
-- transaction. Never do this on the live project from this test file.
UPDATE ocn_private.oauth_resource_bindings_v2
   SET enabled=true
 WHERE client_id='cccccccc-cccc-4ccc-8ccc-cccccccccccc';

CREATE OR REPLACE FUNCTION ocn_private.set_ocn_access_token_audience(event jsonb)
RETURNS jsonb LANGUAGE plpgsql SET search_path = ''
AS $cutover_hook$
DECLARE claims jsonb; mapped_resource text;
BEGIN
  claims := event -> 'claims';
  IF claims IS NULL OR pg_catalog.jsonb_typeof(claims) <> 'object'
    THEN RAISE EXCEPTION 'Invalid claims'; END IF;
  SELECT resource_audience INTO mapped_resource
    FROM ocn_private.oauth_resource_bindings_v2
   WHERE client_id::text=claims->>'client_id' AND enabled IS TRUE;
  IF mapped_resource IS NOT NULL THEN
    claims := pg_catalog.jsonb_set(
      claims,'{aud}',pg_catalog.to_jsonb(mapped_resource),true);
  END IF;
  RETURN pg_catalog.jsonb_build_object('claims',claims);
END $cutover_hook$;

DO $cutover_verification$
DECLARE
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  old_client uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  edge_client uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  old_session uuid := 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  edge_session uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  old_resource text := 'https://ocn-mcp-ping-canary.onrender.com';
  edge_resource text := 'https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review';
BEGIN
  IF (SELECT md5(pg_get_functiondef(
    'ocn_private.set_ocn_access_token_audience(jsonb)'::regprocedure))
    FROM ocn_review_rollback_baseline)=
    (SELECT legacy_hook_digest FROM ocn_review_rollback_baseline)
    THEN RAISE EXCEPTION 'cutover hook was not changed'; END IF;
  IF NOT public.ocn_owner_oauth_session_active(owner_id,old_session,old_client)
    THEN RAISE EXCEPTION 'old client failed during cutover'; END IF;
  IF NOT public.ocn_owner_oauth_resource_session_active(
    owner_id,edge_session,edge_client,edge_resource)
    THEN RAISE EXCEPTION 'Edge authorization failed during simulated cutover'; END IF;
  IF (ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',old_client::text,'aud','authenticated'))
  )->'claims'->>'aud')<>old_resource
    THEN RAISE EXCEPTION 'cutover broke old Render audience'; END IF;
  IF (ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',edge_client::text,'aud','authenticated'))
  )->'claims'->>'aud')<>edge_resource
    THEN RAISE EXCEPTION 'cutover failed new Edge audience'; END IF;
  IF has_function_privilege('anon','public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text)','EXECUTE')
    OR has_function_privilege('authenticated','public.ocn_owner_oauth_resource_session_active(uuid,uuid,uuid,text)','EXECUTE')
    THEN RAISE EXCEPTION 'cutover unexpectedly exposed RPC'; END IF;
END $cutover_verification$;

-- PostgreSQL transactional DDL/function replacement must restore the hook,
-- binding flags and legacy behavior; no independent compensating update.
ROLLBACK TO SAVEPOINT ocn_review_before_cutover;

DO $rollback_verification$
DECLARE
  owner_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  old_client uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  edge_client uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  old_session uuid := 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  edge_session uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  old_resource text := 'https://ocn-mcp-ping-canary.onrender.com';
  edge_resource text := 'https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review';
BEGIN
  IF (SELECT md5(pg_get_functiondef(
    'ocn_private.set_ocn_access_token_audience(jsonb)'::regprocedure))
    FROM ocn_review_rollback_baseline) <>
    (SELECT legacy_hook_digest FROM ocn_review_rollback_baseline)
    THEN RAISE EXCEPTION 'transaction rollback failed to restore old hook'; END IF;
  IF NOT public.ocn_owner_oauth_session_active(owner_id,old_session,old_client)
    THEN RAISE EXCEPTION 'rollback lost old Render RPC'; END IF;
  IF public.ocn_owner_oauth_session_active(owner_id,edge_session,edge_client)
    THEN RAISE EXCEPTION 'rollback allowed Edge client in legacy RPC'; END IF;
  IF public.ocn_owner_oauth_resource_session_active(
    owner_id,edge_session,edge_client,edge_resource)
    THEN RAISE EXCEPTION 'rollback left Edge resource enabled'; END IF;
  IF (ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',old_client::text,'aud','authenticated'))
  )->'claims'->>'aud')<>old_resource
    THEN RAISE EXCEPTION 'rollback lost original Render JWT aud'; END IF;
  IF (ocn_private.set_ocn_access_token_audience(
    jsonb_build_object('claims',jsonb_build_object('client_id',edge_client::text,'aud','authenticated'))
  )->'claims'->>'aud')<>'authenticated'
    THEN RAISE EXCEPTION 'rollback retained new Edge JWT audience'; END IF;
  IF (SELECT count(*) FROM ocn_private.oauth_resource_binding WHERE binding_id=1 AND enabled)<>1
    THEN RAISE EXCEPTION 'rollback lost original singleton row'; END IF;
  IF (SELECT count(*) FROM ocn_private.oauth_resource_bindings_v2
      WHERE client_id=edge_client AND enabled)<>0
    THEN RAISE EXCEPTION 'rollback failed to disable staged Edge resource'; END IF;
  RAISE NOTICE 'OCN_EDGE_REVIEW_TRANSACTIONAL_ROLLBACK_PASS: legacy hook digest, old Render RPC and audience, Edge denied before cutover and after rollback';
END $rollback_verification$;

ROLLBACK; -- Entire fixture disappears at end. Never mutate remote Supabase.
