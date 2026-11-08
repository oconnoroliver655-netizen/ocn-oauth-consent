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
  UNIQUE (user_id, client_id)
);

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
INSERT INTO auth.oauth_consents(id,user_id,client_id) VALUES
  ('11111111-1111-4111-8111-111111111111','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
  ('22222222-2222-4222-8222-222222222222','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','cccccccc-cccc-4ccc-8ccc-cccccccccccc');
INSERT INTO ocn_private.oauth_resource_bindings_v2(client_id,resource_audience,enabled) VALUES
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','https://ocn-mcp-ping-canary.onrender.com',true),
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc','https://ouxniljtjxnrkwakkvbv.supabase.co/functions/v1/ocn-mcp-edge-review',true);

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
BEGIN
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
  RAISE NOTICE 'OCN_RESOURCE_CONTRACT_PASS: dual resource, exact binding, owner/client/session, revoked/expired/disabled/deleted, role grants';
END $test$;
ROLLBACK; -- Entire fixture disappears at end. Never mutate remote Supabase.
