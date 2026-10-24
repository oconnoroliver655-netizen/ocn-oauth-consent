// Pure, metadata-only queue pressure decision. No secrets, I/O, or side effects.
// Used by the owner-OAuth Supabase Edge endpoint; advisory for optional probes only.
const BUSY_PHASES = new Set([
  "execution_lane_busy", "long_user_unresolved",
  "receipt_backpressure", "claim_reconciliation_pending"
]);
const ACTIVE = new Set(["queued", "claimed", "running"]);
export function classifyQueuePressure({observedAt, agents, commands, complete}) {
  const now = Date.parse(observedAt);
  if (!Number.isFinite(now) || !Array.isArray(agents) || !Array.isArray(commands)) {
    return {ok: false, reason: "INVALID_TELEMETRY"};
  }
  const agent = agents[0] || null;
  const stamp = Date.parse(agent?.last_seen_at || "");
  const age = Number.isFinite(stamp) ? Math.round((now - stamp) / 1000) : null;
  const phase = typeof agent?.state?.phase === "string" ? agent.state.phase.slice(0, 64) : null;
  let claimsEnabled = agent?.state?.claims_enabled;
  if (claimsEnabled === "true") claimsEnabled = true;
  if (claimsEnabled === "false") claimsEnabled = false;
  if (typeof claimsEnabled !== "boolean") claimsEnabled = null;
  const counts = {queued: 0, claimed: 0, running: 0};
  let oldestQueuedAge = null, oldestClaimedAge = null, nearExpiry = 0;
  for (const row of commands) {
    const status = row?.status;
    if (!ACTIVE.has(status)) continue;
    counts[status]++;
    const created = Date.parse(row.created_at || "");
    const claimed = Date.parse(row.claimed_at || "");
    const expiry = Date.parse(row.expires_at || "");
    if (status === "queued" && Number.isFinite(created)) {
      const a = Math.max(0, Math.round((now - created) / 1000));
      oldestQueuedAge = Math.max(oldestQueuedAge ?? 0, a);
      if (Number.isFinite(expiry) && expiry >= now - 1000 && expiry - now <= 30000) nearExpiry++;
    }
    if ((status === "claimed" || status === "running") && Number.isFinite(claimed)) {
      const a = Math.max(0, Math.round((now - claimed) / 1000));
      oldestClaimedAge = Math.max(oldestClaimedAge ?? 0, a);
    }
  }
  const heartbeatStale = age === null || age > 35 || age < -15;
  const busy = BUSY_PHASES.has(phase) || claimsEnabled === false;
  let reason = "NO_CURRENT_QUEUE_PRESSURE";
  if (complete !== true) reason = "ACTIVE_QUEUE_SAMPLE_INCOMPLETE";
  else if (heartbeatStale) reason = "AGENT_HEARTBEAT_STALE_OR_UNAVAILABLE";
  else if (busy) reason = "SINGLE_FLIGHT_OR_BACKPRESSURE_ACTIVE";
  else if (claimsEnabled !== true) reason = "CLAIM_READINESS_UNVERIFIED";
  else if ((oldestQueuedAge ?? 0) > 30) reason = "QUEUE_AGE_HIGH";
  else if (nearExpiry) reason = "NEAR_EXPIRY";
  return {
    ok: true, mutated_state: false,
    advisory_admit_nonessential_diagnostics: reason === "NO_CURRENT_QUEUE_PRESSURE",
    reason, heartbeat_age_s: age, agent_phase: phase,
    claims_enabled: claimsEnabled, active_queue_complete: complete === true,
    counts, oldest_queued_age_s: oldestQueuedAge,
    oldest_claimed_age_s: oldestClaimedAge, near_expiry_queued: nearExpiry
  };
}

/** Extract PostgREST's exact total from Content-Range; never infer it from
 * the number of rows returned because the Data API may cap each response. */
export function parseExactContentRange(value) {
  if (typeof value !== "string") return null;
  const parts=value.trim().split("/");
  if (parts.length!==2) return null;
  if (parts[0]!=="*" && !/^[0-9]+-[0-9]+$/.test(parts[0])) return null;
  if (!/^[0-9]+$/.test(parts[1])) return null;
  const total=Number(parts[1]);
  return Number.isSafeInteger(total) && total>=0 ? total : null;
}

/** Returns null for structurally invalid data; otherwise fail-closed when
 * exact total exceeds the sample or the service's configured max_rows. */
export function activeQueueComplete(rows,total,max=2000) {
  if (!Array.isArray(rows) || !Number.isSafeInteger(total) || total<0 ||
      rows.length>max || rows.length>total) return null;
  return total<=max && rows.length===total;
}
