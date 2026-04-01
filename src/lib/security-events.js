export function buildGuardrailEventPayload({ result, pipelineId, repository, commitSha }) {
  return {
    pipeline_id: pipelineId || 'unknown',
    repository: repository || 'unknown',
    commit_sha: commitSha || 'unknown',
    status: result?.status,
    summary: result?.summary || {},
    blocked: result?.blocked || [],
    quarantined: result?.quarantined || [],
  };
}

export function shouldRaiseIncident(status) {
  return status === 'block' || status === 'quarantine';
}

export function createIncident(event, nowIso = () => new Date().toISOString()) {
  const status = event?.status;
  const severity = status === 'block' ? 'critical' : 'high';

  return {
    incident_type: 'dependency_supply_chain_risk',
    created_at: nowIso(),
    severity,
    repository: event?.repository,
    pipeline_id: event?.pipeline_id,
    commit_sha: event?.commit_sha,
    status,
    summary: event?.summary || {},
    blocked: event?.blocked || [],
    quarantined: event?.quarantined || [],
    recommended_actions: [
      status === 'block' ? 'Fail pipeline immediately' : 'Quarantine artifact',
      'Open security incident',
      'Require manual security review',
      'Prevent production promotion',
      'Update central denylist/policy',
    ],
  };
}
