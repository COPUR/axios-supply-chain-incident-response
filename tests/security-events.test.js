import { describe, expect, it } from 'vitest';

import {
  buildGuardrailEventPayload,
  createIncident,
  shouldRaiseIncident,
} from '../src/lib/security-events.js';

describe('security events', () => {
  it('builds guardrail event payload', () => {
    const payload = buildGuardrailEventPayload({
      result: {
        status: 'block',
        summary: { blocked_count: 1 },
        blocked: [{ name: 'axios', version: '1.14.1' }],
        quarantined: [],
      },
      pipelineId: '123',
      repository: 'org/repo',
      commitSha: 'abc123',
    });

    expect(payload).toEqual({
      pipeline_id: '123',
      repository: 'org/repo',
      commit_sha: 'abc123',
      status: 'block',
      summary: { blocked_count: 1 },
      blocked: [{ name: 'axios', version: '1.14.1' }],
      quarantined: [],
    });
  });

  it('identifies incident-worthy statuses', () => {
    expect(shouldRaiseIncident('block')).toBe(true);
    expect(shouldRaiseIncident('quarantine')).toBe(true);
    expect(shouldRaiseIncident('allow')).toBe(false);
  });

  it('creates incident with correct severity and actions', () => {
    const incident = createIncident(
      {
        status: 'block',
        repository: 'org/repo',
        pipeline_id: '42',
        commit_sha: 'deadbeef',
      },
      () => '2026-04-01T00:00:00.000Z',
    );

    expect(incident.severity).toBe('critical');
    expect(incident.created_at).toBe('2026-04-01T00:00:00.000Z');
    expect(incident.recommended_actions[0]).toBe('Fail pipeline immediately');
  });
});
