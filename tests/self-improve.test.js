import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  buildRecommendations,
  generateInsights,
  readEvents,
  renderInsightsMarkdown,
  summarizeEvents,
} from '../src/lib/self-improve.js';

describe('self-improve insights', () => {
  it('reads NDJSON events and skips malformed lines', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'insights-'));
    const file = path.join(tmp, 'events.ndjson');

    await fsp.writeFile(file, [
      JSON.stringify({ event: 'run_end', data: { duration_ms: 100 } }),
      '{bad-json',
      JSON.stringify({ event: 'run_error', data: { error: { kind: 'timeout' } } }),
      '',
    ].join('\n'), 'utf8');

    const events = await readEvents(file);
    expect(events.length).toBe(2);
  });

  it('summarizes runtime behavior and derives recommendations', () => {
    const summary = summarizeEvents([
      { event: 'run_end', data: { duration_ms: 200000, status: 'failure', uncertainty_impacted_projects: 2 } },
      { event: 'run_error', data: { error: { kind: 'timeout' } } },
      { event: 'run_error', data: { error: { kind: 'permission' } } },
      { event: 'run_error', data: { error: { kind: 'parse_error' } } },
      { event: 'run_error', data: { error: { kind: 'other' } } },
      { event: 'self_heal_applied', data: { strategy: 'x' } },
    ]);

    expect(summary.total_events).toBe(6);
    expect(summary.run_end_count).toBe(1);
    expect(summary.run_error_count).toBe(4);
    expect(summary.self_heal_count).toBe(1);
    expect(summary.timeout_errors).toBe(1);
    expect(summary.permission_errors).toBe(1);
    expect(summary.parse_errors).toBe(1);
    expect(summary.unknown_errors).toBe(1);

    const recs = buildRecommendations(summary);
    expect(recs.some((item) => item.includes('Timeout failures'))).toBe(true);
    expect(recs.some((item) => item.includes('Permission failures'))).toBe(true);
    expect(recs.some((item) => item.includes('Parse failures'))).toBe(true);
    expect(recs.some((item) => item.includes('parallelism'))).toBe(true);
  });

  it('handles sparse events and recommends self-heal enablement', () => {
    const summary = summarizeEvents([
      {},
      { event: 'run_end' },
      { event: 'run_error' },
    ]);

    expect(summary.total_events).toBe(3);
    expect(summary.run_end_count).toBe(1);
    expect(summary.cumulative_duration_ms).toBe(0);
    expect(summary.unknown_errors).toBe(1);

    const recs = buildRecommendations(summary);
    expect(recs.some((item) => item.includes('enable OBSERVABILITY_SELF_HEAL'))).toBe(true);
  });

  it('renders markdown insights report', () => {
    const markdown = renderInsightsMarkdown(
      {
        total_events: 1,
        run_end_count: 1,
        run_error_count: 0,
        self_heal_count: 0,
        timeout_errors: 0,
        permission_errors: 0,
        parse_errors: 0,
        unknown_errors: 0,
        cumulative_duration_ms: 200,
        high_uncertainty_runs: 0,
        affected_runs: 0,
      },
      ['No recurring runtime failure pattern detected. Keep current guardrails and continue monitoring.'],
    );

    expect(markdown).toContain('# Observability Insights');
    expect(markdown).toContain('## Runtime Summary');
    expect(markdown).toContain('## Self-Improvement Recommendations');
  });

  it('renders zero average duration when there are no completed runs', () => {
    const markdown = renderInsightsMarkdown(
      {
        total_events: 2,
        run_end_count: 0,
        run_error_count: 1,
        self_heal_count: 0,
        timeout_errors: 0,
        permission_errors: 0,
        parse_errors: 0,
        unknown_errors: 1,
        cumulative_duration_ms: 9999,
        high_uncertainty_runs: 0,
        affected_runs: 0,
      },
      ['Enable self-heal.'],
    );

    expect(markdown).toContain('- Average run duration (ms): 0');
  });

  it('generates insights end-to-end', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'insights-end2end-'));
    const file = path.join(tmp, 'events.ndjson');

    await fsp.writeFile(file, `${JSON.stringify({ event: 'run_end', data: { duration_ms: 1000 } })}\n`, 'utf8');

    const report = await generateInsights(file);
    expect(report.summary.total_events).toBe(1);
    expect(report.recommendations.length).toBeGreaterThanOrEqual(1);
    expect(report.markdown).toContain('Observability Insights');
  });
});
