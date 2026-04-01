import fsp from 'node:fs/promises';

export async function readEvents(eventsFile) {
  const text = await fsp.readFile(eventsFile, 'utf8');
  const events = [];

  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    try {
      events.push(JSON.parse(trimmed));
    } catch {
      // Skip malformed lines so one bad event does not break analysis.
    }
  }

  return events;
}

export function summarizeEvents(events) {
  const summary = {
    total_events: events.length,
    run_end_count: 0,
    run_error_count: 0,
    self_heal_count: 0,
    timeout_errors: 0,
    permission_errors: 0,
    parse_errors: 0,
    unknown_errors: 0,
    cumulative_duration_ms: 0,
    high_uncertainty_runs: 0,
    affected_runs: 0,
  };

  for (const event of events) {
    const name = String(event?.event || '');
    const data = event?.data || {};

    if (name === 'run_end') {
      summary.run_end_count += 1;
      summary.cumulative_duration_ms += Number(data.duration_ms || 0);
      if (Number(data.uncertainty_impacted_projects || 0) > 0) {
        summary.high_uncertainty_runs += 1;
      }
      if (String(data.status || '') === 'failure') {
        summary.affected_runs += 1;
      }
    }

    if (name === 'run_error') {
      summary.run_error_count += 1;
      const kind = String(data?.error?.kind || 'unknown');
      if (kind === 'timeout') {
        summary.timeout_errors += 1;
      } else if (kind === 'permission') {
        summary.permission_errors += 1;
      } else if (kind === 'parse_error') {
        summary.parse_errors += 1;
      } else {
        summary.unknown_errors += 1;
      }
    }

    if (name === 'self_heal_applied') {
      summary.self_heal_count += 1;
    }
  }

  return summary;
}

export function buildRecommendations(summary) {
  const items = [];

  if (summary.run_error_count === 0 && summary.self_heal_count === 0) {
    items.push('No recurring runtime failure pattern detected. Keep current guardrails and continue monitoring.');
  }

  if (summary.timeout_errors > 0) {
    items.push('Timeout failures detected: increase runner timeout and split large scans by repo domain.');
  }

  if (summary.permission_errors > 0) {
    items.push('Permission failures detected: enforce writable local cache/output paths in CI bootstrap.');
  }

  if (summary.parse_errors > 0) {
    items.push('Parse failures detected: quarantine corrupted cache/input artifacts and rehydrate from trusted source.');
  }

  if (summary.high_uncertainty_runs > 0) {
    items.push('Uncertainty-driven compromise assumptions detected: enforce exact dependency pinning and lockfile completeness.');
  }

  if (summary.self_heal_count === 0 && summary.run_error_count > 0) {
    items.push('Failures occurred without automated recovery: enable OBSERVABILITY_SELF_HEAL and define safe retry strategies.');
  }

  if (summary.cumulative_duration_ms > 120000) {
    items.push('High cumulative runtime observed: increase parallelism for lockfile matrix checks and scope scans per workspace.');
  }

  return items;
}

export function renderInsightsMarkdown(summary, recommendations) {
  const avgDuration = summary.run_end_count > 0
    ? Math.round(summary.cumulative_duration_ms / summary.run_end_count)
    : 0;

  const lines = [];
  lines.push('# Observability Insights');
  lines.push('');
  lines.push('## Runtime Summary');
  lines.push('');
  lines.push(`- Total events: ${summary.total_events}`);
  lines.push(`- Completed runs: ${summary.run_end_count}`);
  lines.push(`- Error events: ${summary.run_error_count}`);
  lines.push(`- Self-heal actions: ${summary.self_heal_count}`);
  lines.push(`- Average run duration (ms): ${avgDuration}`);
  lines.push(`- Timeout errors: ${summary.timeout_errors}`);
  lines.push(`- Permission errors: ${summary.permission_errors}`);
  lines.push(`- Parse errors: ${summary.parse_errors}`);
  lines.push(`- Unknown errors: ${summary.unknown_errors}`);
  lines.push(`- High-uncertainty runs: ${summary.high_uncertainty_runs}`);
  lines.push('');
  lines.push('## Self-Improvement Recommendations');
  lines.push('');

  for (const item of recommendations) {
    lines.push(`- ${item}`);
  }

  return `${lines.join('\n')}\n`;
}

export async function generateInsights(eventsFile) {
  const events = await readEvents(eventsFile);
  const summary = summarizeEvents(events);
  const recommendations = buildRecommendations(summary);
  const markdown = renderInsightsMarkdown(summary, recommendations);

  return {
    summary,
    recommendations,
    markdown,
  };
}
