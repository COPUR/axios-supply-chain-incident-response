import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  classifyError,
  createObservabilityContext,
  emitEvent,
  runWithObservability,
  tryDefaultSelfHeal,
} from '../src/lib/observability.js';

function fakeStream() {
  const lines = [];
  return {
    lines,
    write(value) {
      lines.push(String(value));
    },
  };
}

describe('observability', () => {
  it('requires tool and normalizes invalid context settings', () => {
    expect(() => createObservabilityContext()).toThrow('tool is required');

    const ctx = createObservabilityContext({
      tool: 'normalize_tool',
      env: {
        OBSERVABILITY_FORMAT: 'yaml',
        OBSERVABILITY_LEVEL: 'verbose',
        OBSERVABILITY_SELF_HEAL: 'yes',
        OBSERVABILITY_RUN_ID: 'fixed-run-id',
      },
      stdout: fakeStream(),
      stderr: fakeStream(),
    });

    expect(ctx.format).toBe('json');
    expect(ctx.level).toBe('info');
    expect(ctx.selfHealEnabled).toBe(true);
    expect(ctx.runId).toBe('fixed-run-id');
  });

  it('creates context with defaults and emits json events', async () => {
    const stdout = fakeStream();
    const stderr = fakeStream();

    const ctx = createObservabilityContext({
      tool: 'test_tool',
      env: {},
      now: () => new Date('2026-04-01T00:00:00Z'),
      stdout,
      stderr,
    });

    expect(ctx.tool).toBe('test_tool');
    expect(ctx.format).toBe('json');

    const payload = await emitEvent(ctx, 'example_event', { key: 'value' }, 'info');
    expect(payload.event).toBe('example_event');
    expect(stdout.lines.join('')).toContain('example_event');
    expect(stderr.lines.length).toBe(0);
  });

  it('writes events to file and supports text format', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-test-'));
    const eventsFile = path.join(tmp, 'events.ndjson');
    const stdout = fakeStream();

    const ctx = createObservabilityContext({
      tool: 'file_tool',
      env: {
        OBSERVABILITY_FORMAT: 'text',
        OBSERVABILITY_EVENTS_FILE: eventsFile,
      },
      now: () => new Date('2026-04-01T00:00:00Z'),
      stdout,
      stderr: fakeStream(),
    });

    await emitEvent(ctx, 'text_event', { a: 1 }, 'warn');

    expect(stdout.lines.join('')).toContain('[WARN]');
    const saved = await fsp.readFile(eventsFile, 'utf8');
    expect(saved).toContain('text_event');
  });

  it('applies fallback formatting and routes error events to stderr', async () => {
    const stdout = fakeStream();
    const stderr = fakeStream();

    const context = {
      tool: 'fallback_tool',
      runId: 'run-1',
      format: 'text',
      level: 'invalid-level',
      eventsFile: '',
      now: () => new Date('2026-04-01T00:00:00Z'),
      stdout,
      stderr,
    };

    await emitEvent(context, undefined, {}, '');
    const firstLine = stdout.lines.join('');
    expect(firstLine).toContain('[INFO]');
    expect(firstLine).toContain('event');
    expect(firstLine).not.toContain('{');

    await emitEvent(context, 'error_event', {}, 'error');
    expect(stderr.lines.join('')).toContain('[ERROR]');
    expect(stderr.lines.join('')).toContain('error_event');
  });

  it('filters events below configured level', async () => {
    const stdout = fakeStream();
    const ctx = createObservabilityContext({
      tool: 'level_tool',
      env: {
        OBSERVABILITY_LEVEL: 'warn',
      },
      stdout,
      stderr: fakeStream(),
    });

    const skipped = await emitEvent(ctx, 'debug_event', {}, 'info');
    expect(skipped).toBeNull();
    expect(stdout.lines.length).toBe(0);
  });

  it('classifies common error patterns', () => {
    expect(classifyError(new Error('ETIMEDOUT request failed')).kind).toBe('timeout');
    expect(classifyError(new Error('EACCES cache')).kind).toBe('permission');
    expect(classifyError(new Error('Unexpected token in JSON')).kind).toBe('parse_error');
    expect(classifyError(new Error('ENOENT not found')).kind).toBe('missing_path');
    expect(classifyError(new Error('random')).kind).toBe('unknown');
  });

  it('classifies non-error and empty error inputs safely', () => {
    expect(classifyError('permission denied').kind).toBe('permission');
    expect(classifyError(null).message).toBe('unknown_error');
    expect(classifyError('').kind).toBe('unknown');
  });

  it('performs default self-heal for missing result path and parse cache', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'obs-heal-'));
    const resultFile = path.join(tmp, 'nested', 'guardrail-result.json');
    const cacheFile = path.join(tmp, 'cache.json');
    await fsp.writeFile(cacheFile, '{bad', 'utf8');

    const healMissing = await tryDefaultSelfHeal({
      classifiedError: { kind: 'missing_path' },
      env: { GUARDRAIL_RESULT_FILE: resultFile },
    });
    expect(healMissing.healed).toBe(true);
    expect(fs.existsSync(path.dirname(resultFile))).toBe(true);

    const healParse = await tryDefaultSelfHeal({
      classifiedError: { kind: 'parse_error' },
      env: { GUARDRAIL_CACHE_FILE: cacheFile },
    });
    expect(healParse.healed).toBe(true);
    expect(fs.existsSync(cacheFile)).toBe(false);

    const noHeal = await tryDefaultSelfHeal({
      classifiedError: { kind: 'unknown' },
      env: {},
    });
    expect(noHeal.healed).toBe(false);
  });

  it('does not self-heal when required env paths are unavailable', async () => {
    const missingResult = await tryDefaultSelfHeal({
      classifiedError: { kind: 'missing_path' },
      env: {},
    });
    expect(missingResult).toEqual({ healed: false, strategy: 'none' });

    const missingCachePath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'obs-no-cache-')),
      'missing-cache.json',
    );
    const missingCache = await tryDefaultSelfHeal({
      classifiedError: { kind: 'parse_error' },
      env: { GUARDRAIL_CACHE_FILE: missingCachePath },
    });
    expect(missingCache).toEqual({ healed: false, strategy: 'none' });
  });

  it('runs wrapped execution and emits run lifecycle', async () => {
    const stdout = fakeStream();

    const outcome = await runWithObservability({
      tool: 'wrap_success',
      env: {},
      stdout,
      stderr: fakeStream(),
      now: (() => {
        let tick = 0;
        return () => new Date(1711929600000 + (tick += 1));
      })(),
      execute: async () => ({
        exitCode: 0,
        metrics: { status: 'ok' },
      }),
    });

    expect(outcome.exitCode).toBe(0);
    const joined = stdout.lines.join('');
    expect(joined).toContain('run_start');
    expect(joined).toContain('run_end');
  });

  it('normalizes non-finite and non-zero exit codes from execute()', async () => {
    const nonFinite = await runWithObservability({
      tool: 'wrap_non_finite',
      env: {},
      stdout: fakeStream(),
      stderr: fakeStream(),
      execute: async () => ({}),
    });
    expect(nonFinite.exitCode).toBe(0);

    const stdout = fakeStream();
    const nonZero = await runWithObservability({
      tool: 'wrap_non_zero',
      env: {},
      stdout,
      stderr: fakeStream(),
      execute: async () => ({ exitCode: 7 }),
    });
    expect(nonZero.exitCode).toBe(7);

    const runEnd = stdout.lines
      .map((line) => JSON.parse(line))
      .find((event) => event.event === 'run_end');
    expect(runEnd.data.status).toBe('failure');
    expect(runEnd.level).toBe('warn');
  });

  it('self-heals and retries once when enabled', async () => {
    let attempts = 0;

    const outcome = await runWithObservability({
      tool: 'wrap_heal',
      env: {
        OBSERVABILITY_SELF_HEAL: '1',
      },
      stdout: fakeStream(),
      stderr: fakeStream(),
      execute: async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new Error('ENOENT output path missing');
        }
        return { exitCode: 0, metrics: { status: 'recovered' } };
      },
      selfHeal: async () => ({ healed: true, strategy: 'test_retry' }),
    });

    expect(attempts).toBe(2);
    expect(outcome.selfHealed).toBe(true);
    expect(outcome.exitCode).toBe(0);
  });

  it('records self-heal backup metadata and retry failure status', async () => {
    let attempts = 0;
    const stdout = fakeStream();

    const outcome = await runWithObservability({
      tool: 'wrap_heal_fail',
      env: {
        OBSERVABILITY_SELF_HEAL: '1',
      },
      stdout,
      stderr: fakeStream(),
      execute: async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new Error('Unexpected token in JSON');
        }
        return { exitCode: 9 };
      },
      selfHeal: async () => ({
        healed: true,
        strategy: 'quarantine_corrupt_cache',
        backup: '/tmp/corrupt-cache.json',
      }),
    });

    expect(outcome.selfHealed).toBe(true);
    expect(outcome.exitCode).toBe(9);

    const events = stdout.lines.map((line) => JSON.parse(line));
    const healedEvent = events.find((event) => event.event === 'self_heal_applied');
    expect(healedEvent.data.backup).toBe('/tmp/corrupt-cache.json');

    const runEnd = events.filter((event) => event.event === 'run_end').at(-1);
    expect(runEnd.data.status).toBe('failure');
    expect(runEnd.level).toBe('warn');
  });

  it('defaults retry exit code when recovery result is non-numeric', async () => {
    let attempts = 0;

    const outcome = await runWithObservability({
      tool: 'wrap_heal_non_numeric',
      env: {
        OBSERVABILITY_SELF_HEAL: 'true',
      },
      stdout: fakeStream(),
      stderr: fakeStream(),
      execute: async () => {
        attempts += 1;
        if (attempts === 1) {
          throw new Error('ENOENT missing file');
        }
        return { exitCode: 'n/a' };
      },
      selfHeal: async () => ({ healed: true, strategy: 'create_result_directory' }),
    });

    expect(attempts).toBe(2);
    expect(outcome.selfHealed).toBe(true);
    expect(outcome.exitCode).toBe(0);
  });

  it('rethrows errors when not healed', async () => {
    await expect(runWithObservability({
      tool: 'wrap_fail',
      env: {},
      stdout: fakeStream(),
      stderr: fakeStream(),
      execute: async () => {
        throw new Error('boom');
      },
      selfHeal: async () => ({ healed: false, strategy: 'none' }),
    })).rejects.toThrow('boom');
  });
});
