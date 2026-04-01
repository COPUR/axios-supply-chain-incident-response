import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const LEVEL_WEIGHT = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

function isTruthy(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function levelEnabled(configuredLevel, eventLevel) {
  const configured = LEVEL_WEIGHT[configuredLevel] || LEVEL_WEIGHT.info;
  const incoming = LEVEL_WEIGHT[eventLevel] || LEVEL_WEIGHT.info;
  return incoming >= configured;
}

function textLine(payload) {
  const ts = payload.timestamp;
  const level = String(payload.level || 'info').toUpperCase();
  const event = payload.event || 'event';
  const details = payload.data && Object.keys(payload.data).length > 0
    ? ` ${JSON.stringify(payload.data)}`
    : '';

  return `[${ts}] [${level}] [${payload.tool}] ${event}${details}`;
}

async function appendEventToFile(eventsFile, serializedLine) {
  const dir = path.dirname(eventsFile);
  await fsp.mkdir(dir, { recursive: true });
  await fsp.appendFile(eventsFile, `${serializedLine}\n`, 'utf8');
}

export function createObservabilityContext({
  tool,
  env = process.env,
  now = () => new Date(),
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  if (!tool) {
    throw new Error('tool is required');
  }

  const runId = env.OBSERVABILITY_RUN_ID || `${tool}-${crypto.randomUUID()}`;
  const format = String(env.OBSERVABILITY_FORMAT || 'json').trim().toLowerCase();
  const level = String(env.OBSERVABILITY_LEVEL || 'info').trim().toLowerCase();
  const eventsFile = String(env.OBSERVABILITY_EVENTS_FILE || '').trim();

  return {
    tool,
    runId,
    format: format === 'text' ? 'text' : 'json',
    level: LEVEL_WEIGHT[level] ? level : 'info',
    eventsFile,
    selfHealEnabled: isTruthy(env.OBSERVABILITY_SELF_HEAL),
    startedAtMs: now().getTime(),
    now,
    stdout,
    stderr,
  };
}

export async function emitEvent(context, event, data = {}, level = 'info') {
  if (!levelEnabled(context.level, level)) {
    return null;
  }

  const payload = {
    timestamp: context.now().toISOString(),
    level,
    tool: context.tool,
    run_id: context.runId,
    event,
    data,
  };

  const line = context.format === 'text'
    ? textLine(payload)
    : JSON.stringify(payload);

  const stream = level === 'error' ? context.stderr : context.stdout;
  if (stream && typeof stream.write === 'function') {
    stream.write(`${line}\n`);
  }

  if (context.eventsFile) {
    await appendEventToFile(context.eventsFile, JSON.stringify(payload));
  }

  return payload;
}

export function classifyError(error) {
  const message = String(error?.message || error || 'unknown_error');

  if (message.includes('ETIMEDOUT') || message.includes('timed out')) {
    return {
      kind: 'timeout',
      message,
      recommendation: 'Increase timeout or reduce scope for this run.',
    };
  }

  if (message.includes('EACCES') || message.includes('permission')) {
    return {
      kind: 'permission',
      message,
      recommendation: 'Fix filesystem ownership/permissions for cache and output paths.',
    };
  }

  if (message.includes('JSON') || message.includes('Unexpected token')) {
    return {
      kind: 'parse_error',
      message,
      recommendation: 'Reset corrupted cache/input and re-run with strict validation.',
    };
  }

  if (message.includes('ENOENT') || message.includes('not found')) {
    return {
      kind: 'missing_path',
      message,
      recommendation: 'Create missing path or correct configured file locations.',
    };
  }

  return {
    kind: 'unknown',
    message,
    recommendation: 'Capture full diagnostics and investigate recurring failure signatures.',
  };
}

export async function tryDefaultSelfHeal({ classifiedError, env = process.env }) {
  if (classifiedError.kind === 'missing_path') {
    const resultFile = String(env.GUARDRAIL_RESULT_FILE || '').trim();
    if (resultFile) {
      await fsp.mkdir(path.dirname(path.resolve(resultFile)), { recursive: true });
      return {
        healed: true,
        strategy: 'create_result_directory',
      };
    }
  }

  if (classifiedError.kind === 'parse_error') {
    const cacheFile = String(env.GUARDRAIL_CACHE_FILE || '').trim();
    if (cacheFile && fs.existsSync(cacheFile)) {
      const backup = `${cacheFile}.corrupt.${Date.now()}`;
      await fsp.rename(cacheFile, backup);
      return {
        healed: true,
        strategy: 'quarantine_corrupt_cache',
        backup,
      };
    }
  }

  return {
    healed: false,
    strategy: 'none',
  };
}

export async function runWithObservability({
  tool,
  env = process.env,
  execute,
  selfHeal = tryDefaultSelfHeal,
  now,
  stdout,
  stderr,
} = {}) {
  const context = createObservabilityContext({
    tool,
    env,
    now,
    stdout,
    stderr,
  });

  await emitEvent(context, 'run_start', { pid: process.pid });

  try {
    const result = await execute(context);
    const exitCode = Number.isFinite(result?.exitCode) ? Number(result.exitCode) : 0;
    const durationMs = context.now().getTime() - context.startedAtMs;

    await emitEvent(context, 'run_end', {
      status: exitCode === 0 ? 'success' : 'failure',
      exit_code: exitCode,
      duration_ms: durationMs,
      ...(result?.metrics || {}),
    }, exitCode === 0 ? 'info' : 'warn');

    return {
      exitCode,
      result,
      context,
      selfHealed: false,
    };
  } catch (error) {
    const classified = classifyError(error);

    await emitEvent(context, 'run_error', {
      status: 'failure',
      exit_code: 1,
      duration_ms: context.now().getTime() - context.startedAtMs,
      error: classified,
    }, 'error');

    if (context.selfHealEnabled) {
      const healResult = await selfHeal({ classifiedError: classified, context, env });
      if (healResult?.healed) {
        await emitEvent(context, 'self_heal_applied', {
          strategy: healResult.strategy,
          ...(healResult.backup ? { backup: healResult.backup } : {}),
        }, 'warn');

        const retryResult = await execute(context);
        const retryExitCode = Number.isFinite(retryResult?.exitCode) ? Number(retryResult.exitCode) : 0;

        await emitEvent(context, 'run_end', {
          status: retryExitCode === 0 ? 'success' : 'failure',
          exit_code: retryExitCode,
          duration_ms: context.now().getTime() - context.startedAtMs,
          self_healed: true,
          ...(retryResult?.metrics || {}),
        }, retryExitCode === 0 ? 'info' : 'warn');

        return {
          exitCode: retryExitCode,
          result: retryResult,
          context,
          selfHealed: true,
        };
      }
    }

    throw error;
  }
}
