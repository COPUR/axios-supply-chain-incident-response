#!/usr/bin/env node
import { runGuardrail } from '../src/lib/guardrail-core.js';
import { runWithObservability } from '../src/lib/observability.js';

const outcome = await runWithObservability({
  tool: 'guardrail',
  execute: async () => {
    const guardrail = await runGuardrail();
    return {
      exitCode: guardrail.exitCode,
      metrics: {
        status: guardrail.result?.status || 'unknown',
        ...(guardrail.result?.summary || {}),
      },
    };
  },
});

process.exit(outcome.exitCode);
