#!/usr/bin/env node
import { runGuardrail } from '../src/lib/guardrail-core.js';

const { exitCode } = await runGuardrail();
process.exit(exitCode);
