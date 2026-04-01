#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { Kafka } from 'kafkajs';

import { runWithObservability } from '../src/lib/observability.js';
import { buildGuardrailEventPayload } from '../src/lib/security-events.js';

const BOOTSTRAP = process.env.KAFKA_BOOTSTRAP_SERVERS || 'kafka:9092';
const TOPIC = process.env.KAFKA_TOPIC || 'security.dependency.events';
const RESULT_FILE = process.env.GUARDRAIL_RESULT_FILE || 'guardrail-result.json';
const PIPELINE_ID = process.env.CI_PIPELINE_ID || 'unknown';
const REPOSITORY = process.env.CI_REPOSITORY || 'unknown';
const COMMIT_SHA = process.env.CI_COMMIT_SHA || 'unknown';

const outcome = await runWithObservability({
  tool: 'publish_guardrail_event',
  execute: async () => {
    const resultPath = path.resolve(RESULT_FILE);
    const result = JSON.parse(await fs.readFile(resultPath, 'utf8'));
    const payload = buildGuardrailEventPayload({
      result,
      pipelineId: PIPELINE_ID,
      repository: REPOSITORY,
      commitSha: COMMIT_SHA,
    });

    const kafka = new Kafka({ brokers: BOOTSTRAP.split(',').map((item) => item.trim()).filter(Boolean) });
    const producer = kafka.producer();

    await producer.connect();
    await producer.send({ topic: TOPIC, messages: [{ value: JSON.stringify(payload) }] });
    await producer.disconnect();

    process.stdout.write(`Published guardrail event to ${TOPIC}\n`);

    return {
      exitCode: 0,
      metrics: {
        status: 'published',
        topic: TOPIC,
        event_status: payload.status || 'unknown',
      },
    };
  },
});

process.exit(outcome.exitCode);
