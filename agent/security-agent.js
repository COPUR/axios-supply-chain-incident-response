#!/usr/bin/env node
import { Kafka } from 'kafkajs';

import {
  createObservabilityContext,
  emitEvent,
} from '../src/lib/observability.js';
import { createIncident, shouldRaiseIncident } from '../src/lib/security-events.js';

const BOOTSTRAP = process.env.KAFKA_BOOTSTRAP_SERVERS || 'kafka:9092';
const INPUT_TOPIC = process.env.KAFKA_INPUT_TOPIC || 'security.dependency.events';
const INCIDENT_TOPIC = process.env.KAFKA_INCIDENT_TOPIC || 'security.incidents';
const GROUP_ID = process.env.KAFKA_GROUP_ID || 'dependency-security-agent';

const obs = createObservabilityContext({ tool: 'security_agent' });

async function main() {
  const kafka = new Kafka({ brokers: BOOTSTRAP.split(',').map((item) => item.trim()).filter(Boolean) });
  const consumer = kafka.consumer({ groupId: GROUP_ID });
  const producer = kafka.producer();

  const shutdown = async () => {
    await emitEvent(obs, 'agent_shutdown', {});
    try {
      await consumer.disconnect();
    } catch {
      // Ignore shutdown errors
    }
    try {
      await producer.disconnect();
    } catch {
      // Ignore shutdown errors
    }
    process.exit(0);
  };

  process.once('SIGINT', () => {
    void shutdown();
  });
  process.once('SIGTERM', () => {
    void shutdown();
  });

  await producer.connect();
  await consumer.connect();
  await consumer.subscribe({ topic: INPUT_TOPIC, fromBeginning: true });

  await emitEvent(obs, 'agent_started', {
    input_topic: INPUT_TOPIC,
    incident_topic: INCIDENT_TOPIC,
  });
  process.stdout.write(`Listening on topic: ${INPUT_TOPIC}\n`);

  await consumer.run({
    eachMessage: async ({ message }) => {
      try {
        const event = JSON.parse(String(message.value || '{}'));
        const status = event?.status;

        if (shouldRaiseIncident(status)) {
          const incident = createIncident(event);
          await producer.send({ topic: INCIDENT_TOPIC, messages: [{ value: JSON.stringify(incident) }] });
          await emitEvent(obs, 'incident_published', {
            repository: event?.repository,
            status,
            incident_topic: INCIDENT_TOPIC,
          });
          process.stdout.write(`Incident created for repo=${event?.repository} status=${status}\n`);
        } else {
          await emitEvent(obs, 'event_allowed', {
            repository: event?.repository,
            status,
          }, 'debug');
          process.stdout.write(`Allowed dependency set for repo=${event?.repository}\n`);
        }
      } catch (error) {
        await emitEvent(obs, 'agent_processing_error', {
          error: String(error?.message || error),
        }, 'error');
        process.stderr.write(`Processing error: ${error?.message || error}\n`);
      }
    },
  });
}

try {
  await main();
} catch (error) {
  await emitEvent(obs, 'agent_startup_error', {
    error: String(error?.message || error),
  }, 'error');
  process.stderr.write(`Agent startup failure: ${error?.message || error}\n`);
  process.exit(1);
}
