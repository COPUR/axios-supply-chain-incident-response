#!/usr/bin/env node
import { Kafka } from 'kafkajs';

import { createIncident, shouldRaiseIncident } from '../src/lib/security-events.js';

const BOOTSTRAP = process.env.KAFKA_BOOTSTRAP_SERVERS || 'kafka:9092';
const INPUT_TOPIC = process.env.KAFKA_INPUT_TOPIC || 'security.dependency.events';
const INCIDENT_TOPIC = process.env.KAFKA_INCIDENT_TOPIC || 'security.incidents';
const GROUP_ID = process.env.KAFKA_GROUP_ID || 'dependency-security-agent';

async function main() {
  const kafka = new Kafka({ brokers: BOOTSTRAP.split(',').map((item) => item.trim()).filter(Boolean) });
  const consumer = kafka.consumer({ groupId: GROUP_ID });
  const producer = kafka.producer();

  const shutdown = async () => {
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
  process.stdout.write(`Listening on topic: ${INPUT_TOPIC}\n`);

  await consumer.run({
    eachMessage: async ({ message }) => {
      try {
        const event = JSON.parse(String(message.value || '{}'));
        const status = event?.status;

        if (shouldRaiseIncident(status)) {
          const incident = createIncident(event);
          await producer.send({ topic: INCIDENT_TOPIC, messages: [{ value: JSON.stringify(incident) }] });
          process.stdout.write(`Incident created for repo=${event?.repository} status=${status}\n`);
        } else {
          process.stdout.write(`Allowed dependency set for repo=${event?.repository}\n`);
        }
      } catch (error) {
        process.stderr.write(`Processing error: ${error?.message || error}\n`);
      }
    },
  });
}

try {
  await main();
} catch (error) {
  process.stderr.write(`Agent startup failure: ${error?.message || error}\n`);
  process.exit(1);
}
