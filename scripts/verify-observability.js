#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exit(code);
}

const argv = await yargs(hideBin(process.argv))
  .option('events-file', {
    type: 'string',
    default: process.env.OBSERVABILITY_EVENTS_FILE || '',
    describe: 'NDJSON observability event file',
  })
  .option('expected-tools', {
    type: 'array',
    default: [],
    describe: 'Tool names expected to emit run_start/run_end',
  })
  .option('min-events', {
    type: 'number',
    default: 2,
    describe: 'Minimum parsed events required',
  })
  .strict()
  .parse();

const rawEventsFile = String(argv.eventsFile || '').trim();
if (!rawEventsFile) {
  fail('OBSERVABILITY gate failed: events file path is missing. Set OBSERVABILITY_EVENTS_FILE.');
}

const eventsFile = path.resolve(rawEventsFile);
let text;
try {
  text = await fs.readFile(eventsFile, 'utf8');
} catch (error) {
  fail(`OBSERVABILITY gate failed: cannot read events file at ${eventsFile}: ${String(error?.message || error)}`);
}

const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
if (lines.length === 0) {
  fail(`OBSERVABILITY gate failed: no events found in ${eventsFile}.`);
}

const events = [];
for (const [idx, line] of lines.entries()) {
  try {
    events.push(JSON.parse(line));
  } catch (error) {
    fail(`OBSERVABILITY gate failed: malformed JSON at line ${idx + 1} in ${eventsFile}: ${String(error?.message || error)}`);
  }
}

const minEvents = Math.max(1, Math.floor(Number(argv.minEvents) || 1));
if (events.length < minEvents) {
  fail(`OBSERVABILITY gate failed: expected at least ${minEvents} events, found ${events.length}.`);
}

const countEvent = (eventName, toolName = '') => events.filter((event) => {
  const matchesName = String(event?.event || '') === eventName;
  if (!matchesName) {
    return false;
  }
  if (!toolName) {
    return true;
  }
  return String(event?.tool || '') === toolName;
}).length;

if (countEvent('run_start') === 0 || countEvent('run_end') === 0) {
  fail('OBSERVABILITY gate failed: required lifecycle events run_start/run_end were not both observed.');
}

const expectedTools = (argv.expectedTools || []).map((tool) => String(tool || '').trim()).filter(Boolean);
for (const tool of expectedTools) {
  if (countEvent('run_start', tool) === 0) {
    fail(`OBSERVABILITY gate failed: missing run_start event for tool "${tool}".`);
  }
  if (countEvent('run_end', tool) === 0) {
    fail(`OBSERVABILITY gate failed: missing run_end event for tool "${tool}".`);
  }
}

process.stdout.write(`${JSON.stringify({
  status: 'pass',
  events_file: eventsFile,
  total_events: events.length,
  run_start_count: countEvent('run_start'),
  run_end_count: countEvent('run_end'),
  expected_tools: expectedTools,
}, null, 2)}\n`);
