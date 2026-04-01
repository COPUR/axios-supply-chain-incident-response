#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';

import { generateInsights } from '../src/lib/self-improve.js';

const argv = await yargs(hideBin(process.argv))
  .option('events-file', {
    type: 'string',
    default: process.env.OBSERVABILITY_EVENTS_FILE || '.observability/events.ndjson',
    describe: 'Path to observability event log (NDJSON)',
  })
  .option('output', {
    type: 'string',
    default: '',
    describe: 'Optional output markdown file path',
  })
  .strict()
  .parse();

const insights = await generateInsights(path.resolve(String(argv.eventsFile)));
if (argv.output) {
  await fs.writeFile(path.resolve(String(argv.output)), insights.markdown, 'utf8');
} else {
  process.stdout.write(insights.markdown);
}
