import path from 'node:path';
import { describe, expect, it } from 'vitest';

import { anonymizePath, buildRootAliases, sanitizeText } from '../src/lib/anonymize.js';

describe('anonymize helpers', () => {
  it('builds deterministic root aliases', () => {
    const aliases = buildRootAliases(['/tmp/b', '/tmp/a']);
    expect(aliases.get(path.resolve('/tmp/a'))).toBe('<SCAN_ROOT_1>');
    expect(aliases.get(path.resolve('/tmp/b'))).toBe('<SCAN_ROOT_2>');
  });

  it('sanitizes known roots and usernames', () => {
    const aliases = new Map([[path.resolve('/tmp/repo'), '<SCAN_ROOT_1>']]);
    const sanitized = sanitizeText('/tmp/repo/file /Users/alice/secrets /home/bob/.env', aliases);

    expect(sanitized).toContain('<SCAN_ROOT_1>/file');
    expect(sanitized).toContain('/Users/<redacted>/secrets');
    expect(sanitized).toContain('/home/<redacted>/.env');
  });

  it('anonymizes paths relative to repository root', () => {
    const repoRoot = path.resolve('/tmp/project');
    const filePath = path.join(repoRoot, 'sub', 'file.txt');

    const anonymized = anonymizePath(filePath, repoRoot, '<REPO_1>');
    expect(anonymized).toBe('<REPO_1>/sub/file.txt');
    expect(anonymizePath(repoRoot, repoRoot, '<REPO_1>')).toBe('<REPO_1>');
  });

  it('falls back to sanitized text for non-repo paths', () => {
    const result = anonymizePath('/Users/alice/random.txt', '/tmp/repo', '<REPO_1>');
    expect(result).toBe('/Users/<redacted>/random.txt');
  });
});
