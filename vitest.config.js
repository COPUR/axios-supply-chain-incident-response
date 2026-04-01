import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.js'],
    coverage: {
      provider: 'v8',
      reportsDirectory: 'coverage',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/lib/**/*.js'],
      thresholds: {
        lines: 95,
        statements: 95,
        functions: 95,
        branches: 95,
      },
    },
  },
});
