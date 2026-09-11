import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'src/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    // 2026-09-11: raised from 15s. The RSA4096 suite now has enough
    // individually-expensive (multi-second, real prime-search) tests
    // across enough files (rsa4096.test.ts, indexed.test.ts,
    // batch.test.ts, indexed-corpus.test.ts) that running the full
    // suite creates real CPU contention across parallel test-file
    // workers -- a single generation that takes ~5s in isolation can
    // exceed 15s under that load, which is a genuine flake source, not
    // a hang. 30s gives real headroom without masking an actual hang
    // (which would still show up as a real timeout, just at 30s instead
    // of 15s). Tests doing MULTIPLE full generations in one `it()` still
    // need their own explicit, longer per-test timeout on top of this.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
  },
});
