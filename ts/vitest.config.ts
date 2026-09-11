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
    // suite creates real CPU contention -- a single generation that
    // takes ~5s in isolation can exceed 15s under that load, which is a
    // genuine flake source, not a hang. 30s gives real headroom without
    // masking an actual hang (which would still show up as a real
    // timeout, just at 30s instead of 15s). Tests doing MULTIPLE full
    // generations in one `it()` still need their own explicit, longer
    // per-test timeout on top of this.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // fileParallelism: false -- forces test FILES to run one at a time
    // instead of vitest's default of spinning up multiple worker
    // threads to run many files concurrently. Added 2026-09-11 after
    // this exact RSA4096 suite growth caused real CI failures on
    // GitHub's standard runners (far fewer cores than a dev machine):
    // NOT plain per-test timeouts (which testTimeout above already
    // covers generously) but vitest's own internal worker-RPC heartbeat
    // ("[vitest-worker]: Timeout calling onTaskUpdate") -- i.e. the
    // worker process itself was so CPU-starved by SEVERAL files' worth
    // of simultaneous real prime searches that it couldn't even respond
    // to internal IPC pings in time. Since every RSA4096 test here is
    // CPU-bound, not I/O-bound, running test files concurrently doesn't
    // buy real throughput on a core-constrained runner anyway -- it
    // just causes contention. Running files sequentially trades wall-
    // clock time for the reliability a CI gate actually needs.
    fileParallelism: false,
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
