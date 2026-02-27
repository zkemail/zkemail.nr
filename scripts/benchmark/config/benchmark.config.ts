/**
 * Global benchmark configuration for zkemail.nr
 */

import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const BENCHMARK_CONFIG = {
  // Number of proving runs for statistical significance
  numRuns: 3,

  // Warm-up runs (discarded before measurement)
  warmupRuns: 1,

  // Timeouts
  compileTimeoutMs: 30 * 60 * 1000, // 30 minutes per circuit
  gateCountTimeoutMs: 10 * 60 * 1000, // 10 minutes per gate count
  proveTimeoutMs: 30 * 60 * 1000, // 30 minutes per prove operation

  // Paths
  benchmarkDir: path.join(__dirname, '..'),
  circuitsDir: path.join(__dirname, '../circuits'),
  emailsDir: path.join(__dirname, '../emails'),
  keysDir: path.join(__dirname, '../keys'),
  inputsDir: path.join(__dirname, '../inputs'),
  resultsDir: path.join(__dirname, '../results'),

  // Path to the zkemail.nr JS source (for importing prover/input-gen)
  jsDir: path.join(__dirname, '../../../js'),

  // Path to the zkemail library (relative from generated circuit dirs)
  // Generated circuits are at: scripts/benchmark/circuits/<ID>/Nargo.toml
  // Library is at: lib/
  // Relative: ../../../../lib
  libRelativePath: '../../../../lib',

  // Absolute path to the zkemail.nr repo root
  repoRoot: path.join(__dirname, '../../..'),
};

// DKIM configuration (must match between key gen and email gen)
export const DKIM_CONFIG = {
  domain: 'benchmark.test',
  selector: 'dkim',
  signedHeaders: ['from', 'to', 'subject', 'date', 'message-id'],
};
