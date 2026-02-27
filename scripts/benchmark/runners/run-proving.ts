/**
 * Runner: Execute proving benchmarks for all configs.
 *
 * Assumes:
 *   1. Circuits have been compiled (via gate-count or nargo compile)
 *   2. Inputs have been generated (via generate-inputs)
 *
 * Usage:
 *   npm run benchmark:prove
 *   npm run benchmark:prove -- --config SCALE-3
 *   npm run benchmark:prove -- --backend all
 *   npm run benchmark:prove -- --scaling --backend honk
 */

import * as fs from 'fs';
import * as os from 'os';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS } from '../config/circuits.config.js';
import { runProvingBenchmarks, saveProvingResults } from '../lib/noir-prover.js';
import { loadLatestGateResults, loadLatestProvingResults, generateReport, saveReports } from '../lib/reporter.js';

type ProvingBackend = 'honk' | 'plonk';

async function main() {
  const args = process.argv.slice(2);

  let configs = ALL_CONFIGS;
  let backends: ProvingBackend[] = ['honk'];

  // Filter by config ID
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    const targetId = args[configIdx + 1];
    configs = configs.filter(c => c.id === targetId);
    if (configs.length === 0) {
      console.error(`Config '${targetId}' not found.`);
      process.exit(1);
    }
  }

  // Filter by category
  if (args.includes('--scaling')) configs = configs.filter(c => c.category === 'scaling');
  if (args.includes('--rsa')) configs = configs.filter(c => c.category === 'rsa');
  if (args.includes('--features')) configs = configs.filter(c => c.category === 'features');
  if (args.includes('--precompute')) configs = configs.filter(c => c.category === 'precompute');

  // Backend selection
  const backendIdx = args.indexOf('--backend');
  if (backendIdx !== -1 && args[backendIdx + 1]) {
    const b = args[backendIdx + 1];
    if (b === 'plonk') backends = ['plonk'];
    else if (b === 'honk') backends = ['honk'];
    else if (b === 'all') backends = ['plonk', 'honk'];
  }

  // Verify prerequisites
  const missingCircuits = configs.filter(c =>
    !fs.existsSync(`${BENCHMARK_CONFIG.circuitsDir}/${c.id}/target`)
  );
  if (missingCircuits.length > 0) {
    console.error(`Missing compiled circuits: ${missingCircuits.map(c => c.id).join(', ')}`);
    console.error('Run `npm run gate-count` first to compile circuits.');
    process.exit(1);
  }

  const missingInputs = configs.filter(c =>
    !fs.existsSync(`${BENCHMARK_CONFIG.inputsDir}/${c.id}.json`)
  );
  if (missingInputs.length > 0) {
    console.error(`Missing inputs: ${missingInputs.map(c => c.id).join(', ')}`);
    console.error('Run `npm run generate-inputs` first.');
    process.exit(1);
  }

  console.log('=== Noir Proving Benchmark ===\n');
  console.log(`Configs: ${configs.length}`);
  console.log(`Backends: ${backends.join(', ')}`);
  console.log(`Runs: ${BENCHMARK_CONFIG.warmupRuns} warmup + ${BENCHMARK_CONFIG.numRuns} measurement`);
  console.log(`Threads: ${os.cpus().length}\n`);

  // Run proving benchmarks
  const startTime = performance.now();
  const provingResults = await runProvingBenchmarks(
    configs, backends, BENCHMARK_CONFIG.numRuns, BENCHMARK_CONFIG.warmupRuns
  );
  const totalTime = performance.now() - startTime;

  // Save raw proving results
  const provingPath = saveProvingResults(provingResults);
  console.log(`\nProving results saved: ${provingPath}`);

  // Generate combined report if gate count results exist
  const gateResults = loadLatestGateResults();
  if (gateResults.length > 0) {
    const report = generateReport(gateResults, provingResults);
    const reportPaths = saveReports(report);
    console.log(`\nCombined reports saved:`);
    console.log(`  JSON: ${reportPaths.jsonPath}`);
    console.log(`  CSV:  ${reportPaths.csvPath}`);
    console.log(`  MD:   ${reportPaths.mdPath}`);
  }

  // Final summary
  const succeeded = provingResults.filter(r => r.success);
  console.log('\n' + '='.repeat(80));
  console.log(`COMPLETE: ${succeeded.length}/${provingResults.length} runs succeeded in ${(totalTime / 1000).toFixed(0)}s`);
  console.log('='.repeat(80));

  if (provingResults.some(r => !r.success)) process.exit(1);
}

main().catch(console.error);
