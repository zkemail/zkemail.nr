/**
 * Runner: Compile all benchmark circuits and count gates.
 *
 * Assumes circuits have already been generated via `npm run generate-circuits`.
 *
 * Usage:
 *   npm run gate-count
 *   npm run gate-count -- --config SCALE-3
 *   npm run gate-count -- --scaling
 */

import * as fs from 'fs';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS } from '../config/circuits.config.js';
import { runGateCounts, saveResults } from '../lib/gate-counter.js';

async function main() {
  const args = process.argv.slice(2);

  // Check that circuits exist
  if (!fs.existsSync(BENCHMARK_CONFIG.circuitsDir)) {
    console.error('Circuits directory not found. Run `npm run generate-circuits` first.');
    process.exit(1);
  }

  let configs = ALL_CONFIGS;

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

  // Verify selected circuits are generated
  const missing = configs.filter(c =>
    !fs.existsSync(`${BENCHMARK_CONFIG.circuitsDir}/${c.id}/Nargo.toml`)
  );
  if (missing.length > 0) {
    console.error(`Missing circuits: ${missing.map(c => c.id).join(', ')}`);
    console.error('Run `npm run generate-circuits` first.');
    process.exit(1);
  }

  console.log('=== Noir Gate Count Benchmark ===\n');
  console.log(`Circuits to compile: ${configs.length}`);
  console.log(`Output: ${BENCHMARK_CONFIG.resultsDir}\n`);

  const startTime = performance.now();
  const results = await runGateCounts(configs);
  const totalTime = performance.now() - startTime;

  const outputPath = saveResults(results);

  // Final summary
  const succeeded = results.filter(r => r.success);
  const failed = results.filter(r => !r.success);

  console.log('\n' + '='.repeat(80));
  console.log('FINAL SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total configs: ${configs.length}`);
  console.log(`Succeeded: ${succeeded.length}`);
  console.log(`Failed: ${failed.length}`);
  console.log(`Total time: ${(totalTime / 1000).toFixed(1)}s`);
  console.log(`Results: ${outputPath}`);

  if (succeeded.length > 0) {
    const gates = succeeded.map(r => r.backendCircuitSize!);
    console.log(`\nGate count range: ${Math.min(...gates).toLocaleString()} — ${Math.max(...gates).toLocaleString()}`);
  }

  if (failed.length > 0) {
    console.log('\nFailed configs:');
    for (const r of failed) {
      console.log(`  ${r.configId}: ${r.error}`);
    }
    process.exit(1);
  }
}

main().catch(console.error);
