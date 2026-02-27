/**
 * Noir proving benchmark harness.
 *
 * Uses ZKEmailProver (bb.js WASM backend) for witness generation, proving,
 * and verification. Memory is measured via process.memoryUsage().rss delta.
 *
 * Usage: npx tsx lib/noir-prover.ts [--config CONFIG_ID] [--backend honk|plonk]
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS, type NoirCircuitConfig } from '../config/circuits.config.js';

// Dynamic import for CJS/ESM interop with the JS prover package
const proverModulePath = new URL('../../../js/src/prover.ts', import.meta.url).pathname;
const { ZKEmailProver } = await import(proverModulePath);

type ProvingBackend = 'honk' | 'plonk';

export interface ProvingResult {
  configId: string;
  run: number;
  backend: ProvingBackend;
  witnessGenTimeMs: number;
  provingTimeMs: number;
  /** Peak RSS delta during proving in megabytes */
  provingMemoryMb?: number;
  verificationTimeMs: number;
  proofSize: number;
  success: boolean;
  error?: string;
}

/**
 * Load the compiled circuit JSON artifact for a given config.
 */
function loadCircuit(configId: string): any {
  const circuitDir = path.join(BENCHMARK_CONFIG.circuitsDir, configId);
  const targetDir = path.join(circuitDir, 'target');

  if (!fs.existsSync(targetDir)) {
    throw new Error(`No target directory for ${configId}. Run gate-count first to compile.`);
  }

  const jsonFiles = fs.readdirSync(targetDir).filter(f => f.endsWith('.json'));
  if (jsonFiles.length === 0) {
    throw new Error(`No compiled artifact for ${configId} in ${targetDir}`);
  }

  const artifactPath = path.join(targetDir, jsonFiles[0]);
  return JSON.parse(fs.readFileSync(artifactPath, 'utf-8'));
}

/**
 * Load pre-generated inputs for a config.
 */
function loadInputs(configId: string): any {
  const inputsPath = path.join(BENCHMARK_CONFIG.inputsDir, `${configId}.json`);
  if (!fs.existsSync(inputsPath)) {
    throw new Error(`Inputs not found for ${configId}. Run generate-inputs first.`);
  }
  return JSON.parse(fs.readFileSync(inputsPath, 'utf-8'));
}

// ─── Core benchmark ──────────────────────────────────────────────────────────

/**
 * Run a single proving benchmark: witness gen + prove + verify (all in-process via bb.js).
 */
async function runSingleProve(
  prover: InstanceType<typeof ZKEmailProver>,
  inputs: any,
  backend: ProvingBackend,
): Promise<{ witnessGenTimeMs: number; provingTimeMs: number; provingMemoryMb: number; verificationTimeMs: number; proofSize: number }> {
  // Phase 1: Witness generation (Noir JS/WASM)
  const witnessStart = performance.now();
  const { witness } = await prover.simulateWitness(inputs);
  const witnessGenTimeMs = performance.now() - witnessStart;

  // Phase 2: Proving (bb.js WASM) with RSS delta for memory
  if (global.gc) global.gc();
  const rssBefore = process.memoryUsage().rss;

  const proveStart = performance.now();
  const proof = await prover.prove(witness, backend);
  const provingTimeMs = performance.now() - proveStart;

  const rssAfter = process.memoryUsage().rss;
  const provingMemoryMb = Math.max(0, (rssAfter - rssBefore) / (1024 * 1024));

  // Phase 3: Verification (bb.js WASM)
  const verifyStart = performance.now();
  const valid = await prover.verify(proof, backend);
  const verificationTimeMs = performance.now() - verifyStart;

  if (!valid) {
    throw new Error('Verification failed: proof is invalid');
  }

  // Proof size from the proof bytes
  const proofSize = proof.proof.length;

  return { witnessGenTimeMs, provingTimeMs, provingMemoryMb, verificationTimeMs, proofSize };
}

/**
 * Run proving benchmarks for a single config + backend combination.
 */
async function benchmarkConfig(
  config: NoirCircuitConfig,
  backend: ProvingBackend,
  numRuns: number,
  warmupRuns: number,
): Promise<ProvingResult[]> {
  const results: ProvingResult[] = [];
  const threads = os.cpus().length;

  console.log(`\n  [${config.id}/${backend}] Loading circuit & inputs...`);
  const circuit = loadCircuit(config.id);
  const inputs = loadInputs(config.id);

  // Create prover with the specific backend
  const prover = new ZKEmailProver(circuit, backend, threads);

  try {
    // Warmup runs (discarded)
    for (let w = 0; w < warmupRuns; w++) {
      console.log(`  [${config.id}/${backend}] Warmup run ${w + 1}/${warmupRuns}...`);
      try {
        await runSingleProve(prover, inputs, backend);
      } catch (err: any) {
        console.log(`  [${config.id}/${backend}] Warmup failed: ${err.message}`);
      }
    }

    // Measurement runs
    for (let run = 1; run <= numRuns; run++) {
      try {
        const timing = await runSingleProve(prover, inputs, backend);

        console.log(
          `  [${config.id}/${backend}] Run ${run}: ` +
          `witness=${(timing.witnessGenTimeMs / 1000).toFixed(1)}s, ` +
          `prove=${(timing.provingTimeMs / 1000).toFixed(1)}s, ` +
          `mem=${timing.provingMemoryMb.toFixed(0)}MB, ` +
          `verify=${timing.verificationTimeMs.toFixed(0)}ms, ` +
          `proof=${timing.proofSize}B`
        );

        results.push({
          configId: config.id,
          run,
          backend,
          witnessGenTimeMs: timing.witnessGenTimeMs,
          provingTimeMs: timing.provingTimeMs,
          provingMemoryMb: timing.provingMemoryMb,
          verificationTimeMs: timing.verificationTimeMs,
          proofSize: timing.proofSize,
          success: true,
        });
      } catch (err: any) {
        console.log(`  [${config.id}/${backend}] Run ${run}: FAILED — ${err.message}`);
        results.push({
          configId: config.id,
          run,
          backend,
          witnessGenTimeMs: 0,
          provingTimeMs: 0,
          provingMemoryMb: 0,
          verificationTimeMs: 0,
          proofSize: 0,
          success: false,
          error: err.message,
        });
      }
    }
  } finally {
    await prover.destroy();
  }

  return results;
}

/**
 * Run proving benchmarks for multiple configs.
 */
export async function runProvingBenchmarks(
  configs: NoirCircuitConfig[],
  backends: ProvingBackend[] = ['honk'],
  numRuns: number = BENCHMARK_CONFIG.numRuns,
  warmupRuns: number = BENCHMARK_CONFIG.warmupRuns,
): Promise<ProvingResult[]> {
  const allResults: ProvingResult[] = [];

  for (const config of configs) {
    for (const backend of backends) {
      const results = await benchmarkConfig(config, backend, numRuns, warmupRuns);
      allResults.push(...results);
    }
  }

  return allResults;
}

/**
 * Save proving results to JSON.
 */
export function saveProvingResults(results: ProvingResult[]): string {
  const resultsDir = BENCHMARK_CONFIG.resultsDir;
  fs.mkdirSync(resultsDir, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputPath = path.join(resultsDir, `proving_${timestamp}.json`);

  const report = {
    timestamp: new Date().toISOString(),
    environment: captureEnvironment(),
    results,
    summary: {
      total: results.length,
      succeeded: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
    },
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  return outputPath;
}

function captureEnvironment(): Record<string, string | number> {
  return {
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    cpu: os.cpus()[0]?.model || 'unknown',
    cores: os.cpus().length,
    totalMemoryGb: Math.round(os.totalmem() / (1024 * 1024 * 1024)),
    nodeVersion: process.version,
    threads: os.cpus().length,
  };
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  let configs = ALL_CONFIGS;
  let backends: ProvingBackend[] = ['honk'];

  // Filter by config
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
  if (args.includes('--backend')) {
    const backendIdx = args.indexOf('--backend');
    const b = args[backendIdx + 1];
    if (b === 'plonk') backends = ['plonk'];
    else if (b === 'honk') backends = ['honk'];
    else if (b === 'all') backends = ['plonk', 'honk'];
    else {
      console.error(`Unknown backend: ${b}. Use plonk, honk, or all.`);
      process.exit(1);
    }
  }

  console.log(`=== Noir Proving Benchmark ===`);
  console.log(`Configs: ${configs.length}`);
  console.log(`Backends: ${backends.join(', ')}`);
  console.log(`Runs: ${BENCHMARK_CONFIG.warmupRuns} warmup + ${BENCHMARK_CONFIG.numRuns} measurement`);
  console.log(`Threads: ${os.cpus().length}`);

  const startTime = performance.now();
  const results = await runProvingBenchmarks(configs, backends);
  const totalTime = performance.now() - startTime;

  const outputPath = saveProvingResults(results);

  // Summary
  const succeeded = results.filter(r => r.success);
  const failed = results.filter(r => !r.success);

  console.log('\n' + '='.repeat(80));
  console.log('SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total runs: ${results.length} (${succeeded.length} OK, ${failed.length} FAILED)`);
  console.log(`Total time: ${(totalTime / 1000).toFixed(1)}s`);
  console.log(`Results: ${outputPath}`);

  if (succeeded.length > 0) {
    // Print per-config summary
    const byConfig = new Map<string, ProvingResult[]>();
    for (const r of succeeded) {
      const key = `${r.configId}/${r.backend}`;
      if (!byConfig.has(key)) byConfig.set(key, []);
      byConfig.get(key)!.push(r);
    }

    console.log('\nConfig/Backend\t\t\tWitness(med)\tProve(med)\tVerify(med)\tProof Size');
    console.log('-'.repeat(100));
    for (const [key, runs] of byConfig) {
      const wTimes = runs.map(r => r.witnessGenTimeMs).sort((a, b) => a - b);
      const pTimes = runs.map(r => r.provingTimeMs).sort((a, b) => a - b);
      const vTimes = runs.map(r => r.verificationTimeMs).sort((a, b) => a - b);
      const medianW = wTimes[Math.floor(wTimes.length / 2)];
      const medianP = pTimes[Math.floor(pTimes.length / 2)];
      const medianV = vTimes[Math.floor(vTimes.length / 2)];
      console.log(
        `${key.padEnd(28)}\t${(medianW / 1000).toFixed(2)}s\t\t${(medianP / 1000).toFixed(2)}s\t\t${medianV.toFixed(0)}ms\t\t${runs[0].proofSize}B`
      );
    }
  }

  if (failed.length > 0) process.exit(1);
}

if (process.argv[1]?.includes('noir-prover')) {
  main().catch(console.error);
}
