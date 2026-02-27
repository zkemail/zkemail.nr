/**
 * Compile Noir circuits and count gates using nargo + bb.
 *
 * For each generated circuit:
 *   1. `nargo compile --force --silence-warnings` → target/<name>.json
 *   2. `bb gates -b target/<name>.json` → gate count JSON
 *   3. `nargo info` → ACIR opcode count
 *
 * Usage: npx tsx lib/gate-counter.ts [--config CONFIG_ID]
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS, type NoirCircuitConfig } from '../config/circuits.config.js';

const CIRCUITS_DIR = BENCHMARK_CONFIG.circuitsDir;
const RESULTS_DIR = BENCHMARK_CONFIG.resultsDir;

export interface GateCountResult {
  configId: string;
  category: string;
  template: string;
  maxHeadersLength: number;
  maxBodyLength: number;
  rsaBits: number;
  acirOpcodes: number | null;
  backendCircuitSize: number | null;
  compileTimeMs: number;
  success: boolean;
  error?: string;
}

/**
 * Run a shell command with timeout and return combined stdout+stderr.
 * bb gates writes JSON to stdout and status to stderr, so we capture both.
 */
function run(cmd: string, cwd: string, timeoutMs: number): string {
  return execSync(cmd + ' 2>&1', {
    cwd,
    timeout: timeoutMs,
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: 50 * 1024 * 1024,
    shell: '/bin/bash',
  });
}

/**
 * Compile a circuit and get its gate count.
 */
export function compileAndCount(config: NoirCircuitConfig): GateCountResult {
  const circuitDir = path.join(CIRCUITS_DIR, config.id);
  const result: GateCountResult = {
    configId: config.id,
    category: config.category,
    template: config.template,
    maxHeadersLength: config.maxHeadersLength,
    maxBodyLength: config.maxBodyLength,
    rsaBits: config.rsaBits,
    acirOpcodes: null,
    backendCircuitSize: null,
    compileTimeMs: 0,
    success: false,
  };

  if (!fs.existsSync(path.join(circuitDir, 'Nargo.toml'))) {
    result.error = 'Circuit not generated (Nargo.toml missing)';
    return result;
  }

  // Step 1: Compile
  console.log(`  Compiling ${config.id}...`);
  const compileStart = performance.now();
  try {
    run('nargo compile --force --silence-warnings', circuitDir, BENCHMARK_CONFIG.compileTimeoutMs);
  } catch (err: any) {
    result.compileTimeMs = performance.now() - compileStart;
    result.error = `Compilation failed: ${err.message?.substring(0, 200)}`;
    return result;
  }
  result.compileTimeMs = performance.now() - compileStart;

  // Find the compiled artifact
  const targetDir = path.join(circuitDir, 'target');
  if (!fs.existsSync(targetDir)) {
    result.error = 'No target directory after compilation';
    return result;
  }

  const jsonFiles = fs.readdirSync(targetDir).filter(f => f.endsWith('.json'));
  if (jsonFiles.length === 0) {
    result.error = 'No compiled JSON artifact found in target/';
    return result;
  }
  const artifactPath = path.join(targetDir, jsonFiles[0]);

  // Step 2: Get backend gate count via `bb gates`
  console.log(`  Counting gates for ${config.id}...`);
  try {
    const gatesOutput = run(
      `bb gates -b "${artifactPath}"`,
      circuitDir,
      BENCHMARK_CONFIG.gateCountTimeoutMs
    );

    // Parse circuit_size from bb gates output
    // Output format: {"functions": [{"acir_opcodes": N, "circuit_size": M}]}
    const sizeMatch = gatesOutput.match(/"circuit_size"\s*:\s*(\d+)/);
    if (sizeMatch) {
      result.backendCircuitSize = parseInt(sizeMatch[1], 10);
    }

    // Also try to extract acir_opcodes from bb gates output (may differ from nargo info)
    const bbAcirMatch = gatesOutput.match(/"acir_opcodes"\s*:\s*(\d+)/);
    if (bbAcirMatch && result.acirOpcodes === null) {
      result.acirOpcodes = parseInt(bbAcirMatch[1], 10);
    }
  } catch (err: any) {
    result.error = `Gate counting failed: ${err.message?.substring(0, 200)}`;
    // Don't return — we still have compile time data
  }

  // Step 3: Get ACIR opcode count via `nargo info`
  try {
    const infoOutput = run('nargo info', circuitDir, BENCHMARK_CONFIG.gateCountTimeoutMs);

    // Parse ACIR opcodes from nargo info table output
    // Format: | Package | Function | Expression Width | ACIR Opcodes | Brillig Opcodes |
    // We want the row where Function = "main"
    const lines = infoOutput.split('\n');
    for (const line of lines) {
      const cells = line.split('|').map(c => c.trim()).filter(Boolean);
      // Look for the "main" function row (cell[1]) and parse ACIR Opcodes (cell[3])
      if (cells.length >= 4 && cells[1] === 'main') {
        const opcodes = parseInt(cells[3], 10);
        if (!isNaN(opcodes) && opcodes > 0) {
          result.acirOpcodes = opcodes;
          break;
        }
      }
    }
  } catch {
    // Non-fatal — we may still have gate count
  }

  result.success = result.backendCircuitSize !== null;
  return result;
}

/**
 * Capture system environment for reproducibility.
 */
function captureEnvironment(): Record<string, string> {
  const env: Record<string, string> = {
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    cpu: os.cpus()[0]?.model || 'unknown',
    cores: os.cpus().length.toString(),
    totalMemory: `${Math.round(os.totalmem() / (1024 * 1024 * 1024))}GB`,
    nodeVersion: process.version,
  };

  try {
    env.nargoVersion = execSync('nargo --version', { encoding: 'utf-8' }).trim();
  } catch {
    env.nargoVersion = 'unknown';
  }

  try {
    env.bbVersion = execSync('bb --version', { encoding: 'utf-8' }).trim();
  } catch {
    env.bbVersion = 'unknown';
  }

  return env;
}

/**
 * Run gate counting for all configs and save results.
 */
export async function runGateCounts(configs: NoirCircuitConfig[]): Promise<GateCountResult[]> {
  const results: GateCountResult[] = [];

  for (const config of configs) {
    const result = compileAndCount(config);
    results.push(result);

    if (result.success) {
      console.log(
        `  => ${config.id}: ${result.backendCircuitSize?.toLocaleString()} gates, ` +
        `${result.acirOpcodes?.toLocaleString() ?? '?'} ACIR opcodes, ` +
        `compiled in ${(result.compileTimeMs / 1000).toFixed(1)}s`
      );
    } else {
      console.log(`  => ${config.id}: FAILED — ${result.error}`);
    }
    console.log('');
  }

  return results;
}

/**
 * Save results to JSON file.
 */
export function saveResults(results: GateCountResult[]): string {
  fs.mkdirSync(RESULTS_DIR, { recursive: true });

  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputPath = path.join(RESULTS_DIR, `gates_${timestamp}.json`);

  const report = {
    timestamp: new Date().toISOString(),
    environment: captureEnvironment(),
    configs: results,
    summary: {
      total: results.length,
      succeeded: results.filter(r => r.success).length,
      failed: results.filter(r => !r.success).length,
    },
  };

  fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
  return outputPath;
}

/**
 * CLI entry point.
 */
async function main() {
  const args = process.argv.slice(2);

  let configs = ALL_CONFIGS;

  // Filter by specific config ID
  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    const targetId = args[configIdx + 1];
    configs = configs.filter(c => c.id === targetId);
    if (configs.length === 0) {
      console.error(`Config '${targetId}' not found. Available: ${ALL_CONFIGS.map(c => c.id).join(', ')}`);
      process.exit(1);
    }
  }

  // Filter by category
  if (args.includes('--scaling')) configs = configs.filter(c => c.category === 'scaling');
  if (args.includes('--rsa')) configs = configs.filter(c => c.category === 'rsa');
  if (args.includes('--features')) configs = configs.filter(c => c.category === 'features');
  if (args.includes('--precompute')) configs = configs.filter(c => c.category === 'precompute');

  console.log(`=== Noir Gate Count Benchmark ===\n`);
  console.log(`Configs: ${configs.length}`);
  console.log(`Environment: ${captureEnvironment().nargoVersion}, bb ${captureEnvironment().bbVersion}\n`);

  const results = await runGateCounts(configs);
  const outputPath = saveResults(results);

  console.log(`\n=== Results saved to ${outputPath} ===`);

  // Print summary table
  console.log('\n=== Summary ===\n');
  console.log('Config ID\t\tGates\t\tACIR Opcodes\tCompile Time');
  console.log('-'.repeat(80));
  for (const r of results) {
    if (r.success) {
      console.log(
        `${r.configId.padEnd(20)}\t${(r.backendCircuitSize?.toLocaleString() ?? '-').padEnd(12)}\t${(r.acirOpcodes?.toLocaleString() ?? '-').padEnd(12)}\t${(r.compileTimeMs / 1000).toFixed(1)}s`
      );
    } else {
      console.log(`${r.configId.padEnd(20)}\tFAILED\t\t-\t\t${r.error?.substring(0, 40)}`);
    }
  }
}

// Only run main when executed directly
if (process.argv[1]?.includes('gate-counter')) {
  main().catch(console.error);
}
