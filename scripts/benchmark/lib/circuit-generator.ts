/**
 * Generate Noir benchmark circuits by templating existing examples.
 *
 * For each benchmark config, generates:
 *   circuits/<CONFIG_ID>/Nargo.toml
 *   circuits/<CONFIG_ID>/src/main.nr
 *
 * The circuit source is derived from the existing example circuits in
 * zkemail.nr/examples/, with MAX_EMAIL_HEADER_LENGTH and MAX_EMAIL_BODY_LENGTH
 * substituted from the config.
 *
 * Usage: pnpm run generate-circuits
 */

import * as fs from 'fs';
import * as path from 'path';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS, type NoirCircuitConfig, type CircuitTemplate } from '../config/circuits.config.js';

const CIRCUITS_DIR = BENCHMARK_CONFIG.circuitsDir;

/**
 * Map circuit template names to their example directories.
 */
const TEMPLATE_TO_EXAMPLE: Record<CircuitTemplate, string> = {
  'verify_email': 'verify_email_2048_bit_dkim',
  'partial_hash': 'partial_hash',
  'email_mask': 'email_mask',
  'extract_addresses': 'extract_addresses',
};

/**
 * For RSA-1024, the verify_email template uses a different example.
 */
function getExampleDir(config: NoirCircuitConfig): string {
  if (config.template === 'verify_email' && config.rsaBits === 1024) {
    return 'verify_email_1024_bit_dkim';
  }
  return TEMPLATE_TO_EXAMPLE[config.template];
}

/**
 * Generate the Nargo.toml content for a benchmark circuit.
 *
 * Key concern: the dependency path to the library must be correct relative
 * to the generated circuit's location.
 *
 * Circuit location: scripts/benchmark/circuits/<ID>/Nargo.toml
 * Library location: lib/
 * Relative path:    ../../../../lib
 */
function generateNargoToml(config: NoirCircuitConfig): string {
  const name = `bench_${config.id.toLowerCase().replace(/-/g, '_')}`;

  // Read the example's Nargo.toml to pick up any extra dependencies
  const exampleDir = getExampleDir(config);
  const exampleToml = fs.readFileSync(
    path.join(BENCHMARK_CONFIG.repoRoot, 'examples', exampleDir, 'Nargo.toml'),
    'utf-8'
  );

  // Extract non-zkemail dependencies (sha256, etc.)
  const extraDeps: string[] = [];
  for (const line of exampleToml.split('\n')) {
    const trimmed = line.trim();
    // Include any dependency line that is NOT zkemail
    if (trimmed.startsWith('sha256') || trimmed.startsWith('poseidon') || trimmed.startsWith('nodash')) {
      extraDeps.push(trimmed);
    }
  }

  const lines = [
    '[package]',
    `name = "${name}"`,
    'type = "bin"',
    'compiler_version = ">=1.0.0"',
    '',
    '[dependencies]',
    `zkemail = { path = "${BENCHMARK_CONFIG.libRelativePath}" }`,
    ...extraDeps,
  ];

  return lines.join('\n') + '\n';
}

/**
 * Generate the main.nr content for a benchmark circuit.
 *
 * Reads the corresponding example's main.nr and replaces the global constants
 * with the config's values.
 */
function generateMainNr(config: NoirCircuitConfig): string {
  const exampleDir = getExampleDir(config);
  const exampleMainPath = path.join(
    BENCHMARK_CONFIG.repoRoot, 'examples', exampleDir, 'src', 'main.nr'
  );

  let source = fs.readFileSync(exampleMainPath, 'utf-8');

  // Replace MAX_EMAIL_HEADER_LENGTH
  source = source.replace(
    /global MAX_EMAIL_HEADER_LENGTH:\s*u32\s*=\s*\d+;/,
    `global MAX_EMAIL_HEADER_LENGTH: u32 = ${config.maxHeadersLength};`
  );

  // Replace MAX_EMAIL_BODY_LENGTH (if present — extract_addresses doesn't have it)
  if (config.maxBodyLength > 0) {
    source = source.replace(
      /global MAX_EMAIL_BODY_LENGTH:\s*u32\s*=\s*\d+;/,
      `global MAX_EMAIL_BODY_LENGTH: u32 = ${config.maxBodyLength};`
    );
  }

  // For partial_hash, replace MAX_PARTIAL_EMAIL_BODY_LENGTH
  if (config.template === 'partial_hash') {
    source = source.replace(
      /global MAX_PARTIAL_EMAIL_BODY_LENGTH:\s*u32\s*=\s*\d+;/,
      `global MAX_PARTIAL_EMAIL_BODY_LENGTH: u32 = ${config.maxBodyLength};`
    );
  }

  // For RSA-1024, the source already uses KEY_LIMBS_1024 from the 1024 example.
  // For RSA-2048 with verify_email template, source uses KEY_LIMBS_2048.
  // No substitution needed — we pick the right example file.

  return source;
}

/**
 * Generate a single benchmark circuit directory.
 */
function generateCircuit(config: NoirCircuitConfig): string {
  const circuitDir = path.join(CIRCUITS_DIR, config.id);
  const srcDir = path.join(circuitDir, 'src');

  fs.mkdirSync(srcDir, { recursive: true });

  // Write Nargo.toml
  const nargoToml = generateNargoToml(config);
  fs.writeFileSync(path.join(circuitDir, 'Nargo.toml'), nargoToml);

  // Write main.nr
  const mainNr = generateMainNr(config);
  fs.writeFileSync(path.join(srcDir, 'main.nr'), mainNr);

  return circuitDir;
}

/**
 * Validate that a generated circuit's Nargo.toml can resolve its dependencies.
 */
function validateCircuit(config: NoirCircuitConfig): { valid: boolean; error?: string } {
  const circuitDir = path.join(CIRCUITS_DIR, config.id);
  const nargoToml = path.join(circuitDir, 'Nargo.toml');

  if (!fs.existsSync(nargoToml)) {
    return { valid: false, error: 'Nargo.toml not found' };
  }

  // Check that the library path resolves
  const libPath = path.resolve(circuitDir, BENCHMARK_CONFIG.libRelativePath);
  const libNargoToml = path.join(libPath, 'Nargo.toml');

  if (!fs.existsSync(libNargoToml)) {
    return {
      valid: false,
      error: `Library not found at resolved path: ${libPath} (from ${BENCHMARK_CONFIG.libRelativePath})`,
    };
  }

  // Check that main.nr exists
  if (!fs.existsSync(path.join(circuitDir, 'src', 'main.nr'))) {
    return { valid: false, error: 'src/main.nr not found' };
  }

  return { valid: true };
}

async function main() {
  console.log('=== Generating Noir Benchmark Circuits ===\n');

  // Filter by category if specified
  const args = process.argv.slice(2);
  let configs = ALL_CONFIGS;

  if (args.includes('--scaling')) {
    configs = configs.filter(c => c.category === 'scaling');
  } else if (args.includes('--rsa')) {
    configs = configs.filter(c => c.category === 'rsa');
  } else if (args.includes('--features')) {
    configs = configs.filter(c => c.category === 'features');
  } else if (args.includes('--precompute')) {
    configs = configs.filter(c => c.category === 'precompute');
  }

  console.log(`Generating ${configs.length} circuits...\n`);
  console.log('ID\t\t\tTemplate\t\t\tHeaders\tBody\tRSA\tStatus');
  console.log('-'.repeat(100));

  let generated = 0;
  let failed = 0;

  for (const config of configs) {
    try {
      generateCircuit(config);
      const validation = validateCircuit(config);

      if (!validation.valid) {
        console.log(
          `${config.id.padEnd(20)}\t${config.template.padEnd(28)}\t${config.maxHeadersLength}\t${config.maxBodyLength}\t${config.rsaBits}\tFAIL: ${validation.error}`
        );
        failed++;
        continue;
      }

      console.log(
        `${config.id.padEnd(20)}\t${config.template.padEnd(28)}\t${config.maxHeadersLength}\t${config.maxBodyLength}\t${config.rsaBits}\tOK`
      );
      generated++;
    } catch (err: any) {
      console.log(
        `${config.id.padEnd(20)}\t${config.template.padEnd(28)}\t${config.maxHeadersLength}\t${config.maxBodyLength}\t${config.rsaBits}\tERROR: ${err.message}`
      );
      failed++;
    }
  }

  console.log('-'.repeat(100));
  console.log(`\nGenerated: ${generated}, Failed: ${failed}`);
  console.log(`Output: ${CIRCUITS_DIR}`);
}

main().catch(console.error);
