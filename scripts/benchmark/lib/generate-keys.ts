/**
 * Generate RSA key pairs for DKIM signing.
 * Adapted from zk-email-verify/scripts/benchmark/lib/generate-keys.ts
 *
 * Usage: pnpm run generate-keys
 */

import { execSync } from 'child_process';
import * as fs from 'fs';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';

const KEYS_DIR = BENCHMARK_CONFIG.keysDir;
const KEY_SIZES = [1024, 2048];

function main() {
  console.log('=== Generating RSA Key Pairs ===\n');

  fs.mkdirSync(KEYS_DIR, { recursive: true });

  for (const bits of KEY_SIZES) {
    const privKeyPath = `${KEYS_DIR}/dkim_${bits}.pem`;
    const pubKeyPath = `${KEYS_DIR}/dkim_${bits}_pub.pem`;

    console.log(`Generating RSA-${bits} key pair...`);
    execSync(`openssl genrsa -out "${privKeyPath}" ${bits} 2>/dev/null`);
    execSync(`openssl rsa -in "${privKeyPath}" -pubout -out "${pubKeyPath}" 2>/dev/null`);

    console.log(`  Private: ${privKeyPath}`);
    console.log(`  Public:  ${pubKeyPath}`);
  }

  console.log('\n=== Keys Generated ===');
}

main();
