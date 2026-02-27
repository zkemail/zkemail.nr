/**
 * Generate circuit inputs for all benchmark configs.
 *
 * Constructs DKIMVerificationResult manually from synthetic emails
 * (bypassing DNS lookup) and calls generateEmailVerifierInputsFromDKIMResult.
 *
 * Usage: npx tsx lib/input-generator.ts [--config CONFIG_ID]
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import forge from 'node-forge';
import { BENCHMARK_CONFIG, DKIM_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS, type NoirCircuitConfig } from '../config/circuits.config.js';

// Import from the JS package source — deps resolve from js/node_modules/
// Dynamic import for CJS/ESM interop — js/ package has no "type" field (CJS default)
const jsIndexPath = new URL('../../../js/src/index.ts', import.meta.url).pathname;
const zkemailModule = await import(jsIndexPath);
const generateEmailVerifierInputsFromDKIMResult = zkemailModule.generateEmailVerifierInputsFromDKIMResult;

const EMAILS_DIR = `${BENCHMARK_CONFIG.emailsDir}/synthetic`;
const KEYS_DIR = BENCHMARK_CONFIG.keysDir;
const INPUTS_DIR = BENCHMARK_CONFIG.inputsDir;

// ─── Email catalog (matches generate-signed-emails.ts output) ────────────────

interface EmailInfo {
  filename: string;
  bodySize: number;
  headerSize: number;
  rsaBits: 1024 | 2048;
}

const AVAILABLE_EMAILS: EmailInfo[] = [
  { filename: 'email_h384_b192_rsa2048.eml', bodySize: 192, headerSize: 384, rsaBits: 2048 },
  { filename: 'email_h384_b256_rsa2048.eml', bodySize: 256, headerSize: 384, rsaBits: 2048 },
  { filename: 'email_h512_b512_rsa2048.eml', bodySize: 512, headerSize: 512, rsaBits: 2048 },
  { filename: 'email_h512_b768_rsa1024.eml', bodySize: 768, headerSize: 512, rsaBits: 1024 },
  { filename: 'email_h512_b768_rsa2048.eml', bodySize: 768, headerSize: 512, rsaBits: 2048 },
  { filename: 'email_h1024_b1024_rsa2048.eml', bodySize: 1024, headerSize: 1024, rsaBits: 2048 },
  { filename: 'email_h1024_b2048_rsa2048.eml', bodySize: 2048, headerSize: 1024, rsaBits: 2048 },
  { filename: 'email_h2048_b4096_rsa2048.eml', bodySize: 4096, headerSize: 2048, rsaBits: 2048 },
];

// ─── DKIM parsing helpers ────────────────────────────────────────────────────

interface ParsedDKIM {
  v: string;
  a: string;
  c: string;
  d: string;
  s: string;
  t?: string;
  bh: string;
  h: string;
  b: string;
}

function parseDKIMSignature(dkimLine: string): ParsedDKIM {
  const value = dkimLine.replace(/^DKIM-Signature:\s*/i, '');
  const normalized = value.replace(/\r?\n\s+/g, '');
  const parts: Record<string, string> = {};
  for (const part of normalized.split(/;\s*/)) {
    const [key, ...vals] = part.split('=');
    if (key && vals.length) {
      parts[key.trim()] = vals.join('=').trim();
    }
  }
  return parts as unknown as ParsedDKIM;
}

function canonicalizeHeadersRelaxed(headers: string): string {
  return headers
    .split('\r\n')
    .map(line => {
      line = line.replace(/\s+/g, ' ').trim();
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) return line;
      const name = line.substring(0, colonIdx).trim().toLowerCase();
      const value = line.substring(colonIdx + 1).trim();
      return `${name}:${value}`;
    })
    .join('\r\n');
}

function canonicalizeBodyRelaxed(body: string): string {
  let result = body
    .split('\r\n')
    .map(line => line.replace(/\s+/g, ' ').replace(/\s+$/, ''))
    .join('\r\n');
  result = result.replace(/(\r\n)+$/, '');
  if (result.length > 0) result += '\r\n';
  return result;
}

// ─── DKIMVerificationResult construction ─────────────────────────────────────

interface DKIMVerificationResult {
  publicKey: bigint;
  signature: bigint;
  headers: Buffer;
  body: Buffer;
  bodyHash: string;
  signingDomain: string;
  selector: string;
  algo: string;
  format: string;
  modulusLength: number;
}

function constructDKIMResult(emailContent: string, rsaBits: 1024 | 2048): DKIMVerificationResult {
  // Normalize line endings
  const normalized = emailContent.replace(/\r?\n/g, '\r\n');
  const separatorIdx = normalized.indexOf('\r\n\r\n');
  const headerSection = normalized.substring(0, separatorIdx);
  const bodySection = normalized.substring(separatorIdx + 4);

  const headerLines = headerSection.split('\r\n');

  // Find and parse DKIM-Signature
  // Handle folded headers: DKIM-Signature may span multiple lines
  let dkimLine = '';
  let inDkim = false;
  for (const line of headerLines) {
    if (line.toLowerCase().startsWith('dkim-signature:')) {
      inDkim = true;
      dkimLine = line;
    } else if (inDkim && /^\s/.test(line)) {
      dkimLine += '\r\n' + line;
    } else {
      inDkim = false;
    }
  }

  if (!dkimLine) {
    throw new Error('No DKIM-Signature header found');
  }

  const dkim = parseDKIMSignature(dkimLine);

  // Build signed headers: the headers listed in h= tag + DKIM-Signature (with b= stripped)
  const signedHeaderNames = dkim.h.split(':').map(h => h.trim().toLowerCase());
  const headersToSign: string[] = [];

  for (const hName of signedHeaderNames) {
    const found = headerLines.find(line =>
      line.toLowerCase().startsWith(hName + ':')
    );
    if (found) headersToSign.push(found);
  }

  // Strip the b= value from DKIM-Signature for signing
  const dkimWithoutSig = dkimLine.replace(/b=[A-Za-z0-9+/=\s]+$/, 'b=');
  headersToSign.push(dkimWithoutSig);

  // Canonicalize headers (relaxed)
  const canonHeaders = canonicalizeHeadersRelaxed(headersToSign.join('\r\n'));

  // Canonicalize body (relaxed)
  const canonBody = canonicalizeBodyRelaxed(bodySection);

  // Read public key and convert modulus to bigint
  const pubKeyPem = fs.readFileSync(path.join(KEYS_DIR, `dkim_${rsaBits}_pub.pem`), 'utf-8');
  const pubKeyAsn1 = forge.pki.publicKeyFromPem(pubKeyPem);
  const modulusHex = (pubKeyAsn1 as any).n.toString(16);
  const publicKey = BigInt('0x' + modulusHex);

  // Convert DKIM signature to bigint
  const sigBase64 = dkim.b.replace(/\s/g, '');
  const sigBytes = Buffer.from(sigBase64, 'base64');
  const signature = BigInt('0x' + sigBytes.toString('hex'));

  return {
    publicKey,
    signature,
    headers: Buffer.from(canonHeaders),
    body: Buffer.from(canonBody),
    bodyHash: dkim.bh,
    signingDomain: dkim.d,
    selector: dkim.s,
    algo: 'rsa-sha256',
    format: 'rs',
    modulusLength: rsaBits,
  };
}

// ─── Email selection ─────────────────────────────────────────────────────────

/** SHA-256 padded size for a given input length */
function shaPaddedSize(len: number): number {
  return Math.ceil((len + 9) / 64) * 64;
}

/**
 * Select the best email for a given circuit config.
 * For body-aware configs: find the largest email whose body SHA-pads within maxBodyLength.
 * For partial_hash with sourceEmailBodySize: match against the source email body size
 * to ensure all precompute configs use the same underlying email.
 */
function selectEmail(config: NoirCircuitConfig): EmailInfo {
  const matching = AVAILABLE_EMAILS.filter(e => e.rsaBits === config.rsaBits);

  if (config.template === 'extract_addresses') {
    // Header-only — any matching email works
    return matching.find(e => e.rsaBits === config.rsaBits)!;
  }

  // When sourceEmailBodySize is set, match against that instead of maxBodyLength.
  // This ensures all precompute configs use the same underlying email.
  const effectiveMaxBody = config.sourceEmailBodySize
    ? Math.floor((config.sourceEmailBodySize + 63 + 65) / 64) * 64
    : config.maxBodyLength;

  // Find largest email whose body SHA-pads within the effective limit
  const suitable = matching
    .filter(e => shaPaddedSize(e.bodySize) <= effectiveMaxBody)
    .sort((a, b) => b.bodySize - a.bodySize);

  if (suitable.length === 0) {
    throw new Error(
      `No email fits config ${config.id} (maxBody=${effectiveMaxBody}, RSA=${config.rsaBits}). ` +
      `Smallest SHA-padded body: ${shaPaddedSize(matching[0]?.bodySize || 0)}`
    );
  }

  return suitable[0];
}

// ─── Selector finding for partial_hash ───────────────────────────────────────

/**
 * Extract a selector from the body buffer at a fractional position (0–1).
 *
 * Uses a raw byte substring (not word-aligned) to avoid triggering the
 * naive non-backtracking bug in @zk-email/helpers' findIndexInUint8Array,
 * which misses matches when a partial match prefix overlaps the real match
 * (e.g., "labore labore tempor" — the first "labore " partial match causes
 * the search to skip past the second "labore" where the real match starts).
 *
 * Extracts a 16–32 byte substring at the cutoff-aligned position and verifies
 * it is found by the same buggy search that generatePartialSHA will use.
 */
function extractSelectorAtPosition(body: Buffer, position: number): string {
  const target = Math.floor(body.length * Math.max(0, Math.min(1, position)));
  // Snap to 64-byte block boundary (SHA-256 block size) since generatePartialSHA
  // will floor the found index to a 64-byte boundary anyway.
  const cutoff = Math.floor(target / 64) * 64;

  // Try increasing selector lengths (16..32 bytes) to find one that the
  // buggy findIndexInUint8Array can locate.
  for (let selectorLen = 16; selectorLen <= 32; selectorLen++) {
    if (cutoff + selectorLen > body.length) break;
    const selectorBytes = body.slice(cutoff, cutoff + selectorLen);
    const selector = selectorBytes.toString();

    // Verify with the same naive search that generatePartialSHA will use
    const encoded = new TextEncoder().encode(selector);
    if (naiveFindIndex(body, encoded) >= 0) {
      return selector;
    }
  }

  throw new Error(
    `Cannot extract selector at position ${position} (cutoff=${cutoff}, bodyLen=${body.length}) — ` +
    `no substring found by naive search`
  );
}

/**
 * Mirrors the buggy findIndexInUint8Array from @zk-email/helpers.
 * Used to pre-validate that generatePartialSHA will find the selector.
 */
function naiveFindIndex(array: Buffer | Uint8Array, selector: Uint8Array): number {
  let i = 0;
  let j = 0;
  while (i < array.length) {
    if (array[i] === selector[j]) {
      j++;
      if (j === selector.length) {
        return i - j + 1;
      }
    } else {
      j = 0;
    }
    i++;
  }
  return -1;
}

/**
 * Find a suitable SHA precompute selector string in the email body.
 *
 * The selector determines where the SHA-256 precomputation cutoff happens:
 *   cutoff = floor(selectorIndex / 64) * 64
 *   remaining = bodyLength - cutoff
 *
 * We need: shaPaddedSize(remaining) <= maxBodyLength
 */
function findSelector(body: Buffer, maxBodyLength: number): string {
  const bodyLen = body.length;

  // Compute max remaining body that fits in maxBodyLength
  // shaPaddedSize(remaining) <= maxBodyLength
  // => remaining <= maxBodyLength - 9 (when maxBodyLength is multiple of 64)
  const maxRemaining = maxBodyLength - 9;

  // Required minimum cutoff
  const minCutoff = bodyLen - maxRemaining;

  // Round UP to next 64-byte boundary
  const cutoff = Math.ceil(Math.max(minCutoff, 1) / 64) * 64;

  if (cutoff >= bodyLen) {
    throw new Error(
      `Cannot find selector: cutoff ${cutoff} >= bodyLen ${bodyLen} for maxBody ${maxBodyLength}`
    );
  }

  // Verify remaining fits
  const remaining = bodyLen - cutoff;
  if (shaPaddedSize(remaining) > maxBodyLength) {
    throw new Error(
      `Selector position invalid: remaining=${remaining}, shaPad=${shaPaddedSize(remaining)} > maxBody=${maxBodyLength}`
    );
  }

  // Extract a 15-char substring starting at the cutoff position
  // This ensures the selector's first occurrence is at or near the cutoff
  const selectorStart = cutoff;
  const selectorEnd = Math.min(selectorStart + 15, bodyLen);
  const selector = body.slice(selectorStart, selectorEnd).toString();

  // Verify the selector is found at the expected position
  const foundIndex = body.indexOf(selector);
  if (foundIndex < 0) {
    throw new Error('Selector not found in body (should not happen)');
  }

  // The actual cutoff will be floor(foundIndex / 64) * 64
  const actualCutoff = Math.floor(foundIndex / 64) * 64;
  const actualRemaining = bodyLen - actualCutoff;
  if (shaPaddedSize(actualRemaining) > maxBodyLength) {
    // Selector found at earlier position than expected, try a longer/later substring
    const laterStart = cutoff + 10;
    const laterEnd = Math.min(laterStart + 20, bodyLen);
    const laterSelector = body.slice(laterStart, laterEnd).toString();
    const laterFound = body.indexOf(laterSelector);
    if (laterFound < 0) {
      throw new Error(`Fallback selector not found in body: "${laterSelector.substring(0, 30)}"`);
    }
    const laterCutoff = Math.floor(laterFound / 64) * 64;
    const laterRemaining = bodyLen - laterCutoff;
    if (shaPaddedSize(laterRemaining) <= maxBodyLength) {
      return laterSelector;
    }
    throw new Error(
      `Cannot find selector with remaining body fitting in ${maxBodyLength}: actual remaining=${actualRemaining}`
    );
  }

  return selector;
}

// ─── Input generation per config ─────────────────────────────────────────────

interface InputGenerationArgs {
  ignoreBodyHashCheck?: boolean;
  shaPrecomputeSelector?: string;
  maxHeadersLength?: number;
  maxBodyLength?: number;
  headerMask?: number[];
  bodyMask?: number[];
  extractFrom?: boolean;
  extractTo?: boolean;
}

function getInputParams(config: NoirCircuitConfig, dkimResult: DKIMVerificationResult): InputGenerationArgs {
  const params: InputGenerationArgs = {
    maxHeadersLength: config.maxHeadersLength,
  };

  switch (config.template) {
    case 'verify_email':
      params.maxBodyLength = config.maxBodyLength;
      break;

    case 'partial_hash': {
      params.maxBodyLength = config.maxBodyLength;

      // Resolve selector: position-based extraction, 0% precompute, or fallback
      let selector: string | undefined;
      if (config.shaPrecomputePosition != null) {
        selector = extractSelectorAtPosition(dkimResult.body, config.shaPrecomputePosition);
      } else if (config.sourceEmailBodySize) {
        // 0% precompute: sourceEmailBodySize is set but no position, so hash entire
        // body in-circuit. Input generator uses SHA-256 initial state for partial_body_hash.
        selector = undefined;
      } else {
        selector = findSelector(dkimResult.body, config.maxBodyLength);
      }

      if (selector) {
        params.shaPrecomputeSelector = selector;
        const selectorIdx = dkimResult.body.indexOf(selector);
        if (selectorIdx >= 0) {
          console.log(`    Selector for ${config.id}: "${selector.substring(0, 30)}..." (cutoff at ${Math.floor(selectorIdx / 64) * 64})`);
        } else {
          console.log(`    Selector for ${config.id}: "${selector.substring(0, 30)}..." (WARNING: not found in body)`);
        }
      } else {
        console.log(`    ${config.id}: no selector (0% precompute — full body in-circuit)`);
      }
      break;
    }

    case 'email_mask': {
      params.maxBodyLength = config.maxBodyLength;
      // Generate deterministic random masks (seeded by config ID for reproducibility)
      const seed = config.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0);
      const rng = (n: number) => {
        let s = seed + n;
        s = ((s >>> 16) ^ s) * 0x45d9f3b;
        s = ((s >>> 16) ^ s) * 0x45d9f3b;
        return ((s >>> 16) ^ s) & 1;
      };
      params.headerMask = Array.from({ length: config.maxHeadersLength }, (_, i) => rng(i));
      params.bodyMask = Array.from({ length: config.maxBodyLength }, (_, i) => rng(i + 10000));
      break;
    }

    case 'extract_addresses':
      // Circuit is header-only (maxBodyLength=0 in config), but DKIM verification
      // during input generation requires computing the body hash to validate the
      // DKIM-Signature header. This 1024 is for input gen only, not circuit params.
      params.maxBodyLength = 1024;
      params.extractFrom = true;
      params.extractTo = true;
      break;

  }

  return params;
}

/**
 * Generate inputs for a single config and save to JSON.
 */
async function generateInputForConfig(config: NoirCircuitConfig): Promise<{ success: boolean; error?: string }> {
  try {
    const emailInfo = selectEmail(config);
    const emailPath = path.join(EMAILS_DIR, emailInfo.filename);

    if (!fs.existsSync(emailPath)) {
      return { success: false, error: `Email not found: ${emailPath}` };
    }

    const emailContent = fs.readFileSync(emailPath, 'utf-8');
    const dkimResult = constructDKIMResult(emailContent, config.rsaBits);

    const params = getInputParams(config, dkimResult);
    const inputs = generateEmailVerifierInputsFromDKIMResult(dkimResult, params);

    // Resize body.storage to match circuit's MAX_EMAIL_BODY_LENGTH.
    // The library's sha256Pad uses a conservative bodySHALength formula that can
    // overshoot maxBodyLength by one 64-byte block, and partial_hash remainders
    // can be smaller than maxBodyLength. The circuit expects exact-sized arrays.
    if (inputs.body && config.template !== 'extract_addresses' && config.maxBodyLength > 0) {
      const target = config.maxBodyLength;
      const actual = inputs.body.storage.length;
      if (actual !== target) {
        const resized: string[] = new Array(target).fill("0");
        const copyLen = Math.min(actual, target);
        for (let i = 0; i < copyLen; i++) {
          resized[i] = inputs.body.storage[i];
        }
        inputs.body.storage = resized;
        console.log(`    Body array resized: ${actual} → ${target}`);
      }
    }

    // Resize header.storage to match circuit's MAX_EMAIL_HEADER_LENGTH (same issue).
    if (inputs.header) {
      const target = config.maxHeadersLength;
      const actual = inputs.header.storage.length;
      if (actual !== target) {
        const resized: string[] = new Array(target).fill("0");
        const copyLen = Math.min(actual, target);
        for (let i = 0; i < copyLen; i++) {
          resized[i] = inputs.header.storage[i];
        }
        inputs.header.storage = resized;
        console.log(`    Header array resized: ${actual} → ${target}`);
      }
    }

    // Save inputs as JSON
    const outputPath = path.join(INPUTS_DIR, `${config.id}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(inputs, null, 2));

    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────

export async function generateAllInputs(configs: NoirCircuitConfig[]): Promise<Map<string, boolean>> {
  fs.mkdirSync(INPUTS_DIR, { recursive: true });

  const results = new Map<string, boolean>();

  for (const config of configs) {
    console.log(`  Generating inputs for ${config.id} (${config.template}, ${config.maxHeadersLength}/${config.maxBodyLength})...`);
    const result = await generateInputForConfig(config);

    if (result.success) {
      console.log(`    => OK`);
    } else {
      console.log(`    => FAILED: ${result.error}`);
    }
    results.set(config.id, result.success);
  }

  return results;
}

async function main() {
  console.log('=== Generating Circuit Inputs ===\n');

  const args = process.argv.slice(2);
  let configs = ALL_CONFIGS;

  const configIdx = args.indexOf('--config');
  if (configIdx !== -1 && args[configIdx + 1]) {
    const targetId = args[configIdx + 1];
    configs = configs.filter(c => c.id === targetId);
    if (configs.length === 0) {
      console.error(`Config '${targetId}' not found.`);
      process.exit(1);
    }
  }

  if (args.includes('--scaling')) configs = configs.filter(c => c.category === 'scaling');
  if (args.includes('--rsa')) configs = configs.filter(c => c.category === 'rsa');
  if (args.includes('--features')) configs = configs.filter(c => c.category === 'features');
  if (args.includes('--precompute')) configs = configs.filter(c => c.category === 'precompute');

  const results = await generateAllInputs(configs);

  const succeeded = [...results.values()].filter(v => v).length;
  const failed = [...results.values()].filter(v => !v).length;

  console.log(`\n=== Input Generation Complete ===`);
  console.log(`Succeeded: ${succeeded}, Failed: ${failed}`);
  console.log(`Output: ${INPUTS_DIR}`);

  if (failed > 0) process.exit(1);
}

if (process.argv[1]?.includes('input-generator')) {
  main().catch(console.error);
}
