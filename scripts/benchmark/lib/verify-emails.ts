/**
 * Verify DKIM signatures of generated emails.
 * Adapted from zk-email-verify/scripts/benchmark/lib/verify-emails.ts
 *
 * Usage: npm run verify-emails
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';

const KEYS_DIR = BENCHMARK_CONFIG.keysDir;
const EMAILS_DIR = `${BENCHMARK_CONFIG.emailsDir}/synthetic`;

interface DKIMHeader {
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

function parseDKIMSignature(dkimLine: string): DKIMHeader {
  const value = dkimLine.replace(/^DKIM-Signature:\s*/i, '');
  const parts: Record<string, string> = {};
  const normalized = value.replace(/\r?\n\s+/g, '');

  for (const part of normalized.split(/;\s*/)) {
    const [key, ...vals] = part.split('=');
    if (key && vals.length) {
      parts[key.trim()] = vals.join('=').trim();
    }
  }
  return parts as unknown as DKIMHeader;
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

function verifyDKIM(emailContent: string, publicKeyPem: string): {
  valid: boolean;
  bodyHashValid: boolean;
  signatureValid: boolean;
  error?: string;
} {
  try {
    const parts = emailContent.split(/\r?\n\r?\n/);
    const headerSection = parts[0];
    const body = parts.slice(1).join('\r\n\r\n');

    const normalizedHeaders = headerSection.replace(/\r?\n/g, '\r\n');
    const normalizedBody = body.replace(/\r?\n/g, '\r\n');

    const headerLines = normalizedHeaders.split('\r\n');
    const dkimLine = headerLines.find(l => l.toLowerCase().startsWith('dkim-signature:'));

    if (!dkimLine) {
      return { valid: false, bodyHashValid: false, signatureValid: false, error: 'No DKIM-Signature found' };
    }

    const dkim = parseDKIMSignature(dkimLine);

    // Verify body hash
    const canonBody = canonicalizeBodyRelaxed(normalizedBody);
    const computedBodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');
    const bodyHashValid = computedBodyHash === dkim.bh;

    // Get headers to verify
    const signedHeaderNames = dkim.h.split(':').map(h => h.trim().toLowerCase());
    const headersToVerify: string[] = [];

    for (const hName of signedHeaderNames) {
      const found = headerLines.find(line =>
        line.toLowerCase().startsWith(hName + ':')
      );
      if (found) headersToVerify.push(found);
    }

    // Add DKIM-Signature header (without b= value)
    const dkimWithoutSig = dkimLine.replace(/b=[^;]+/, 'b=');
    headersToVerify.push(dkimWithoutSig);

    const canonHeaders = canonicalizeHeadersRelaxed(headersToVerify.join('\r\n'));

    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(canonHeaders);
    const signatureValid = verify.verify(publicKeyPem, dkim.b, 'base64');

    return { valid: bodyHashValid && signatureValid, bodyHashValid, signatureValid };
  } catch (err: any) {
    return { valid: false, bodyHashValid: false, signatureValid: false, error: err.message };
  }
}

async function main() {
  console.log('=== Verifying DKIM Signatures ===\n');

  if (!fs.existsSync(EMAILS_DIR)) {
    console.error(`Emails directory not found: ${EMAILS_DIR}`);
    console.error('Run generate-emails first.');
    process.exit(1);
  }

  const files = fs.readdirSync(EMAILS_DIR).filter(f => f.endsWith('.eml'));
  if (files.length === 0) {
    console.error('No .eml files found. Run generate-emails first.');
    process.exit(1);
  }

  console.log('File\t\t\t\t\t\tBody Hash\tSig\tStatus');
  console.log('-'.repeat(90));

  let passed = 0;
  let failed = 0;

  for (const file of files) {
    const emailContent = fs.readFileSync(`${EMAILS_DIR}/${file}`, 'utf-8');

    const rsaMatch = file.match(/rsa(\d+)/);
    const rsaBits = rsaMatch ? rsaMatch[1] : '2048';
    const pubKeyPath = `${KEYS_DIR}/dkim_${rsaBits}_pub.pem`;

    if (!fs.existsSync(pubKeyPath)) {
      console.log(`${file.padEnd(44)}\t-\t\t-\tMISSING KEY`);
      failed++;
      continue;
    }

    const publicKey = fs.readFileSync(pubKeyPath, 'utf-8');
    const result = verifyDKIM(emailContent, publicKey);

    const bodyStatus = result.bodyHashValid ? 'OK' : 'FAIL';
    const sigStatus = result.signatureValid ? 'OK' : 'FAIL';
    const status = result.valid ? 'PASS' : 'FAIL';

    console.log(`${file.padEnd(44)}\t${bodyStatus}\t\t${sigStatus}\t${status}`);

    if (result.valid) {
      passed++;
    } else {
      failed++;
      if (result.error) console.log(`  Error: ${result.error}`);
    }
  }

  console.log('-'.repeat(90));
  console.log(`\nResults: ${passed} passed, ${failed} failed`);

  if (failed > 0) {
    process.exit(1);
  }
}

main().catch(console.error);
