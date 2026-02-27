/**
 * Generate DKIM-signed synthetic emails for benchmarking.
 * Adapted from zk-email-verify/scripts/benchmark/lib/generate-signed-emails.ts
 *
 * Generates emails with configurable header/body sizes and RSA key sizes.
 * Each email is DKIM-signed with relaxed/relaxed canonicalization.
 *
 * Usage: pnpm run generate-emails
 */

import * as fs from 'fs';
import * as crypto from 'crypto';
import { BENCHMARK_CONFIG, DKIM_CONFIG } from '../config/benchmark.config.js';

const KEYS_DIR = BENCHMARK_CONFIG.keysDir;
const OUTPUT_DIR = `${BENCHMARK_CONFIG.emailsDir}/synthetic`;

interface EmailConfig {
  bodySize: number;
  headerSize: number;
  rsaBits: 1024 | 2048;
}

/**
 * Canonicalize headers using "relaxed" algorithm (RFC 6376 Section 3.4.2)
 */
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

/**
 * Canonicalize body using "relaxed" algorithm (RFC 6376 Section 3.4.4)
 */
function canonicalizeBodyRelaxed(body: string): string {
  let result = body
    .split('\r\n')
    .map(line => line.replace(/\s+/g, ' ').replace(/\s+$/, ''))
    .join('\r\n');

  result = result.replace(/(\r\n)+$/, '');
  if (result.length > 0) {
    result += '\r\n';
  }
  return result;
}

/**
 * Generate DKIM signature header
 */
function signEmail(
  headers: string,
  body: string,
  privateKey: string,
  signedHeaders: string[]
): string {
  const canonBody = canonicalizeBodyRelaxed(body);
  const bodyHash = crypto.createHash('sha256').update(canonBody).digest('base64');

  const timestamp = Math.floor(Date.now() / 1000);
  const dkimTemplate = [
    `v=1`,
    `a=rsa-sha256`,
    `c=relaxed/relaxed`,
    `d=${DKIM_CONFIG.domain}`,
    `s=${DKIM_CONFIG.selector}`,
    `t=${timestamp}`,
    `bh=${bodyHash}`,
    `h=${signedHeaders.join(':')}`,
    `b=`
  ].join('; ');

  const dkimHeader = `DKIM-Signature: ${dkimTemplate}`;

  const headerLines = headers.split('\r\n');
  const headersToSign: string[] = [];

  for (const hName of signedHeaders) {
    const found = headerLines.find(line =>
      line.toLowerCase().startsWith(hName.toLowerCase() + ':')
    );
    if (found) headersToSign.push(found);
  }
  headersToSign.push(dkimHeader);

  const canonHeaders = canonicalizeHeadersRelaxed(headersToSign.join('\r\n'));
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(canonHeaders);
  const signature = sign.sign(privateKey, 'base64');

  return `DKIM-Signature: ${dkimTemplate}${signature}`;
}

/**
 * Generate email body of specified size using Lorem Ipsum words
 */
function generateBody(size: number): string {
  const words = [
    'Lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur',
    'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor',
    'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna', 'aliqua'
  ];

  let body = '';
  let lineLen = 0;

  while (body.length < size) {
    const word = words[Math.floor(Math.random() * words.length)];
    if (lineLen + word.length > 76) {
      body += '\r\n';
      lineLen = 0;
    } else if (lineLen > 0) {
      body += ' ';
      lineLen++;
    }
    body += word;
    lineLen += word.length;
  }

  return body.substring(0, size).replace(/\s+$/, '');
}

/**
 * Generate email headers of approximately specified size
 */
function generateHeaders(targetSize: number, messageId: string): string {
  const baseHeaders = [
    `From: benchmark@${DKIM_CONFIG.domain}`,
    `To: test@example.com`,
    `Subject: Benchmark Test Email`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${messageId}@${DKIM_CONFIG.domain}>`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=UTF-8`,
  ];

  let headers = baseHeaders.join('\r\n');

  let padCount = 0;
  while (headers.length < targetSize - 50) {
    const padding = 'X'.repeat(Math.min(60, targetSize - headers.length - 30));
    headers += `\r\nX-Padding-${padCount}: ${padding}`;
    padCount++;
  }

  return headers;
}

/**
 * Generate a complete DKIM-signed email
 */
function generateSignedEmail(config: EmailConfig): string {
  const messageId = crypto.randomBytes(16).toString('hex');
  const keyPath = `${KEYS_DIR}/dkim_${config.rsaBits}.pem`;

  if (!fs.existsSync(keyPath)) {
    throw new Error(`Private key not found: ${keyPath}. Run generate-keys first.`);
  }

  const privateKey = fs.readFileSync(keyPath, 'utf-8');
  const headers = generateHeaders(config.headerSize, messageId);
  const body = generateBody(config.bodySize);

  const dkimSignature = signEmail(headers, body, privateKey, DKIM_CONFIG.signedHeaders);

  return `${dkimSignature}\r\n${headers}\r\n\r\n${body}`;
}

/**
 * Write email to file preserving CRLF line endings (RFC 5322)
 */
function writeEmailFile(filePath: string, content: string): void {
  const normalizedContent = content.replace(/\r?\n/g, '\r\n');
  fs.writeFileSync(filePath, Buffer.from(normalizedContent, 'utf-8'));
}

/**
 * Determine which email sizes are needed based on circuit configs.
 * This ensures we generate emails that actually fit the circuits.
 */
function getRequiredEmailConfigs(): EmailConfig[] {
  // Generate emails that cover all circuit config needs:
  // - For each scaling config, we need an email whose SHA-padded body fits maxBodyLength
  // - For RSA-1024, we need a 1024-bit signed email
  // - Header sizes should be generous enough for DKIM headers
  return [
    // Small bodies for smaller scaling configs
    { bodySize: 192, headerSize: 384, rsaBits: 2048 },  // SCALE-MIN: shaPad(192)=256
    { bodySize: 256, headerSize: 384, rsaBits: 2048 },
    { bodySize: 512, headerSize: 512, rsaBits: 2048 },
    // Medium — baseline for SCALE-3 / feature configs
    { bodySize: 768, headerSize: 512, rsaBits: 2048 },
    // Larger bodies
    { bodySize: 1024, headerSize: 1024, rsaBits: 2048 },
    { bodySize: 2048, headerSize: 1024, rsaBits: 2048 },
    { bodySize: 4096, headerSize: 2048, rsaBits: 2048 },

    // RSA-1024 variant (same size as baseline)
    { bodySize: 768, headerSize: 512, rsaBits: 1024 },
  ];
}

async function main() {
  console.log('=== Generating DKIM-Signed Synthetic Emails ===\n');

  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  const configs = getRequiredEmailConfigs();

  console.log('RSA\tHeaders\tBody\tFile');
  console.log('-'.repeat(70));

  for (const config of configs) {
    try {
      const email = generateSignedEmail(config);
      const filename = `email_h${config.headerSize}_b${config.bodySize}_rsa${config.rsaBits}.eml`;
      const outputPath = `${OUTPUT_DIR}/${filename}`;

      writeEmailFile(outputPath, email);

      console.log(`${config.rsaBits}\t${config.headerSize}\t${config.bodySize}\t${filename}`);
    } catch (err: any) {
      console.error(`FAILED ${config.rsaBits}/${config.headerSize}/${config.bodySize}: ${err.message}`);
    }
  }

  // Print DNS TXT records for reference
  console.log('\n=== DNS TXT Records ===\n');
  for (const bits of [1024, 2048] as const) {
    const pubKeyPath = `${KEYS_DIR}/dkim_${bits}_pub.pem`;
    if (fs.existsSync(pubKeyPath)) {
      const pubKey = fs.readFileSync(pubKeyPath, 'utf-8')
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
      console.log(`${DKIM_CONFIG.selector}._domainkey.${DKIM_CONFIG.domain} (RSA-${bits}):`);
      console.log(`  v=DKIM1; k=rsa; p=${pubKey}\n`);
    }
  }

  console.log('=== Generation Complete ===');
}

main().catch(console.error);
