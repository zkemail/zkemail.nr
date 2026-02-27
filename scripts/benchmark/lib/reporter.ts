/**
 * Generate benchmark reports in JSON, CSV, and Markdown formats.
 * Matches the Circom benchmark reporter output structure.
 *
 * Usage: npx tsx lib/reporter.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { BENCHMARK_CONFIG } from '../config/benchmark.config.js';
import { ALL_CONFIGS } from '../config/circuits.config.js';
import type { GateCountResult } from './gate-counter.js';
import type { ProvingResult } from './noir-prover.js';

// ─── Report interfaces ──────────────────────────────────────────────────────

export interface BenchmarkReport {
  timestamp: string;
  environment: EnvironmentInfo;
  gateResults: GateCountResult[];
  provingResults: ProvingResult[];
  summary: SummaryStats;
}

export interface EnvironmentInfo {
  os: string;
  arch: string;
  nodeVersion: string;
  nargoVersion: string;
  bbVersion: string;
  cpuModel: string;
  cpuCores: number;
  totalMemoryGb: number;
  threads: number;
}

export interface SummaryStats {
  totalConfigs: number;
  totalRuns: number;
  successfulRuns: number;
  minGates: number;
  maxGates: number;
  avgProvingTimeMs: number;
  avgWitnessGenTimeMs: number;
}

// ─── Environment ─────────────────────────────────────────────────────────────

export function captureEnvironment(): EnvironmentInfo {
  let nargoVersion = 'unknown';
  let bbVersion = 'unknown';

  try { nargoVersion = execSync('nargo --version', { encoding: 'utf-8' }).trim(); } catch { }
  try { bbVersion = execSync('bb --version', { encoding: 'utf-8' }).trim(); } catch { }

  return {
    os: `${os.type()} ${os.release()}`,
    arch: os.arch(),
    nodeVersion: process.version,
    nargoVersion,
    bbVersion,
    cpuModel: os.cpus()[0]?.model || 'unknown',
    cpuCores: os.cpus().length,
    totalMemoryGb: Math.round(os.totalmem() / (1024 * 1024 * 1024)),
    threads: os.cpus().length,
  };
}

// ─── Statistics ──────────────────────────────────────────────────────────────

export function calcStats(values: number[]): {
  median: number; mean: number; stdDev: number; min: number; max: number;
} {
  if (values.length === 0) return { median: 0, mean: 0, stdDev: 0, min: 0, max: 0 };

  const sorted = [...values].sort((a, b) => a - b);
  const n = sorted.length;
  const median = n % 2 === 0
    ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    : sorted[Math.floor(n / 2)];
  const mean = values.reduce((a, b) => a + b, 0) / n;
  // Sample standard deviation (n-1)
  const variance = n > 1
    ? values.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (n - 1)
    : 0;
  const stdDev = Math.sqrt(variance);

  return { median, mean, stdDev, min: sorted[0], max: sorted[n - 1] };
}

// ─── CSV report ──────────────────────────────────────────────────────────────

export function generateCSVReport(
  gateResults: GateCountResult[],
  provingResults: ProvingResult[],
): string {
  const lines: string[] = [];

  lines.push([
    'configId', 'category', 'template', 'maxHeaders', 'maxBody', 'rsaBits',
    'backendGates', 'acirOpcodes', 'compileTimeMs',
    'backend', 'witnessGenTimeMs_median', 'provingTimeMs_median',
    'provingMemoryMb_median', 'verificationTimeMs_median', 'proofSize', 'numRuns', 'successRate',
  ].join(','));

  // Group proving results by configId+backend
  const provingByKey = new Map<string, ProvingResult[]>();
  for (const r of provingResults) {
    const key = `${r.configId}/${r.backend}`;
    if (!provingByKey.has(key)) provingByKey.set(key, []);
    provingByKey.get(key)!.push(r);
  }

  for (const gate of gateResults) {
    const config = ALL_CONFIGS.find(c => c.id === gate.configId);
    if (!config) continue;

    // Find proving results for this config (may have multiple backends)
    const backends = ['honk', 'plonk'];
    for (const backend of backends) {
      const key = `${gate.configId}/${backend}`;
      const proving = provingByKey.get(key) || [];
      if (proving.length === 0 && backend === 'plonk') continue; // Skip plonk if not run

      const successful = proving.filter(p => p.success);
      const witnessStats = calcStats(successful.map(p => p.witnessGenTimeMs));
      const provingStats = calcStats(successful.map(p => p.provingTimeMs));
      const memoryStats = calcStats(successful.map(p => p.provingMemoryMb ?? 0));
      const verifyStats = calcStats(successful.map(p => p.verificationTimeMs));

      lines.push([
        gate.configId,
        config.category,
        config.template,
        config.maxHeadersLength,
        config.maxBodyLength,
        config.rsaBits,
        gate.backendCircuitSize ?? '',
        gate.acirOpcodes ?? '',
        gate.compileTimeMs.toFixed(0),
        backend,
        witnessStats.median.toFixed(0) || '',
        provingStats.median.toFixed(0) || '',
        memoryStats.median.toFixed(1),
        verifyStats.median.toFixed(0) || '',
        successful[0]?.proofSize ?? '',
        proving.length,
        proving.length > 0 ? (successful.length / proving.length * 100).toFixed(0) + '%' : '',
      ].join(','));
    }
  }

  return lines.join('\n');
}

// ─── Full report ─────────────────────────────────────────────────────────────

export function generateReport(
  gateResults: GateCountResult[],
  provingResults: ProvingResult[],
): BenchmarkReport {
  const successful = provingResults.filter(r => r.success);
  const provingTimes = successful.map(r => r.provingTimeMs);
  const witnessTimes = successful.map(r => r.witnessGenTimeMs);
  const gates = gateResults.filter(g => g.success).map(g => g.backendCircuitSize!);

  return {
    timestamp: new Date().toISOString(),
    environment: captureEnvironment(),
    gateResults,
    provingResults,
    summary: {
      totalConfigs: gateResults.length,
      totalRuns: provingResults.length,
      successfulRuns: successful.length,
      minGates: gates.length > 0 ? Math.min(...gates) : 0,
      maxGates: gates.length > 0 ? Math.max(...gates) : 0,
      avgProvingTimeMs: provingTimes.length > 0 ? provingTimes.reduce((a, b) => a + b, 0) / provingTimes.length : 0,
      avgWitnessGenTimeMs: witnessTimes.length > 0 ? witnessTimes.reduce((a, b) => a + b, 0) / witnessTimes.length : 0,
    },
  };
}

// ─── Save reports ────────────────────────────────────────────────────────────

export function saveReports(report: BenchmarkReport): {
  jsonPath: string; csvPath: string; mdPath: string;
} {
  const resultsDir = BENCHMARK_CONFIG.resultsDir;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

  fs.mkdirSync(path.join(resultsDir, 'raw'), { recursive: true });
  fs.mkdirSync(path.join(resultsDir, 'csv'), { recursive: true });

  const jsonPath = path.join(resultsDir, 'raw', `benchmark_${timestamp}.json`);
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  const csv = generateCSVReport(report.gateResults, report.provingResults);
  const csvPath = path.join(resultsDir, 'csv', `benchmark_${timestamp}.csv`);
  fs.writeFileSync(csvPath, csv);

  const md = generateMarkdownSummary(report);
  const mdPath = path.join(resultsDir, `summary_${timestamp}.md`);
  fs.writeFileSync(mdPath, md);

  return { jsonPath, csvPath, mdPath };
}

// ─── Markdown summary ────────────────────────────────────────────────────────

function generateMarkdownSummary(report: BenchmarkReport): string {
  const provingByKey = new Map<string, ProvingResult[]>();
  for (const r of report.provingResults) {
    const key = `${r.configId}/${r.backend}`;
    if (!provingByKey.has(key)) provingByKey.set(key, []);
    provingByKey.get(key)!.push(r);
  }

  return `# Noir ZKEmail Benchmark Results

**Date:** ${report.timestamp}

## Environment

| Property | Value |
|----------|-------|
| OS | ${report.environment.os} |
| Architecture | ${report.environment.arch} |
| CPU | ${report.environment.cpuModel} |
| CPU Cores | ${report.environment.cpuCores} |
| Threads | ${report.environment.threads} |
| Memory | ${report.environment.totalMemoryGb} GB |
| Node.js | ${report.environment.nodeVersion} |
| Nargo | ${report.environment.nargoVersion} |
| BB | ${report.environment.bbVersion} |

## Summary

| Metric | Value |
|--------|-------|
| Configurations | ${report.summary.totalConfigs} |
| Total Proving Runs | ${report.summary.totalRuns} |
| Successful Runs | ${report.summary.successfulRuns} |
| Min Gates | ${report.summary.minGates.toLocaleString()} |
| Max Gates | ${report.summary.maxGates.toLocaleString()} |
| Avg Proving Time | ${(report.summary.avgProvingTimeMs / 1000).toFixed(2)}s |
| Avg Witness Gen | ${(report.summary.avgWitnessGenTimeMs / 1000).toFixed(2)}s |

## Gate Count Results

| Config | Category | Template | Headers | Body | RSA | Gates | ACIR Opcodes | Compile |
|--------|----------|----------|---------|------|-----|-------|-------------|---------|
${report.gateResults.map(g => {
    const config = ALL_CONFIGS.find(c => c.id === g.configId);
    return `| ${g.configId} | ${config?.category || ''} | ${g.template} | ${g.maxHeadersLength} | ${g.maxBodyLength} | ${g.rsaBits} | ${g.backendCircuitSize?.toLocaleString() ?? '-'} | ${g.acirOpcodes?.toLocaleString() ?? '-'} | ${(g.compileTimeMs / 1000).toFixed(1)}s |`;
  }).join('\n')}

## Proving Results (Median)

| Config | Backend | Witness Gen | Proving | Memory (MB) | Verification | Proof Size |
|--------|---------|-------------|---------|-------------|--------------|------------|
${report.gateResults.map(g => {
    const rows: string[] = [];
    for (const backend of ['honk', 'plonk'] as const) {
      const key = `${g.configId}/${backend}`;
      const proving = provingByKey.get(key) || [];
      const successful = proving.filter(p => p.success);
      if (successful.length === 0) continue;

      const wStats = calcStats(successful.map(p => p.witnessGenTimeMs));
      const pStats = calcStats(successful.map(p => p.provingTimeMs));
      const mStats = calcStats(successful.map(p => p.provingMemoryMb ?? 0));
      const vStats = calcStats(successful.map(p => p.verificationTimeMs));

      rows.push(`| ${g.configId} | ${backend} | ${(wStats.median / 1000).toFixed(2)}s | ${(pStats.median / 1000).toFixed(2)}s | ${mStats.median.toFixed(1)} | ${vStats.median.toFixed(0)}ms | ${successful[0].proofSize} B |`);
    }
    return rows.join('\n');
  }).filter(Boolean).join('\n')}
`;
}

// ─── Load latest results ─────────────────────────────────────────────────────

export function loadLatestGateResults(): GateCountResult[] {
  const resultsDir = BENCHMARK_CONFIG.resultsDir;
  if (!fs.existsSync(resultsDir)) return [];

  const files = fs.readdirSync(resultsDir)
    .filter(f => f.startsWith('gates_') && f.endsWith('.json'))
    .sort()
    .reverse();

  if (files.length === 0) return [];

  const data = JSON.parse(fs.readFileSync(path.join(resultsDir, files[0]), 'utf-8'));
  return data.configs || [];
}

export function loadLatestProvingResults(): ProvingResult[] {
  const resultsDir = BENCHMARK_CONFIG.resultsDir;
  if (!fs.existsSync(resultsDir)) return [];

  const files = fs.readdirSync(resultsDir)
    .filter(f => f.startsWith('proving_') && f.endsWith('.json'))
    .sort()
    .reverse();

  if (files.length === 0) return [];

  const data = JSON.parse(fs.readFileSync(path.join(resultsDir, files[0]), 'utf-8'));
  return data.results || [];
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

async function main() {
  console.log('=== Generating Benchmark Reports ===\n');

  const gateResults = loadLatestGateResults();
  const provingResults = loadLatestProvingResults();

  if (gateResults.length === 0) {
    console.error('No gate count results found. Run gate-count first.');
    process.exit(1);
  }

  console.log(`Found ${gateResults.length} gate count results`);
  console.log(`Found ${provingResults.length} proving results\n`);

  const report = generateReport(gateResults, provingResults);
  const paths = saveReports(report);

  console.log('Reports saved:');
  console.log(`  JSON: ${paths.jsonPath}`);
  console.log(`  CSV:  ${paths.csvPath}`);
  console.log(`  MD:   ${paths.mdPath}`);
}

if (process.argv[1]?.includes('reporter')) {
  main().catch(console.error);
}
