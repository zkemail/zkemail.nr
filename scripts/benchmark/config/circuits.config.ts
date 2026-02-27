/**
 * Circuit configuration definitions for Noir zkemail benchmarking.
 *
 * Noir circuits differ from Circom:
 * - Parameters are compile-time `global` constants, not template params
 * - RSA-1024 IS supported (KEY_LIMBS_1024 = 9)
 * - Feature variants map to different example circuit templates
 * - No ignoreBodyHashCheck flag — features are distinct circuit files
 */

export type CircuitTemplate =
  | 'verify_email'       // Basic DKIM verification
  | 'partial_hash'       // SHA precomputation
  | 'email_mask'         // Header + body masking
  | 'extract_addresses'; // Address extraction (header-only)

export interface NoirCircuitConfig {
  id: string;
  category: 'scaling' | 'rsa' | 'features' | 'precompute';
  template: CircuitTemplate;
  maxHeadersLength: number;
  maxBodyLength: number;
  rsaBits: 1024 | 2048;
  /** When set, selectEmail matches emails against this body size instead of maxBodyLength.
   *  Use for SHA-precompute configs where maxBodyLength is smaller than the full email body. */
  sourceEmailBodySize?: number;
  /** Position (0–1) in body to auto-extract a selector for SHA precomputation. */
  shaPrecomputePosition?: number;
}

/**
 * Scaling configs — measure how gate count scales with header/body size.
 *
 * Constraints learned from Circom benchmark validation:
 * - DKIM signed headers canonicalize to ~355-360 bytes, SHA-pad to ~384-448 bytes
 * - Headers < 512 are fragile (exact fit depends on DKIM-Signature length)
 * - All sizes use RSA-2048 to isolate the size variable
 */
export const SCALING_CONFIGS: NoirCircuitConfig[] = [
  {
    // Minimum viable DKIM circuit: 384 = smallest multiple of 64 that fits ~359-byte signed headers
    id: 'SCALE-MIN',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 384,
    maxBodyLength: 256,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-1',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 512,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-2',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 768,
    rsaBits: 2048,
  },
  {
    // Baseline — matches existing examples (512/1024)
    id: 'SCALE-3',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 1024,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-4',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 1024,
    maxBodyLength: 1024,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-5',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 1024,
    maxBodyLength: 2048,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-6',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 1024,
    maxBodyLength: 4096,
    rsaBits: 2048,
  },
  {
    id: 'SCALE-7',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 2048,
    maxBodyLength: 4096,
    rsaBits: 2048,
  },
  {
    // Header-heavy: measures gate cost when headers dominate (4096 headers, minimal body)
    id: 'SCALE-HEADER-HEAVY',
    category: 'scaling',
    template: 'verify_email',
    maxHeadersLength: 4096,
    maxBodyLength: 320,
    rsaBits: 2048,
  },
];

/**
 * RSA key size configs — Noir supports both 1024 and 2048.
 * Uses SCALE-3 dimensions (512/1024) to isolate the RSA variable.
 */
export const RSA_CONFIGS: NoirCircuitConfig[] = [
  {
    id: 'RSA-1024',
    category: 'rsa',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 1024,
    rsaBits: 1024,
  },
  {
    // Same as SCALE-3 — included for explicit comparison
    id: 'RSA-2048',
    category: 'rsa',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 1024,
    rsaBits: 2048,
  },
];

/**
 * Feature variant configs — each uses a different circuit template.
 * All use SCALE-3 dimensions (512/1024) to isolate feature cost.
 *
 * Note: extract_addresses only needs headers, no body param.
 */
export const FEATURE_CONFIGS: NoirCircuitConfig[] = [
  {
    id: 'FEAT-BASE',
    category: 'features',
    template: 'verify_email',
    maxHeadersLength: 512,
    maxBodyLength: 1024,
    rsaBits: 2048,
  },
  {
    id: 'FEAT-PARTIAL',
    category: 'features',
    template: 'partial_hash',
    maxHeadersLength: 512,
    maxBodyLength: 192, // Must be multiple of 64 (partial_sha256_var_end requirement)
    rsaBits: 2048,
    sourceEmailBodySize: 1024, // Use same 1024-byte email as FEAT-BASE for fair comparison
    shaPrecomputePosition: 0.875, // Cutoff at byte 896 → 128 bytes remainder → shaPad(128)=192
  },
  {
    id: 'FEAT-MASK',
    category: 'features',
    template: 'email_mask',
    maxHeadersLength: 512,
    maxBodyLength: 1024,
    rsaBits: 2048,
  },
  {
    id: 'FEAT-ADDR',
    category: 'features',
    template: 'extract_addresses',
    maxHeadersLength: 512,
    maxBodyLength: 0, // Not used — extract_addresses is header-only
    rsaBits: 2048,
  },
];

/**
 * SHA precomputation sweep — ALL configs use partial_hash template with varying
 * in-circuit body sizes, ensuring apples-to-apples comparison.
 * All body lengths must be multiples of 64 (partial_sha256_var_end BLOCK_SIZE assertion).
 * All configs use the same underlying 1024-byte email (via sourceEmailBodySize).
 *
 * maxBodyLength must account for SHA-256 padding overhead because generatePartialSHA
 * (from @zk-email/helpers) checks bodyRemainingLength (SHA-padded) against maxBodyLength.
 * Formula: ceil((remaining_raw + 9) / 64) * 64 + 128 (2-block margin for cutoff alignment).
 */
export const PRECOMPUTE_CONFIGS: NoirCircuitConfig[] = [
  {
    id: 'PRECOMP-25',
    category: 'precompute',
    template: 'partial_hash',
    maxHeadersLength: 512,
    maxBodyLength: 960,   // ~75% remaining (768) + SHA padding (64) + 2-block margin (128)
    rsaBits: 2048,
    sourceEmailBodySize: 1024,
    shaPrecomputePosition: 0.25,
  },
  {
    id: 'PRECOMP-50',
    category: 'precompute',
    template: 'partial_hash',
    maxHeadersLength: 512,
    maxBodyLength: 704,   // ~50% remaining (512) + SHA padding (64) + 2-block margin (128)
    rsaBits: 2048,
    sourceEmailBodySize: 1024,
    shaPrecomputePosition: 0.50,
  },
  {
    id: 'PRECOMP-75',
    category: 'precompute',
    template: 'partial_hash',
    maxHeadersLength: 512,
    maxBodyLength: 448,   // ~25% remaining (256) + SHA padding (64) + 2-block margin (128)
    rsaBits: 2048,
    sourceEmailBodySize: 1024,
    shaPrecomputePosition: 0.75,
  },
];

export const ALL_CONFIGS: NoirCircuitConfig[] = [
  ...SCALING_CONFIGS,
  ...RSA_CONFIGS,
  ...FEATURE_CONFIGS,
  ...PRECOMPUTE_CONFIGS,
];

export function getConfigById(id: string): NoirCircuitConfig | undefined {
  return ALL_CONFIGS.find(c => c.id === id);
}

export function getConfigsByCategory(category: NoirCircuitConfig['category']): NoirCircuitConfig[] {
  return ALL_CONFIGS.filter(c => c.category === category);
}
