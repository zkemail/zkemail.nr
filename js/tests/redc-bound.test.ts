import { randomBytes } from "crypto";
import { computeBarrettReductionParameter } from "@mach-34/noir-bignum-paramgen";

// The circuit range-checks the top 120-bit limb of a 2048-bit key's redc to 17 bits (lib/src/dkim.nr),
// the bits that poseidon_large hashes. This checks that honest redc values, as computed by the same
// paramgen the input generator uses (floor(2^(2k+4) / n), noir-bignum v0.6.0), never need more.
// 1024-bit keys keep their 120-bit bound: the zero-padded hash covers all of limb 8.
const bitLength = (x: bigint) => (x === 0n ? 0 : x.toString(2).length);
const topLimbBits = (redc: bigint, limbs: number) => bitLength(redc >> BigInt(120 * (limbs - 1)));

function randomModulus(bits: number, topBitSet: boolean): bigint {
  let n = BigInt(`0x${randomBytes(bits / 8).toString("hex")}`) | 1n;
  if (topBitSet) n |= 1n << BigInt(bits - 1);
  else n = (n & ((1n << BigInt(bits - 1)) - 1n)) | (1n << BigInt(bits - 2));
  return n;
}

describe.each([
  { k: 2048, limbs: 18, bound: 17, honestMax: 13 },
  { k: 1024, limbs: 9, bound: 120, honestMax: 69 },
])("redc top limb, $k-bit keys", ({ k, limbs, bound, honestMax }) => {
  it("3000 random k-bit moduli", () => {
    let max = 0;
    for (let i = 0; i < 3000; i++) max = Math.max(max, topLimbBits(computeBarrettReductionParameter(randomModulus(k, true), k), limbs));
    expect(max).toBe(honestMax);
    expect(max).toBeLessThanOrEqual(bound);
  });

  it("edge moduli", () => {
    const K = BigInt(k);
    const edges = [(1n << (K - 1n)) + 1n, (1n << K) - 1n, randomModulus(k, false) /* (k-1)-bit */, (1n << (K - 2n)) + 1n];
    for (const n of edges) expect(topLimbBits(computeBarrettReductionParameter(n, k), limbs)).toBeLessThanOrEqual(bound);
    // 2^(k-1)+1 (smallest k-bit odd modulus) gives the largest redc of any k-bit key
    expect(topLimbBits(computeBarrettReductionParameter((1n << (K - 1n)) + 1n, k), limbs)).toBe(honestMax);
  });
});
