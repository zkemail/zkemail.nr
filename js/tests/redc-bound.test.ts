import { randomBytes } from "crypto";
import { generateEmailVerifierInputsFromDKIMResult } from "../src/index";

// Adapted from zkemail/zkemail.nr#67 (Divide-By-0). The circuit range-checks the top 120-bit limb
// of a 2048-bit key's redc to 17 bits (lib/src/dkim.nr), the bits that poseidon_large hashes. This
// checks that honest redc values never need more. The input generator computes
// redc = floor(2^(2k+6) / n), as BigNum v0.11 expects (#67 uses noir-bignum-paramgen's 2^(2k+4)).
// 1024-bit keys keep their 120-bit bound: the zero-padded hash covers all of limb 8.
const bitLength = (x: bigint) => (x === 0n ? 0 : x.toString(2).length);
const topLimbBits = (redc: bigint, limbs: number) => bitLength(redc >> BigInt(120 * (limbs - 1)));
const redcOf = (n: bigint, k: number) => (1n << BigInt(2 * k + 6)) / n;

function randomModulus(bits: number, topBitSet: boolean): bigint {
  let n = BigInt(`0x${randomBytes(bits / 8).toString("hex")}`) | 1n;
  if (topBitSet) n |= 1n << BigInt(bits - 1);
  else n = (n & ((1n << BigInt(bits - 1)) - 1n)) | (1n << BigInt(bits - 2));
  return n;
}

describe.each([
  { k: 2048, limbs: 18, bound: 17, honestMax: 15 },
  { k: 1024, limbs: 9, bound: 120, honestMax: 71 },
])("redc top limb, $k-bit keys", ({ k, limbs, bound, honestMax }) => {
  it("3000 random k-bit moduli", () => {
    let max = 0;
    for (let i = 0; i < 3000; i++) max = Math.max(max, topLimbBits(redcOf(randomModulus(k, true), k), limbs));
    expect(max).toBe(honestMax);
    expect(max).toBeLessThanOrEqual(bound);
  });

  it("edge moduli", () => {
    const K = BigInt(k);
    const edges = [(1n << (K - 1n)) + 1n, (1n << K) - 1n, randomModulus(k, false) /* (k-1)-bit */, (1n << (K - 2n)) + 1n];
    for (const n of edges) expect(topLimbBits(redcOf(n, k), limbs)).toBeLessThanOrEqual(bound);
    // 2^(k-1)+1 (smallest k-bit odd modulus) gives the largest redc of any k-bit key
    expect(topLimbBits(redcOf((1n << (K - 1n)) + 1n, k), limbs)).toBe(honestMax);
  });

  it("matches the redc the input generator emits", () => {
    const n = randomModulus(k, true);
    const dkim = "dkim-signature:v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=";
    const dkimResult: any = {
      headers: Buffer.from(`from:a@example.com\r\n${dkim}`),
      body: Buffer.from(""),
      bodyHash: "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
      signingDomain: "example.com",
      selector: "sel",
      publicKey: n,
      signature: 3n,
      modulusLength: k,
    };
    const inputs = generateEmailVerifierInputsFromDKIMResult(dkimResult, { maxHeadersLength: 512, maxBodyLength: 64 });
    const redcLimbs = inputs.pubkey.redc.map((limb: string) => BigInt(limb));
    const redc = redcLimbs.reduce((acc: bigint, limb: bigint, i: number) => acc + (limb << BigInt(120 * i)), 0n);
    expect(redc).toBe(redcOf(n, k));
  });
});
