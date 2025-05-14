import { buildPoseidon } from "circomlibjs";

export type Sequence = {
  index: string;
  length: string;
};

export type BoundedVec = {
  storage: string[];
  len: string;
};
/**
 * Transforms a u32 array to a u8 array in big-endian format
 * @dev sha-utils in zk-email-verify encodes partial hash as u8 array but noir expects u32
 *      transform back to keep upstream code but not have noir worry about transformation
 *
 * @param input - the input to convert to 32 bit array
 * @returns - the input as a 32 bit array
 */
export function u8ToU32(input: Uint8Array): Uint32Array {
  const out = new Uint32Array(input.length / 4);
  for (let i = 0; i < out.length; i++) {
    out[i] =
      (input[i * 4 + 0] << 24) |
      (input[i * 4 + 1] << 16) |
      (input[i * 4 + 2] << 8) |
      (input[i * 4 + 3] << 0);
  }
  return out;
}

/**
 * Format circuit inputs for a Prover.toml file
 *
 * @param inputs - the inputs to convert to Prover.toml format
 * @param exactLength - whether toNoirInputs should have exact length for header or keep 0-padding
 * @returns - the inputs as bb cli expects them to appear in a Prover.toml file
 */
export function toProverToml(inputs: any): string {
  const lines: string[] = [];
  const structs: string[] = [];
  for (const [key, value] of Object.entries(inputs)) {
    if (Array.isArray(value)) {
      const valueStrArr = value.map((val) => `'${val}'`);
      lines.push(`${key} = [${valueStrArr.join(", ")}]`);
    } else if (typeof value === "string") {
      lines.push(`${key} = '${value}'`);
    } else {
      let values = "";
      for (const [k, v] of Object.entries(value!)) {
        if (Array.isArray(v)) {
          values = values.concat(
            `${k} = [${v.map((val) => `'${val}'`).join(", ")}]\n`
          );
        } else {
          values = values.concat(`${k} = '${v}'\n`);
        }
      }
      structs.push(`[${key}]\n${values}`);
    }
  }
  return lines.concat(structs).join("\n");
}

/**
 * Get the index and length of a header field to use
 *
 * @param header - the header to search for the field in
 * @param headerField - the field name to search for
 * @returns - the index and length of the field in the header
 */
export function getHeaderSequence(
  header: Buffer,
  headerField: string
): Sequence {
  const regex = new RegExp(
    `[${headerField[0].toUpperCase()}${headerField[0].toLowerCase()}]${headerField
      .slice(1)
      .toLowerCase()}:.*(?:\r?\n)?`
  );
  const match = header.toString().match(regex);
  if (match === null)
    throw new Error(`Field "${headerField}" not found in header`);
  return {
    index: match.index!.toString(),
    length: match[0].length.toString(),
  };
}

/**
 * Get the index and length of a header field as well as the address in the field
 * @dev only works for to, from. Not set up for cc
 *
 * @param header - the header to search for the field in
 * @param headerField - the field name to search for
 * @returns - the index and length of the field in the header and the index and length of the address in the field
 */
export function getAddressHeaderSequence(header: Buffer, headerField: string) {
  const regexPrefix = `[${headerField[0].toUpperCase()}${headerField[0].toLowerCase()}]${headerField
    .slice(1)
    .toLowerCase()}`;
  const regex = new RegExp(
    `${regexPrefix}:.*?<([^>]+)>|${regexPrefix}:.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+.[a-zA-Z]{2,})`
  );
  const headerStr = header.toString();
  const match = headerStr.match(regex);
  if (match === null)
    throw new Error(`Field "${headerField}" not found in header`);
  if (match[1] === null && match[2] === null)
    throw new Error(`Address not found in "${headerField}" field`);
  const address = match[1] || match[2];
  const addressIndex = headerStr.indexOf(address);
  return [
    { index: match.index!.toString(), length: match[0].length.toString() },
    { index: addressIndex.toString(), length: address.length.toString() },
  ];
}

/**
 * Build a ROM table for allowable email characters
 * === This function is used to generate a table to reference in Noir code ===
 */
export function makeEmailAddressCharTable(): string {
  // max value: z = 122
  const tableLength = 123;
  const table = new Array(tableLength).fill(0);
  const emailChars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-@";
  const precedingChars = "<: ";
  const proceedingChars = ">\r\n";
  // set valid email chars
  for (let i = 0; i < emailChars.length; i++) {
    table[emailChars.charCodeAt(i)] = 1;
  }
  // set valid preceding chars
  for (let i = 0; i < precedingChars.length; i++) {
    table[precedingChars.charCodeAt(i)] = 2;
  }
  // set valid proceding chars
  for (let i = 0; i < proceedingChars.length; i++) {
    table[proceedingChars.charCodeAt(i)] = 3;
  }
  let tableStr = `global EMAIL_ADDRESS_CHAR_TABLE: [u8; ${tableLength}] = [\n`;
  for (let i = 0; i < table.length; i += 10) {
    const end = i + 10 < table.length ? i + 10 : table.length;
    tableStr += `    ${table.slice(i, end).join(", ")},\n`;
  }
  tableStr += "];";
  return tableStr;
}

/**
 * Hashes an RSA public key (modulus and redc limbs) using a hierarchical Poseidon scheme,
 * mirroring the logic in zkemail.nr's RSAPubkey<KEY_LIMBS_2048>::hash function.
 *
 * The process is:
 * 1. Modulus and Redc are each provided as 18 x 120-bit limbs.
 * 2. Two 'chunks' of 9 elements each are formed:
 *    - chunk1_element[i] = modulus_limb[2i] * 2^120 + modulus_limb[2i+1]
 *    - chunk2_element[i] = redc_limb[2i] * 2^120 + redc_limb[2i+1]
 * 3. Poseidon(chunk1) -> hash1
 * 4. Poseidon(chunk2) -> hash2
 * 5. Poseidon([hash1, hash2]) -> final_hash
 *
 * @param modulusLimbs An array of 18 BigInts representing the 120-bit limbs of the RSA modulus.
 * @param redcLimbs An array of 18 BigInts representing the 120-bit limbs of the RSA redc value.
 * @returns A Promise resolving to a BigInt which is the final Poseidon hash.
 */
export async function hashRSAPublicKey(
  modulusLimbs: bigint[],
  redcLimbs: bigint[]
): Promise<bigint> {
  const NUM_TOTAL_LIMBS = 18;
  const NUM_ELEMENTS_PER_POSEIDON_CHUNK = 9;
  const BITS_PER_INPUT_LIMB = 120n; // Each limb in modulus/redc arrays is 120 bits
  const SHIFT_VALUE_FOR_COMPOSITION = 2n ** BITS_PER_INPUT_LIMB;

  if (
    modulusLimbs.length !== NUM_TOTAL_LIMBS ||
    redcLimbs.length !== NUM_TOTAL_LIMBS
  ) {
    throw new Error(
      `Expected ${NUM_TOTAL_LIMBS} limbs for both modulus and redc, but received ${modulusLimbs.length} and ${redcLimbs.length}`
    );
  }

  const poseidon = await buildPoseidon();

  const chunk1_composed: bigint[] = [];
  const chunk2_composed: bigint[] = [];

  for (let i = 0; i < NUM_ELEMENTS_PER_POSEIDON_CHUNK; i++) {
    // Compose elements for chunk1 from modulus limbs
    const mod_limb_A = modulusLimbs[i * 2];
    const mod_limb_B = modulusLimbs[i * 2 + 1];
    chunk1_composed.push(mod_limb_A * SHIFT_VALUE_FOR_COMPOSITION + mod_limb_B);

    // Compose elements for chunk2 from redc limbs
    const redc_limb_A = redcLimbs[i * 2];
    const redc_limb_B = redcLimbs[i * 2 + 1];
    chunk2_composed.push(
      redc_limb_A * SHIFT_VALUE_FOR_COMPOSITION + redc_limb_B
    );
  }

  // Hash chunk1 (9 elements)
  const hash_of_chunk1_raw = poseidon(chunk1_composed);
  const hash_of_chunk1 = poseidon.F.toObject(hash_of_chunk1_raw);

  // Hash chunk2 (9 elements)
  const hash_of_chunk2_raw = poseidon(chunk2_composed);
  const hash_of_chunk2 = poseidon.F.toObject(hash_of_chunk2_raw);

  // Hash the two intermediate hashes ([hash1, hash2] - 2 elements)
  const final_hash_inputs = [hash_of_chunk1, hash_of_chunk2];
  const final_hash_raw = poseidon(final_hash_inputs);
  const final_hash = poseidon.F.toObject(final_hash_raw);

  return final_hash;
}
