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
 * Find every field named `headerField` in a canonicalized header, as [start, end) byte offsets.
 *
 * Matches the circuit's `constrain_header_field`:
 * - the field name is matched case-insensitively at the start of a header line ("DKIM-Signature"
 *   under c=simple canonicalization, "dkim-signature" under c=relaxed);
 * - folded continuation lines (CRLF followed by SP or HTAB) belong to the field;
 * - `end` excludes the CRLF that terminates the field.
 *
 * NOTE: the header is decoded as latin1 so every byte is one string index. The default utf8 decoding
 * shifts every later offset when the header contains non-ASCII bytes.
 */
function findHeaderFields(header: Buffer, headerField: string): { index: number; end: number }[] {
  const headerStr = header.toString("latin1");
  const lowerHeader = headerStr.toLowerCase();
  const prefix = `${headerField.toLowerCase()}:`;
  const fields: { index: number; end: number }[] = [];
  let lineStart = 0;
  while (lineStart !== -1) {
    if (lowerHeader.startsWith(prefix, lineStart)) {
      // the field ends at the first CRLF not followed by SP / HTAB (a fold), or at the header end
      let end = headerStr.length;
      for (let i = headerStr.indexOf("\r\n", lineStart); i !== -1; i = headerStr.indexOf("\r\n", i + 2)) {
        const next = headerStr[i + 2];
        if (next !== " " && next !== "\t") {
          end = i;
          break;
        }
      }
      fields.push({ index: lineStart, end });
    }
    const lineEnd = headerStr.indexOf("\r\n", lineStart);
    lineStart = lineEnd === -1 ? -1 : lineEnd + 2;
  }
  return fields;
}

/**
 * Get the index and length of a header field to use
 *
 * See findHeaderFields for how fields are matched. For the DKIM-Signature field use
 * getVerifiedDkimSignatureSequence instead: a header can carry several DKIM-Signature fields.
 *
 * @param header - the header to search for the field in
 * @param headerField - the field name to search for
 * @param occurrence - which matching field to return when the field occurs more than once
 * @returns - the index and length of the field in the header
 */
export function getHeaderSequence(
  header: Buffer,
  headerField: string,
  occurrence: "first" | "last" = "first"
): Sequence {
  const fields = findHeaderFields(header, headerField);
  if (fields.length === 0) throw new Error(`Field "${headerField}" not found in header`);
  const field = occurrence === "first" ? fields[0] : fields[fields.length - 1];
  return {
    index: field.index.toString(),
    length: (field.end - field.index).toString(),
  };
}

/** Tags of a DKIM-Signature field value, with folding whitespace removed (RFC 6376 s3.2). */
function parseDkimTags(fieldValue: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of fieldValue.split(";")) {
    const eq = part.indexOf("=");
    if (eq !== -1) {
      tags.set(part.slice(0, eq).replace(/[\s]/g, "").toLowerCase(), part.slice(eq + 1).replace(/[\s]/g, ""));
    }
  }
  return tags;
}

/**
 * Locate the DKIM-Signature field that helpers' verifyDKIMSignature actually verified, and the index
 * of its bh= value, in the canonicalized signed header (`DKIMVerificationResult.headers`).
 *
 * REASON: the canonicalized header can contain more than one DKIM-Signature field. Besides the
 * verified one, any other DKIM-Signature listed in its h= tag is included (e.g. Google Workspace
 * signs with both d=<domain> and d=<domain>.<date>.gappssmtp.com; ESPs add their own d=). The
 * circuit must use the field of the verified signature, so it is picked by content, not position:
 * - d= and s= equal the verified result's signingDomain / selector,
 * - bh= equals the verified body hash (when known),
 * - b= is empty: the verifier empties b= of the signature it verifies (RFC 6376 s3.7), while
 *   other DKIM-Signature fields keep theirs,
 * - it is the last field of the header. RFC 6376 s3.7 appends the verified signature last, and the
 *   circuit's get_body_hash requires that.
 * Exactly one field must satisfy all of these; anything else is an error rather than a guess.
 */
export function getVerifiedDkimSignatureSequence(
  header: Buffer,
  verified: { signingDomain: string; selector: string; bodyHash?: string }
): { sequence: Sequence; bodyHashIndex: number } {
  const headerStr = header.toString("latin1");
  const candidates = findHeaderFields(header, "dkim-signature").filter(({ index, end }) => {
    const tags = parseDkimTags(headerStr.slice(index + "dkim-signature:".length, end));
    return (
      tags.get("d")?.toLowerCase() === verified.signingDomain.toLowerCase() &&
      tags.get("s")?.toLowerCase() === verified.selector.toLowerCase() &&
      (verified.bodyHash === undefined || tags.get("bh") === verified.bodyHash) &&
      tags.get("b") === ""
    );
  });
  if (candidates.length !== 1) {
    throw new Error(
      `Expected exactly one DKIM-Signature field for d=${verified.signingDomain} s=${verified.selector} with an empty b=, found ${candidates.length}`
    );
  }
  const { index, end } = candidates[0];
  if (end !== headerStr.length) {
    throw new Error("The verified DKIM-Signature field is not the last field of the signed header");
  }
  // bh= must start a tag in one of the forms the circuit accepts (headers/body_hash.nr)
  const field = headerStr.slice(index, end);
  const match = /(?::|; ?|;\r\n[ \t])bh=/i.exec(field);
  if (match === null) throw new Error("bh= tag not found in a position the circuit accepts");
  const bodyHashIndex = index + match.index + match[0].length;
  if (verified.bodyHash !== undefined && headerStr.slice(bodyHashIndex, bodyHashIndex + 44) !== verified.bodyHash) {
    // e.g. a bh= value folded across lines: the circuit reads 44 contiguous bytes
    throw new Error("bh= value is not stored contiguously after the tag");
  }
  return {
    sequence: { index: index.toString(), length: (end - index).toString() },
    bodyHashIndex,
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
  if (match === null) throw new Error(`Field "${headerField}" not found in header`);
  if (match[1] === null && match[2] === null) throw new Error(`Address not found in "${headerField}" field`);
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
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-@";
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

export type RSAPublicKeyHashes = {
  modulusHash: bigint;
  redcHash: bigint;
};

function hashLimbArrayToPoseidon(
  limbs120: bigint[],
  poseidon: Awaited<ReturnType<typeof buildPoseidon>>
): bigint {
  const NUM_INPUT_LIMBS_120 = 18; // 18 x 120-bit limbs
  const NUM_LIMBS_1024 = 9; // 9 x 120-bit limbs for 1024-bit keys
  const NUM_CHUNKS_121 = 17; // produce 17 contiguous 121-bit chunks
  const NUM_POSEIDON_INPUTS = 9;
  const BASE_121 = 1n << 121n;

  if (limbs120.length !== NUM_INPUT_LIMBS_120 && limbs120.length !== NUM_LIMBS_1024) {
    throw new Error(
      `Expected ${NUM_INPUT_LIMBS_120} or ${NUM_LIMBS_1024} limbs, but received ${limbs120.length}`
    );
  }

  // Pad 1024-bit (9 limbs) to 2048-bit width (18 limbs) — mirrors Noir's poseidon_large_padded_1024
  const padded = limbs120.length === NUM_INPUT_LIMBS_120
    ? limbs120
    : [...limbs120, ...new Array(NUM_INPUT_LIMBS_120 - limbs120.length).fill(0n)];

  // Step 1: Build 17 contiguous 121-bit chunks from 18 x 120-bit limbs
  const chunks121: bigint[] = new Array(NUM_CHUNKS_121).fill(0n);
  for (let j = 0; j < NUM_CHUNKS_121; j++) {
    const a0 = padded[j];
    const a1 = j + 1 < NUM_INPUT_LIMBS_120 ? padded[j + 1] : 0n;

    const shiftLow = BigInt(j);
    const lower = a0 >> shiftLow; // a0 / 2^j

    const maskBits = 1n + BigInt(j); // (1 + j)
    const highMask = (1n << maskBits) - 1n; // (2^(1+j)) - 1
    const takeFromNext = a1 & highMask;

    const leftShift = BigInt(120 - j);
    const high = takeFromNext << leftShift; // * 2^(120 - j)

    chunks121[j] = lower + high;
  }

  // Step 2: Merge into 9 Poseidon inputs: for i in 0..7: chunks[2i] + base * chunks[2i+1], last is chunks[16]
  const poseidonInputs: bigint[] = new Array(NUM_POSEIDON_INPUTS);
  for (let i = 0; i < 8; i++) {
    poseidonInputs[i] = chunks121[2 * i] + BASE_121 * chunks121[2 * i + 1];
  }
  poseidonInputs[8] = chunks121[16];

  const finalHashRaw = poseidon(poseidonInputs);
  return poseidon.F.toObject(finalHashRaw);
}

/**
 * Hash RSA pubkey limbs into separate Poseidon hashes for modulus and redc.
 *
 * This mirrors the Noir limb-conversion and folding path used in
 * RSAPubkey<2048>::hash-compatible hashing.
 */
export async function hashRSAPublicKey(
  modulusLimbs: bigint[],
  redcLimbs: bigint[]
): Promise<RSAPublicKeyHashes> {
  const poseidon = await buildPoseidon();

  return {
    modulusHash: hashLimbArrayToPoseidon(modulusLimbs, poseidon),
    redcHash: hashLimbArrayToPoseidon(redcLimbs, poseidon),
  };
}
