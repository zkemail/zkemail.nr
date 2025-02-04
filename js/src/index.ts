import {
  Uint8ArrayToCharArray,
  MAX_BODY_PADDED_BYTES,
  MAX_HEADER_PADDED_BYTES,
  generatePartialSHA,
  sha256Pad,
  findIndexInUint8Array,
} from "@zk-email/helpers";
import {
  DKIMVerificationResult,
  verifyDKIMSignature,
} from "@zk-email/helpers/dist/dkim";
import * as NoirBignum from "@mach-34/noir-bignum-paramgen";
import {
  u8ToU32,
  getHeaderSequence,
  getAddressHeaderSequence,
  Sequence,
  BoundedVec,
} from "./utils";

export { verifyDKIMSignature } from "@zk-email/helpers/dist/dkim";

// This file is essentially https://github.com/zkemail/zk-email-verify/blob/main/packages/helpers/src/input-generators.ts
// modified for noir input generation

export type CircuitInput = {
  // required inputs for all zkemail verifications
  header: BoundedVec;
  pubkey: {
    modulus: string[];
    redc: string[];
  };
  signature: string[];
  dkim_header_sequence: Sequence;
  // inputs used for verifying full or partial hash
  body?: BoundedVec;
  body_hash_index?: string;
  // inputs used for only partial hash
  partial_body_real_length?: string;
  partial_body_hash?: string[];
  // inputs used for only masking
  header_mask?: string[];
  body_mask?: string[];
  // input for decoded body
  decoded_body?: BoundedVec;
  // inputs used for address extraction
  from_header_sequence?: Sequence;
  from_address_sequence?: Sequence;
  to_header_sequence?: Sequence;
  to_address_sequence?: Sequence;
};

export type InputGenerationArgs = {
  ignoreBodyHashCheck?: boolean;
  shaPrecomputeSelector?: string;
  maxHeadersLength?: number;
  maxBodyLength?: number;
  removeSoftLineBreaks?: boolean;
  headerMask?: number[];
  bodyMask?: number[];
  // todo: probably move these out into a separate extended type?
  extractFrom?: boolean;
  extractTo?: boolean;
};

/** Formatted for BoundedVec in case used in other places */
function removeSoftLineBreaks(body: BoundedVec): BoundedVec {
  const result = [];
  let i = 0;
  let count = 0;
  while (i < body.storage.length) {
    if (
      i + 2 < body.storage.length &&
      body.storage[i] === "61" && // '=' character
      body.storage[i + 1] === "13" && // '\r' character
      body.storage[i + 2] === "10"
    ) {
      // '\n' character
      // Skip the soft line break sequence
      i += 3; // Move past the soft line break
    } else {
      result.push(body.storage[i]);
      i++;
      count++;
    }
  }
  // Pad the result with zeros to make it the same length as the body
  while (result.length < body.storage.length) {
    result.push("0");
  }
  return {
    storage: result,
    len: count.toString()
  };
}

/**
 * @description Generate circuit inputs for the EmailVerifier circuit from raw email content
 * @param rawEmail Full email content as a buffer or string
 * @param params Arguments to control the input generation
 * @returns Circuit inputs for the EmailVerifier circuit
 */
export async function generateEmailVerifierInputs(
  rawEmail: Buffer | string,
  params: InputGenerationArgs = {}
) {
  const dkimResult = await verifyDKIMSignature(rawEmail, undefined, undefined, true);

  return generateEmailVerifierInputsFromDKIMResult(dkimResult, params);
}

/**
 * @description Generate circuit inputs for the EmailVerifier circuit from DKIMVerification result
 * @param dkimResult DKIMVerificationResult containing email data and verification result
 * @param params Arguments to control the input generation
 * @returns Circuit inputs for the EmailVerifier circuit
 */
export function generateEmailVerifierInputsFromDKIMResult(
  dkimResult: DKIMVerificationResult,
  params: InputGenerationArgs = {}
): CircuitInput {
  const { headers, body, bodyHash, publicKey, signature, modulusLength } = dkimResult;

  // SHA add padding
  const [messagePadded] = sha256Pad(
    headers,
    params.maxHeadersLength || MAX_HEADER_PADDED_BYTES
  );

  // set inputs used in all cases
  const circuitInputs: CircuitInput = {
    header: {
      storage: Uint8ArrayToCharArray(messagePadded),
      len: headers.length.toString(),
    },
    pubkey: {
      modulus: NoirBignum.bnToLimbStrArray(publicKey, modulusLength),
      redc: NoirBignum.bnToRedcLimbStrArray(publicKey, modulusLength),
    },
    // modified from original: use noir bignum to format
    signature: NoirBignum.bnToLimbStrArray(signature, modulusLength),
    dkim_header_sequence: getHeaderSequence(headers, "dkim-signature"),
  };

  // removed: header mask

  if (!params.ignoreBodyHashCheck) {
    if (!body || !bodyHash) {
      throw new Error(
        "body and bodyHash are required when ignoreBodyHashCheck is false"
      );
    }

    const bodyHashIndex = headers.toString().indexOf(bodyHash);
    const maxBodyLength = params.maxBodyLength || MAX_BODY_PADDED_BYTES;

    // 65 comes from the 64 at the end and the 1 bit in the start, then 63 comes from the formula to round it up to the nearest 64.
    // see sha256algorithm.com for a more full explanation of padding length
    const bodySHALength = Math.floor((body.length + 63 + 65) / 64) * 64;
    const [bodyPadded, bodyPaddedLen] = sha256Pad(
      body,
      Math.max(maxBodyLength, bodySHALength)
    );

    const { precomputedSha, bodyRemainingLength, ...rest } = generatePartialSHA(
      {
        body: bodyPadded,
        bodyLength: bodyPaddedLen,
        selectorString: params.shaPrecomputeSelector,
        maxRemainingBodyLength: maxBodyLength,
      }
    );

    // code smell but it passes the linter
    let { bodyRemaining } = rest;
    // idk why this gets out of sync, todo: fix
    if (
      params.shaPrecomputeSelector &&
      bodyRemaining.length !== bodyRemainingLength
    ) {
      bodyRemaining = bodyRemaining.slice(0, bodyRemainingLength);
    }

    circuitInputs.body = {
      storage: Uint8ArrayToCharArray(bodyRemaining),
      len: body.length.toString(),
    };
    circuitInputs.body_hash_index = bodyHashIndex.toString();

    if (params.shaPrecomputeSelector) {
      // can use exact body lengths
      const selector = new TextEncoder().encode(params.shaPrecomputeSelector);
      const selectorIndex = findIndexInUint8Array(body, selector);
      const shaCutoffIndex = Math.floor(selectorIndex / 64) * 64;
      const remainingBodyLength = body.length - shaCutoffIndex;
      circuitInputs.partial_body_real_length = body.length.toString();
      circuitInputs.body.len = remainingBodyLength.toString();

      // format back into u32 so noir doesn't have to do it
      circuitInputs.partial_body_hash = Array.from(u8ToU32(precomputedSha)).map(
        (x) => x.toString()
      );
    }

    // masking
    if (params.headerMask) circuitInputs.header_mask = params.headerMask.map((x) => x.toString());
    if (params.bodyMask) circuitInputs.body_mask = params.bodyMask.map((x) => x.toString());

    // remove soft line breaks
    if (params.removeSoftLineBreaks) {
      circuitInputs.decoded_body = removeSoftLineBreaks(circuitInputs.body);
    }

    // address extraction
    if (params.extractFrom) {
      const fromSequences = getAddressHeaderSequence(headers, "from");
      circuitInputs.from_header_sequence = fromSequences[0];
      circuitInputs.from_address_sequence = fromSequences[1];
    }
    if (params.extractTo) {
      const toSequences = getAddressHeaderSequence(headers, "to");
      circuitInputs.to_header_sequence = toSequences[0];
      circuitInputs.to_address_sequence = toSequences[1];
    }
  }

  return circuitInputs;
}
