import {
  Uint8ArrayToCharArray,
  MAX_BODY_PADDED_BYTES,
  MAX_HEADER_PADDED_BYTES,
  generatePartialSHA,
  sha256Pad,
} from "@zk-email/helpers";
import {
  DKIMVerificationResult,
  verifyDKIMSignature,
} from "@zk-email/helpers/dist/dkim";
import * as NoirBignum from "noir_bignum";

// This file is essentially https://github.com/zkemail/zk-email-verify/blob/main/packages/helpers/src/input-generators.ts
// with a few modifications for noir input generation
// also removes some of the unused functionality like masking

type CircuitInput = {
  emailHeader: string[];
  emailHeaderLength: string;
  pubkey: string[];
  redcParams?: string[];
  signature: string[];
  emailBody?: string[];
  emailBodyLength?: string;
  precomputedSHA?: string[];
  bodyHashIndex?: string;
  decodedEmailBodyIn?: string[];
};

type InputGenerationArgs = {
  ignoreBodyHashCheck?: boolean;
  shaPrecomputeSelector?: string;
  maxHeadersLength?: number; // Max length of the email header including padding
  maxBodyLength?: number; // Max length of the email body after shaPrecomputeSelector including padding
  removeSoftLineBreaks?: boolean;
};

// copied without modification, but not publicly exported in original
function removeSoftLineBreaks(body: string[]): string[] {
  const result = [];
  let i = 0;
  while (i < body.length) {
    if (
      i + 2 < body.length &&
      body[i] === "61" && // '=' character
      body[i + 1] === "13" && // '\r' character
      body[i + 2] === "10"
    ) {
      // '\n' character
      // Skip the soft line break sequence
      i += 3; // Move past the soft line break
    } else {
      result.push(body[i]);
      i++;
    }
  }
  // Pad the result with zeros to make it the same length as the body
  while (result.length < body.length) {
    result.push("0");
  }
  return result;
}

// copied without modification, needed for different generateEmailVerifierInnputsFromDKIMResult
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
  const dkimResult = await verifyDKIMSignature(rawEmail);

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
  const { headers, body, bodyHash, publicKey, signature } = dkimResult;

  // SHA add padding
  const [messagePadded] = sha256Pad(
    headers,
    params.maxHeadersLength || MAX_HEADER_PADDED_BYTES
  );

  const circuitInputs: CircuitInput = {
    emailHeader: Uint8ArrayToCharArray(messagePadded), // Packed into 1 byte signals
    // modified from original: can use exact email header length
    emailHeaderLength: headers.length.toString(),
    // modified from original: use noir bignum to format
    pubkey: NoirBignum.bn_limbs_from_string(publicKey.toString(16)),
    // modified from original: use noir bignum to format
    signature: NoirBignum.bn_limbs_from_string(signature.toString(16)),
    // not in original: add barrett reduction param for efficient rsa sig verification
    redcParams: NoirBignum.redc_limbs_from_string(publicKey.toString(16)),
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

    const { precomputedSha, bodyRemaining } = generatePartialSHA({
      body: bodyPadded,
      bodyLength: bodyPaddedLen,
      selectorString: params.shaPrecomputeSelector,
      maxRemainingBodyLength: maxBodyLength,
    });

    // modified from original: can use exact email body length
    // since circom needs 64 byte chunks and noir doesnt
    circuitInputs.emailBodyLength = body.length.toString();
    circuitInputs.precomputedSHA = Uint8ArrayToCharArray(precomputedSha);
    circuitInputs.bodyHashIndex = bodyHashIndex.toString();
    circuitInputs.emailBody = Uint8ArrayToCharArray(bodyRemaining);

    if (params.removeSoftLineBreaks) {
      circuitInputs.decodedEmailBodyIn = removeSoftLineBreaks(
        circuitInputs.emailBody
      );
    }
  }

  return circuitInputs;
}

/**
 * Rename inputs for Noir format
 * @todo handle optional values
 *
 * @param inputs - the inputs to convert to Noir format
 * @param exactLength - whether to have exact length for header or (default) keep 0-padding
 * @returns - the inputs as the NoirJS witness simulator expects them
 */
export function toNoirInputs(inputs: CircuitInput, exactLength = false) {
  return {
    body_hash_index: inputs.bodyHashIndex!,
    header: exactLength
      ? inputs.emailHeader.slice(0, Number(inputs.emailHeaderLength))!
      : inputs.emailHeader!,
    body: exactLength
      ? inputs.emailBody!.slice(0, Number(inputs.emailBodyLength))!
      : inputs.emailBody!,
    body_length: inputs.emailBodyLength!,
    header_length: inputs.emailHeaderLength!,
    pubkey: inputs.pubkey!,
    pubkey_redc: inputs.redcParams!,
    signature: inputs.signature!,
  };
}

/**
 * Format circuit inputs for a Prover.toml file
 *
 * @param inputs - the inputs to convert to Prover.toml format
 * @param exactLength - whether toNoirInputs should have exact length for header or keep 0-padding
 * @returns - the inputs as bb cli expects them to appear in a Prover.toml file
 */
export function toProverToml(
  inputs: CircuitInput,
  exactLength = false
): string {
  const formatted = toNoirInputs(inputs, exactLength);
  const lines: string[] = [];
  for (const [key, value] of Object.entries(formatted)) {
    let valueStr = "";
    if (Array.isArray(value)) {
      const valueStrArr = value.map((val) => `'${val}'`);
      valueStr = `[${valueStrArr.join(", ")}]`;
    } else {
      valueStr = `'${value}'`;
    }
    lines.push(`${key} = ${valueStr}`);
  }
  return lines.join("\n");
}
