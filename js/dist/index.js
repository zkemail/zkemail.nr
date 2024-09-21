"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateEmailVerifierInputsFromDKIMResult = generateEmailVerifierInputsFromDKIMResult;
exports.toNoirInputs = toNoirInputs;
exports.toProverToml = toProverToml;
const helpers_1 = require("@zk-email/helpers");
const NoirBignum = __importStar(require("noir_bignum"));
// copied without modification, but not publicly exported in original
function removeSoftLineBreaks(body) {
    const result = [];
    let i = 0;
    while (i < body.length) {
        if (i + 2 < body.length &&
            body[i] === "61" && // '=' character
            body[i + 1] === "13" && // '\r' character
            body[i + 2] === "10") {
            // '\n' character
            // Skip the soft line break sequence
            i += 3; // Move past the soft line break
        }
        else {
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
/**
 *
 * @description Generate circuit inputs for the EmailVerifier circuit from DKIMVerification result
 * @param dkimResult DKIMVerificationResult containing email data and verification result
 * @param params Arguments to control the input generation
 * @returns Circuit inputs for the EmailVerifier circuit
 */
function generateEmailVerifierInputsFromDKIMResult(dkimResult, params = {}) {
    const { headers, body, bodyHash, publicKey, signature } = dkimResult;
    // SHA add padding
    const [messagePadded] = (0, helpers_1.sha256Pad)(headers, params.maxHeadersLength || helpers_1.MAX_HEADER_PADDED_BYTES);
    const circuitInputs = {
        emailHeader: (0, helpers_1.Uint8ArrayToCharArray)(messagePadded), // Packed into 1 byte signals
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
            throw new Error("body and bodyHash are required when ignoreBodyHashCheck is false");
        }
        const bodyHashIndex = headers.toString().indexOf(bodyHash);
        const maxBodyLength = params.maxBodyLength || helpers_1.MAX_BODY_PADDED_BYTES;
        // 65 comes from the 64 at the end and the 1 bit in the start, then 63 comes from the formula to round it up to the nearest 64.
        // see sha256algorithm.com for a more full explanation of padding length
        const bodySHALength = Math.floor((body.length + 63 + 65) / 64) * 64;
        const [bodyPadded, bodyPaddedLen] = (0, helpers_1.sha256Pad)(body, Math.max(maxBodyLength, bodySHALength));
        const { precomputedSha, bodyRemaining } = (0, helpers_1.generatePartialSHA)({
            body: bodyPadded,
            bodyLength: bodyPaddedLen,
            selectorString: params.shaPrecomputeSelector,
            maxRemainingBodyLength: maxBodyLength,
        });
        // modified from original: can use exact email body length
        // since circom needs 64 byte chunks and noir doesnt
        circuitInputs.emailBodyLength = body.length.toString();
        circuitInputs.precomputedSHA = (0, helpers_1.Uint8ArrayToCharArray)(precomputedSha);
        circuitInputs.bodyHashIndex = bodyHashIndex.toString();
        circuitInputs.emailBody = (0, helpers_1.Uint8ArrayToCharArray)(bodyRemaining);
        if (params.removeSoftLineBreaks) {
            circuitInputs.decodedEmailBodyIn = removeSoftLineBreaks(circuitInputs.emailBody);
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
function toNoirInputs(inputs, exactLength = false) {
    return {
        body_hash_index: inputs.bodyHashIndex,
        header: exactLength
            ? inputs.emailHeader.slice(0, Number(inputs.emailHeaderLength))
            : inputs.emailHeader,
        body: exactLength
            ? inputs.emailBody.slice(0, Number(inputs.emailBodyLength))
            : inputs.emailBody,
        body_length: inputs.emailBodyLength,
        header_length: inputs.emailHeaderLength,
        pubkey: inputs.pubkey,
        pubkey_redc: inputs.redcParams,
        signature: inputs.signature,
    };
}
/**
 * Format circuit inputs for a Prover.toml file
 *
 * @param inputs - the inputs to convert to Prover.toml format
 * @param exactLength - whether toNoirInputs should have exact length for header or keep 0-padding
 * @returns - the inputs as bb cli expects them to appear in a Prover.toml file
 */
function toProverToml(inputs, exactLength = false) {
    const formatted = toNoirInputs(inputs, exactLength);
    const lines = [];
    for (const [key, value] of Object.entries(formatted)) {
        let valueStr = "";
        if (Array.isArray(value)) {
            const valueStrArr = value.map((val) => `'${val}'`);
            valueStr = `[${valueStrArr.join(", ")}]`;
        }
        else {
            valueStr = `'${value}'`;
        }
        lines.push(`${key} = ${valueStr}`);
    }
    return lines.join("\n");
}
