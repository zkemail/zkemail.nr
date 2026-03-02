import fs from "fs";
import os from "os";
import path from "path";
import { ZKEmailProver } from "../src/prover";
import { generateEmailVerifierInputs } from "../src/index";
// import circuit1024 from "../../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
import circuit2048 from "../../examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";
import circuitPartialHash from "../../examples/partial_hash/target/partial_hash.json";
import circuitEmailMask from "../../examples/email_mask/target/email_mask.json";
import circuitExtractAddresses from "../../examples/extract_addresses/target/extract_addresses.json";
import circuitRemoveSoftLineBreak from "../../examples/remove_soft_line_breaks/target/remove_soft_line_breaks.json";
import { hashRSAPublicKey } from "../src/utils";

const emails = {
  small: fs.readFileSync(path.join(__dirname, "./test-data/email-good.eml")),
  large: fs.readFileSync(
    path.join(__dirname, "./test-data/email-good-large.eml")
  ),
};

// default header/ body lengths to use for input gen
const inputParams = {
  maxHeadersLength: 512,
  maxBodyLength: 1024,
};

describe("ZKEmail.nr Circuit Unit Tests", () => {
  let prover2048: ZKEmailProver;
  let proverPartialHash: ZKEmailProver;
  let proverMasked: ZKEmailProver;
  let proverExtractAddresses: ZKEmailProver;
  let proverRemoveSoftLineBreak: ZKEmailProver;

  beforeAll(() => {
    //@ts-ignore
    // prover1024 = new ZKEmailProver(circuit1024, "all");
    let num_cpus = os.cpus().length;
    // @ts-ignore
    prover2048 = new ZKEmailProver(circuit2048, num_cpus);
    //@ts-ignore
    proverPartialHash = new ZKEmailProver(circuitPartialHash, num_cpus);
    //@ts-ignore
    proverMasked = new ZKEmailProver(circuitEmailMask, num_cpus);
    //@ts-ignore
    proverExtractAddresses = new ZKEmailProver(
      circuitExtractAddresses,
      num_cpus
    );
    //@ts-ignore
    proverRemoveSoftLineBreak = new ZKEmailProver(
      circuitRemoveSoftLineBreak,
      num_cpus
    );
  });

  afterAll(async () => {
    // await prover1024.destroy();
    await prover2048.destroy();
    await proverPartialHash.destroy();
    await proverMasked.destroy();
    await proverExtractAddresses.destroy();
    await proverRemoveSoftLineBreak.destroy();
  });

  describe("Simulate Witnesses", () => {
    it("2048-bit DKIM", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      await prover2048.simulateWitness(inputs);
      // console.log(toProverToml(inputs));
    });
    it("Partial Hash", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector:
          "All nodes in the Bitcoin network can consult it",
        maxHeadersLength: 512,
        maxBodyLength: 192,
      });
      await proverPartialHash.simulateWitness(inputs);
    });
    it("Masked Header/ Body", async () => {
      // make masks
      const headerMask = Array.from(
        { length: inputParams.maxHeadersLength },
        () => Math.floor(Math.random() * 2)
      );
      const bodyMask = Array.from({ length: inputParams.maxBodyLength }, () =>
        Math.floor(Math.random() * 2)
      );
      const inputs = await generateEmailVerifierInputs(emails.small, {
        headerMask,
        bodyMask,
        ...inputParams,
      });
      // simulate witness
      const result = await proverMasked.simulateWitness(inputs);
      // compute mask locally
      const expectedMaskedHeader = inputs.header.storage.map((byte, i) =>
        headerMask[i] === 1 ? parseInt(byte) : 0
      );
      const expectedMaskedBody = inputs.body!.storage.map((byte, i) =>
        bodyMask[i] === 1 ? parseInt(byte) : 0
      );
      // compare results
      const acutalMaskedHeader = result.returnValue[1].map((byte) =>
        parseInt(byte, 16)
      );
      const acutalMaskedBody = result.returnValue[2].map((byte) =>
        parseInt(byte, 16)
      );
      expect(expectedMaskedHeader).toEqual(acutalMaskedHeader);
      expect(expectedMaskedBody).toEqual(acutalMaskedBody);
    });
    it("Extract Sender/ Recipient", async () => {
      const inputs = await generateEmailVerifierInputs(emails.small, {
        extractFrom: true,
        extractTo: true,
        ...inputParams,
      });
      // simulate witness
      const result = await proverExtractAddresses.simulateWitness(inputs);
      // parse expected addresses
      const header = Buffer.from(
        inputs.header.storage.map((byte) => parseInt(byte))
      ).toString();
      const fromAddressStart = parseInt(inputs.from_address_sequence!.index);
      const fromAddressEnd =
        fromAddressStart + parseInt(inputs.from_address_sequence!.length);
      const expectedFrom = header.slice(fromAddressStart, fromAddressEnd);
      const toAddressStart = parseInt(inputs.to_address_sequence!.index);
      const toAddressEnd =
        toAddressStart + parseInt(inputs.to_address_sequence!.length);
      const expectedTo = header.slice(toAddressStart, toAddressEnd);
      // parse actual addresses
      const parseSequence = (len: string, storage: string[]) => {
        return Buffer.from(
          storage.slice(0, parseInt(len)).map((byte) => parseInt(byte))
        ).toString();
      };
      const actualFrom = parseSequence(
        result.returnValue[1].len,
        result.returnValue[1].storage
      );
      const actualTo = parseSequence(
        result.returnValue[2].len,
        result.returnValue[2].storage
      );
      expect(expectedFrom).toEqual(actualFrom);
      expect(expectedTo).toEqual(actualTo);
    });
    it("Remove Soft Line Breaks", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large, {
        removeSoftLineBreaks: true,
        ...inputParams,
      });
      await proverRemoveSoftLineBreak.simulateWitness(inputs);
    });
    it("Hash RSAPublicKey", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      let modulus = inputs.pubkey.modulus.map((limb) => BigInt(limb));
      let redc = inputs.pubkey.redc.map((limb) => BigInt(limb));
      let computedHashes = await hashRSAPublicKey(modulus, redc);
      const result = await prover2048.simulateWitness(inputs);
      // returnValue[0] = modulus hash, returnValue[1] = redc hash, returnValue[2] = email nullifier
      expect(result.returnValue[0].slice(2)).toEqual(
        computedHashes.modulusHash.toString(16)
      );
      expect(result.returnValue[1].slice(2)).toEqual(
        computedHashes.redcHash.toString(16)
      );
    });
  });
});

describe("hashRSAPublicKey 1024-bit parity", () => {
  it("1024-bit (9-limb) hash matches zero-padded 2048-bit (18-limb) hash", async () => {
    // Synthetic 1024-bit key: 9 limbs for modulus and redc
    const modulus9 = [
      0xaabbccdd11223344aabbccdd1122n,
      0x112233445566778899aabbccddeen,
      0xffeeddccbbaa99887766554433n,
      0x00112233445566778899aabbccddeen,
      0xdeadbeefcafebabe12345678abcdn,
      0xfedcba98765432100fedcba98765n,
      0x0123456789abcdef0123456789abn,
      0xabcdef0123456789abcdef012345n,
      0xdeadbeefcafebaben,
    ];
    const redc9 = [
      0x111111111111111111111111111111n,
      0x222222222222222222222222222222n,
      0x333333333333333333333333333333n,
      0x444444444444444444444444444444n,
      0x555555555555555555555555555555n,
      0x666666666666666666666666666666n,
      0x777777777777777777777777777777n,
      0x888888888888888888888888888888n,
      0x99999999999999999999n,
    ];

    // Hash with 9 limbs (1024-bit path)
    const hash1024 = await hashRSAPublicKey(modulus9, redc9);

    // Same data, manually zero-padded to 18 limbs (2048-bit path)
    const modulus18 = [...modulus9, ...new Array(9).fill(0n)];
    const redc18 = [...redc9, ...new Array(9).fill(0n)];
    const hash2048Padded = await hashRSAPublicKey(modulus18, redc18);

    // Both paths must produce identical hashes — this validates the JS padding
    // logic mirrors Noir's poseidon_large_padded_1024
    expect(hash1024.modulusHash).toEqual(hash2048Padded.modulusHash);
    expect(hash1024.redcHash).toEqual(hash2048Padded.redcHash);
  });

  it("1024-bit hash changes when redc is modified", async () => {
    const modulus = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n];
    const redc = [10n, 20n, 30n, 40n, 50n, 60n, 70n, 80n, 90n];
    const tamperedRedc = [11n, 20n, 30n, 40n, 50n, 60n, 70n, 80n, 90n]; // redc[0] changed

    const original = await hashRSAPublicKey(modulus, redc);
    const tampered = await hashRSAPublicKey(modulus, tamperedRedc);

    // modulus hash unchanged (same modulus)
    expect(original.modulusHash).toEqual(tampered.modulusHash);
    // redc hash changed
    expect(original.redcHash).not.toEqual(tampered.redcHash);
  });
});
