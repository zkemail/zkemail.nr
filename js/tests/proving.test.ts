import fs from "fs";
import path from "path";
import { ZKEmailProver } from "../src/prover";
import { generateEmailVerifierInputs } from "../src/index";
// import circuit1024 from "../../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
import circuit2048 from "../../examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";
import circuitPartialHash from "../../examples/partial_hash/target/partial_hash.json";
import circuitEmailMask from "../../examples/email_mask/target/email_mask.json";
import circuitExtractAddresses from "../../examples/extract_addresses/target/extract_addresses.json";

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

describe("ZKEmail.nr E2E Tests", () => {
  // todo: get a github email from a throwaway account to verify
  // let prover1024: ZKEmailProver;
  const selectorText = "All nodes in the Bitcoin network can consult it";
  let prover2048: ZKEmailProver;
  let proverPartialHash: ZKEmailProver;
  let proverMasked: ZKEmailProver;
  let proverExtractAddresses: ZKEmailProver;

  beforeAll(() => {
    //@ts-ignore
    // prover1024 = new ZKEmailProver(circuit1024, "all");
    //@ts-ignore
    prover2048 = new ZKEmailProver(circuit2048, "all");
    //@ts-ignore
    proverPartialHash = new ZKEmailProver(circuitPartialHash, "all");
    //@ts-ignore
    proverMasked = new ZKEmailProver(circuitEmailMask, "all");
    //@ts-ignore
    proverExtractAddresses = new ZKEmailProver(circuitExtractAddresses, "all");
  });

  afterAll(async () => {
    // await prover1024.destroy();
    await prover2048.destroy();
    await proverPartialHash.destroy();
    await proverMasked.destroy();
    await proverExtractAddresses.destroy();
  });

  describe("UltraPlonk", () => {
    it("UltraPlonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      const proof = await prover2048.fullProve(inputs, "plonk");
      const result = await prover2048.verify(proof, "plonk");
      expect(result).toBeTruthy();
    });

    it("UltraPlonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.large,
        inputParams
      );
      const proof = await prover2048.fullProve(inputs, "plonk");
      const result = await prover2048.verify(proof, "plonk");
      expect(result).toBeTruthy();
    });
    it("UltraPlonk::PartialHash", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector: selectorText,
        maxHeadersLength: 512,
        maxBodyLength: 192,
      });
      const proof = await proverPartialHash.fullProve(inputs, "plonk");
      const result = await proverPartialHash.verify(proof, "plonk");
      expect(result).toBeTruthy();
    });
    it("UltraPlonk::Masked", async () => {
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
      const proof = await proverMasked.fullProve(inputs, "plonk");
      const result = await proverMasked.verify(proof, "plonk");
      expect(result).toBeTruthy();
    });
    it("UltraPlonk::ExtractAddresses", async () => {
      const inputs = await generateEmailVerifierInputs(emails.small, {
        extractFrom: true,
        extractTo: true,
        ...inputParams,
      });
      const proof = await proverExtractAddresses.fullProve(inputs, "plonk");
      const result = await proverExtractAddresses.verify(proof, "plonk");
      expect(result).toBeTruthy();
    });
  });

  describe("UltraHonk", () => {
    it("UltraHonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      const proof = await prover2048.fullProve(inputs, "honk");
      const result = await prover2048.verify(proof, "honk");
      expect(result).toBeTruthy();
    });

    it("UltraHonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.large,
        inputParams
      );
      const proof = await prover2048.fullProve(inputs, "honk");
      const result = await prover2048.verify(proof, "honk");
      expect(result).toBeTruthy();
    });
    it("UltraHonk::PartialHash", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector: selectorText,
        maxHeadersLength: 512,
        maxBodyLength: 192,
      });
      const proof = await proverPartialHash.fullProve(inputs, "honk");
      const result = await proverPartialHash.verify(proof, "phonklonk");
      expect(result).toBeTruthy();
    });
    it("UltraHonk::Masked", async () => {
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
      const proof = await proverMasked.fullProve(inputs, "honk");
      const result = await proverMasked.verify(proof, "honk");
      expect(result).toBeTruthy();
    });
    it("UltraHonk::ExtractAddresses", async () => {
      const inputs = await generateEmailVerifierInputs(emails.small, {
        extractFrom: true,
        extractTo: true,
        ...inputParams,
      });
      const proof = await proverExtractAddresses.fullProve(inputs, "honk");
      const result = await proverExtractAddresses.verify(proof, "honk");
      expect(result).toBeTruthy();
    });
  });
});
