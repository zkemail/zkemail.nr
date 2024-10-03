import fs from "fs";
import path from "path";
import { ZKEmailProver } from "../src/prover";
import { generateEmailVerifierInputs } from "../src/index";
// import circuit1024 from "../../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
import circuit2048 from "../../examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";
import partialHash from "../../examples/partial_hash/target/partial_hash.json";
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

describe("Fixed Size Circuit Input", () => {
  // todo: get a github email from a throwaway account to verify
  // let prover1024: ZKEmailProver;
  let prover2048: ZKEmailProver;
  let proverPartialHash: ZKEmailProver;

  beforeAll(() => {
    //@ts-ignore
    // prover1024 = new ZKEmailProver(circuit1024, "all");
    //@ts-ignore
    prover2048 = new ZKEmailProver(circuit2048, "all");
    //@ts-ignore
    proverPartialHash = new ZKEmailProver(partialHash, "all");
  });

  afterAll(async () => {
    // await prover1024.destroy();
    await prover2048.destroy();
    await proverPartialHash.destroy();
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
  });

  describe("Partial Hash", () => {
    const selectorText = "All nodes in the Bitcoin network can consult it";
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
    it("UltraHonk::PartialHash", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector: selectorText,
        maxHeadersLength: 512,
        maxBodyLength: 192,
      });
      const proof = await proverPartialHash.fullProve(inputs, "honk");
      const result = await proverPartialHash.verify(proof, "honk");
      expect(result).toBeTruthy();
    });
  });
});
