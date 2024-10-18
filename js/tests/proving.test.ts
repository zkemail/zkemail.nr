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

  describe("2048-bit circuit", () => {
    let prover: ZKEmailProver;
    describe("UltraPlonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuit2048, "plonk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Small Email", async () => {
        const inputs = await generateEmailVerifierInputs(
          emails.small,
          inputParams
        );
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
      it("Large Email", async () => {
        const inputs = await generateEmailVerifierInputs(
          emails.large,
          inputParams
        );
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
    describe("UltraHonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuit2048, "honk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Small Email", async () => {
        const inputs = await generateEmailVerifierInputs(
          emails.small,
          inputParams
        );
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
      it("Large Email", async () => {
        const inputs = await generateEmailVerifierInputs(
          emails.large,
          inputParams
        );
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
  });
  describe("Partial Hash Circuit", () => {
    let prover: ZKEmailProver;
    describe("UltraPlonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitPartialHash, "plonk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Partial Hash", async () => {
        const inputs = await generateEmailVerifierInputs(emails.large, {
          shaPrecomputeSelector: selectorText,
          maxHeadersLength: 512,
          maxBodyLength: 192,
        });
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
    describe("UltraHonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitPartialHash, "honk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Partial Hash", async () => {
        const inputs = await generateEmailVerifierInputs(emails.large, {
          shaPrecomputeSelector: selectorText,
          maxHeadersLength: 512,
          maxBodyLength: 192,
        });
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
  });
  describe("Masking Circuit", () => {
    let prover: ZKEmailProver;
    describe("UltraPlonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitEmailMask, "plonk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Masking", async () => {
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
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
    describe("UltraHonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitEmailMask, "honk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Masking", async () => {
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
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
  });
  describe("Address Extraction Circuit", () => {
    let prover: ZKEmailProver;
    describe("UltraPlonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitExtractAddresses, "plonk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Address Extraction", async () => {
        const inputs = await generateEmailVerifierInputs(emails.small, {
          extractFrom: true,
          extractTo: true,
          ...inputParams,
        });
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
    describe("UltraHonk", () => {
      beforeAll(async () => {
        //@ts-ignore
        prover = new ZKEmailProver(circuitExtractAddresses, "honk");
      });
      afterAll(async () => {
        prover.destroy();
      });
      it("Address Extraction", async () => {
        const inputs = await generateEmailVerifierInputs(emails.small, {
          extractFrom: true,
          extractTo: true,
          ...inputParams,
        });
        const proof = await prover.fullProve(inputs);
        const result = await prover.verify(proof);
        expect(result).toBeTruthy();
      });
    });
  });
});
