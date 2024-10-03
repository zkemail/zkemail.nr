import fs from "fs";
import path from "path";
import {
  BarretenbergBackend,
  CompiledCircuit,
  UltraHonkBackend,
} from "@noir-lang/backend_barretenberg";
import { Noir, acvm } from "@noir-lang/noir_js";
import { generateEmailVerifierInputs } from "../src";
import circuit1024 from "../../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
import circuit2048 from "../../examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";
import partialHash from "../../examples/partial_hash/target/partial_hash.json";
const emails = {
  small: fs.readFileSync(path.join(__dirname, "./test-data/email-good.eml")),
  large: fs.readFileSync(
    path.join(__dirname, "./test-data/email-good-large.eml")
  ),
};

type Prover = {
  noir: Noir;
  barretenberg: BarretenbergBackend;
  ultraHonk: UltraHonkBackend;
};

function makeProver(circuit: CompiledCircuit): Prover {
  return {
    noir: new Noir(circuit),
    barretenberg: new BarretenbergBackend(circuit),
    ultraHonk: new UltraHonkBackend(circuit),
  };
}

async function teardownProver(prover: Prover) {
  await prover.barretenberg.destroy(), await prover.ultraHonk.destroy();
}

describe("Fixed Size Circuit Input", () => {
  let prover1024: Prover;
  let prover2048: Prover;
  let proverPartialHash: Prover;
  const inputParams = {
    maxHeadersLength: 512,
    maxBodyLength: 1024,
  };
  jest.setTimeout(100000);
  beforeAll(async () => {
    //@ts-ignore
    prover1024 = makeProver(circuit1024);
    //@ts-ignore
    prover2048 = makeProver(circuit2048);
    //@ts-ignore
    proverPartialHash = makeProver(partialHash);
  });
  afterAll(async () => {
    teardownProver(prover1024);
    teardownProver(prover2048);
    teardownProver(proverPartialHash);
  });
  xdescribe("UltraHonk", () => {
    xit("UltraHonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      const { witness } = await prover2048.noir.execute(inputs);
      const proof = await prover2048.ultraHonk.generateProof(witness);
      const result = await prover2048.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });

    it("UltraHonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.large,
        inputParams
      );
      const { witness } = await prover2048.noir.execute(inputs);
      const proof = await prover2048.ultraHonk.generateProof(witness);
      const result = await prover2048.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });
  });

  xdescribe("UltraPlonk", () => {
    it("UltraPlonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.small,
        inputParams
      );
      const { witness } = await prover2048.noir.execute(inputs);
      const proof = await prover2048.barretenberg.generateProof(witness);
      const result = await prover2048.barretenberg.verifyProof(proof);
      expect(result).toBeTruthy();
    });

    it("UltraPlonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(
        emails.large,
        inputParams
      );
      const { witness } = await prover2048.noir.execute(inputs);
      const proof = await prover2048.barretenberg.generateProof(witness);
      const result = await prover2048.barretenberg.verifyProof(proof);
      expect(result).toBeTruthy();
    });
  });

  describe("Partial Hash", () => {
    it("UltraPlonk::PartialHash", async () => {
      const selectorText = "All nodes in the Bitcoin network can consult it";
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector: selectorText,
        maxHeadersLength: 512,
        maxBodyLength: 192
      });
      const { witness } = await proverPartialHash.noir.execute(inputs);
      const proof = await proverPartialHash.barretenberg.generateProof(witness);
      const result = await proverPartialHash.barretenberg.verifyProof(proof);
      expect(result).toBeTruthy();
    });
    it("UltraHonk::PartialHash", async () => {
      const selectorText = "All nodes in the Bitcoin network can consult it";
      const inputs = await generateEmailVerifierInputs(emails.large, {
        shaPrecomputeSelector: selectorText,
        maxHeadersLength: 512,
        maxBodyLength: 192
      });
      const { witness } = await proverPartialHash.noir.execute(inputs);
      const proof = await proverPartialHash.ultraHonk.generateProof(witness);
      const result = await proverPartialHash.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });
  });
});
