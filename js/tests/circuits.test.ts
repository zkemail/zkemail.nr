import fs from "fs";
import path from "path";
import {
  BarretenbergBackend,
  CompiledCircuit,
  UltraHonkBackend,
} from "@noir-lang/backend_barretenberg";
import { Noir } from "@noir-lang/noir_js";
import {
  generateEmailVerifierInputs,
  toNoirInputs,
} from "../src";
import circuit1024 from "../../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
import circuit2048 from "../../examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";
const emails = {
  small: fs.readFileSync(
    path.join(__dirname, "./test-data/email-good.eml")
  ),
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

describe("Fixed Size Circuit Input", () => {
  let prover1024: Prover;
  let prover2048: Prover;
  jest.setTimeout(100000);
  beforeAll(async () => {
    //@ts-ignore
    prover1024 = makeProver(circuit1024);
    //@ts-ignore
    prover2048 = makeProver(circuit2048);
  });

  describe("UltraHonk", () => {
    it("UltraHonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(emails.small);
      const noirInputs = toNoirInputs(inputs);
      const { witness } = await prover2048.noir.execute(noirInputs);
      const proof = await prover2048.ultraHonk.generateProof(witness);
      const result = await prover2048.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });

    it("UltraHonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large);
      const noirInputs = toNoirInputs(inputs);
      const { witness } = await prover2048.noir.execute(noirInputs);
      const proof = await prover2048.ultraHonk.generateProof(witness);
      const result = await prover2048.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });
    xit("UltraHonk::1024-Bit", async () => {
      // todo: make github account to make this email for
      // const inputs = await generateEmailVerifierInputs(emails.github);
      const inputs = await generateEmailVerifierInputs(emails.large);
      const noirInputs = toNoirInputs(inputs);
      const { witness } = await prover1024.noir.execute(noirInputs);
      const proof = await prover1024.ultraHonk.generateProof(witness);
      const result = await prover1024.ultraHonk.verifyProof(proof);
      expect(result).toBeTruthy();
    });
  });

  xdescribe("UltraPlonk", () => {
    it("UltraPlonk::SmallEmail", async () => {
      const inputs = await generateEmailVerifierInputs(emails.small);
      const noirInputs = toNoirInputs(inputs);
      const { witness } = await prover2048.noir.execute(noirInputs);
      const proof = await prover2048.barretenberg.generateProof(witness);
      const result = await prover2048.barretenberg.verifyProof(proof);
      expect(result).toBeTruthy();
    });

    it("UltraPlonk::LargeEmail", async () => {
      const inputs = await generateEmailVerifierInputs(emails.large);
      const noirInputs = toNoirInputs(inputs);
      const { witness } = await prover2048.noir.execute(noirInputs);
      const proof = await prover2048.barretenberg.generateProof(witness);
      const result = await prover2048.barretenberg.verifyProof(proof);
      expect(result).toBeTruthy();
    });
  });
});
