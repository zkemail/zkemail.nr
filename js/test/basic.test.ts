// import {
//   generateEmailVerifierInputsFromDKIMResult,
//   toNoirInputs,
// } from "../src";
// import fs from "fs";
// import path from "path";
// import {
//   BarretenbergBackend,
//   UltraHonkBackend,
// } from "@noir-lang/backend_barretenberg";
// import { Noir } from "@noir-lang/noir_js";
// import circuit1024 from "../examples/verify_email_1024_bit_dkim/target/verify_email_1024_bit_dkim.json";
// import circuit2048 from "../zkemail.nr/examples/verify_email_2048_bit_dkim/target/verify_email_2048_bit_dkim.json";

// const emails = {
//   small: fs.readFileSync(
//     path.join(__dirname, "../../circuits/tests/test-emails/test.eml")
//   ),
//   large: fs.readFileSync(
//     path.join(__dirname, "../../helpers/tests/test-data/email-good-large.eml")
//   ),
//   ownership: fs.readFileSync(
//     path.join(__dirname, "../../helpers/tests/test-data/ownership.eml")
//   ),
// };

// type Prover = {
//   noir: Noir;
//   barretenberg: BarretenbergBackend;
//   ultraHonk: UltraHonkBackend;
// };

// describe("Fixed Size Circuit Input", () => {
//   let prover1024: Prover;
//   let prover2048: Prover;
//   jest.setTimeout(100000);
//   beforeAll(async () => {
//     prover1024 = {
//       noir: new Noir(circuit1024),
//       barretenberg: new BarretenbergBackend(circuit1024),
//       ultraHonk: new UltraHonkBackend(circuit1024),
//     };
//     prover2048 = {
//       noir: new Noir(circuit2048),
//       barretenberg: new BarretenbergBackend(circuit2048),
//       ultraHonk: new UltraHonkBackend(circuit2048),
//     };
//   });

//   describe("UltraHonk", () => {
//     it("UltraHonk::SmallEmail", async () => {
//       const inputs = await generateEmailVerifierInputs(emails.small, {
//         backend: CircuitBackend.Noir,
//       });
//       const noirInputs = toNoirInputs(inputs);
//       const { witness } = await prover2048.noir.execute(noirInputs);
//       const proof = await prover2048.ultraHonk.generateProof(witness);
//       const result = await prover2048.ultraHonk.verifyProof(proof);
//       expect(result).toBeTruthy();
//     });

//     it("UltraHonk::LargeEmail", async () => {
//       const inputs = await generateEmailVerifierInputs(emails.large, {
//         backend: CircuitBackend.Noir,
//       });
//       const noirInputs = toNoirInputs(inputs);
//       const { witness } = await prover2048.noir.execute(noirInputs);
//       const proof = await prover2048.ultraHonk.generateProof(witness);
//       const result = await prover2048.ultraHonk.verifyProof(proof);
//       expect(result).toBeTruthy();
//     });
//     it("UltraHonk::Ownership", async () => {
//       const inputs = await generateEmailVerifierInputs(emails.ownership, {
//         backend: CircuitBackend.Noir,
//       });
//       const noirInputs = toNoirInputs(inputs);
//       const { witness } = await prover1024.noir.execute(noirInputs);
//       const proof = await prover1024.ultraHonk.generateProof(witness);
//       const result = await prover1024.ultraHonk.verifyProof(proof);
//       expect(result).toBeTruthy();
//     });
//   });

//   xdescribe("UltraPlonk", () => {
//     it("UltraPlonk::SmallEmail", async () => {
//       const inputs = await generateEmailVerifierInputs(emails.small, {
//         backend: CircuitBackend.Noir,
//       });
//       const noirInputs = toNoirInputs(inputs);
//       const { witness } = await prover2048.noir.execute(noirInputs);
//       const proof = await prover2048.barretenberg.generateProof(witness);
//       const result = await prover2048.barretenberg.verifyProof(proof);
//       expect(result).toBeTruthy();
//     });

//     it("UltraPlonk::LargeEmail", async () => {
//       const inputs = await generateEmailVerifierInputs(emails.large, {
//         backend: CircuitBackend.Noir,
//       });
//       const noirInputs = toNoirInputs(inputs);
//       const { witness } = await prover2048.noir.execute(noirInputs);
//       const proof = await prover2048.barretenberg.generateProof(witness);
//       const result = await prover2048.barretenberg.verifyProof(proof);
//       expect(result).toBeTruthy();
//     });
//   });
// });
