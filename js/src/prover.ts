import { UltraPlonkBackend, UltraHonkBackend } from "@aztec/bb.js";
import { ProofData } from "@aztec/bb.js/dest/node-cjs/proof";
import { Noir, InputMap, CompiledCircuit } from "@noir-lang/noir_js";
import { InputValue, } from "@noir-lang/noirc_abi";

type ProvingBackend = "honk" | "plonk" | "all";

export class ZKEmailProver {
  private plonk?: UltraPlonkBackend;

  private honk?: UltraHonkBackend;

  private noir: Noir;

  constructor(
    /* The ACIR of the Noir circuit to prove */
    circuit: CompiledCircuit,
    /* Define the prover backend to use */
    private provingBackend: ProvingBackend = "plonk",
    /* Threads to use */
    private threads: number = 1
  ) {
    // initialize the backends
    if (provingBackend === "plonk" || provingBackend === "all") {
      this.plonk = new UltraPlonkBackend(circuit.bytecode, { threads: this.threads });
    }
    if (provingBackend === "honk" || provingBackend === "all") {
      this.honk = new UltraHonkBackend(circuit.bytecode, { threads: this.threads });
    }
    // initialize the Noir instance
    this.noir = new Noir(circuit);
  }

  /**
   * Compute the witness for a given input to the circuit without generating a proof
   *
   * @param input - the input that should produce a satisfying witness for the circuit
   * @returns - the witness for the input and the output of the circuit if satisfiable
   */
  async simulateWitness(
    input: InputMap
  ): Promise<{ witness: Uint8Array; returnValue: InputValue }> {
    return this.noir.execute(input);
  }

  /**
   * Generate a proof of a satisfying input to the circuit using a provided witness
   *
   * @param input - a satisfying witness for the circuit
   * @param provingBackend - optionally provided if the class was initialized with both proving schemes
   * @returns proof of valid execution of the circuit
   */
  async prove(
    witness: Uint8Array,
    provingBackend?: ProvingBackend
  ): Promise<ProofData> {
    // determine proving backend to use
    let backend: UltraPlonkBackend | UltraHonkBackend;
    if (
      (provingBackend && this.plonk) ||
      (this.provingBackend === "plonk" && this.plonk)
    ) {
      backend = this.plonk;
    } else if (
      (provingBackend === "honk" && this.honk) ||
      (this.provingBackend === "honk" && this.honk)
    ) {
      backend = this.honk;
    } else {
      throw new Error(`Proving scheme ${this.provingBackend} not initialized`);
    }

    // generate the proof
    return backend.generateProof(witness);
  }

  /**
   * Simulate the witness for a given input and generate a proof
   *
   * @param input - the input that should produce a satisfying witness for the circuit
   * @param provingBackend - optionally provided if the class was initialized with both proving schemes
   * @returns proof of valid execution of the circuit
   */
  async fullProve(
    input: InputMap,
    provingBackend?: ProvingBackend
  ): Promise<ProofData> {
    const { witness } = await this.simulateWitness(input);
    return this.prove(witness, provingBackend);
  }

  /**
   * Verify a proof of a satisfying input to the circuit for a given proving scheme
   *
   * @param proof - the proof to verify
   * @param provingBackend - optionally provided if the class was initialized with both proving schemes
   * @returns true if the proof is valid, false otherwise
   */
  async verify(
    proof: ProofData,
    provingBackend?: ProvingBackend
  ): Promise<boolean> {
    // determine proving backend to use
    let backend: UltraHonkBackend | UltraPlonkBackend;
    if (
      (provingBackend && this.plonk) ||
      (this.provingBackend === "plonk" && this.plonk)
    ) {
      backend = this.plonk;
    } else if (
      (provingBackend === "honk" && this.honk) ||
      (this.provingBackend === "honk" && this.honk)
    ) {
      backend = this.honk;
    } else {
      throw new Error(`Proving scheme ${this.provingBackend} not initialized`);
    }
    // verify the proof
    return backend.verifyProof(proof);
  }

  /**
   * End the prover wasm instance(s) and clean up resources
   */
  async destroy() {
    if (this.plonk) {
      await this.plonk.destroy();
    }
    if (this.honk) {
      await this.honk.destroy();
    }
  }
}
