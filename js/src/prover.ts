import { Barretenberg, UltraHonkBackend, ProofData } from "@aztec-foundation/bb.js";
import { Noir, InputMap, CompiledCircuit } from "@noir-lang/noir_js";
import { InputValue, } from "@noir-lang/noirc_abi";

// bb.js 6 only provides UltraHonk; UltraPlonk was removed
type ProvingBackend = "honk";

export class ZKEmailProver {
  private api?: Promise<Barretenberg>;

  private honk?: Promise<UltraHonkBackend>;

  private noir: Noir;

  constructor(
    /* The ACIR of the Noir circuit to prove */
    private circuit: CompiledCircuit,
    /* Define the prover backend to use */
    private provingBackend: ProvingBackend = "honk",
    /* Threads to use */
    private threads: number = 1
  ) {
    // initialize the Noir instance; the backend is created on first use
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
   * @param provingBackend - optionally provided; only "honk" is supported
   * @returns proof of valid execution of the circuit
   */
  async prove(
    witness: Uint8Array,
    provingBackend?: ProvingBackend
  ): Promise<ProofData> {
    const backend = await this.backend(provingBackend);
    // generate the proof
    return backend.generateProof(witness);
  }

  /**
   * Simulate the witness for a given input and generate a proof
   *
   * @param input - the input that should produce a satisfying witness for the circuit
   * @param provingBackend - optionally provided; only "honk" is supported
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
   * @param provingBackend - optionally provided; only "honk" is supported
   * @returns true if the proof is valid, false otherwise
   */
  async verify(
    proof: ProofData,
    provingBackend?: ProvingBackend
  ): Promise<boolean> {
    const backend = await this.backend(provingBackend);
    // verify the proof
    return backend.verifyProof(proof);
  }

  /**
   * End the prover wasm instance(s) and clean up resources
   */
  async destroy() {
    if (this.api) {
      await (await this.api).destroy();
    }
  }

  private backend(provingBackend?: ProvingBackend): Promise<UltraHonkBackend> {
    const scheme = provingBackend ?? this.provingBackend;
    if (scheme !== "honk") {
      throw new Error(`Proving scheme ${scheme} not supported`);
    }
    if (!this.honk) {
      this.api = Barretenberg.new({ threads: this.threads });
      this.honk = this.api.then(
        (api) => new UltraHonkBackend(this.circuit.bytecode, api)
      );
    }
    return this.honk;
  }
}
