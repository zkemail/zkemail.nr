/**
 * Transforms a u32 array to a u8 array
 * @dev sha-utils in zk-email-verify encodes partial hash as u8 array but noir expects u32
 *      transform back to keep upstream code but not have noir worry about transformation
 * 
 * @param input - the input to convert to 32 bit array
 * @returns - the input as a 32 bit array
 */
export function u8ToU32(input: Uint8Array): Uint32Array {
  const out = new Uint32Array(input.length / 4);
  for (let i = 0; i < out.length; i++) {
    out[i] =
      (input[i * 4 + 0] << 24) |
      (input[i * 4 + 1] << 16) |
      (input[i * 4 + 2] << 8) |
      (input[i * 4 + 3] << 0);
  }
  return out;
}

/**
 * Format circuit inputs for a Prover.toml file
 *
 * @param inputs - the inputs to convert to Prover.toml format
 * @param exactLength - whether toNoirInputs should have exact length for header or keep 0-padding
 * @returns - the inputs as bb cli expects them to appear in a Prover.toml file
 */
export function toProverToml(inputs: any): string {
  const lines: string[] = [];
  const structs: string[] = [];
  for (const [key, value] of Object.entries(inputs)) {
    if (Array.isArray(value)) {
      const valueStrArr = value.map((val) => `'${val}'`);
      lines.push(`${key} = [${valueStrArr.join(", ")}]`);
    } else if (typeof value === "string") {
      lines.push(`${key} = '${value}'`);
    } else {
      let values = "";
      for (const [k, v] of Object.entries(value!)) {
        values = values.concat(`${k} = '${v}'\n`);
      }
      structs.push(`[${key}]\n${values}`);
    }
  }
  return lines.concat(structs).join("\n");
}
