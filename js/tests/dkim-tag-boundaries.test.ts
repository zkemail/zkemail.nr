import { getVerifiedDkimSignatureSequence } from "../src/utils";

const bodyHash = "A".repeat(43) + "=";
const identity = { signingDomain: "example.org", selector: "sel", bodyHash };
const select = (header: string, checkHash = true) => getVerifiedDkimSignatureSequence(Buffer.from(header), {
  ...identity, bodyHash: checkHash ? bodyHash : undefined,
});

describe("DKIM helper tag boundaries agree with the circuit", () => {
  it.each([true, false])("ignores :bh= inside a copied z= value (checkHash=%s)", (checkHash) => {
    const header = `dkim-signature:v=1; d=example.org; s=sel; z=Subject:bh=3Dcopied; bh=${bodyHash}; b=`;
    expect(select(header, checkHash).bodyHashIndex).toBe(header.lastIndexOf(bodyHash));
  });
  it.each([";bh=", "; bh=", ";\r\n bh=", ";\r\n\tbh="])("accepts real tag prefix %j", (prefix) => {
    const header = `dkim-signature:d=example.org; s=sel${prefix}${bodyHash}; b=`;
    expect(select(header).bodyHashIndex).toBe(header.indexOf(bodyHash));
  });
  it.each(["dkim-signature:", "DKIM-SIGNATURE:", "DKIM-Signature: "])("accepts first tag after %j", (prefix) => {
    const header = `${prefix}bh=${bodyHash}; d=example.org; s=sel; b=`;
    expect(select(header).bodyHashIndex).toBe(header.indexOf(bodyHash));
  });
  it.each(["d=example.org", "s=sel", `bh=${bodyHash}`, "b="])("rejects duplicate tag %j", (duplicate) => {
    const header = `dkim-signature:d=example.org; s=sel; bh=${bodyHash}; b=; ${duplicate}`;
    expect(() => select(header)).toThrow();
  });
  it("does not allow malformed duplicate bh tags when body checking is omitted", () => {
    expect(() => select(`dkim-signature:d=example.org; s=sel; bh=${bodyHash}; bh=${bodyHash}; b=`, false)).toThrow();
  });
});
