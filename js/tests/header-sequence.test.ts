import { createHash } from "crypto";
import { generateEmailVerifierInputsFromDKIMResult } from "../src/index";
import { getHeaderSequence, getVerifiedDkimSignatureSequence } from "../src/utils";

// Synthetic headers only; no real mail. Header buffers have the shape of
// DKIMVerificationResult.headers: the h= fields, then the verified DKIM-Signature with b= emptied.
const bodyHash = createHash("sha256").update("").digest("base64"); // 47DEQpj8...
const otherBodyHash = createHash("sha256").update("\r\n").digest("base64");
const fakeB = "A".repeat(340) + "==";

function field(header: string, seq: { index: string; length: string }) {
  return header.slice(Number(seq.index), Number(seq.index) + Number(seq.length));
}

function inputsFor(headers: string, signingDomain: string, selector: string) {
  const dkimResult: any = {
    headers: Buffer.from(headers, "latin1"),
    body: Buffer.from(""),
    bodyHash,
    signingDomain,
    selector,
    // arbitrary 2048-bit odd numbers: input generation does not check the signature
    publicKey: (1n << 2047n) + 12345n,
    signature: 3n,
    modulusLength: 2048,
  };
  return generateEmailVerifierInputsFromDKIMResult(dkimResult, { maxHeadersLength: 1024, maxBodyLength: 64 });
}

describe("getHeaderSequence", () => {
  it("matches c=simple names (any case) and keeps folded lines in the field", () => {
    const subject = "Subject: hi\r\n there";
    const header = `${subject}\r\nFrom: a@example.com`;
    expect(field(header, getHeaderSequence(Buffer.from(header), "subject"))).toBe(subject);
  });

  it("only matches the name at the start of a line", () => {
    const header = "x-note: see subject: below\r\nsubject:hi";
    expect(getHeaderSequence(Buffer.from(header), "subject").index).toBe(String(header.indexOf("\r\n") + 2));
  });

  it("uses byte offsets when the header has non-ASCII bytes", () => {
    const header = Buffer.concat([Buffer.from("subject:café\r\n", "utf8"), Buffer.from("to:b@example.org")]);
    expect(getHeaderSequence(header, "to").index).toBe(String(header.indexOf("to:")));
  });
});

describe("getVerifiedDkimSignatureSequence", () => {
  it("relaxed, single signature", () => {
    const dkim = `dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to; bh=${bodyHash}; b=`;
    const header = `from:a@example.com\r\nto:b@example.org\r\n${dkim}`;
    const { sequence, bodyHashIndex } = getVerifiedDkimSignatureSequence(Buffer.from(header), {
      signingDomain: "example.com",
      selector: "sel",
      bodyHash,
    });
    expect(field(header, sequence)).toBe(dkim);
    expect(header.slice(bodyHashIndex, bodyHashIndex + 44)).toBe(bodyHash);
  });

  it("c=simple: original case and folded lines", () => {
    const dkim = `DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.com;\r\n\ts=sel; h=From:To;\r\n\tbh=${bodyHash};\r\n b=`;
    const header = `From: a@example.com\r\nTo: b@example.org\r\n${dkim}`;
    const { sequence, bodyHashIndex } = getVerifiedDkimSignatureSequence(Buffer.from(header), {
      signingDomain: "example.com",
      selector: "sel",
      bodyHash,
    });
    expect(field(header, sequence)).toBe(dkim);
    expect(header.slice(bodyHashIndex - 7, bodyHashIndex)).toBe(";\r\n\tbh=");
  });

  // Google Workspace style: d=<domain> plus d=<domain>.<date>.gappssmtp.com, where one signature's
  // h= lists DKIM-Signature so the other signature is part of the signed header.
  const domainSig = (b: string) =>
    `dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=google; h=from:to:dkim-signature; bh=${bodyHash}; b=${b}`;
  const gappsSig = (b: string) =>
    `dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example-com.20230601.gappssmtp.com; s=20230601; h=from:to:dkim-signature; bh=${bodyHash}; b=${b}`;

  it("multi-signature: picks the verified d=example.com field, not the gappssmtp one", () => {
    const header = `from:a@example.com\r\nto:b@example.org\r\n${gappsSig(fakeB)}\r\n${domainSig("")}`;
    const inputs = inputsFor(header, "example.com", "google");
    expect(field(header, inputs.dkim_header_sequence)).toBe(domainSig(""));
    expect(Number(inputs.body_hash_index)).toBeGreaterThan(header.lastIndexOf("dkim-signature:"));
  });

  it("multi-signature: picks the verified gappssmtp field when that is the one verified", () => {
    const header = `from:a@example.com\r\nto:b@example.org\r\n${domainSig(fakeB)}\r\n${gappsSig("")}`;
    const inputs = inputsFor(header, "example-com.20230601.gappssmtp.com", "20230601");
    expect(field(header, inputs.dkim_header_sequence)).toBe(gappsSig(""));
  });

  it("multi-signature: ESP and From-domain signatures with different bh= / c=", () => {
    const esp = `dkim-signature:v=1; a=rsa-sha256; c=simple/simple; d=esp.example.net; s=s1; h=from:to; l=0; bh=${otherBodyHash}; b=${fakeB}`;
    const own = `dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s2; h=from:to:dkim-signature; bh=${bodyHash}; b=`;
    const header = `from:a@example.com\r\nto:b@example.org\r\n${esp}\r\n${own}`;
    const inputs = inputsFor(header, "example.com", "s2");
    expect(field(header, inputs.dkim_header_sequence)).toBe(own);
    const i = Number(inputs.body_hash_index);
    expect(header.slice(i, i + 44)).toBe(bodyHash);
  });

  it("refuses to guess when the verified signature cannot be identified", () => {
    const header = `from:a@example.com\r\n${domainSig("")}`;
    expect(() => getVerifiedDkimSignatureSequence(Buffer.from(header), { signingDomain: "example.com", selector: "other" })).toThrow(
      /found 0/
    );
    // a field that matches but is not last cannot be used by the circuit
    const notLast = `${domainSig("")}\r\nfrom:a@example.com`;
    expect(() =>
      getVerifiedDkimSignatureSequence(Buffer.from(notLast), { signingDomain: "example.com", selector: "google", bodyHash })
    ).toThrow(/not the last field/);
  });
});
