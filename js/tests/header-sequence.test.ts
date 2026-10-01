import { createHash } from "crypto";
import { generateEmailVerifierInputsFromDKIMResult } from "../src/index";
import { getHeaderSequence } from "../src/utils";

// Synthetic headers only; no real mail.
const bodyHash = createHash("sha256").update("").digest("base64"); // 47DEQpj8...

function field(header: string, seq: { index: string; length: string }) {
  return header.slice(Number(seq.index), Number(seq.index) + Number(seq.length));
}

describe("getHeaderSequence", () => {
  it("finds a relaxed (lowercase, unfolded) DKIM-Signature at the end of the header", () => {
    const dkim = `dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=from:to; bh=${bodyHash}; b=`;
    const header = `from:a@example.com\r\nto:b@example.org\r\n${dkim}`;
    const seq = getHeaderSequence(Buffer.from(header), "dkim-signature", "last");
    expect(field(header, seq)).toBe(dkim);
  });

  it("finds a c=simple DKIM-Signature: original case and folded lines", () => {
    const dkim = `DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.com;\r\n\ts=sel; h=From:To;\r\n\tbh=${bodyHash};\r\n b=`;
    const header = `From: a@example.com\r\nTo: b@example.org\r\n${dkim}`;
    const seq = getHeaderSequence(Buffer.from(header), "dkim-signature", "last");
    expect(field(header, seq)).toBe(dkim);
  });

  it("excludes the terminating CRLF of a field that is not last", () => {
    const header = "Subject: hi\r\n there\r\nFrom: a@example.com\r\n";
    const seq = getHeaderSequence(Buffer.from(header), "subject");
    expect(field(header, seq)).toBe("Subject: hi\r\n there");
  });

  it("only matches the name at the start of a line", () => {
    const header = "x-note: see dkim-signature: below\r\ndkim-signature:v=1; b=";
    const seq = getHeaderSequence(Buffer.from(header), "dkim-signature");
    expect(seq.index).toBe(String(header.indexOf("\r\n") + 2));
  });

  it("returns the last DKIM-Signature when several are signed", () => {
    const first = "dkim-signature:v=1; d=other.example; b=abc";
    const last = "dkim-signature:v=1; d=example.com; b=";
    const header = `${first}\r\nfrom:a@example.com\r\n${last}`;
    const seq = getHeaderSequence(Buffer.from(header), "dkim-signature", "last");
    expect(field(header, seq)).toBe(last);
  });

  it("uses byte offsets when the header has non-ASCII bytes", () => {
    const header = Buffer.concat([
      Buffer.from("subject:café\r\n", "utf8"), // é is 2 bytes in UTF-8
      Buffer.from("dkim-signature:v=1; b="),
    ]);
    const seq = getHeaderSequence(header, "dkim-signature", "last");
    expect(seq.index).toBe(String(header.indexOf("dkim-signature")));
  });
});

describe("generateEmailVerifierInputsFromDKIMResult", () => {
  it("locates a c=simple DKIM-Signature and its bh= value", () => {
    const dkim = `DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.com;\r\n\ts=sel; h=From:Subject;\r\n\tbh=${bodyHash};\r\n\tb=`;
    const headers = Buffer.from(`From: a@example.com\r\nSubject: hello\r\n${dkim}`);
    const dkimResult: any = {
      headers,
      body: Buffer.from(""),
      bodyHash,
      // arbitrary 2048-bit odd numbers: input generation does not check the signature
      publicKey: (1n << 2047n) + 12345n,
      signature: 3n,
      modulusLength: 2048,
    };
    const inputs = generateEmailVerifierInputsFromDKIMResult(dkimResult, {
      maxHeadersLength: 512,
      maxBodyLength: 64,
    });
    const headerStr = headers.toString("latin1");
    expect(field(headerStr, inputs.dkim_header_sequence)).toBe(dkim);
    const bhIndex = Number(inputs.body_hash_index);
    expect(headerStr.slice(bhIndex - 7, bhIndex)).toBe(";\r\n\tbh=");
    expect(headerStr.slice(bhIndex, bhIndex + 44)).toBe(bodyHash);
  });
});
