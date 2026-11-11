import { getAddressHeaderSequence } from "../src/utils";

function extracted(header: Buffer, name = "from") {
  const [field, address] = getAddressHeaderSequence(header, name);
  return {
    field: header.subarray(+field.index, +field.index + +field.length).toString("latin1"),
    address: header.subarray(+address.index, +address.index + +address.length).toString("latin1"),
    index: +address.index,
  };
}

describe("address sequences stay inside the complete named field", () => {
  it.each(["From", "FROM", "fRoM"])("matches %s case insensitively", (name) => {
    expect(extracted(Buffer.from(`${name}: <a@example.org>`)).address).toBe("a@example.org");
  });
  it.each(["subject:from:attacker@example.org", "x-from:attacker@example.org", "subject:copy\r\n from:attacker@example.org"])("ignores lookalike fields: %s", (prefix) => {
    const header = Buffer.from(`${prefix}\r\nfrom:real@example.org`);
    expect(extracted(header).address).toBe("real@example.org");
  });
  it("uses the selected field's address offset when another field repeats it", () => {
    const header = Buffer.from("subject:a@example.org\r\nfrom:<a@example.org>");
    expect(extracted(header).index).toBe(header.lastIndexOf("a@example.org"));
  });
  it("keeps UTF-8 byte offsets", () => {
    const header = Buffer.from("subject:café🙂\r\nfrom:real@example.org", "utf8");
    expect(extracted(header).index).toBe(header.indexOf("real@example.org"));
  });
  it.each(["\r\n ", "\r\n\t"])("includes folded continuation %j", (fold) => {
    const field = `From: Display${fold}<real@example.org>`;
    expect(extracted(Buffer.from(`${field}\r\nsubject:next`))).toMatchObject({ field, address: "real@example.org" });
  });
  // The circuit rejects these (headers/mod.nr scan_address_field, headers/email_address.nr), so the
  // input generator does too.
  it.each([
    "From: Display\r\n <real@example.org> (comment)",
    "from:Display (comment) <real@example.org>",
    'from:"Dis\\"play" <real@example.org>',
    'from:"Display <real@example.org>',
    "from:<real@example.org> trailing",
    'from:"<other@example.org>" real@example.org',
    'from:real@example.org "x"',
    "from:<real@example.org>\n",
    "from:\treal@example.org",
    "from:real@example.org ",
  ])("rejects syntax the circuit rejects %j", (header) => {
    expect(() => getAddressHeaderSequence(Buffer.from(header), "from")).toThrow();
  });
  it.each([
    ['from:"Doe, John (Sales)" <jd@example.org>', "jd@example.org"],
    ["From: <real@example.org> \t", "real@example.org"],
    ["From: Display\r\n <real@example.org>\r\n \r\nsubject:next", "real@example.org"],
    ["from: real@example.org\r\n\t\r\nsubject:next", "real@example.org"],
  ])("accepts what the circuit accepts %j", (header, address) => {
    expect(extracted(Buffer.from(header)).address).toBe(address);
  });
  it("supports a last field without a trailing CRLF", () => {
    expect(extracted(Buffer.from("to:a@example.org"), "to").address).toBe("a@example.org");
  });
  it.each([
    "from:a@example.org\r\nfrom:b@example.org",
    "from:first@example.org, second@example.org",
    "from:not-an-address",
    "from:a@@example.org",
    "from:<a@example.org",
    "from:a+tag@example.org",
  ])("rejects ambiguous or unsupported address syntax %j", (header) => {
    expect(() => getAddressHeaderSequence(Buffer.from(header), "from")).toThrow();
  });
  it("rejects a header name outside the supported address API", () => {
    expect(() => getAddressHeaderSequence(Buffer.from("x:a@example.org"), "x.*")).toThrow();
  });
});
