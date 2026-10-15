# Daybreak Blue security investigation (2026-10-14)

## Scope and evidence

- Owned branch: `agent/daybreak-hardening-20261014`, starting at `08c755e3835ea0c09071e855b3fe83e786b35333` (`origin/stack/02-bh-injection-tests`). Fetched origin before work; the upstream tip remained at that SHA throughout validation.
- Reviewed GitHub PRs [#68](https://github.com/zkemail/zkemail.nr/pull/68), [#67](https://github.com/zkemail/zkemail.nr/pull/67), [#66](https://github.com/zkemail/zkemail.nr/pull/66), [#65](https://github.com/zkemail/zkemail.nr/pull/65), and merged [#62](https://github.com/zkemail/zkemail.nr/pull/62)/[#64](https://github.com/zkemail/zkemail.nr/pull/64) read-only. #67/#68 form the tested stack; #66 independently identifies the early value scan bug, and #65 targets a different Noir toolchain.
- Inspected `headers/body_hash.nr`, `headers/mod.nr`, `headers/email_address.nr`, `dkim.nr`, `hash.nr`, `masking.nr`, `partial_hash.nr`, `utils.nr`, `remove_soft_line_breaks.nr`, `lib.nr`, JS `utils.ts`/`index.ts`, and example circuits. The relevant [blog trust boundaries](https://blog.aayushg.com/zkemail/) are field separation, a body hash from the verified signature, source provenance, and application-level key/recipient/nullifier checks.
- Used only synthetic new test inputs. The private email corpus was not copied, printed, or committed; the main investigator owns its structural and JS corpus checks.

## Confirmed library defects and changes

1. **Early address-field value bytes were skipped.** `constrain_header_field_detect_last_angle_bracket` added the field-name offset twice. A synthetic `From` field with an early `<real@a.bc>` could select a later `fake@b.cd`, and an early bare CR was accepted. Both new `#[test(should_fail_with = ...)]` tests failed on the unchanged implementation with “Test passed when it should have failed.” The scan now begins at value offset zero and validates complete CRLF + whitespace folds. A positive folded-From and early-bracket control passes. This is a parser acceptance flaw on signed header text; no forged end-to-end DKIM proof was attempted.
2. **Address syntax lacked an `@` check.** `parse_email_address` accepted `from:fake` as an address. The new regression failed before the change. It now requires exactly one `@`; a double-`@` test passes after the change. This deliberately does not claim full RFC mailbox parsing.
3. **`bh=` terminator could come from unauthenticated storage.** `get_body_hash` allowed `body_hash_index + 44 == dkim_header_field_sequence.end_index()` and then read the required `;` at that index. In a synthetic `BoundedVec`, the field ended after the base64 hash while its storage tail contained `;`; the function accepted it. The new regression failed before the change. The bound now requires the semicolon itself to be inside the selected authenticated DKIM field. A signed in-field terminator remains accepted. This establishes a helper-level boundary defect, not a complete proof forgery.

## Adversarial matrix

| Case | Evidence | Result |
| --- | --- | --- |
| Subject `;bh=` with no space; folded Subject continuation; Content-Type and List-Unsubscribe `;bh=` | Executed Noir tests (existing #68 plus new) | Rejected when index targets another field |
| `dkim-signature:` lookalike inside Subject; signature-like field names | Executed existing #68 tests | Rejected by field start/name checks |
| Multiple DKIM-Signature fields; first vs last field | Executed existing tests | Earlier field rejected; selected last field accepted |
| First-tag and subsequent-tag `bh=`; folded tab/space tag; uppercase field name | Executed existing and new positive tests | Accepted where supported |
| `bh=` index zero, `u32` maximum, and tag terminator beyond declared length | Executed new tests | Rejected after fix; tail-terminator case accepted before fix |
| Early `<`, bare CR, no `@`, double `@`, folded valid From | Executed new tests | Invalid cases rejected; valid cases accepted after fix |
| RSA redc top-limb bound, changed-redc hash, mask output past length | Existing Noir tests executed; code inspected | Existing guards passed; no new proof soundness claim |
| Duplicate `bh=` tags, malformed tag grammar, arbitrary MIME/canonicalization, partial-hash state trust, soft-line-break collision resistance | Source inspection and existing tests only | No exploit verdict; circuit does not fully parse DKIM tags |
| DNS/key provenance and rotation, sender/receiver server trust, Bcc/unsigned-field claims, recipient binding, nullifier linkability | Application boundary review | Outside this library test; integrating applications must enforce these claims |

## Validation and limits

- Baseline at `08c755e`: `nargo test` **84/84 passed** with official Nargo/noirc `1.0.0-beta.5` (`c651df6e2bf5db3966aa0c95abea2fc4c69d4513`), downloaded only to `/tmp/zkemail-daybreak-20261014/tools`.
- Before fixes: three address regressions failed as expected; the authenticated-tail `bh=` regression separately failed as expected. After fixes: `nargo test` **97/97 passed**, `nargo fmt --check` passed, and `nargo check` passed for all six examples. The repository pins JS `@noir-lang/noir_js`/`@noir-lang/noirc_abi` to `1.0.0-beta.5` and `@aztec/bb.js` to `0.84.0`; JS behavior was inspected but its suite was not run in this owned task.
- These are Noir interpreter and compile results, not full proof generation/verification, browser behavior, or production deployment. The private corpus findings and complementary JS checks belong to the parent investigation. No all-secure verdict is implied.
