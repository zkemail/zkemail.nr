#!/usr/bin/env node
/* Offline parser compatibility checks. No DNS requests, signature verification, or proving.
 * Run `npm run build`, then `node scripts/check-private-corpus.cjs /path/to/emls`.
 * Output contains aggregate counts only. Never copy private fixtures into this repository.
 */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { parseHeaders, parseDkimHeaders, getSigningHeaderLines } = require('@zk-email/helpers/dist/lib/mailauth/tools');
const { generateCanonicalizedHeader } = require('@zk-email/helpers/dist/lib/mailauth/header');
const { getVerifiedDkimSignatureSequence, getHeaderSequence, getAddressHeaderSequence } = require('../dist/utils');

const root = process.argv[2];
if (!root || !fs.statSync(root).isDirectory()) {
  console.error('Usage: node scripts/check-private-corpus.cjs /path/to/emls');
  process.exit(2);
}
const counts = {};
const bump = (key) => { counts[key] = (counts[key] || 0) + 1; };
function* emails(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* emails(file);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith('.eml')) yield file;
  }
}

function inspectAddresses(header, signedNames) {
  for (const name of ['from', 'to']) {
    if (!signedNames.includes(name)) { bump(`address_${name}_unsigned`); continue; }
    try {
      const whole = getHeaderSequence(header, name);
      const [field, address] = getAddressHeaderSequence(header, name);
      if (field.index !== whole.index || field.length !== whole.length) {
        bump('address_field_sequence_mismatch');
      } else if (+address.index < +whole.index || +address.index + +address.length > +whole.index + +whole.length) {
        bump('address_outside_field');
      } else if (!/^[A-Za-z0-9._@-]+$/.test(header.subarray(+address.index, +address.index + +address.length).toString('latin1'))) {
        bump('address_unsupported_characters');
      } else {
        bump('address_structurally_compatible');
      }
    } catch { bump('address_helper_rejected'); }
  }
}

// These mutate canonicalized input to exercise the real selection helper. They do NOT
// preserve the RSA signature and cannot establish circuit soundness or authenticity.
function mutations(header, identity, selected) {
  const h = identity.bodyHash;
  const fake = `dkim-signature:d=${identity.signingDomain}; s=${identity.selector}; bh=${h}; b=not-empty\r\n`;
  const prefixes = [
    `subject:prefix;bh=${h};\r\n`,
    `content-type:text/plain;bh=${h};\r\n`,
    `subject:prefix;\r\n bh=${h};\r\n`,
    `subject:prefix;\r\n\tbh=${h};\r\n`,
    'subject:non-ascii \u00e9\u00ff\r\n',
    fake,
  ];
  for (const prefix of prefixes) {
    const bytes = Buffer.from(prefix, 'latin1');
    const result = getVerifiedDkimSignatureSequence(Buffer.concat([bytes, header]), identity);
    assert.equal(+result.sequence.index, +selected.sequence.index + bytes.length);
    assert.equal(result.bodyHashIndex, selected.bodyHashIndex + bytes.length);
    bump('mutation_positive_controls_passed');
  }
  assert.throws(() => getVerifiedDkimSignatureSequence(Buffer.concat([header, Buffer.from('\r\nx-extra:value')]), identity));
  bump('mutation_negative_controls_passed');
  assert.throws(() => getVerifiedDkimSignatureSequence(header, { ...identity, bodyHash: h === 'A'.repeat(43) + '=' ? 'B'.repeat(43) + '=' : 'A'.repeat(43) + '=' }));
  bump('mutation_negative_controls_passed');
  const duplicate = Buffer.from(fake.replace('b=not-empty', 'b='), 'latin1');
  assert.throws(() => getVerifiedDkimSignatureSequence(Buffer.concat([duplicate, header]), identity));
  bump('mutation_negative_controls_passed');
}

for (const file of emails(root)) {
  bump('messages');
  const raw = fs.readFileSync(file);
  const split = /\r?\n\r?\n/.exec(raw.toString('latin1'));
  if (!split) { bump('missing_header_separator'); continue; }
  const parsed = parseHeaders(raw.subarray(0, split.index));
  const signatures = parsed.parsed.filter((row) => row.key === 'dkim-signature');
  bump(`messages_with_${signatures.length}_signatures`);
  for (const row of signatures) {
    bump('signatures');
    try {
      const signature = parseDkimHeaders(row.line);
      const tags = signature.parsed;
      const identity = { signingDomain: tags.d?.value, selector: tags.s?.value, bodyHash: tags.bh?.value?.replace(/\s/g, '') };
      if (!identity.signingDomain || !identity.selector || !identity.bodyHash || !tags.h?.value) {
        bump('missing_required_dkim_tags'); continue;
      }
      const signedNames = tags.h.value.split(':').map((name) => name.trim().toLowerCase());
      if (new Set(signedNames).size !== signedNames.length) bump('signatures_with_repeated_h_names');
      const { canonicalizedHeader } = generateCanonicalizedHeader('DKIM', getSigningHeaderLines(parsed.parsed, tags.h.value, true), {
        signatureHeaderLine: signature.original,
        canonicalization: tags.c?.value || 'simple/simple',
      });
      inspectAddresses(canonicalizedHeader, signedNames);
      let selected;
      try { selected = getVerifiedDkimSignatureSequence(canonicalizedHeader, identity); }
      catch (error) {
        bump('signature_selection_rejected');
        const reason = error.message.includes('contiguously') ? 'noncontiguous_hash'
          : error.message.includes('not found') ? 'unsupported_tag_prefix'
            : error.message.includes('Duplicate') ? 'duplicate_tag' : 'identity_or_field_boundary';
        bump(`signature_selection_rejected_${reason}`);
        continue;
      }
      assert.equal(canonicalizedHeader.subarray(selected.bodyHashIndex, selected.bodyHashIndex + 44).toString('latin1'), identity.bodyHash);
      if (+selected.sequence.length > 1024) bump('signature_field_exceeds_noir_limit');
      bump('signature_selection_compatible');
      mutations(canonicalizedHeader, identity, selected);
    } catch { bump('unexpected_check_failure'); }
  }
}
console.log(JSON.stringify({ scope: 'offline canonicalization and helper selection only; no DKIM authentication or proofs', counts }, null, 2));
if (!counts.messages || counts.unexpected_check_failure || counts.missing_header_separator || counts.missing_required_dkim_tags) process.exitCode = 1;
