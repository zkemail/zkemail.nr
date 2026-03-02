#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { makeEmailAddressCharTable } = require("../dist/utils");

// Extract values from JS function output
const jsOutput = makeEmailAddressCharTable();
const jsArrayContent = jsOutput.match(/=\s*\[([\s\S]*)\]/);
if (!jsArrayContent) {
  console.error("ERROR: Could not parse JS makeEmailAddressCharTable() output");
  process.exit(1);
}
const jsValues = jsArrayContent[1].match(/\d+/g).map(Number);

// Extract values from Noir source file
const noirPath = path.resolve(__dirname, "../../lib/src/lib.nr");
const noirContent = fs.readFileSync(noirPath, "utf-8");
const tableMatch = noirContent.match(
  /global\s+EMAIL_ADDRESS_CHAR_TABLE\s*:\s*\[[^\]]*\]\s*=\s*\[([\s\S]*?)\];/
);
if (!tableMatch) {
  console.error("ERROR: Could not find EMAIL_ADDRESS_CHAR_TABLE in lib/src/lib.nr");
  process.exit(1);
}
const noirValues = tableMatch[1].match(/\d+/g).map(Number);

// Compare
if (jsValues.length !== noirValues.length) {
  console.error(
    `MISMATCH: JS table has ${jsValues.length} values, Noir table has ${noirValues.length} values.`
  );
  process.exit(1);
}

const diffs = [];
for (let i = 0; i < jsValues.length; i++) {
  if (jsValues[i] !== noirValues[i]) {
    const char = i >= 32 && i < 127 ? ` ('${String.fromCharCode(i)}')` : "";
    diffs.push(`  index ${i}${char}: JS=${jsValues[i]}, Noir=${noirValues[i]}`);
  }
}

if (diffs.length > 0) {
  console.error("EMAIL_ADDRESS_CHAR_TABLE mismatch between JS and Noir:\n");
  console.error(diffs.join("\n"));
  console.error(
    "\nTo fix: update the table in lib/src/lib.nr to match the output of" +
      " makeEmailAddressCharTable() in js/src/utils.ts (or vice versa)."
  );
  process.exit(1);
}

console.log("OK: EMAIL_ADDRESS_CHAR_TABLE is in sync between JS and Noir.");
