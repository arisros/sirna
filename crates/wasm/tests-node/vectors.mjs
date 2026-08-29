// Cross-target conformance: the committed corpus, run through the real
// wasm-bindgen glue.
//
// This is deliberately Node rather than a pure-Rust wasm test. A `cargo test`
// under wasm32 exercises the Rust, but not the generated JavaScript that every
// browser actually calls — and that glue is where the interesting bugs are.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import init, { openEnvelope, openEnvelopeWithPassphrase, formatVersion } from "../pkg/sirna_wasm.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorDir = path.join(here, "../../../spec/vectors");

await init({ module_or_path: fs.readFileSync(path.join(here, "../pkg/sirna_wasm_bg.wasm")) });

const manifest = JSON.parse(fs.readFileSync(path.join(vectorDir, "vectors.json"), "utf8"));

if (manifest.format_version !== formatVersion()) {
  console.error(
    `corpus targets format ${manifest.format_version}, this build produces ${formatVersion()}`,
  );
  process.exit(1);
}

// The same fixed clock the generator used. A real clock would make expiry
// vectors start failing on their own.
const NOW = 1800000000n;

let passed = 0;
let failed = 0;

for (const v of manifest.vectors) {
  const envelope = fs.readFileSync(path.join(vectorDir, v.envelope_file));

  let outcome;
  try {
    const opened = v.passphrase
      ? openEnvelopeWithPassphrase(envelope, v.passphrase, NOW)
      : openEnvelope(envelope, v.mnemonic, NOW);
    outcome = { ok: true, opened };
  } catch (e) {
    outcome = { ok: false, code: String(e?.code ?? "?") };
  }

  if (v.expect === "ok") {
    if (!outcome.ok) {
      console.error(`FAIL ${v.id}: expected success, got code ${outcome.code}`);
      failed++;
      continue;
    }
    if (BigInt(outcome.opened.plaintext.length) !== BigInt(v.plaintext_len)) {
      console.error(
        `FAIL ${v.id}: length ${outcome.opened.plaintext.length} != ${v.plaintext_len}`,
      );
      failed++;
      continue;
    }
    passed++;
  } else {
    // Assert the numeric code, never the message. Codes are the contract that
    // holds three clients together; messages are UI copy.
    if (outcome.ok) {
      console.error(`FAIL ${v.id}: expected error ${v.expect}, but it opened`);
      failed++;
    } else if (outcome.code !== v.expect) {
      console.error(`FAIL ${v.id}: expected error ${v.expect}, got ${outcome.code}`);
      failed++;
    } else {
      passed++;
    }
  }
}

console.log(`wasm vectors: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
