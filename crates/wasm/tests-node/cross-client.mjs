// Cross-client interop: what the CLI writes, the browser build must open, and
// the reverse. This is the property the whole shared-core design exists to buy,
// and it is worth asserting rather than assuming.

import fs from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import init, { sealBytes, openEnvelope } from "../pkg/sirna_wasm.js";

const here = path.dirname(fileURLToPath(import.meta.url));
await init({ module_or_path: fs.readFileSync(path.join(here, "../pkg/sirna_wasm_bg.wasm")) });

const CLI = process.env.SIRNA_CLI;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sirna-x-"));
const now = BigInt(Math.floor(Date.now() / 1000));
let failed = 0;

function check(name, ok, detail = "") {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? " — " + detail : ""}`);
  if (!ok) failed++;
}

// --- CLI seals, browser opens -------------------------------------------
{
  const secret = "written by the command line";
  fs.writeFileSync(path.join(tmp, "a.txt"), secret);
  // The key is printed to stderr on purpose, so that `sirna seal - > out` does
  // not write the key into the envelope file.
  const run = spawnSync(CLI, ["seal", path.join(tmp, "a.txt"), "--out", path.join(tmp, "a.sirna")],
    { encoding: "utf8" });
  const uri = run.stderr.match(/sirna1:[A-Za-z0-9_-]+/)[0];

  const envelope = new Uint8Array(fs.readFileSync(path.join(tmp, "a.sirna")));
  const opened = openEnvelope(envelope, uri, now);
  const text = new TextDecoder().decode(opened.plaintext).trim();

  check("CLI seals, browser opens", text === secret, text);
  check("filename survives the crossing", opened.filename === "a.txt", String(opened.filename));
}

// --- browser seals, CLI opens -------------------------------------------
{
  const secret = "written by the browser build";
  const sealed = sealBytes(new TextEncoder().encode(secret), "b.txt", "text/plain", 0n, now);
  fs.writeFileSync(path.join(tmp, "b.sirna"), Buffer.from(sealed.envelope));

  const out = execFileSync(CLI, ["open", path.join(tmp, "b.sirna"), "--key", sealed.mnemonic],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  check("browser seals, CLI opens (mnemonic)", out === secret, out);

  // The same key in its other encoding must also work — one key, two spellings.
  const out2 = execFileSync(CLI, ["open", path.join(tmp, "b.sirna"), "--key", sealed.uri],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  check("browser seals, CLI opens (sirna1 URI)", out2 === secret, out2);
}

// --- a wrong key must fail identically on both sides ---------------------
{
  const sealed = sealBytes(new TextEncoder().encode("x"), null, null, 0n, now);
  const other = sealBytes(new TextEncoder().encode("y"), null, null, 0n, now);
  let code = null;
  try {
    openEnvelope(sealed.envelope, other.mnemonic, now);
  } catch (e) {
    code = Number(e.code);
  }
  check("wrong key reports code 5 in the browser", code === 5, String(code));
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log(failed === 0 ? "\ncross-client: all good" : `\ncross-client: ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
