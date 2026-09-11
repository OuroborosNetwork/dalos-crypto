// Same checks as validate.mjs, run across every entry in golden_vectors.json
// instead of just the single jwk.json sample -- broader confidence that
// this isn't a one-lucky-key fluke.
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const ARWEAVE_CORE = "/home/ancientbox/ClaudeWS/AncientPantheon/constructors/Codex/packages/arweave-core/dist";
const { importKeyfile } = await import(`${ARWEAVE_CORE}/keys/keyfile.js`);
const { addressOf } = await import(`${ARWEAVE_CORE}/keys/address.js`);

const vectors = JSON.parse(readFileSync(new URL("./golden_vectors.json", import.meta.url)));

let failures = 0;
for (const vec of vectors) {
  const jwk = vec.jwk;
  let ok = true;
  let detail = [];

  let imported;
  try {
    imported = importKeyfile(jwk);
  } catch (err) {
    ok = false;
    detail.push(`importKeyfile threw: ${err}`);
  }

  if (imported) {
    const realAddress = await addressOf(imported);
    if (realAddress !== vec.address) {
      ok = false;
      detail.push(`address mismatch: Go said ${vec.address}, arweave-core said ${realAddress}`);
    }
  }

  try {
    const priv = await webcrypto.subtle.importKey(
      "jwk",
      { ...jwk, alg: "PS256", ext: true, key_ops: ["sign"] },
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["sign"],
    );
    const { d, p, q, dp, dq, qi, ...pubOnly } = jwk;
    const pub = await webcrypto.subtle.importKey(
      "jwk",
      { ...pubOnly, alg: "PS256", ext: true, key_ops: ["verify"] },
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["verify"],
    );
    const msg = new TextEncoder().encode(`golden vector ${vec.seed_name}`);
    const sig = await webcrypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, priv, msg);
    const verified = await webcrypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pub, sig, msg);
    if (!verified) {
      ok = false;
      detail.push("sign/verify round-trip failed");
    }
  } catch (err) {
    ok = false;
    detail.push(`WebCrypto import/sign/verify threw: ${err}`);
  }

  console.log(`[${ok ? "PASS" : "FAIL"}] ${vec.seed_name} (address ${vec.address})${detail.length ? " -- " + detail.join("; ") : ""}`);
  if (!ok) failures++;
}

console.log();
console.log(failures === 0 ? `ALL ${vectors.length} GOLDEN VECTORS PASSED real arweave-core + WebCrypto validation.` : `${failures}/${vectors.length} GOLDEN VECTORS FAILED.`);
process.exit(failures === 0 ? 0 : 1);
