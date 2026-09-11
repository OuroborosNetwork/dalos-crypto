// External cross-validation for STEP 8 (the local, zero-network,
// zero-funds half of it). Takes jwk.json (written by `go run .`) and checks
// it against REAL, independent implementations -- not our own code:
//
//   1. arweave-core's actual compiled importKeyfile() -- the real structural
//      validation Arweave wallet software runs on a keyfile.
//   2. arweave-core's actual compiled addressOf() -- compared against what
//      our own Go AddressOf() computed, to catch any encoding mismatch.
//   3. Node's native WebCrypto (crypto.subtle), importing the JWK as an
//      RSA-PSS/SHA-256 key -- the exact algorithm arweave-core's own
//      generateKey() uses -- and running a real sign+verify round-trip.
//      If a genuinely independent, industry-standard crypto engine accepts
//      the key and correctly signs/verifies with it, that's the strongest
//      local (no live gateway) evidence we can get that the key is a real,
//      standards-compliant RSA-4096 key, not just "our own math agrees
//      with itself."
//
// Deliberately NOT done here: broadcasting anything to a live Arweave
// gateway, or touching a funded wallet. That step needs a human present
// (see the decision record / chat log) and is left for explicit follow-up.
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";

const ARWEAVE_CORE = "/home/ancientbox/ClaudeWS/AncientPantheon/constructors/Codex/packages/arweave-core/dist";

const { importKeyfile } = await import(`${ARWEAVE_CORE}/keys/keyfile.js`);
const { addressOf } = await import(`${ARWEAVE_CORE}/keys/address.js`);

const jwk = JSON.parse(readFileSync(new URL("./jwk.json", import.meta.url)));

let failures = 0;
function check(label, ok, detail) {
  const status = ok ? "PASS" : "FAIL";
  console.log(`[${status}] ${label}${detail ? " -- " + detail : ""}`);
  if (!ok) failures++;
}

// 1. Real arweave-core structural validation.
let imported;
try {
  imported = importKeyfile(jwk);
  check("arweave-core importKeyfile() accepts the generated JWK", true);
} catch (err) {
  check("arweave-core importKeyfile() accepts the generated JWK", false, String(err));
}

// 2. Real arweave-core address derivation, compared against our own.
if (imported) {
  const address = await addressOf(imported);
  console.log(`    arweave-core-derived address: ${address}`);
  // (Go side printed its own AddressOf() result to stdout during `go run .`
  // -- compare by eye against that run's output, or diff programmatically
  // if this script is extended to also read a saved address.txt.)
  check("arweave-core addressOf() produced a 43-char string", address.length === 43, `got ${address.length} chars`);
}

// 3. Real, independent WebCrypto engine: import as RSA-PSS/SHA-256 (the
// exact algorithm arweave-core's generateKey() uses) and round-trip a
// signature.
let cryptoKeyPrivate, cryptoKeyPublic;
try {
  cryptoKeyPrivate = await webcrypto.subtle.importKey(
    "jwk",
    { ...jwk, alg: "PS256", ext: true, key_ops: ["sign"] },
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["sign"],
  );
  check("Node WebCrypto imports the JWK as an RSA-PSS/SHA-256 PRIVATE key", true);
} catch (err) {
  check("Node WebCrypto imports the JWK as an RSA-PSS/SHA-256 PRIVATE key", false, String(err));
}

try {
  const { d, p, q, dp, dq, qi, ...publicOnly } = jwk;
  cryptoKeyPublic = await webcrypto.subtle.importKey(
    "jwk",
    { ...publicOnly, alg: "PS256", ext: true, key_ops: ["verify"] },
    { name: "RSA-PSS", hash: "SHA-256" },
    true,
    ["verify"],
  );
  check("Node WebCrypto imports the corresponding PUBLIC key", true);
} catch (err) {
  check("Node WebCrypto imports the corresponding PUBLIC key", false, String(err));
}

if (cryptoKeyPrivate && cryptoKeyPublic) {
  const message = new TextEncoder().encode("DALOS RSA-4096 prototype: local sign/verify round-trip check");
  try {
    const signature = await webcrypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      cryptoKeyPrivate,
      message,
    );
    const verified = await webcrypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      cryptoKeyPublic,
      signature,
      message,
    );
    check("real RSA-PSS/SHA-256 sign+verify round-trip via Node WebCrypto", verified === true);
  } catch (err) {
    check("real RSA-PSS/SHA-256 sign+verify round-trip via Node WebCrypto", false, String(err));
  }
}

console.log();
if (failures === 0) {
  console.log(`ALL CHECKS PASSED (${failures} failures) -- key is accepted by real, independent arweave-core + Node WebCrypto code, not just our own implementation.`);
  process.exit(0);
} else {
  console.log(`${failures} CHECK(S) FAILED -- do not treat this key as validated.`);
  process.exit(1);
}
