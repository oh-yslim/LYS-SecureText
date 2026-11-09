"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { createHash, pbkdf2Sync, webcrypto } = require("node:crypto");
const { join } = require("node:path");
const root = join(__dirname, "..");
const argon = require(join(root, "site", "vendor", "argon2.umd.min.js"));
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

async function verify() {
  const source = readFileSync(join(root, "index.html"), "utf8");
  const script = source.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(script, "Inline application script not found");
  const hash = createHash("sha256").update(script[1]).digest("base64");
  assert.ok(source.includes("'sha256-" + hash + "'"), "Application CSP hash does not match");

  const salt = encoder.encode("0123456789abcdef");
  const password = encoder.encode("password");
  const expectedArgon = "ae4415b36b8a199502b180098f74ffb8c4069d382e180dc4746167f1b766f398";
  const argonKey = await argon.argon2id({
    password, salt, iterations: 3, memorySize: 32768,
    parallelism: 1, hashLength: 32, outputType: "binary"
  });
  assert.equal(Buffer.from(argonKey).toString("hex"), expectedArgon, "Argon2id known-answer test failed");
  // The browser maps the empty password to the invalid UTF-8 sentinel 0xFF.
  // hash-wasm 4.12.0 rejects truly empty input before running Argon2id.
  const emptyPasswordKey = await argon.argon2id({
    password: new Uint8Array([0xff]), salt, iterations: 3, memorySize: 32768,
    parallelism: 1, hashLength: 32, outputType: "binary"
  });
  assert.equal(Buffer.from(emptyPasswordKey).toString("hex"),
    "0e0001476e04ef4406c84fbd72983d2d0b1b67d4d16444847bebfacbdd90e387",
    "Empty-password Argon2id test failed");

  // Check that the actual browser worker uses the same empty-password mapping.
  const workerSource = readFileSync(join(root, "argon2-worker.js"), "utf8");
  assert.ok(workerSource.includes("new Uint8Array([0xff])"),
    "Argon2id worker must use the documented empty-password mapping");

  const expectedPbkdf = "996d7c90f74a4a169cf7adef42b06848f7d1bac3e568d1cc94d4f79be1ee0263";
  const pbkdfKey = pbkdf2Sync(password, salt, 600000, 32, "sha256");
  assert.equal(pbkdfKey.toString("hex"), expectedPbkdf, "PBKDF2 known-answer test failed");

  for (const [version, derivedKey] of [[1, pbkdfKey], [2, argonKey]]) {
    const header = new Uint8Array(version === 1 ? 36 : 44);
    const iv = Uint8Array.from({ length: 12 }, (_, i) => i + 100);
    header.set([0x53, 0x43, version, version]);
    const view = new DataView(header.buffer);
    if (version === 1) {
      view.setUint32(4, 600000, false);
      header.set(salt, 8);
      header.set(iv, 24);
    } else {
      view.setUint32(4, 32768, false);
      view.setUint32(8, 3, false);
      header[12] = 1;
      header.set(salt, 16);
      header.set(iv, 32);
    }
    const key = await webcrypto.subtle.importKey("raw", derivedKey, "AES-GCM", false, ["encrypt", "decrypt"]);
    const plain = encoder.encode("Hello 한글 日本語 😀");
    const sealed = await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: header, tagLength: 128 }, key, plain
    );
    const decrypted = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: header, tagLength: 128 }, key, sealed
    );
    assert.equal(decoder.decode(decrypted), "Hello 한글 日本語 😀");
    const changed = header.slice();
    changed[version === 1 ? 8 : 16] ^= 1;
    await assert.rejects(() => webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: changed, tagLength: 128 }, key, sealed
    ), "Header modification must fail authentication");
  }
  console.log("PASS: CSP, Argon2id, PBKDF2, both AEAD formats, Unicode, authenticated headers");
}

verify().catch((err) => { console.error(err); process.exitCode = 1; });
