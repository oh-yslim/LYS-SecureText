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

  // Verify the new policy and the existing empty-password mapping.
  const workerSource = readFileSync(join(root, "argon2-worker.js"), "utf8");
  assert.ok(source.includes('max="256"') && source.includes('max="10"'), "Advanced controls missing");
  assert.ok(source.includes('id="argonParallelism"') && source.includes('max="4"'),
    "Parallelism 1–4 control missing");
  assert.ok(source.includes('id="argonPreset"'), "KDF presets missing");
  assert.ok(source.includes('id="runBenchmark"'), "KDF benchmark missing");
  assert.ok(workerSource.includes("new Uint8Array([0xff])"),
    "Argon2id worker must use the documented empty-password mapping");

  const expectedPbkdf = "996d7c90f74a4a169cf7adef42b06848f7d1bac3e568d1cc94d4f79be1ee0263";
  const pbkdfKey = pbkdf2Sync(password, salt, 600000, 32, "sha256");
  assert.equal(pbkdfKey.toString("hex"), expectedPbkdf, "PBKDF2 known-answer test failed");

  const argonKeyBalanced = await argon.argon2id({
    password, salt, iterations: 6, memorySize: 32768,
    parallelism: 1, hashLength: 32, outputType: "binary"
  });
  assert.equal(Buffer.from(argonKeyBalanced).toString("hex"),
    "b30ff726ff05d87f345c6dc9388977bbc190c9104e209eb778c33a4d8094f187",
    "Balanced Argon2id known-answer test failed");

  // Independent Argon2id v1.3 reference outputs generated with libargon2.
  // These exercise the real WASM implementation at p=1, 2, 3, and 4.
  const parallelismVectors = [
    [1, "d2ab07b39ef7f8b806227cd86fbb11aa5393066a98e17eacacd126eb26e9276d"],
    [2, "4d25216325889ce3edade653945e2fe748cb62e65c9cb1af6a4c0f122234ef1b"],
    [3, "ebae28842a992d35c2ed2c9664329b3634172403f62f1f9c4aa70eb13a542738"],
    [4, "50140867aedd2774a174c344fadc19e191fb31d0b9b3070b5e0a7761b701a682"]
  ];
  for (const [parallelism, expectedHex] of parallelismVectors) {
    const actual = await argon.argon2id({
      password, salt, iterations: 2, memorySize: 19456,
      parallelism, hashLength: 32, outputType: "binary"
    });
    assert.equal(Buffer.from(actual).toString("hex"), expectedHex,
      `Argon2id p=${parallelism} independent known-answer test failed`);

    // The existing v2 header encodes p at byte 12 and authenticates it as AAD.
    const header = new Uint8Array(44);
    const view = new DataView(header.buffer);
    header.set([0x53, 0x43, 0x02, 0x02]);
    view.setUint32(4, 19456, false);
    view.setUint32(8, 2, false);
    header[12] = parallelism;
    header.set(salt, 16);
    const iv = Uint8Array.from({ length: 12 }, (_, i) => i + 17);
    header.set(iv, 32);
    const key = await webcrypto.subtle.importKey("raw", actual, "AES-GCM", false, ["encrypt", "decrypt"]);
    const plain = encoder.encode(`Argon2id round trip p=${parallelism}: 한국어 日本語 😀`);
    const sealed = await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: header, tagLength: 128 }, key, plain
    );
    const packageBytes = Buffer.concat([Buffer.from(header), Buffer.from(sealed)]);
    assert.equal(packageBytes[12], parallelism);
    const decrypted = await webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: packageBytes.subarray(0, 44), tagLength: 128 },
      key, packageBytes.subarray(44)
    );
    assert.equal(decoder.decode(decrypted), `Argon2id round trip p=${parallelism}: 한국어 日本語 😀`);
    const alteredHeader = header.slice();
    alteredHeader[12] = parallelism === 4 ? 3 : parallelism + 1;
    await assert.rejects(() => webcrypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: alteredHeader, tagLength: 128 }, key, sealed
    ), "Parallelism header tampering must fail authentication");
  }

  for (const [version, derivedKey] of [[1, pbkdfKey], [2, argonKey], [2, argonKeyBalanced]]) {
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
      view.setUint32(8, derivedKey === argonKey ? 3 : 6, false);
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
  console.log("PASS: CSP, Argon2id p=1..4 reference vectors, PBKDF2, v1/v2 AEAD, Unicode, authenticated headers");
}

verify().catch((err) => { console.error(err); process.exitCode = 1; });
