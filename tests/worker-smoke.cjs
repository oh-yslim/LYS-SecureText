"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const vm = require("node:vm");

const source = readFileSync(join(__dirname, "..", "argon2-worker.js"), "utf8");

async function run(inputPassword, failLoad = false) {
  let result;
  let receivedPassword;
  const self = {
    postMessage(message) { result = message; },
    hashwasm: null
  };
  const context = {
    self,
    Uint8Array,
    ArrayBuffer,
    Error,
    RangeError,
    importScripts(filename) {
      assert.equal(filename, "./vendor/argon2.umd.min.js");
      if (failLoad) throw new Error("404");
      self.hashwasm = {
        async argon2id(options) {
          receivedPassword = Buffer.from(options.password);
          assert.equal(options.memorySize, 32768);
          assert.equal(options.iterations, 3);
          assert.equal(options.parallelism, 1);
          assert.equal(options.hashLength, 32);
          assert.equal(options.outputType, "binary");
          return Uint8Array.from({ length: 32 }, (_, i) => i);
        }
      };
    }
  };
  vm.runInNewContext(source, context, { filename: "argon2-worker.js" });
  await self.onmessage({ data: {
    password: Uint8Array.from(inputPassword).buffer,
    salt: new Uint8Array(16).buffer,
    memorySize: 32768,
    iterations: 3,
    parallelism: 1
  } });
  return { result, receivedPassword };
}

(async () => {
  const normal = await run([0x61, 0x62]);
  assert.equal(normal.result.ok, true);
  assert.equal(normal.result.key.byteLength, 32);
  assert.equal(normal.receivedPassword.toString("hex"), "6162");

  const empty = await run([]);
  assert.equal(empty.result.ok, true);
  assert.equal(empty.receivedPassword.toString("hex"), "ff");

  const missing = await run([0x61], true);
  assert.equal(missing.result.ok, false);
  assert.equal(missing.result.code, "VENDOR_LOAD_FAILED");
  console.log("PASS: Worker argument handling, zero-length password mapping, vendor error classification");
})().catch((error) => { console.error(error); process.exitCode = 1; });
