"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const vm = require("node:vm");

const source = readFileSync(join(__dirname, "..", "argon2-worker.js"), "utf8");

async function run(inputPassword, memorySize, iterations, options = {}) {
  let result;
  let observed;
  const self = {
    postMessage(message) { result = message; },
    hashwasm: null
  };
  const context = {
    self,
    Uint8Array,
    ArrayBuffer,
    Number,
    Error,
    RangeError,
    performance: { now: () => 50 },
    importScripts(filename) {
      assert.equal(filename, "./vendor/argon2.umd.min.js");
      if (options.failLoad) throw new Error("404");
      self.hashwasm = {
        async argon2id(arguments_) {
          observed = {
            password: Buffer.from(arguments_.password),
            memorySize: arguments_.memorySize,
            iterations: arguments_.iterations,
            parallelism: arguments_.parallelism
          };
          assert.equal(arguments_.hashLength, 32);
          assert.equal(arguments_.outputType, "binary");
          return Uint8Array.from({ length: 32 }, (_, i) => i);
        }
      };
    }
  };
  vm.runInNewContext(source, context, { filename: "argon2-worker.js" });
  await self.onmessage({ data: {
    password: Uint8Array.from(inputPassword).buffer,
    salt: new Uint8Array(16).buffer,
    memorySize,
    iterations,
    parallelism: options.parallelism ?? 1
  } });
  return { result, observed };
}

(async () => {
  for (const [mem, passes] of [[32768, 3], [32768, 6], [65536, 3], [262144, 10], [19456, 2]]) {
    const test = await run([0x61, 0x62], mem, passes);
    assert.equal(test.result.ok, true, `Worker failed for ${mem}/${passes}`);
    assert.equal(test.result.key.byteLength, 32);
    assert.equal(test.observed.memorySize, mem);
    assert.equal(test.observed.iterations, passes);
    assert.equal(test.observed.parallelism, 1);
    assert.equal(test.observed.password.toString("hex"), "6162");
  }
  const empty = await run([], 32768, 3);
  assert.equal(empty.result.ok, true);
  assert.equal(empty.observed.password.toString("hex"), "ff");
  for (const [mem, passes, parallelism] of [
    [18*1024, 2, 1], [257*1024, 2, 1], [32768, 1, 1], [32768, 11, 1],
    [32768, 3, 2], [19457, 2, 1]
  ]) {
    const test = await run([0x61], mem, passes, { parallelism });
    assert.equal(test.result.ok, false);
    assert.equal(test.result.code, "INVALID_PARAMETERS");
  }
  const missing = await run([0x61], 32768, 3, { failLoad: true });
  assert.equal(missing.result.ok, false);
  assert.equal(missing.result.code, "VENDOR_LOAD_FAILED");
  console.log("PASS: Worker parameters, legacy defaults, new maximum, empty password, validation, vendor failure");
})().catch((error) => { console.error(error); process.exitCode = 1; });
