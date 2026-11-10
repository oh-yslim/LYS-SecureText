"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const vm = require("node:vm");

const source = readFileSync(join(__dirname, "..", "argon2-worker.js"), "utf8");

async function run(inputPassword, memorySize, iterations, options = {}) {
  let result;
  let observed;
  let tick = 100;
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
    performance: { now: () => ++tick },
    importScripts(filename) {
      assert.equal(filename, "./vendor/argon2.umd.min.js");
      if (options.failLoad) throw new Error("Simulated missing vendor file");
      self.hashwasm = {
        async argon2id(args) {
          observed = {
            password: Buffer.from(args.password),
            memorySize: args.memorySize,
            iterations: args.iterations,
            parallelism: args.parallelism
          };
          assert.equal(args.hashLength, 32);
          assert.equal(args.outputType, "binary");
          if (options.failMemory) throw new RangeError("Simulated memory allocation failure");
          if (options.failKdf) throw new Error("Simulated KDF failure");
          if (options.invalidKey) return new Uint8Array(16);
          return Uint8Array.from({ length: 32 }, (_, i) => i);
        }
      };
    }
  };

  vm.runInNewContext(source, context, { filename: "argon2-worker.js" });
  await self.onmessage({
    data: {
      password: Uint8Array.from(inputPassword).buffer,
      salt: new Uint8Array(16).buffer,
      memorySize,
      iterations,
      parallelism: options.parallelism ?? 1
    }
  });
  assert.ok(result, "Worker did not post a result");
  return { result, observed };
}

(async () => {
  for (const [memorySize, iterations, parallelism] of [
    [32768, 3, 1],
    [32768, 6, 1],
    [32768, 3, 2],
    [32768, 3, 3],
    [32768, 3, 4],
    [65536, 3, 4],
    [131072, 3, 2],
    [262144, 10, 4],
    [19456, 2, 4]
  ]) {
    const test = await run([0x61, 0x62], memorySize, iterations, { parallelism });
    assert.equal(test.result.ok, true,
      `Worker rejected valid parameters: ${memorySize} KiB, ${iterations} passes, p=${parallelism}; code=${test.result.code}`);
    assert.equal(test.result.key.byteLength, 32);
    assert.equal(test.result.durationMs, 1);
    assert.equal(test.observed.memorySize, memorySize);
    assert.equal(test.observed.iterations, iterations);
    assert.equal(test.observed.parallelism, parallelism);
    assert.equal(test.observed.password.toString("hex"), "6162");
  }

  const empty = await run([], 32768, 3);
  assert.equal(empty.result.ok, true);
  assert.equal(empty.observed.password.toString("hex"), "ff");

  for (const [memorySize, iterations, parallelism] of [
    [18 * 1024, 2, 1],
    [257 * 1024, 2, 1],
    [32768, 1, 1],
    [32768, 11, 1],
    [32768, 3, 0],
    [32768, 3, 5],
    [32768, 3, 1.5],
    [19457, 2, 1]
  ]) {
    const test = await run([0x61], memorySize, iterations, { parallelism });
    assert.equal(test.result.ok, false);
    assert.equal(test.result.code, "INVALID_PARAMETERS");
  }

  for (const [option, expectedCode] of [
    ["failLoad", "VENDOR_LOAD_FAILED"],
    ["failMemory", "MEMORY_ALLOCATION_FAILED"],
    ["failKdf", "ARGON2_FAILED"],
    ["invalidKey", "INVALID_KEY"]
  ]) {
    const test = await run([0x61], 32768, 3, { [option]: true });
    assert.equal(test.result.ok, false);
    assert.equal(test.result.code, expectedCode);
  }

  console.log("PASS: Worker timings, p=1..4, KDF bounds, legacy and empty-password compatibility, and error codes");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
