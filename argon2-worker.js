"use strict";

self.onmessage = async (event) => {
  const input = event.data || {};
  const password = new Uint8Array(input.password || new ArrayBuffer(0));
  const salt = new Uint8Array(input.salt || new ArrayBuffer(0));
  let derived = null;
  let code = "ARGON2_FAILED";

  try {
    if (input.memorySize !== 32768 || input.iterations !== 3 ||
        input.parallelism !== 1 || salt.length !== 16 || password.length > 2048) {
      code = "INVALID_PARAMETERS";
      throw new Error(code);
    }

    try {
      importScripts("./vendor/argon2.umd.min.js");
    } catch {
      code = "VENDOR_LOAD_FAILED";
      throw new Error(code);
    }

    if (!self.hashwasm || typeof self.hashwasm.argon2id !== "function") {
      code = "VENDOR_INVALID";
      throw new Error(code);
    }

    // The pinned hash-wasm version rejects empty passwords. The byte 0xFF is
    // not a valid standalone UTF-8 encoding, so it cannot collide with any
    // non-empty password produced by TextEncoder.
    const kdfPassword = password.length === 0 ? new Uint8Array([0xff]) : password;

    try {
      derived = await self.hashwasm.argon2id({
        password: kdfPassword,
        salt,
        memorySize: input.memorySize,
        iterations: input.iterations,
        parallelism: input.parallelism,
        hashLength: 32,
        outputType: "binary"
      });
    } catch (error) {
      code = error instanceof RangeError ? "MEMORY_ALLOCATION_FAILED" : "ARGON2_FAILED";
      throw error;
    } finally {
      if (kdfPassword !== password) kdfPassword.fill(0);
    }

    if (!(derived instanceof Uint8Array) || derived.length !== 32) {
      code = "INVALID_KEY";
      throw new Error(code);
    }

    const keyCopy = derived.slice();
    self.postMessage({ ok: true, key: keyCopy.buffer }, [keyCopy.buffer]);
  } catch {
    self.postMessage({ ok: false, code });
  } finally {
    password.fill(0);
    salt.fill(0);
    if (derived instanceof Uint8Array && derived.buffer.byteLength > 0) derived.fill(0);
  }
};
