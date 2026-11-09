"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const { createHash, pbkdf2Sync, webcrypto } = require("node:crypto");
const vm = require("node:vm");
const root = join(__dirname, "..");
const html = readFileSync(join(root, "index.html"), "utf8");
const inline = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(inline, "Inline application script is missing");
const sha256 = createHash("sha256").update(inline[1]).digest("base64");
assert.ok(html.includes("'sha256-" + sha256 + "'"), "CSP hash mismatch");

class Element {
  constructor(id, initialValue = "") {
    this.id = id;
    this.value = initialValue;
    this.hidden = false;
    this.disabled = false;
    this.textContent = "";
    this.dataset = {};
    this.handlers = {};
    this.attributes = {};
  }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  setAttribute(name, value) { this.attributes[name] = value; }
  async trigger(name) {
    if (!this.handlers[name]) throw new Error(`Missing handler: ${this.id}.${name}`);
    return this.handlers[name]({ preventDefault() {} });
  }
  focus() {}
  select() {}
  get valueAsNumber() { return Number(this.value); }
}

const ids = [...html.matchAll(/id="([A-Za-z][A-Za-z0-9]*)"/g)].map((m) => m[1]);
const elements = Object.fromEntries(ids.map((id) => [id, new Element(id)]));
const initial = {
  kdfChoice: "argon2id", argonPreset: "balanced", argonMemory: "32",
  argonPasses: "6", pbkdfIterations: "600000"
};
for (const [id, value] of Object.entries(initial)) elements[id].value = value;
const events = {};
const fakeLocation = {
  href: "https://example.test/cipherlink-lite/",
  hash: "",
  pathname: "/cipherlink-lite/",
  search: ""
};

class FakeWorker {
  constructor() { this.terminated = false; }
  postMessage(data) {
    const password = Buffer.from(data.password);
    const salt = Buffer.from(data.salt);
    const params = Buffer.alloc(12);
    params.writeUInt32BE(data.memorySize, 0);
    params.writeUInt32BE(data.iterations, 4);
    params.writeUInt32BE(data.parallelism, 8);
    const key = pbkdf2Sync(Buffer.concat([params, password.length ? password : Buffer.from([0xff])]), salt, 1200, 32, "sha256");
    const bytes = Uint8Array.from(key);
    setImmediate(() => {
      if (!this.terminated) this.onmessage({ data: { ok: true, key: bytes.buffer, durationMs: 1 } });
    });
  }
  terminate() { this.terminated = true; }
}

const context = {
  document: {
    getElementById(id) { assert.ok(elements[id], `Unknown DOM element ${id}`); return elements[id]; },
    baseURI: fakeLocation.href,
    documentElement: { dataset: {} }
  },
  crypto: webcrypto,
  URL,
  URLSearchParams,
  Uint8Array,
  TextEncoder,
  TextDecoder,
  DataView,
  Number,
  ArrayBuffer,
  Object,
  String,
  Promise,
  Error,
  Math,
  AbortController,
  performance: { now: () => Date.now() },
  navigator: { clipboard: { async writeText() {} } },
  location: fakeLocation,
  history: { state: null, replaceState() {} },
  matchMedia: () => ({ matches: false }),
  addEventListener(name, callback) { events[name] = callback; },
  Worker: FakeWorker,
  btoa: (str) => Buffer.from(str, "binary").toString("base64"),
  atob: (str) => Buffer.from(str, "base64").toString("binary"),
  setImmediate
};
vm.runInNewContext(inline[1], context, { filename: "index.html:inline" });
const $ = (id) => elements[id];

(async () => {
  assert.equal($("argonMemory").value, "32");
  assert.equal($("argonPasses").value, "6");
  assert.match($("argonCompatibility").textContent || html, /Decryption requires the same/);
  assert.match($("passwordAdvice").textContent, /empty password/i);

  $("argonPreset").value = "expert";
  await $("argonPreset").trigger("change");
  assert.equal($("argonMemory").value, 256);
  assert.equal($("argonPasses").value, 6);
  assert.match($("resourceAdvice").textContent, /Warning:/);
  $("argonPasses").value = "10";
  await $("argonPasses").trigger("input");
  assert.equal($("argonPreset").value, "custom");
  assert.match($("benchmarkStatus").textContent, /Not tested/);

  // Worker is a local protocol stub; actual hash-wasm is tested in verify.cjs.
  $("argonMemory").value = "19";
  $("argonPasses").value = "2";
  $("plainInput").value = "Hello 한글 日本語 😀";
  $("encryptPassword").value = "";
  $("confirmPassword").value = "";
  await $("encryptForm").trigger("submit");
  const argonData = $("encryptedData").value;
  assert.ok(argonData.length > 20);
  assert.match($("encryptedUrl").value, /#data=/);
  assert.doesNotMatch($("encryptedUrl").value, /#v=/);
  let payload = Buffer.from(argonData.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  assert.equal(payload.readUInt8(2), 2);
  assert.equal(payload.readUInt32BE(4), 19 * 1024);
  assert.equal(payload.readUInt32BE(8), 2);
  assert.equal(payload.readUInt8(12), 1);
  $("decryptData").value = "#v=2&data=" + argonData;
  $("decryptPassword").value = "";
  await $("decryptForm").trigger("submit");
  assert.equal($("decryptedText").value, "Hello 한글 日本語 😀");

  $("kdfChoice").value = "pbkdf2";
  await $("kdfChoice").trigger("input");
  $("pbkdfIterations").value = "1000000";
  await $("pbkdfIterations").trigger("input");
  $("plainInput").value = "PBKDF2 text";
  $("encryptPassword").value = "example-password";
  $("confirmPassword").value = "example-password";
  await $("encryptForm").trigger("submit");
  const pbkdfData = $("encryptedData").value;
  assert.ok(pbkdfData);
  payload = Buffer.from(pbkdfData.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  assert.equal(payload.readUInt8(2), 1);
  assert.equal(payload.readUInt32BE(4), 1000000);
  $("decryptData").value = "#v=1&data=" + pbkdfData;
  $("decryptPassword").value = "example-password";
  await $("decryptForm").trigger("submit");
  assert.equal($("decryptedText").value, "PBKDF2 text");

  // Existing v1 layout and fixed-work-factor URLs must remain decodable.
  $("pbkdfIterations").value = "600000";
  $("plainInput").value = "Old v1 style";
  $("encryptPassword").value = "";
  $("confirmPassword").value = "";
  await $("encryptForm").trigger("submit");
  $("decryptData").value = "#v=1&data=" + $("encryptedData").value;
  $("decryptPassword").value = "";
  await $("decryptForm").trigger("submit");
  assert.equal($("decryptedText").value, "Old v1 style");

  $("kdfChoice").value = "argon2id";
  await $("kdfChoice").trigger("input");
  $("argonMemory").value = "257";
  await $("argonMemory").trigger("input");
  await $("runBenchmark").trigger("click");
  assert.match($("benchmarkStatus").textContent, /19–256/);
  $("argonMemory").value = "32";
  $("argonPasses").value = "6";
  await $("runBenchmark").trigger("click");
  assert.match($("benchmarkStatus").textContent, /ms total on this device/);
  assert.equal($("runBenchmark").disabled, false);
  const cancellable = $("runBenchmark").trigger("click");
  assert.equal($("cancelBenchmark").hidden, false);
  await $("cancelBenchmark").trigger("click");
  await cancellable;
  assert.match($("benchmarkStatus").textContent, /cancelled/i);
  assert.equal($("runBenchmark").disabled, false);
  console.log("PASS: CSP, live guidance, presets, KDF bounds, v1/v2 round-trip, Unicode, empty password, benchmark UI");
})().catch((error) => { console.error(error); process.exitCode = 1; });
