# CipherLink Lite

CipherLink Lite is a lightweight browser-only tool for encrypting and sharing text through URL fragments. The published website is static, has no application backend, and never sends your plaintext or password to an encryption server.

**Security notice:** This project has not undergone an independent security audit. Do not rely on it as your only way to store high-value secrets. A zero-length password is allowed but provides **no meaningful confidentiality**.

## Features

- **AES-256-GCM** authenticated encryption and decryption through Web Crypto API.
- **Argon2id v1.3** via self-hosted `hash-wasm@4.12.0` WebAssembly in a dedicated worker.
- **PBKDF2-HMAC-SHA256** via the browser's Web Crypto API, without a separate KDF library.
- Adjustable KDF costs, five Argon2id presets, and a real optional on-device KDF benchmark.
- KDF cost and password warnings update immediately as you type or change settings; no warning modal dialog.
- Zero-length passwords supported for both algorithms, with an inline confidentiality warning.
- Copyable Base64URL ciphertext and shareable `#data=...` URLs; legacy `#v=1&data=...` and `#v=2&data=...` links still work.
- Automatic algorithm detection and a warning when a pasted Argon2id URL requires high resources.
- UTF-8 plaintext and NFC-normalized UTF-8 passwords, including CJK text, emojis, and combining marks.
- Fresh 16-byte salt and 12-byte IV for every encryption; each header is authenticated as AES-GCM additional data.
- Light/dark UI, no external fonts, no runtime CDN, no browser-storage persistence.

## Default parameters and permitted ranges

| Algorithm | Parameter | Minimum | Default | Maximum |
|---|---|---:|---:|---:|
| Argon2id | Memory | 19 MiB | 32 MiB | 256 MiB |
| Argon2id | Passes | 2 | 6 | 10 |
| Argon2id | Parallelism (lanes) | 1 | 1 | **4** |
| PBKDF2-SHA256 | Iterations | 600,000 | 600,000 | 2,000,000 |

Argon2id presets are **Compatibility** (32 MiB, 3 passes), **Balanced** (32 MiB, 6 passes), **Strong** (64 MiB, 3 passes), **High** (128 MiB, 3 passes), and **Expert** (256 MiB, 6 passes). Selecting other values switches the preset label to **Custom**. The presets are usability labels, not certified security tiers or quantitative equivalence claims.

These are application resource limits, **not validated hardware limits or guarantees of cryptographic security**. Decryption always repeats the selected KDF costs. Some mobile browsers may be unable to decrypt packages created with large memory settings. For maximal portability, benchmark on the least powerful device that must decrypt the data.

Parallelism is selectable from **1 to 4** (inclusive). The default stays **1** for compatibility and predictable behavior. The UI provides an immediate warning when `p > 1`, but does not block encryption or require a benchmark. The parameter changes the Argon2id derived key; it does not imply that the current WebAssembly implementation uses multiple CPU threads or becomes faster. Use `p=2`, `p=3`, or `p=4` only when your intended decryption device can process the chosen settings. No benchmark is required by the application before using these settings.

## Device Benchmark

1. Choose Argon2id or PBKDF2 and set the cost parameters.
2. Click **Run Benchmark**.
3. The browser executes the selected KDF using a disposable, nonsecret input and a fresh random salt. No plaintext or user-entered password is sent to the benchmark.
4. The displayed numbers describe only the current device and browser. **Argon2id** reports approximate time inside the worker's hash call and end-to-end time including worker startup; **PBKDF2** reports end-to-end Web Crypto time.
5. Argon2id benchmarks can be cancelled with **Cancel**, which terminates the worker. The PBKDF2 operation is not cancellable using the Web Crypto API.
6. Changing algorithm or parameters invalidates the previous benchmark result. Results are not persisted.

**Decryption requires the same Argon2id memory, iteration, and parallelism settings. High values may prevent decryption on low-memory devices.** A benchmark that succeeds on your PC does not prove it will work on a different PC or smartphone.

## Repository layout

```text
cipherlink-lite/
├── index.html
├── argon2-worker.js
├── README.md
├── .github/workflows/deploy.yml
└── tests/
    ├── verify.cjs
    ├── worker-smoke.cjs
    └── contract.cjs
```

The published Pages artifact contains `index.html`, `argon2-worker.js`, `vendor/argon2.umd.min.js`, `vendor/LICENSE.hash-wasm`, and `.nojekyll`. GitHub Actions creates the `vendor/` files at deploy time; browsers do not request a third-party CDN.

## Deploy to GitHub Pages

1. Create a public repository named `cipherlink-lite` or another name you prefer.
2. Upload the entire repository **without changing its folder structure**.
3. In **Settings → Pages → Build and deployment**, select **GitHub Actions**, not *Deploy from a branch*.
4. Commit/push to the `main` branch, or run **Actions → Deploy CipherLink Lite → Run workflow** manually.
5. Confirm the workflow succeeds. It retrieves the pinned `hash-wasm@4.12.0` release, runs the tests, and deploys the static artifact.
6. Test `https://USERNAME.github.io/cipherlink-lite/` and `https://USERNAME.github.io/cipherlink-lite/vendor/argon2.umd.min.js` (replace `USERNAME` with your account name).
7. In a fresh browser tab, verify both algorithms, empty and non-empty passwords, and compatibility with older links.

Changing the Pages deployment source alone does not deploy updated source files. If this release replaces the files in an existing repository, commit the modified files and verify the subsequent Actions run. The workflow pins the GitHub-hosted runner to Ubuntu 24.04 and sets up Node.js 24. For a failed run, open **Actions → Deploy CipherLink Lite → deploy** and expand the failing step; an `exit code 1` annotation alone does not identify the cause.

### Local development

The `index.html` file can be edited directly. Argon2id requires a correctly deployed `vendor/argon2.umd.min.js` under the same origin. For local HTTP testing use a localhost server (or GitHub Pages); browser policies often disallow workers loaded from `file://`.

The inline application JavaScript is protected by a **SHA-256 CSP hash**. When changing the contents of the `<script>` element, recompute its CSP hash before deployment. The workflow's verification test rejects stale hashes.

```bash
node -e "const fs=require('fs'),c=require('crypto');const p='index.html';let s=fs.readFileSync(p,'utf8');const m=s.match(/<script>([\s\S]*?)<\/script>/);if(!m)throw Error('Inline script missing');const h=c.createHash('sha256').update(m[1]).digest('base64');s=s.replace(/script-src 'sha256-[^']+'/,\"script-src 'sha256-\"+h+\"'\");fs.writeFileSync(p,s);"
```

## Encrypted data formats and backward compatibility

### PBKDF2 v1

| Offset | Length | Meaning |
|---|---:|---|
| 0–1 | 2 | ASCII `SC` (`53 43`) |
| 2 | 1 | Format version `01` |
| 3 | 1 | KDF ID `01` (PBKDF2-HMAC-SHA256) |
| 4–7 | 4 | Iterations, unsigned 32-bit big-endian |
| 8–23 | 16 | Random salt |
| 24–35 | 12 | Random AES-GCM IV |
| 36 onward | variable | AES-GCM ciphertext followed by the 16-byte tag |

An older v1 package with 600,000 iterations remains valid. The range is 600,000–2,000,000.

### Argon2id v2

| Offset | Length | Meaning |
|---|---:|---|
| 0–1 | 2 | ASCII `SC` (`53 43`) |
| 2 | 1 | Format version `02` |
| 3 | 1 | KDF ID `02` (Argon2id v1.3) |
| 4–7 | 4 | Memory cost in KiB, unsigned 32-bit big-endian |
| 8–11 | 4 | Pass count, unsigned 32-bit big-endian |
| 12 | 1 | Parallelism, unsigned byte (`01` through `04`) |
| 13–15 | 3 | Reserved bytes, all zero |
| 16–31 | 16 | Random salt |
| 32–43 | 12 | Random AES-GCM IV |
| 44 onward | variable | AES-GCM ciphertext followed by the 16-byte tag |

The binary layout **has not changed**. Older 32 MiB / 3-pass / `p=1` packages and new variable-cost / `p=1..4` packages use the same v2 layout. The 44-byte header is authenticated as AES-GCM additional data. All parameter limits are validated **before** starting KDF work; this reduces, but cannot eliminate, denial-of-service risk from hostile URLs.

**Empty-password convention:** the pinned `hash-wasm@4.12.0` implementation rejects a zero-byte password. For Argon2id v2 only, when the NFC-normalized UTF-8 password is empty, it is mapped to the one-byte sentinel `FF` before calling Argon2id. This mapping is preserved for compatibility. No nonempty UTF-8 password can produce the invalid standalone byte `FF`. Third-party decryptors must implement the same rule. PBKDF2 uses actual empty password bytes.

All new URLs use `#data=BASE64URL`, without an external version prefix. The binary package still contains the format version and KDF ID. Legacy `#v=1&data=...` and `#v=2&data=...` formats are recognized and checked against the inner version. Omitting the visible version does **not** hide the algorithm or provide additional secrecy.

## Security considerations

- The AES key is derived in the browser, not on GitHub Pages. Runtime memory usage and CPU costs are paid by the user device, not GitHub Pages.
- An attacker who knows the ciphertext can attempt offline password guessing, regardless of the selected KDF. **An empty or easily guessed password defeats meaningful confidentiality.**
- Strong passwords and a carefully selected KDF cost are complementary. Larger numbers do not automatically guarantee safety.
- Ciphertexts in URL fragments are not normally sent in HTTP requests, but browser history, clipboard history, extensions, messages, and script running in the page can access them.
- The publisher of the GitHub Pages application can change the JavaScript. Review updates and protect repository permissions and the GitHub account.
- Applications sharing the same origin are not isolated merely because their URL paths differ. Consider a dedicated domain for high-value use.
- HTML-looking decrypted content is displayed as text, not interpreted as markup.
- Application code does not log or persist passwords or plaintext, but browsers cannot guarantee complete erasure of secrets from memory.
- Only one KDF job can run in the UI at a time. An Argon2id benchmark is cancelable, but a user-provided URL within supported resource bounds can still be intentionally expensive.
- This is an unaudited application and should not be treated as a replacement for professionally audited password managers.

## Tests

GitHub Actions runs these checks **before deployment**:

- `node tests/verify.cjs`: CSP SHA-256, Argon2id known-answer test vectors (legacy and new default), PBKDF2, Unicode and AES-GCM authenticated-header checks using the deployed pinned WASM bundle.
- `node tests/worker-smoke.cjs`: Worker validation for minimum, default, maximum, p=1 through p=4, legacy parameters, empty-password mapping, invalid parameters, and missing-vendor error reporting using a test double.
- `node tests/contract.cjs`: UI logic using a simulated DOM, inline warnings, presets, bounds, share-link forms, Unicode and empty-password round trips with native PBKDF2 and a **mocked Argon2id Worker**, benchmark UI state, and p=1 through p=4 encrypted-data compatibility.

**Important:** A mocked Worker test is not an actual browser WASM integration test. The GitHub Actions tests cover the real `hash-wasm` algorithm via Node, but the complete deployed browser Worker and device-specific performance must still be tested manually.

Recommended manual tests after deployment:

| Test | Expected result |
|---|---|
| Open a legacy v1 URL | PBKDF2 decrypts |
| Open a legacy 32 MiB / 3-pass v2 URL | Argon2id decrypts |
| Encrypt with Balanced and decrypt on a different device | Round-trip succeeds |
| Set 19 MiB / 2 passes and 256 MiB / 10 passes | Parameter validation accepts both; high-cost tests are optional |
| Encrypt/decrypt using `p=1`, `p=2`, `p=3`, and `p=4` | Each round-trip succeeds and the v2 header byte 12 stores the exact selected value |
| Decrypt an older `p=1` package after the upgrade | The previous password and ciphertext still decrypt |
| Set `p=0` or `p=5` | Input validation blocks encryption; invalid values inside the ciphertext header are rejected |
| Enter an empty password | Inline warning appears; no modal dialog |
| Enter mismatched passwords | Inline error appears |
| Select an expensive profile | Immediate device-resource warning appears |
| Paste an expensive ciphertext URL | The decryption form shows its parameters and warning |
| Run Benchmark and cancel Argon2id | Worker is stopped and page remains responsive |
| Change settings after benchmark | Previous benchmark result is invalidated |
| Corrupt ciphertext or header | AES-GCM authentication fails or the format is rejected |
| Inspect Network | No external API/CDN calls, only same-origin assets |

Do not commit private test passwords or real plaintext. Keep test vectors public and nonsecret.
