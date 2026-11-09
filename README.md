# CipherLink Lite

A lightweight, browser-only text encryption tool that creates password-protected, shareable links. The app runs on GitHub Pages without a backend, database, login, external API, or runtime CDN.

## Features

- AES-256-GCM authenticated encryption using the browser's Web Crypto API.
- Two password-based key derivation methods:
  - **Argon2id v1.3 (default):** 32 MiB of memory, 3 passes, parallelism 1, 32-byte key, via a self-hosted WASM bundle.
  - **PBKDF2-HMAC-SHA256:** 600,000 iterations using native Web Crypto; also decrypts the previous `v=1` links.
- Select KDF when encrypting. The correct method is automatically detected when decrypting.
- Fresh random 16-byte salt and 12-byte AES-GCM nonce for every encryption.
- UTF-8 plaintext and NFC-normalized UTF-8 passwords, including Korean, Japanese, emoji, and combining marks.
- Share URLs using `#v=1&data=...` or `#v=2&data=...`, without exposing the password in the URL.
- Base64URL data format, copyable ciphertext, and automatic Decrypt mode on shared links.
- Responsive UI, light/dark toggle, no third-party fonts or tracking scripts.
- Empty passwords are allowed. **They provide no meaningful confidentiality** and require an explicit warning acknowledgment when encrypting. For Argon2id v2, an empty UTF-8 password is mapped to the single raw byte `FF` before key derivation because the pinned `hash-wasm@4.12.0` library refuses zero-length input. This is a versioned application convention, not the RFC Argon2id result for an actual empty byte sequence.
- Size limit: 16 KiB of UTF-8 plaintext. No persistent application storage of plaintext/passwords.

## Source files

```text
cipherlink-lite/
├── index.html                 # UI and Web Crypto code
├── argon2-worker.js           # Dedicated Argon2id worker; released after each operation
├── README.md                  # User and format documentation
├── .github/workflows/deploy.yml  # GitHub Pages deployment and pinned vendor packaging
├── tests/verify.cjs           # Node.js cryptographic known-answer and format checks
└── tests/worker-smoke.cjs     # Worker protocol and error-handling tests
```

The published site contains `index.html`, `argon2-worker.js`, `vendor/argon2.umd.min.js`, `vendor/LICENSE.hash-wasm`, and `.nojekyll`. Only the two JavaScript-related files and HTML are executable. The WASM implementation is bundled into the vendor JavaScript file.

## Deploy to GitHub Pages (GitHub Actions)

GitHub Actions is used only at **deployment time** to fetch and bundle an exact, pinned open-source Argon2id implementation. End-user browsers never fetch external CDN resources. No Node.js installation is required on your PC and no build step runs when visitors open the page.

1. Create a GitHub repository called `cipherlink-lite`.
2. Upload all source files, **preserving the `.github/workflows/deploy.yml` and `tests/verify.cjs` paths**.
3. Go to **Settings → Pages → Build and deployment**, and select **GitHub Actions** (not *Deploy from a branch*).
4. Push the files to the `main` branch. The workflow can also be launched from **Actions → Deploy CipherLink Lite → Run workflow**.
5. Confirm the GitHub Actions workflow is green; if a test fails, the new version will not deploy. Verify `https://USERNAME.github.io/cipherlink-lite/`.
6. Choose Argon2id or PBKDF2 in the Encrypt tab. A shared URL automatically selects Decrypt and detects the key derivation method without user intervention.

If you prefer **Deploy from a branch** without GitHub Actions, you must manually place the exact version `4.12.0` of `hash-wasm/dist/argon2.umd.min.js` under `vendor/argon2.umd.min.js` and its license under `vendor/LICENSE.hash-wasm` in the repository. Official package: <https://www.npmjs.com/package/hash-wasm/v/4.12.0>. The downloaded package is used locally; there is no runtime CDN. The main HTML and worker are still build-free.

### Dependency pinning and licensing

The deploy workflow obtains `hash-wasm@4.12.0` using `npm pack`, then extracts only `package/dist/argon2.umd.min.js` and `package/LICENSE`. This project uses `hash-wasm`'s standalone Argon2 bundle (MIT license). Upgrading the pinned version must be treated as a controlled security-sensitive change. The included known-answer tests and Worker smoke tests check the KDF result, authenticated encryption behavior, and Worker protocol before GitHub Pages deployment, but are not a substitute for a comprehensive security audit or independent supply-chain verification.


## Troubleshooting Argon2id

If encryption displays an Argon2id error, check the exact message before changing memory settings.

1. Verify **Settings → Pages → Build and deployment → Source** is **GitHub Actions**. The source ZIP intentionally does not contain the third-party vendor bundle; the workflow adds it to the published artifact.
2. Open `https://USERNAME.github.io/cipherlink-lite/vendor/argon2.umd.min.js` (replace USERNAME). It must return JavaScript, not 404 or the HTML of an error page. Also check `.../argon2-worker.js`.
3. In **Actions → Deploy CipherLink Lite**, check that the latest workflow succeeded. The original v2 verification test incorrectly called `hash-wasm` with an empty password, which the library rejects; this release fixes that test and the browser Worker.
4. For failures on a deployed site, use the browser's DevTools Network tab and Console to check whether the local vendor file was blocked or failed to load. Do **not** paste passwords or decrypted content into issue reports.
5. If the vendor file exists and Argon2id still fails, test a non-empty password and try a current desktop browser. The Worker now distinguishes library load errors, missing API, resource allocation problems, and other calculation failures.

The browser does not automatically fall back from Argon2id to PBKDF2. Each ciphertext carries its own KDF identifier and must be decrypted using that KDF.

## Wire format: PBKDF2 v1 (backward-compatible)

URL: `#v=1&data=BASE64URL`

| Byte offset | Length | Content |
|---|---:|---|
| 0–1 | 2 | ASCII `SC` = `53 43` hexadecimal |
| 2 | 1 | Format version `01` |
| 3 | 1 | KDF ID `01` (PBKDF2-HMAC-SHA256) |
| 4–7 | 4 | Iterations, unsigned 32-bit big-endian |
| 8–23 | 16 | Random salt |
| 24–35 | 12 | Random AES-GCM IV |
| 36 onward | variable | Ciphertext followed by 16-byte GCM authentication tag |

The app encrypts using 600,000 iterations, and accepts iteration counts from 600,000 to 2,000,000 for compatible v1 decryption. Version 1 is unchanged from the previous release. Overhead is 52 bytes plus Base64URL expansion.

## Wire format: Argon2id v2

URL: `#v=2&data=BASE64URL`

| Byte offset | Length | Content |
|---|---:|---|
| 0–1 | 2 | ASCII `SC` = `53 43` hexadecimal |
| 2 | 1 | Format version `02` |
| 3 | 1 | KDF ID `02` (Argon2id version 1.3 / 0x13) |
| 4–7 | 4 | Memory cost in KiB; unsigned 32-bit big-endian; **32768** |
| 8–11 | 4 | Passes; unsigned 32-bit big-endian; **3** |
| 12 | 1 | Parallelism, **1** |
| 13–15 | 3 | Reserved flags, all zeros |
| 16–31 | 16 | Random salt |
| 32–43 | 12 | Random AES-GCM IV |
| 44 onward | variable | Ciphertext followed by 16-byte GCM authentication tag |

**Argon2id v2 empty-password convention:** after NFC normalization and UTF-8 encoding, if and only if the password has zero bytes, pass a one-byte array `FF` into Argon2id. All non-empty UTF-8 passwords remain unchanged. Because the byte `FF` is invalid UTF-8, no non-empty browser password can collide with this sentinel. Third-party clients must replicate this rule to decrypt v2 empty-password links. In particular, applying Argon2id directly to the empty byte string will not reproduce such keys. Empty passwords still offer no meaningful confidentiality.

The total v2 overhead is 60 bytes. For v2, the parser accepts only the exact resource parameters listed above. Future settings should use a new format version rather than altering the published v2 contract. This protects the browser from arbitrary KDF resource costs in attacker-controlled links.

Both formats use UTF-8 plaintext without normalization; the password is normalized to NFC before UTF-8 encoding, including when empty. AES-GCM uses the **entire binary header as authenticated additional data (AAD)** and a 128-bit tag. Base64URL omits `=` padding and must be canonical. A URL's outer `v=` must match the embedded package version. The key derivation returns a 32-byte AES key; it is never embedded in the URL.

## Security boundaries

- **Base64URL is an encoding, not encryption.** AES-256-GCM authenticates and encrypts data; the KDF slows offline password guessing but does not replace a strong password.
- Empty, weak, or predictable passwords allow attackers with the encrypted URL to recover the plaintext. Argon2id does **not** make an empty password secret.
- URL fragments are ordinarily excluded from HTTP requests and `Referer`, but may appear in browser history, extensions, clipboard, screenshots, sync, and messaging systems.
- The HTML and local Argon2 vendor code can access sensitive data while running. Compromised GitHub Pages content, a compromised repository account, or a malicious update can steal plaintext/passwords.
- No app code intentionally writes passwords or plaintext to URLs, logs, localStorage, sessionStorage, cookies, or IndexedDB. Browser memory and historical clipboard contents cannot be reliably erased.
- GitHub Pages projects on the same hostname share an origin. Consider a dedicated origin if unrelated scripts are hosted on the same `USERNAME.github.io` hostname.
- The app uses an in-page CSP that permits same-origin scripts, the hashed inline app script, WebAssembly, and same-origin Web Workers. HTML meta CSP cannot set all HTTP-header-only policies.
- A new Argon2id Worker is created for each operation, and terminated after its answer to release references and reduce persistent WASM memory. This does not guarantee complete memory erasure.
- Keep shared links and passwords on separate communication channels where practical. Avoid relying on the URL as your only backup: preserve a known-good copy of the decryption application and the format specification.

## Manual testing checklist

| ID | Test | Expected outcome |
|---|---|---|
| T01 | Argon2id with English text and nonempty password | Round-trip success, URL `v=2` |
| T02 | PBKDF2 with English text and nonempty password | Round-trip success, URL `v=1` |
| T03 | Use a previously created PBKDF2 v1 link | Still decrypts without changes |
| T04 | Korean, Japanese, emoji, composed and decomposed characters | Plaintext round-trips exactly |
| T05 | Empty password with Argon2id and PBKDF2 | Warning shown; confirmation permits encryption and empty-password decryption succeeds |
| T06 | Cancel empty-password warning | No encrypted result generated |
| T07 | Incorrect password for either format | Authenticated decryption fails |
| T08 | Tamper with GCM tag or header | Authentication or format validation fails |
| T09 | Modify v2 memory, passes, parallelism, flags | Rejected before starting worker |
| T10 | Change URL version to disagree with encrypted binary | Mismatch error |
| T11 | Identical plaintext/password encrypted twice | Different salts, nonces, and ciphertext |
| T12 | Open `#v=1&data=...`, `#v=2&data=...`, or `#data=...` | Automatic Decrypt mode and correct KDF detection |
| T13 | Paste only Base64URL ciphertext | Detected and decrypted using embedded header |
| T14 | Encrypt more than 16 KiB UTF-8 | Rejected |
| T15 | Remove bundled vendor JS from deployed site | PBKDF2 works; Argon2id reports an error and does not silently downgrade |
| T16 | Toggle themes / test on narrow mobile width | Functional layout; no localStorage writes |
| T17 | Inspect browser network after opening a deployed site | No API or external CDN requests |
| T18 | Open page with incorrect script hash | CSP blocks inline script; update hash before deployment |
| T19 | Remove `vendor/argon2.umd.min.js` | Explicit vendor load error; no automatic fallback |
| T20 | Use an empty password with Argon2id v2 | The reserved `FF` sentinel is used; the same link decrypts with an empty password |
| T19 | Copy encrypted URL, open in another device | Correct plaintext with same password and compatible browser |
| T20 | Add `<script>` markup to plaintext | Result remains inert text, not executable markup |

The GitHub Actions workflow also runs `tests/verify.cjs`, which validates a fixed Argon2id v1.3 KDF result, a PBKDF2-SHA256 result, both AES-GCM header layouts, Unicode round trips, authenticated-header tampering, and the inline CSP hash. This does **not** substitute for testing the actual deployed browser Worker and CSP behavior in Chrome, Edge, Firefox, Android Chrome, and Safari.

### Updating inline JavaScript

The inline application JavaScript uses a SHA-256 CSP hash. **If you edit the `<script>` contents, recalculate the hash in `index.html`.** Use this Node.js snippet on your development machine:

```bash
node -e "const fs=require('fs'),crypto=require('crypto');const p='index.html';let s=fs.readFileSync(p,'utf8');const m=s.match(/<script>([\s\S]*?)<\/script>/);if(!m)throw Error('script not found');const h=crypto.createHash('sha256').update(m[1]).digest('base64');s=s.replace(/script-src 'sha256-[^']+'/,\"script-src 'sha256-\"+h+\"'\");fs.writeFileSync(p,s);"
```

No persistent browser storage, build tool, or external service is required **at runtime**. The default deployment requires GitHub Actions only to package a pinned self-hosted Argon2id dependency and validate crypto test vectors.
