# PRIME BIT — NoLogin rebuild: deep-dig report

Input: `5_6181698127930598959.apk` (package `com.star.android`, 146 ZIP entries)
Output: `PRIMEBIT-NoLogin.apk` (149 entries, v1-signed with a throwaway debug key)
Patcher: `tools/patch_apk.py` (reproducible — same input + same key = same bytes)

Goal: remove the login gate so the app boots straight to the menu / floating
icon, then rebuild a working, installable, signed APK.

---

## 1. What the login gate looks like

Entry: `MainActivity.onCreate$lambda$11` reads a `Boolean` preference flag.

- `FALSE` → continue into the login UI.
- `TRUE` → skip login and continue toward the main menu.

Deeper in the flow:

- `FloatingService.c()` calls
  `KeyLoginClient.nativeVerifyApp(Context)` (native, `libPrimeBit.so`) and
  returns its result. `false` = unverified → login enforced.
- `FloatingService.b()` calls the same native check; a non-zero result jumps
  to an `Anti-Patch: Signature mismatch or APK repacked!` Toast + abort path.
  Any repack must neutralise this branch or the app refuses to run.
- `FloatingService.onStartCommand()` reads an `isPaid`-style boolean from the
  incoming Intent (intent path) and from SharedPreferences (prefs path) into
  the field that gates paid/menu features.
- Offline fallback: `KeyLoginClient.c()` falls back to the sentinel
  `AUTH_TOKEN:INVALID:INVALID:0:Free:INVALID`, so forcing the verified/paided
  flags is consistent with the app's own offline path.
- Menu dispatch runs through `nc.a()` / `mk.a()` handler objects driven by
  `lambda9` callbacks: `OPEN MENU` (e=3 → `nc` case-3) and a `TextButton`
  (e=5 → `mk` case-5); `mk.a@cu0xb3` is e=0. These were confirmed exclusive
  call sites, so rewriting those two cases only affects the login-gated
  buttons.

## 2. The patches (7 sites, all guard-checked)

| ID | File offset | Old bytes | New bytes | Effect |
|----|-------------|-----------|-----------|--------|
| P1 | `0x1086ec` | `620c930e` (`FALSE`) | `620c940e` (`TRUE`) | boot-to-menu: login preference reads TRUE |
| P2 | `0x10a2d6` | `0a00` (`const/4 v0,0`) | `1210` (`const/4 v0,1`) | `FloatingService.c()` keeps calling native verify but always returns true |
| P3 | `0x109f94` | `0a0d` (`move-result v13`) | `120d` (`const/4 v13,0`) | `FloatingService.b()`: verify result forced 0 = OK, anti-repack Toast unreachable |
| P4a | `0x10be28` | `0a04` (`move-result v4`) | `1214` (`const/4 v4,1`) | paid flag forced true (intent path) |
| P4b | `0x10be46` | `0a04` (`move-result v4`) | `1214` (`const/4 v4,1`) | paid flag forced true (prefs path) |
| P6a | `0x1aae0a` | 148 B original `nc` case-3 | 148 B rewritten menu starter | `nc` case-3 now starts `FloatingService` via `startForegroundService` (root-checked, error Toast + `jn1` fallback preserved) |
| P6b | `0x1a28c0` | 22 B original `mk` case-5 prologue | 22 B `new nc(e=3, act, rooted=true)` + `nc.a()` | `mk` case-5 delegates to the same menu starter |

Details:

- Dalvik `11n` encoding packs literal in the HIGH nibble (`const/4 v4,1` =
  `12 14`); `const/4` is opcode `0x12`, `const/16` is `0x13`.
- P6a keeps the original register frame (`regs=5`, params `v3/v4`) and the
  original `if-nez v2 → error Toast` guard; the success path builds an
  explicit `Intent(pkg, FloatingService)` and calls `startForegroundService`,
  then falls through to the original `sget jn1; return` tail. All branch
  targets land on the original code unit grid.
- P6b constructs `nc(3, activity, true)` and invokes `nc.a()` inline, so both
  menu buttons converge on the single rewritten starter. Duplication is safe:
  a `jz` injection flag in the service start path makes repeats idempotent.
- The patcher refuses to write unless every `old` guard matches the input
  bytes exactly, so it can never half-patch a different APK version.

## 3. Rebuild pipeline (same script, `tools/patch_apk.py`)

1. Apply the 7 guarded patches to `classes.dex` in memory.
2. Recompute the DEX header: SHA-1 over bytes `[32:]` → header offset 12,
   adler32 over bytes `[12:]` → header offset 8 (`file_size` untouched).
3. Re-zip: original file order, original per-entry compression
   (`classes.dex`/`.so` DEFLATED; `resources.arsc`, images, baseline STORED),
   original timestamps preserved, STORED data 4-byte aligned, UTF-8 flag set.
4. v1 (JAR) sign: `MANIFEST.MF` (SHA-256 per entry) → `CERT.SF` (manifest +
   per-section digests) → `CERT.RSA` (detached RSA/SHA-256 CMS over `CERT.SF`,
   committed throwaway key `tools/primebit-debug.key`). Sig-file timestamps
   fixed at 2024-01-01 for reproducibility.

## 4. Verification evidence (all on the shipped bytes)

`python tools/patch_apk.py PRIMEBIT-NoLogin.apk --verify`:

- 7/7 patch byte-patterns present
- DEX signature + checksum valid
- `MANIFEST.MF`: 147/147 entry digests valid (incl. 72-column wrapped names)
- `CERT.SF`: manifest digest + 147/147 section digests valid
- STORED-entry 4-byte alignment checked

Independent checks:

- `openssl smime -verify` of `CERT.RSA` against `CERT.SF`: **Verification
  successful** (repeated runs).
- Full disassembly of the patched regions decodes exactly as designed
  (register frames, invoke prototypes, branch targets, string/type/method
  indices all resolve).
- Androguard re-parses the APK cleanly: 14,732 methods / 2,682 classes,
  patched classes `Lnc;`, `Lmk;`, `LFloatingService;` all resolve.
- `zipfile.testzip()` clean; original entry timestamps preserved.

## 5. Install / usage notes

- **Uninstall the original app first**: the rebuild is signed with a different
  (debug) key, and Android refuses to install over a mismatched signature.
- Launch: the app boots directly toward the menu; the floating service icon
  is the post-login UI. No credentials are requested.
- Root-gated branch: on a non-rooted device the `OPEN MENU` starter shows the
  original `ERR: NO_SUPERUSER_ACCESS_DETECTED` Toast instead of starting the
  overlay — that behaviour is inherited from the original app.
- Rebuild it yourself: `pip install cryptography asn1crypto`, then
  `python tools/patch_apk.py 5_6181698127930598959.apk -o PRIMEBIT-NoLogin.apk`
  (CI in `.github/workflows/rebuild.yml` does exactly this on every push).
