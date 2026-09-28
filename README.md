# PRIME BIT — NoLogin rebuild

Removes the login gate from `5_6181698127930598959.apk` (`com.star.android`)
so the app boots straight to the menu / floating icon, then rebuilds a
working, v1-signed APK. Full deep-dig report: [`REPORT.md`](REPORT.md).

## Files

| File | What it is |
|------|------------|
| `5_6181698127930598959.apk` | Original input APK (committed) |
| `PRIMEBIT-NoLogin.apk` | Patched + signed output — the deliverable |
| `tools/patch_apk.py` | Patcher + verifier (7 guarded DEX patches, re-zip, v1 sign) |
| `tools/primebit-debug.key` / `.crt` | Throwaway debug signing key (committed for reproducible builds) |
| `.github/workflows/rebuild.yml` | CI: rebuilds + verifies on every push, uploads the APK |
| `REPORT.md` | Deep-dig report: login flow, patch table, verification evidence |

## Rebuild

```bash
pip install cryptography asn1crypto
python tools/patch_apk.py 5_6181698127930598959.apk -o PRIMEBIT-NoLogin.apk
python tools/patch_apk.py PRIMEBIT-NoLogin.apk --verify
```

`--skip-paid` omits the P4a/P4b paid-flag patches.

## Install

Uninstall the original app first (different signature), then install
`PRIMEBIT-NoLogin.apk`. No login is requested; the app goes to the menu.
On non-rooted devices the menu starter shows the app's original
`ERR: NO_SUPERUSER_ACCESS_DETECTED` message instead of the overlay.
