#!/usr/bin/env python3
"""PRIMEBIT Injector - NoLogin patcher.

Takes the original (login-gated) APK and produces a rebuilt APK that:
  * boots straight into the main menu (no login screen),
  * starts the floating menu service from OPEN MENU (reconstructs the
    missing MainActivity.i() logic inline - the original call crashes),
  * fixes the inverted root check on OPEN MENU (rooted devices were
    shown a bogus "Access Unauthorized" dialog),
  * bypasses the signature/key gates so the menu + injection work
    offline (anti-repack + AUTH_TOKEN checks neutralised),
  * forces paid-mode flag so the full menu is unlocked,
  * re-zips (zipalign-style 4-byte alignment for STORED entries) and
    re-signs with APK Signature Scheme v1 (JAR signing).

All DEX edits are same-size, in-place binary patches (no offsets shift),
so the DEX stays structurally valid. The DEX header signature/checksum
are recomputed afterwards.

Usage:
    python3 tools/patch_apk.py 5_6181698127930598959.apk -o PRIMEBIT-NoLogin.apk
    python3 tools/patch_apk.py INPUT.apk -o OUT.apk --skip-paid   # free-mode flag
    python3 tools/patch_apk.py OUT.apk --verify                   # self-check digests

Requires: pip install cryptography
"""
import argparse
import base64
import hashlib
import os
import struct
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(HERE, "primebit-debug.key")
CRT_PATH = os.path.join(HERE, "primebit-debug.crt")

# --------------------------------------------------------------------------
# DEX patches: (file_offset, expected_bytes, new_bytes, description)
# --------------------------------------------------------------------------
P6A_NEW = bytes.fromhex(
    "62008e01"          # 0x17: sget-object v0, Build$VERSION.SDK_INT
    "13011a00"          # 0x19: const/16 v1, 26
    "34101700"          # 0x1b: if-lt v0,v1, :end      (API<26 -> skip start, no crash)
    "1c00bf02"          # 0x1d: const-class v0, FloatingService
    "6e1010180000"      # 0x1f: invoke-virtual {v0}, Class.getName()
    "0c00"              # 0x22: move-result-object v0  (service class name)
    "6e1059020300"      # 0x23: invoke-virtual {v3}, Context.getPackageName()
    "0c01"              # 0x26: move-result-object v1  (package name)
    "22027c00"          # 0x27: new-instance v2, Intent
    "701065020200"      # 0x29: invoke-direct {v2}, Intent.<init>()
    "6e3070021200"      # 0x2c: invoke-virtual {v2,v1,v0}, Intent.setClassName()
    "6e20d3012300"      # 0x2f: invoke-virtual {v3,v2}, Activity.startForegroundService()
    # :end (0x32):
    "6200770f"          # 0x32: sget-object v0, Unit.a
    "1100"              # 0x34: return-object v0
    "00000000000000000000000000000000000000000000000000000000000000000000"  # 0x35-0x45: nops x17
)

P6B_NEW = bytes.fromhex(
    "2200cc07"          # 0x1a: new-instance v0, Lnc;
    "1231"              # 0x1c: const/4 v1, 3         (e = case 3 -> menu starter)
    "1213"              # 0x1d: const/4 v3, 1         (rooted = true)
    "704096221034"      # 0x1e: invoke-direct {v0,v1,v4,v3}, Lnc;.<init>(I,Object,Z)V
    "6e1098220000"      # 0x21: invoke-virtual {v0}, Lnc;.a()Object
    "0000"              # 0x24: nop                   (0x25: existing return kept)
)

PATCHES = [
    (0x1086ec,
     bytes.fromhex("620c930e"),
     bytes.fromhex("620c940e"),
     "P1 boot-to-menu (Boolean.FALSE -> TRUE)"),
    (0x10a2d6,
     bytes.fromhex("0a00"),
     bytes.fromhex("1210"),
     "P2 force FloatingService.c()=true (keep native call, force result=1)"),
    (0x109f94,
     bytes.fromhex("0a0d"),
     bytes.fromhex("120d"),
     "P3 neutralise anti-repack in FloatingService.b() (force verify result=0=OK)"),
    (0x10be28,
     bytes.fromhex("0a04"),
     bytes.fromhex("1214"),  # const/4 v4, 1 (11n: byte = lit<<4|reg)
     "P4a force paid-mode flag (intent path)"),
    (0x10be46,
     bytes.fromhex("0a04"),
     bytes.fromhex("1214"),  # const/4 v4, 1 (11n: byte = lit<<4|reg)
     "P4b force paid-mode flag (prefs path)"),
    (0x1aae0a,
     bytes.fromhex(
         "1f03be0260003905390221006e1082180300220058007020d90130001a038103"
         "6e20dc0130000c031a004f176e20da0103000c031a00c91912026e30db010302"
         "0c036e10dd010300280a6e10110c03000a00380005006e10120c03001101"),
     P6A_NEW,
     "P6a reconstruct menu starter (nc case-3 inline service start)"),
    (0x1a28c0,
     bytes.fromhex("600039056e10110c04000a00380005006e10120c0400"),
     P6B_NEW,
     "P6b second button delegates to menu starter (mk case-5)"),
    (0x10be5a,
     bytes.fromhex("2204ff0b7030d83534006e2064044500"),
     bytes.fromhex("00000000000000000000000000000000"),
     "P7a silence crack-toast at service start (nop xy(1) post)"),
    (0x1fa616,
     bytes.fromhex("1a00d6067110da2500000c006e1003060f000c0f"),
     bytes.fromhex("1a00000000000000000000006e1003060f000c0f"),
     "P7f defuse CHECK-button socket crash (t4e3: empty status, show Cannot-connect)"),
]

SKIP_PAID = {"P4a force paid-mode flag (intent path)",
             "P4b force paid-mode flag (prefs path)"}


def patch_dex(buf: bytearray, skip_paid=False):
    applied = []
    for off, expect, new, desc in PATCHES:
        if skip_paid and desc in SKIP_PAID:
            print(f"  [skip] {desc}")
            continue
        assert len(expect) == len(new), f"size mismatch: {desc}"
        actual = bytes(buf[off:off + len(expect)])
        if actual != expect:
            raise SystemExit(
                f"GUARD FAILED: {desc}\n"
                f"  offset 0x{off:x}: expected {expect.hex()}, found {actual.hex()}\n"
                f"  (input APK does not match the analysed build - aborting)")
        buf[off:off + len(new)] = new
        applied.append(desc)
        print(f"  [ok] {desc}")
    # Recompute DEX header signature (SHA-1 over bytes [32:]) and
    # checksum (adler32 over bytes [12:]).
    sig = hashlib.sha1(bytes(buf[32:])).digest()
    buf[12:32] = sig  # signature field lives at header offset 12
    chk = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", buf, 8, chk)
    print(f"  [ok] DEX signature={sig.hex()[:16]}... checksum=0x{chk:08x}")
    return applied


# --------------------------------------------------------------------------
# ZIP rebuild (zipalign-style) + v1 signing
# --------------------------------------------------------------------------
SIG_EXTS = (".SF", ".RSA", ".DSA", ".EC")


def is_signature_file(name: str) -> bool:
    up = name.upper()
    if up == "META-INF/MANIFEST.MF":
        return True
    if up.startswith("META-INF/"):
        base = up.rsplit("/", 1)[-1]
        if any(base.endswith(e) for e in SIG_EXTS):
            return True
        if base.startswith("SIG-"):
            return True
    return False


def wrap_manifest_line(line: bytes) -> bytes:
    # Manifest spec: max 72 bytes per line; continuation lines start with ' '.
    if len(line) <= 72:
        return line + b"\r\n"
    out = [line[:72] + b"\r\n"]
    rest = line[72:]
    while len(rest) > 71:
        out.append(b" " + rest[:71] + b"\r\n")
        rest = rest[71:]
    out.append(b" " + rest + b"\r\n")
    return b"".join(out)


def build_manifest(entries):
    # entries: list of (name, sha256_bytes)
    out = [b"Manifest-Version: 1.0\r\n",
           b"Created-By: PRIMEBIT-NoLogin-Patcher\r\n", b"\r\n"]
    sections = {}
    for name, digest in entries:
        sec = wrap_manifest_line(b"Name: " + name.encode("utf-8"))
        sec += wrap_manifest_line(b"SHA-256-Digest: " +
                                  base64.b64encode(digest))
        sec += b"\r\n"
        sections[name] = sec
        out.append(sec)
    return b"".join(out), sections


def build_sf(manifest: bytes, sections):
    out = [b"Signature-Version: 1.0\r\n",
           b"Created-By: PRIMEBIT-NoLogin-Patcher\r\n"]
    out.append(wrap_manifest_line(
        b"SHA-256-Digest-Manifest: " +
        base64.b64encode(hashlib.sha256(manifest).digest())))
    out.append(b"\r\n")
    for name, sec in sections.items():
        out.append(wrap_manifest_line(b"Name: " + name.encode("utf-8")))
        out.append(wrap_manifest_line(
            b"SHA-256-Digest: " +
            base64.b64encode(hashlib.sha256(sec).digest())))
        out.append(b"\r\n")
    return b"".join(out)


def ensure_key():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone
    if os.path.exists(KEY_PATH) and os.path.exists(CRT_PATH):
        key = serialization.load_pem_private_key(
            open(KEY_PATH, "rb").read(), password=None)
        cert = x509.load_pem_x509_certificate(open(CRT_PATH, "rb").read())
        return key, cert
    print("  [..] generating throwaway debug signing key ...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "PrimeBit-NoLogin-Debug")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), True)
            .sign(key, hashes.SHA256()))
    open(KEY_PATH, "wb").write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    open(CRT_PATH, "wb").write(
        cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    print(f"  [ok] wrote {KEY_PATH} + {CRT_PATH} (public debug key)")
    return key, cert


def build_rsa(sf_bytes: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    key, cert = ensure_key()
    return (pkcs7.PKCS7SignatureBuilder()
            .set_data(sf_bytes)
            .add_signer(cert, key, hashes.SHA256())
            .sign(Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature,
                                 pkcs7.PKCS7Options.Binary]))


def rebuild_apk(in_path: str, dex_patched: bytes, out_path: str):
    zin = zipfile.ZipFile(in_path, "r")
    # Collect entries (skip dirs + old signature files), keep order.
    items = []
    for info in zin.infolist():
        if info.is_dir():
            continue
        if is_signature_file(info.filename):
            continue
        data = zin.read(info.filename)
        if info.filename == "classes.dex":
            data = dex_patched
        items.append((info, data))
    zin.close()

    # Manifest/SF over final entry bytes.
    digests = [(info.filename, hashlib.sha256(data).digest())
               for info, data in items]
    manifest, sections = build_manifest(digests)
    sf = build_sf(manifest, sections)
    rsa = build_rsa(sf)
    print(f"  [ok] MANIFEST.MF ({len(manifest)} B) + CERT.SF ({len(sf)} B) "
          f"+ CERT.RSA ({len(rsa)} B)")

    with open(out_path, "wb") as f:
        offset = 0

        def write_entry(name, data, method, dt):
            nonlocal offset
            if method == zipfile.ZIP_STORED:
                comp_data = data
            else:
                comp_obj = zlib.compressobj(9, zlib.DEFLATED, -15)
                comp_data = comp_obj.compress(data) + comp_obj.flush()
            crc = zlib.crc32(data) & 0xFFFFFFFF
            name_b = name.encode("utf-8")
            # Local header is 30 bytes + name + extra; align STORED data to 4
            # with plain zero padding (matches aapt/zipalign output; the 0xd935
            # TLV form got rejected at install with "package appears invalid").
            extra = b""
            local_ver = 20
            if method == zipfile.ZIP_STORED:
                local_ver = 10
                pad = (-(offset + 30 + len(name_b))) % 4
                extra = b"\x00" * pad
            # Local header order is mod-TIME then mod-DATE; dt=(date,time).
            header = struct.pack("<IHHHHHIIIHH", 0x04034B50, local_ver, 0x0800,
                                 method, dt[1], dt[0], crc,
                                 len(comp_data), len(data),
                                 len(name_b), len(extra))
            f.write(header)
            f.write(name_b)
            f.write(extra)
            f.write(comp_data)
            rec = (name, method, crc, len(comp_data), len(data), offset,
                   dt, len(extra))
            offset += 30 + len(name_b) + len(extra) + len(comp_data)
            return rec

        central = []
        # Fixed DOS date/time for signature files: 2024-01-01 00:00:00.
        SIG_DT = (((2024 - 1980) << 9) | (1 << 5) | 1, 0)
        central.append(write_entry("META-INF/MANIFEST.MF", manifest,
                                   zipfile.ZIP_DEFLATED, SIG_DT))
        central.append(write_entry("META-INF/CERT.SF", sf,
                                   zipfile.ZIP_DEFLATED, SIG_DT))
        central.append(write_entry("META-INF/CERT.RSA", rsa,
                                   zipfile.ZIP_STORED, SIG_DT))
        for info, data in items:
            y, mo, d, h, mi, s = info.date_time
            dt = (((y - 1980) << 9) | (mo << 5) | d,
                  (h << 11) | (mi << 5) | (s // 2))
            central.append(write_entry(info.filename, data,
                                       info.compress_type, dt))
        # Central directory.
        cd_start = offset
        for (name, method, crc, csize, usize, lh_off, dt,
             extra_len) in central:
            name_b = name.encode("utf-8")
            # Central dir order is also mod-TIME then mod-DATE.
            cd_ver = 10 if method == zipfile.ZIP_STORED else 20
            # Central flags must match local flags (0x0800 UTF-8) and central
            # extras stay empty (matches aapt/zipalign output).
            f.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, cd_ver,
                                0x0800, method, dt[1], dt[0], crc, csize,
                                usize, len(name_b), 0, 0, 0, 0, 0, lh_off))
            f.write(name_b)
            offset += 46 + len(name_b)
        cd_size = offset - cd_start
        f.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central),
                            len(central), cd_size, cd_start, 0))
    print(f"  [ok] wrote {out_path} ({os.path.getsize(out_path)} bytes, "
          f"{len(central)} entries)")


# --------------------------------------------------------------------------
# Verify mode (self-check: DEX patches present + MF/SF digests consistent)
# --------------------------------------------------------------------------
def verify_apk(path: str) -> bool:
    ok = True
    z = zipfile.ZipFile(path)
    names = z.namelist()
    for need in ("META-INF/MANIFEST.MF", "META-INF/CERT.SF",
                 "META-INF/CERT.RSA", "classes.dex"):
        if need not in names:
            print(f"  [FAIL] missing {need}")
            ok = False
    dex = z.read("classes.dex")
    for off, _expect, new, desc in PATCHES:
        if bytes(dex[off:off + len(new)]) == new:
            print(f"  [ok] patch present: {desc}")
        else:
            print(f"  [FAIL] patch missing: {desc}")
            ok = False
    # DEX header check.
    sig = hashlib.sha1(dex[32:]).digest()
    chk = zlib.adler32(dex[12:]) & 0xFFFFFFFF
    if dex[12:32] == sig and struct.unpack_from("<I", dex, 8)[0] == chk:
        print("  [ok] DEX signature + checksum valid")
    else:
        print("  [FAIL] DEX signature/checksum mismatch")
        ok = False
    # MF digest check (unwrap manifest continuation lines first).
    mf = z.read("META-INF/MANIFEST.MF")
    text = mf.replace(b"\r\n", b"\n").decode("utf-8")
    unwrapped = []
    for line in text.split("\n"):
        if line.startswith(" ") and unwrapped:
            unwrapped[-1] += line[1:]
        else:
            unwrapped.append(line)
    raw_sections = "\n".join(unwrapped).split("\n\n")
    mf_ok = True
    sf = z.read("META-INF/CERT.SF").replace(b"\r\n", b"\n").decode("utf-8")
    # Rebuild expected manifest bytes per file.
    for info in z.infolist():
        if info.is_dir() or is_signature_file(info.filename):
            continue
        want = base64.b64encode(
            hashlib.sha256(z.read(info.filename)).digest()).decode()
        # find section
        found = None
        for sec in raw_sections[1:]:
            if sec.startswith(f"Name: {info.filename}\n"):
                for line in sec.split("\n"):
                    if line.startswith("SHA-256-Digest: "):
                        found = line.split(": ", 1)[1]
                break
        if found != want:
            print(f"  [FAIL] MANIFEST digest mismatch: {info.filename}")
            mf_ok = False
            ok = False
    if mf_ok:
        print(f"  [ok] MANIFEST.MF digests valid "
              f"({len(raw_sections) - 1} entries)")
    # SF manifest digest.
    for line in sf.split("\n"):
        if line.startswith("SHA-256-Digest-Manifest: "):
            got = line.split(": ", 1)[1]
            want = base64.b64encode(hashlib.sha256(mf).digest()).decode()
            if got == want:
                print("  [ok] CERT.SF manifest digest valid")
            else:
                print("  [FAIL] CERT.SF manifest digest mismatch")
                ok = False
    # SF per-section digests (SHA-256 over raw manifest section bytes).
    mf_parts = mf.split(b"\r\n\r\n")
    sf_text = z.read("META-INF/CERT.SF").replace(b"\r\n", b"\n").decode(
        "utf-8")
    sf_unwrapped = []
    for line in sf_text.split("\n"):
        if line.startswith(" ") and sf_unwrapped:
            sf_unwrapped[-1] += line[1:]
        else:
            sf_unwrapped.append(line)
    sf_sections = "\n".join(sf_unwrapped).split("\n\n")[1:]
    mf_map = {}
    for part in mf_parts[1:]:
        if part.startswith(b"Name: "):
            # Unwrap continuation lines to recover the full entry name.
            lines = part.split(b"\r\n")
            nm = lines[0][6:].decode("utf-8")
            for cont in lines[1:]:
                if cont.startswith(b" ") and not cont.startswith(
                        b"SHA-256-Digest:"):
                    nm += cont[1:].decode("utf-8")
                else:
                    break
            mf_map[nm] = hashlib.sha256(part + b"\r\n\r\n").digest()
    bad_sf = 0
    for sec in sf_sections:
        if not sec.startswith("Name: "):
            continue
        nm = sec.split("\n", 1)[0][6:]
        got = None
        for line in sec.split("\n"):
            if line.startswith("SHA-256-Digest: "):
                got = base64.b64decode(line.split(": ", 1)[1])
        if mf_map.get(nm) != got:
            print(f"  [FAIL] CERT.SF section digest mismatch: {nm}")
            bad_sf += 1
            ok = False
    if not bad_sf:
        print(f"  [ok] CERT.SF section digests valid ({len(sf_sections)} "
              f"entries)")
    # Alignment check for STORED entries (uses the LOCAL header extra
    # length - central-directory extras are empty by design).
    raw = open(path, "rb").read()
    for info in z.infolist():
        if info.compress_type == zipfile.ZIP_STORED and not info.is_dir():
            lh = info.header_offset
            assert raw[lh:lh + 4] == b"PK\x03\x04", info.filename
            local_extra_len = struct.unpack_from("<H", raw, lh + 28)[0]
            data_off = (lh + 30 + len(info.filename.encode("utf-8")) +
                        local_extra_len)
            if data_off % 4:
                print(f"  [FAIL] {info.filename} STORED data not "
                      f"4-aligned (off={data_off})")
                ok = False
    print("  [ok] STORED-entry alignment checked")
    z.close()
    return ok


def main():
    ap = argparse.ArgumentParser(description="PRIMEBIT NoLogin APK patcher")
    ap.add_argument("input", help="input APK (original, login-gated)")
    ap.add_argument("-o", "--output", help="output APK path")
    ap.add_argument("--skip-paid", action="store_true",
                    help="do not force the paid-mode flag (P4)")
    ap.add_argument("--verify", action="store_true",
                    help="verify an already-patched APK and exit")
    args = ap.parse_args()

    if args.verify:
        print(f"Verifying {args.input} ...")
        sys.exit(0 if verify_apk(args.input) else 1)

    if not args.output:
        ap.error("need -o/--output (or use --verify)")
    print(f"Reading {args.input} ...")
    dex = bytearray(zipfile.ZipFile(args.input).read("classes.dex"))
    if dex[:4] != b"dex\n":
        raise SystemExit("classes.dex has bad magic - not a DEX file?")
    print(f"  classes.dex: {len(dex)} bytes, "
          f"version {dex[4:8].decode('ascii', 'replace')}")
    print("Applying DEX patches ...")
    patch_dex(dex, skip_paid=args.skip_paid)
    print("Rebuilding + signing ...")
    rebuild_apk(args.input, bytes(dex), args.output)
    print("Done.")


if __name__ == "__main__":
    main()
