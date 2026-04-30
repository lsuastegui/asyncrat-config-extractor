#!/usr/bin/env python3
"""
AsyncRAT IoC Extractor
======================
Extracts and decrypts C2 configuration and indicators of compromise from
AsyncRAT .NET stub binaries.

Decryption scheme (reversed from decompiled source):
  - All config fields stored as AES-256-CBC + HMAC-SHA256 blobs, base64-encoded
  - Blob layout: HMAC[32 bytes] | IV[16 bytes] | Ciphertext
  - Key material: PBKDF2-HMAC-SHA1(masterkey_string, hardcoded_salt, 50000 iter) -> 96 bytes
      bytes[0:32]  = AES-256 key
      bytes[32:96] = HMAC-SHA256 key

Usage:
  python3 extract_asyncrat_iocs.py <sample.exe> [--out iocs.json]

Requirements:
  - ilspycmd  (apt install ilspycmd  /  dotnet tool install ilspycmd)
  - pycryptodome OR cryptography  (pip3 install pycryptodome)
  - strings (binutils)
"""

import sys
import os
import re
import json
import hmac as hmac_mod
import hashlib
import struct
import subprocess
import argparse
import base64
import ipaddress
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _import_aes():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        return AES, unpad, "pycryptodome"
    except ImportError:
        pass
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import unpad
        return AES, unpad, "cryptodome"
    except ImportError:
        pass
    return None, None, None


def derive_keys(master_key_str: str, salt: bytes) -> tuple:
    """Derive AES-256 key (32 bytes) and HMAC-SHA256 key (64 bytes) via PBKDF2."""
    key_material = hashlib.pbkdf2_hmac(
        "sha1",
        master_key_str.encode("utf-8"),
        salt,
        50000,
        dklen=96,
    )
    aes_key = key_material[:32]
    hmac_key = key_material[32:96]
    return aes_key, hmac_key


def decrypt_config_field(b64_value: str, aes_key: bytes, hmac_key: bytes) -> str | None:
    """
    Decrypt a single AsyncRAT config field.
    Blob = HMAC[32] | IV[16] | AES-CBC(PKCS7) ciphertext
    """
    AES, unpad, _ = _import_aes()
    if AES is None:
        return None

    try:
        raw = base64.b64decode(b64_value)
    except Exception:
        return None

    if len(raw) < 48:          # 32 HMAC + 16 IV minimum
        return None

    stored_hmac = raw[:32]
    payload = raw[32:]         # IV + ciphertext — this is what's MACed

    # Verify HMAC
    computed_hmac = hmac_mod.new(hmac_key, payload, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(stored_hmac, computed_hmac):
        return None            # MAC mismatch — wrong key or not a config field

    iv = payload[:16]
    ciphertext = payload[16:]

    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), 16)
        return plaintext.decode("utf-8")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Decompiler helpers
# ---------------------------------------------------------------------------

def run_ilspycmd(sample_path: str) -> str | None:
    """Decompile the .NET binary with ilspycmd and return the C# source."""
    print("[*] Decompiling with ilspycmd ...")
    try:
        result = subprocess.run(
            ["ilspycmd", sample_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
    except FileNotFoundError:
        print("    [!] ilspycmd not found — skipping decompilation-based extraction")
    except subprocess.TimeoutExpired:
        print("    [!] ilspycmd timed out")
    return None


def run_strings(sample_path: str) -> tuple[list[str], list[str]]:
    """Return (ascii_strings, unicode_strings) from the binary."""
    ascii_strs, uni_strs = [], []
    try:
        r = subprocess.run(["strings", sample_path], capture_output=True, text=True, timeout=30)
        ascii_strs = r.stdout.splitlines()
    except Exception:
        pass
    try:
        r = subprocess.run(["strings", "-el", sample_path], capture_output=True, text=True, timeout=30)
        uni_strs = r.stdout.splitlines()
    except Exception:
        pass
    return ascii_strs, uni_strs


# ---------------------------------------------------------------------------
# Parsing helpers for decompiled source
# ---------------------------------------------------------------------------

# Matches:  public static string SomeName = "base64value==";
_FIELD_RE = re.compile(
    r'public\s+static\s+string\s+(\w+)\s*=\s*"([A-Za-z0-9+/=]{20,})"',
)

# Matches the salt byte array:  new byte[32] { 191, 235, 30, ... }
_SALT_RE = re.compile(
    r'new\s+byte\s*\[\s*32\s*\]\s*\{([^}]+)\}',
    re.DOTALL,
)

# PBKDF2 call:  new Rfc2898DeriveBytes(varA, varB, 50000)
_PBKDF2_RE = re.compile(
    r'new\s+Rfc2898DeriveBytes\s*\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\d+)\s*\)'
)

# Master-key decode:  fieldName = Encoding.UTF8.GetString(Convert.FromBase64String(fieldName))
_MASTERKEY_DECODE_RE = re.compile(
    r'(\w+)\s*=\s*Encoding\.UTF8\.GetString\s*\(\s*Convert\.FromBase64String\s*\(\s*\1\s*\)\s*\)'
)

# Decrypt call:  someObj.UTzuwMCNWppD(fieldName)  — any method on IyJZlhxuAV
_DECRYPT_CALL_RE = re.compile(
    r'\w+\.\w+\(\s*(\w+)\s*\)'   # loose; we refine by cross-referencing
)

# Specifically the decrypt wrapper:  field = cryptoObj.SomeDecryptMethod(field)
_FIELD_DECRYPT_RE = re.compile(
    r'(\w+)\s*=\s*\w+\.\w+\(\s*\1\s*\)'
)


def extract_salt_from_source(source: str) -> bytes | None:
    """Find and parse the hardcoded PBKDF2 salt from decompiled C# source."""
    matches = _SALT_RE.findall(source)
    for m in matches:
        nums = re.findall(r'\d+', m)
        if len(nums) == 32:
            return bytes(int(n) for n in nums)
    return None


def extract_fields_from_source(source: str) -> dict[str, str]:
    """Return all static string fields and their values from decompiled source."""
    return {name: value for name, value in _FIELD_RE.findall(source)}


def find_master_key_field(source: str, fields: dict[str, str]) -> tuple[str, str] | None:
    """
    Identify the master key field by finding the pattern:
        fieldName = Encoding.UTF8.GetString(Convert.FromBase64String(fieldName))
    Returns (field_name, decoded_master_key_string) or None.
    """
    for m in _MASTERKEY_DECODE_RE.finditer(source):
        fname = m.group(1)
        if fname in fields:
            try:
                master_key = base64.b64decode(fields[fname]).decode("utf-8")
                return fname, master_key
            except Exception:
                pass
    return None


def find_encrypted_fields(source: str, fields: dict[str, str], master_key_field: str) -> list[str]:
    """
    Find all field names that are decrypted via the crypto object
    (pattern: fieldName = cryptoObj.Method(fieldName)).
    """
    encrypted_names = []
    for m in _FIELD_DECRYPT_RE.finditer(source):
        fname = m.group(1)
        if fname in fields and fname != master_key_field:
            encrypted_names.append(fname)
    return list(dict.fromkeys(encrypted_names))  # deduplicate, preserve order


# ---------------------------------------------------------------------------
# IoC labelling heuristics
# ---------------------------------------------------------------------------

def label_config_value(plaintext: str) -> str:
    """Guess the semantic label for a decrypted config value."""
    if not plaintext or plaintext == "null":
        return "null_field"
    # Large base64-only blobs are cert/signature data, not readable config
    if len(plaintext) > 100 and re.match(r'^[A-Za-z0-9+/]+=*$', plaintext):
        return "cert_or_sig_blob"
    # C2 hosts: comma-separated hostnames/IPs
    parts = [p.strip() for p in plaintext.split(",")]
    ip_count = sum(1 for p in parts if _is_ip(p))
    host_count = sum(1 for p in parts if "." in p)
    if len(parts) >= 2 and (ip_count + host_count) >= len(parts) - 1:
        return "c2_hosts"
    # C2 ports: comma-separated 4-digit numbers
    if all(p.isdigit() and 1 <= int(p) <= 65535 for p in parts):
        return "c2_ports"
    # Mutex
    if "mutex" in plaintext.lower() or re.match(r'[A-Za-z]+Mutex', plaintext):
        return "mutex"
    # Version
    if re.match(r'^\d+\.\d+', plaintext):
        return "version"
    # Boolean flags
    if plaintext.lower() in ("true", "false"):
        return "flag"
    # Delay (numeric)
    if plaintext.isdigit():
        return "delay_seconds"
    # URL / Pastebin fallback
    if plaintext.startswith("http") or "pastebin" in plaintext.lower():
        return "c2_url_fallback"
    # Group / campaign tag
    return "campaign_group"


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# String-based IoC extraction (no decompiler needed)
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:eu|com|net|org|io|info|biz|co|ydns|publicvm)\b',
    re.IGNORECASE,
)
_MUTEX_RE = re.compile(r'[A-Za-z]{3,}Mutex[_\-]?\w+')
_RAT_PORT_RE = re.compile(r'\b(6606|7707|8808|4782|6606|1604|8080|4444|1337)\b')
_REGISTRY_RE = re.compile(
    r'(?:HKEY_[A-Z_]+|HK[CLU][MU]?)\\[\\A-Za-z0-9_. ]+',
    re.IGNORECASE,
)
_B64_LIKELY_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')


def extract_iocs_from_strings(ascii_strs: list[str], uni_strs: list[str]) -> dict:
    """Regex-based IoC extraction from raw strings output."""
    all_strings = ascii_strs + uni_strs
    combined = "\n".join(all_strings)

    ips = sorted(set(_IP_RE.findall(combined)))
    # Filter out obvious false positives (version numbers, etc.)
    ips = [ip for ip in ips if not ip.startswith(("127.", "0.", "255."))]

    domains = sorted(set(_DOMAIN_RE.findall(combined)))
    domains = [d for d in domains if len(d) > 5]

    mutexes = sorted(set(_MUTEX_RE.findall(combined)))

    ports = sorted(set(_RAT_PORT_RE.findall(combined)))

    registry_keys = sorted(set(_REGISTRY_RE.findall(combined)))

    return {
        "ips": ips,
        "domains": domains,
        "mutexes": mutexes,
        "ports": ports,
        "registry_keys": registry_keys,
    }


# ---------------------------------------------------------------------------
# PE metadata via exiftool
# ---------------------------------------------------------------------------

def get_pe_metadata(sample_path: str) -> dict:
    meta = {}
    try:
        r = subprocess.run(
            ["exiftool", sample_path],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                meta[k.strip()] = v.strip()
    except Exception:
        pass
    return meta


def get_file_hashes(sample_path: str) -> dict:
    hashes = {}
    for algo in ("md5", "sha1", "sha256"):
        try:
            r = subprocess.run(
                [f"{algo}sum", sample_path],
                capture_output=True, text=True, timeout=10
            )
            hashes[algo] = r.stdout.split()[0]
        except Exception:
            pass
    return hashes


# ---------------------------------------------------------------------------
# Main extraction logic
# ---------------------------------------------------------------------------

# Hardcoded fallback salt (AsyncRAT 0.5.7B) — used if auto-detection fails
KNOWN_SALT = bytes([
    191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
    2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
    210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
    57, 65,
])

# Map of known AsyncRAT 0.5.7B field semantic labels (by position in config class)
# Used as fallback when heuristics are ambiguous
FIELD_ORDER_LABELS = [
    "c2_ports",
    "c2_hosts",
    "version",
    "install_flag",
    # master_key is separate
    "mutex",
    "cert_blob",      # large embedded X.509 cert — skip
    "rsa_signature",  # RSA sig blob — skip
    "anti_analysis_flag",
    # X509Certificate2 object — skip
    "c2_url_fallback",
    "critical_process_flag",
    # FuTiCNMtwMUvO = null (skip)
    # dyAJwyKpFn = "3" (plaintext)
    "campaign_group",
]


def extract_decrypted_config(source: str) -> dict:
    """
    Full config extraction pipeline from decompiled C# source:
    1. Find PBKDF2 salt
    2. Find master key field and decode it
    3. Derive AES + HMAC keys
    4. Find and decrypt all encrypted config fields
    5. Label each decrypted value
    """
    result = {}

    # 1. Find salt
    salt = extract_salt_from_source(source)
    if salt is None:
        print("    [!] Salt not found in source — using known AsyncRAT 0.5.7B salt")
        salt = KNOWN_SALT
    else:
        print(f"    [+] PBKDF2 salt found: {salt.hex()}")

    # 2. Find all static string fields
    fields = extract_fields_from_source(source)
    if not fields:
        print("    [!] No config fields found in decompiled source")
        return result
    print(f"    [+] Found {len(fields)} static string fields")

    # 3. Identify master key
    mk_info = find_master_key_field(source, fields)
    if mk_info is None:
        print("    [!] Master key field not auto-detected — trying known b64 value")
        # fallback: look for the known master key b64
        for fname, fval in fields.items():
            try:
                decoded = base64.b64decode(fval).decode("utf-8")
                if 20 <= len(decoded) <= 50 and decoded.isprintable():
                    mk_info = (fname, decoded)
                    break
            except Exception:
                pass

    if mk_info is None:
        print("    [!] Could not identify master key — cannot decrypt config")
        return result

    master_key_field, master_key = mk_info
    print(f"    [+] Master key field: {master_key_field}")
    print(f"    [+] Master key: {master_key}")
    result["master_key"] = master_key

    # 4. Derive crypto keys
    aes_key, hmac_key = derive_keys(master_key, salt)
    result["aes_key_hex"] = aes_key.hex()

    # 5. Find encrypted fields and decrypt
    enc_fields = find_encrypted_fields(source, fields, master_key_field)
    print(f"    [+] Found {len(enc_fields)} encrypted config fields")

    decrypted = {}
    for fname in enc_fields:
        b64val = fields[fname]
        plaintext = decrypt_config_field(b64val, aes_key, hmac_key)
        if plaintext is not None:
            label = label_config_value(plaintext)
            decrypted[fname] = {"value": plaintext, "label": label}
            print(f"    [+] {fname} ({label}): {plaintext!r}")
        else:
            # Could be cert blob or RSA signature — skip silently
            pass

    result["config_fields"] = decrypted
    return result


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def build_ioc_report(
    sample_path: str,
    hashes: dict,
    pe_meta: dict,
    string_iocs: dict,
    config: dict,
) -> dict:
    """Assemble the final structured IoC report."""

    # Merge C2 hosts from config + string extraction
    c2_hosts, c2_ports, mutex, version, group = [], [], None, None, None

    for fname, info in config.get("config_fields", {}).items():
        label = info["label"]
        val = info["value"]
        if label == "c2_hosts":
            c2_hosts = [h.strip() for h in val.split(",") if h.strip()]
        elif label == "c2_ports":
            c2_ports = [p.strip() for p in val.split(",") if p.strip()]
        elif label == "mutex":
            mutex = val
        elif label == "version":
            version = val
        elif label == "campaign_group" and group is None:
            group = val

    # Fall back to string-extracted values where config decryption didn't run
    if not c2_hosts:
        c2_hosts = string_iocs.get("domains", []) + [
            ip for ip in string_iocs.get("ips", [])
        ]
    if not c2_ports:
        c2_ports = string_iocs.get("ports", [])
    if not mutex:
        mutexes = string_iocs.get("mutexes", [])
        mutex = mutexes[0] if mutexes else None

    # Separate IPs from domains in the C2 host list
    c2_ips = [h for h in c2_hosts if _is_ip(h)]
    c2_domains = [h for h in c2_hosts if not _is_ip(h)]

    # Build per-host:port combinations
    c2_sockets = [
        f"{host}:{port}"
        for host in c2_hosts
        for port in c2_ports
    ] if c2_ports else c2_hosts

    return {
        "report_generated": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "path": os.path.abspath(sample_path),
            "filename": os.path.basename(sample_path),
            "sha256": hashes.get("sha256"),
            "sha1": hashes.get("sha1"),
            "md5": hashes.get("md5"),
            "size_bytes": os.path.getsize(sample_path),
            "compile_time": pe_meta.get("Time Stamp"),
            "original_name": pe_meta.get("Original File Name") or pe_meta.get("Internal Name"),
            "file_type": pe_meta.get("File Type"),
            "framework": ".NET (Mono/.NET assembly)",
        },
        "classification": {
            "family": "AsyncRAT",
            "version": version,
            "confidence": "high",
        },
        "network_iocs": {
            "c2_hosts": c2_hosts,
            "c2_ips": c2_ips,
            "c2_domains": c2_domains,
            "c2_ports": c2_ports,
            "c2_sockets": c2_sockets,
        },
        "host_iocs": {
            "mutex": mutex,
            "registry_keys": string_iocs.get("registry_keys", []),
            "install_path": "%AppData%",
            "scheduled_task": "schtasks /create /f /sc onlogon /rl highest",
        },
        "config": {
            "master_key": config.get("master_key"),
            "aes_key_hex": config.get("aes_key_hex"),
            "campaign_group": group,
            "raw_fields": {
                fname: info["value"]
                for fname, info in config.get("config_fields", {}).items()
                if info["label"] not in ("cert_blob", "rsa_signature", "cert_or_sig_blob")
            },
        },
    }


def print_human_report(report: dict) -> None:
    """Print a human-readable summary to stdout."""
    sep = "=" * 60
    print(f"\n{sep}")
    print("  AsyncRAT IoC Extraction Report")
    print(sep)

    s = report["sample"]
    print(f"\n[SAMPLE]")
    print(f"  File      : {s['filename']}")
    print(f"  SHA256    : {s['sha256']}")
    print(f"  SHA1      : {s['sha1']}")
    print(f"  MD5       : {s['md5']}")
    print(f"  Size      : {s['size_bytes']} bytes")
    print(f"  Compiled  : {s['compile_time']}")
    print(f"  Orig name : {s['original_name']}")

    c = report["classification"]
    print(f"\n[CLASSIFICATION]")
    print(f"  Family    : {c['family']}")
    print(f"  Version   : {c['version']}")
    print(f"  Confidence: {c['confidence']}")

    n = report["network_iocs"]
    print(f"\n[NETWORK IOCs]")
    print(f"  C2 Domains : {', '.join(n['c2_domains']) or 'none'}")
    print(f"  C2 IPs     : {', '.join(n['c2_ips']) or 'none'}")
    print(f"  C2 Ports   : {', '.join(n['c2_ports']) or 'none'}")
    print(f"  C2 Sockets :")
    for sock in n["c2_sockets"]:
        print(f"    - {sock}")

    h = report["host_iocs"]
    print(f"\n[HOST IOCs]")
    print(f"  Mutex         : {h['mutex']}")
    print(f"  Install path  : {h['install_path']}")
    if h["registry_keys"]:
        print(f"  Registry keys :")
        for rk in h["registry_keys"]:
            print(f"    - {rk}")

    cfg = report["config"]
    print(f"\n[CONFIG]")
    print(f"  Master key     : {cfg['master_key']}")
    print(f"  AES key (hex)  : {cfg['aes_key_hex']}")
    print(f"  Campaign group : {cfg['campaign_group']}")
    if cfg["raw_fields"]:
        print(f"  Decrypted fields:")
        for k, v in cfg["raw_fields"].items():
            print(f"    {k}: {v!r}")

    print(f"\n{sep}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract IoCs from AsyncRAT .NET binary samples"
    )
    parser.add_argument("sample", help="Path to the .exe sample")
    parser.add_argument(
        "--out", "-o",
        default=None,
        help="Write JSON report to this file (default: <sample_sha256>_iocs.json)",
    )
    parser.add_argument(
        "--no-decompile",
        action="store_true",
        help="Skip ilspycmd decompilation (string extraction only)",
    )
    args = parser.parse_args()

    sample_path = args.sample
    if not os.path.isfile(sample_path):
        print(f"[!] File not found: {sample_path}")
        sys.exit(1)

    AES, _, lib = _import_aes()
    if AES is None:
        print("[!] No AES library found — install pycryptodome:  pip3 install pycryptodome")
        print("    Config decryption will be skipped.")

    print(f"[*] Sample: {sample_path}")

    # Collect metadata
    print("[*] Computing hashes ...")
    hashes = get_file_hashes(sample_path)
    print(f"    SHA256: {hashes.get('sha256')}")

    print("[*] Reading PE metadata ...")
    pe_meta = get_pe_metadata(sample_path)

    # String extraction
    print("[*] Extracting strings ...")
    ascii_strs, uni_strs = run_strings(sample_path)
    string_iocs = extract_iocs_from_strings(ascii_strs, uni_strs)
    print(f"    IPs found       : {string_iocs['ips']}")
    print(f"    Domains found   : {string_iocs['domains']}")
    print(f"    Mutexes found   : {string_iocs['mutexes']}")
    print(f"    Ports found     : {string_iocs['ports']}")

    # Decompilation-based config extraction
    config = {}
    if not args.no_decompile and AES is not None:
        source = run_ilspycmd(sample_path)
        if source:
            print("[*] Extracting and decrypting config ...")
            config = extract_decrypted_config(source)
        else:
            print("[!] Decompilation failed — falling back to string extraction only")
    else:
        print("[*] Skipping decompilation (--no-decompile or no AES library)")

    # Build and display report
    report = build_ioc_report(sample_path, hashes, pe_meta, string_iocs, config)
    print_human_report(report)

    # Write JSON
    out_path = args.out
    if out_path is None:
        sha = hashes.get("sha256", "unknown")[:16]
        out_path = os.path.join(
            os.path.dirname(os.path.abspath(sample_path)),
            f"{sha}_iocs.json",
        )
        # If running from output dir, place report there instead
        script_dir = os.path.dirname(os.path.abspath(__file__))
        out_path = os.path.join(script_dir, f"{sha}_iocs.json")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON report written to: {out_path}")


if __name__ == "__main__":
    main()
