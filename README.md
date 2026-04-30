# asyncrat-config-extractor

Static AsyncRAT configuration extractor for recovering C2 indicators, ports, mutex values, and campaign metadata from compatible AsyncRAT samples.


## Overview

This repository provides:

- YARA rules to validate AsyncRAT samples and confirm compatibility
- A Python script to decrypt and extract embedded configuration (C2, ports, etc.)

The extractor only works on specific AsyncRAT versions/config formats, so validation is critical.


## Requirements

| Tool | Purpose |
|---|---|
| yara | Validate sample |
| ilspycmd | Decompile .NET binary |
| strings | Extract raw strings |
| exiftool | Extract PE metadata |
| pycryptodome | AES decryption |

Install dependency:

`pip3 install pycryptodome`



## Step 1 — Validate the Sample with YARA

`yara asyncrat_extractor_compatible.yara sample.exe`

### Output Meaning

- AsyncRAT_v057B_ScriptCompatible → Compatible → Run script
- AsyncRAT_Generic → Likely incompatible → Do NOT run
- No match → Not AsyncRAT → Do NOT run


## Step 2 — Run the Extractor

`python3 extract_asyncrat_iocs.py sample.exe`



## Notes

- Script is version-dependent (requires correct PBKDF2 salt)
- Static analysis only
- May fail on packed or obfuscated samples
- Always validate IoCs before use

