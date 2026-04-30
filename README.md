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

## Example Output

```
[+] JSON report written to: /home/remnux/analysis/asyncrat_collection/115f7c92978a13e1_iocs.json
[*] Sample: 14197e339d1b93bd5ea72eab1557e8fec14ddd84fe562739e59383058d2199ce
[*] Computing hashes ...
    SHA256: 14197e339d1b93bd5ea72eab1557e8fec14ddd84fe562739e59383058d2199ce
[*] Reading PE metadata ...
[*] Extracting strings ...
    IPs found       : ['1.0.0.0']
    Domains found   : ['System.IO', 'System.Net', 'schemas.microsoft.com']
    Mutexes found   : []
    Ports found     : []
[*] Decompiling with ilspycmd ...
[*] Extracting and decrypting config ...
    [+] PBKDF2 salt found: bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941
    [+] Found 12 static string fields
    [+] Master key field: Key
    [+] Master key: VheBh9hz0H366jRIu4HY8MiEvk3MpXrD
    [+] Found 10 encrypted config fields
    [+] Ports (c2_ports): '443'
    [+] Hosts (c2_hosts): 'agaoutofoffice.com,www.agaoutofoffice.com'
    [+] Version (version): '0.5.8'
    [+] Install (flag): 'true'
    [+] MTX (campaign_group): '3z1aHdhqQhMQ'
    [+] Pastebin (null_field): 'null'
    [+] Anti (flag): 'false'
    [+] BDOS (flag): 'false'
    [+] Group (campaign_group): 'Default'
    [+] Serversignature (cert_or_sig_blob): 'QILQGI79MKiTftj1R9DT2975Ll7ohlAFvtZpaP/T/mCHnDWymenyOHiQ7BVHI+gzG20x8dhEBI4rSsrZbhcGbKwGQ80GNm+YkPTm/hf/uiFMBRwwHvnhQdLdJuuMPEbn/RycUf9uZUGng1bFWQ1/xlxV4Bo5LC9uegARSThXFKguNCLbAHKAirMiZO4+MhN6b+6ptQbuvjdPu33JFRP8ZrpwL0SxLnzEbxmpCm3XIvfS5JlW6Rqu8R9eA6Q6+zui8uq/XWfRUZyvygQUHp4Fn+FEMOYpRiSGOKcPz03ROUl2ffCEPDhrF2jce8WmyhaRMD8uur3bHJe/8ndDkl+a3YPYze9ihRRVpdBTuvlm4c+5xqpRxZI9/o298MCX/UiPdILtNVSABZ+moZ0dPwgVwwV4cgjprg+tYZextaUv04gTtZkGcMmwNbJCh0vDom97i8rtJv/hMTsTn6yASQg9byhwZIddwa+El00mRrEM7JuuHNihdX5PRLEVB2Kvq6B+FT5gHn3ZVHBy134b77nYVe45AQRH+Y/TuEkrcgYiy9bjt+CBvbNhMeuueoI1X7nY+UBZ6cHbfK2xSorvl/ojCEpur+jdvSa2vU1SciE8CdG1OstFo0n+RN7pgBjTpHNSC7EgEKRgvAnZBM46KeAPXDVpVEOOhCWrqweMbWO0Vhg='

============================================================
  AsyncRAT IoC Extraction Report
============================================================

[SAMPLE]
  File      : 14197e339d1b93bd5ea72eab1557e8fec14ddd84fe562739e59383058d2199ce
  SHA256    : 14197e339d1b93bd5ea72eab1557e8fec14ddd84fe562739e59383058d2199ce
  SHA1      : 569d711e833a3e638c402a6dfbf071c42a61078b
  MD5       : 93151a1bdf42febbaf8e8319d7dc2947
  Size      : 46080 bytes
  Compiled  : 2023:10:16 21:40:53+00:00
  Orig name : Stub.exe

[CLASSIFICATION]
  Family    : AsyncRAT
  Version   : 0.5.8
  Confidence: high

[NETWORK IOCs]
  C2 Domains : agaoutofoffice.com, www.agaoutofoffice.com
  C2 IPs     : none
  C2 Ports   : 443
  C2 Sockets :
    - agaoutofoffice.com:443
    - www.agaoutofoffice.com:443

[HOST IOCs]
  Mutex         : None
  Install path  : %AppData%

[CONFIG]
  Master key     : VheBh9hz0H366jRIu4HY8MiEvk3MpXrD
  AES key (hex)  : 945c86da5750af58edfb98bb32180a1be10cd628c7e15fa696f72284bbe23725
  Campaign group : 3z1aHdhqQhMQ
  Decrypted fields:
    Ports: '443'
    Hosts: 'agaoutofoffice.com,www.agaoutofoffice.com'
    Version: '0.5.8'
    Install: 'true'
    MTX: '3z1aHdhqQhMQ'
    Pastebin: 'null'
    Anti: 'false'
    BDOS: 'false'
    Group: 'Default'

```


## Notes

- Script is version-dependent (requires correct PBKDF2 salt)
- Static analysis only
- May fail on packed or obfuscated samples
- Always validate IoCs before use

