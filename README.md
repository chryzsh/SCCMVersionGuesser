# SCCMVersionGuesser

Automated SCCM build and patch level detection tool

## Requirements
- requests

## Usage

```sh
$ python3 SCCMVersionGuesser.py http://sccm.example.com
```

## Example output

The tool extracts the client version from `ccmsetup.exe`, identifies the release by build number, and lists the hotfix stack with the CVEs each update addresses.

A host on the current release. None of the 2603 hotfixes rebuild `ccmsetup.exe`, so every update shares the base client version and shows as current:

```
$ python3 SCCMVersionGuesser.py http://sccm.example.com
[+] Extracted Client Version: 5.00.9146.1000

[!] MATCHED BUILD: 9146 (SCCM 2603)
Status      | KB / Update  | Client Version | Full Version   | Security Info
-------------------------------------------------------------------------------------
[CURRENT*]  | Base         | 5.00.9146.1000 | 5.00.9146.1000 | -
[CURRENT*]  | KB38232642   | 5.00.9146.1000 | 5.00.9146.1021 | CVE-2026-47301 (AdminService EoP)
[CURRENT*]  | KB38982839   | 5.00.9146.1000 | 5.00.9146.1026 | CVE-2026-26128 (SMS Provider EoP)
[CURRENT*]  | KB39398030   | 5.00.9146.1000 | 5.00.9146.1027 | CVE-2026-47301 (AdminService EoP), CVE-2026-26128 (SMS Provider EoP)

*Note: [INSTALLED]/[MISSING] compare the detected ccmsetup build as a floor.
	Updates sharing a client version can't be distinguished by ccmsetup.exe alone.
```

A host that is behind. The detected ccmsetup revision (`.1007`) is not one of the listed hotfix versions, so the release is identified by build number and patch status is reported as a floor. Missing updates and the CVEs they fix are listed:

```
$ python3 SCCMVersionGuesser.py http://sccm.example.com
[+] Extracted Client Version: 5.00.9128.1007

[!] MATCHED BUILD: 9128 (SCCM 2403)
[~] ccmsetup build 5.00.9128.1007 sits between listed updates; hotfix status is a floor (ccmsetup.exe lags the site build).
Status      | KB / Update  | Client Version | Full Version   | Security Info
-------------------------------------------------------------------------------------
[INSTALLED] | Base         | 5.00.9128.1005 | 5.00.9128.1000 | -
[INSTALLED] | KB28290310   | 5.00.9128.1005 | 5.00.9128.1012 | -
[MISSING]   | KB28458746   | 5.00.9128.1014 | 5.00.9128.1014 | -
[MISSING]   | KB29166583   | 5.00.9128.1014 | 5.00.9128.1024 | CVE-2024-43468 (Unauth SQLi)
[MISSING]   | KB28204160   | 5.00.9128.1030 | 5.00.9128.1030 | -
[MISSING]   | KB33177653   | 5.00.9128.1033 | 5.00.9128.1033 | -
[MISSING]   | KB33926600   | 5.00.9128.1033 | 5.00.9128.1034 | CVE-2025-47178 (Auth SQLi)
[MISSING]   | KB34503768   | 5.00.9128.1033 | 5.00.9128.1035 | CVE-2025-59213 (Unauth SQLi), CVE-2025-55320 (Auth SQLi)
[MISSING]   | KB35360093   | 5.00.9128.1033 | 5.00.9128.1037 | CVE-2025-59501 (Auth Bypass)
```

Only HTTP is supported; the tool rejects HTTPS URLs.

## Reference
- https://learn.microsoft.com/en-us/intune/configmgr/hotfix/
- https://github.com/MicrosoftDocs/memdocs/tree/main/intune/configmgr/hotfix