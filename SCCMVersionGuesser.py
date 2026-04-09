import requests
import re
import sys

# Mapping CVE -> List of KBs that fix it
CVE_MAP = {
    "CVE-2025-59501 (Auth Bypass)": ["KB35360093", "KB32851084"], # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-59501
    "CVE-2025-59213 (Unauth SQLi)": ["KB34503790", "KB34503768"], # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59213
    "CVE-2025-55320 (Auth SQLi)": ["KB34503790", "KB34503768"], # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-55320
    "CVE-2025-47178 (Auth SQLi)": ["KB31909343", "KB33926600", "KB32480179"], # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-47178
    "CVE-2024-43468 (Unauth SQLi)": ["KB29166583"], # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-43468
}

# Structure: "BuildNumber": { "BaseName": "...", "Updates": [ (ClientVer, KB, Name), ... ] }
# Sorted by release order (ascending) within each build
# Structure: (ClientVer, KB, Name, FullVersionNumber)
# https://aka.ms/KB<...>_FileList
# https://aka.ms/KB<...>_FileList_2509
# https://aka.ms/KB<...>_2509_FileList
# Source: https://github.com/MicrosoftDocs/memdocs/tree/main/intune/configmgr/hotfix
BUILD_MAP = {
    "9141": {
        "BaseName": "SCCM 2509",
        "Stack": [
            ("5.00.9141.1000", "Base", "SCCM 2509 Release", "5.00.9141.1000"),
            ("5.00.9141.1015", "KB36495448", "Update", "5.00.9141.1015"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2509/KB36495448_9141.1015/KB36495448_FileList.txt
            ("5.00.9141.1015", "KB36419072", "Update", "5.00.9141.1017"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2509/KB36419072_9141.1017/KB36419072_FileList.txt
        ]
    },
    "9135": {
        "BaseName": "SCCM 2503",
        "Stack": [
            ("5.00.9135.1001", "Base", "SCCM 2503 Release", "5.00.9135.1000"),
            ("5.00.9135.1001", "KB31909343", "Hotfix for 2503", "5.00.9135.1001"), # ??
            ("5.00.9135.1001", "KB32480179", "Hotfix for 2503", "5.00.9135.1003"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB32480179_9135.1003/UploadContent/KB32480179_FileList.txt
            ("5.00.9135.1006", "KB33177653", "Update for 2503", "5.00.9135.1006"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB33177653_9135.1006/KB33177653_FileList.txt
            ("5.00.9135.1006", "KB34503790", "Hotfix for 2503", "5.00.9135.1008"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB34503790_9135.1008/KB34503790_FileList.txt
            ("5.00.9135.1013", "KB32851084", "Hotfix for 2503", "5.00.9135.1013"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB32851084_9135.1013/KB32851084_FileList.txt
            ("5.00.9135.1013", "KB35958849", "Hotfix for 2503", "5.00.9135.1014"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB35958849_9135.1014/KB35958849_FileList.txt
            ("5.00.9135.1017", "KB36495448", "Hotfix for 2503", "5.00.9135.1017"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB36495448_9135.1017/KB36495448_FileList.txt
            ("5.00.9132.1017", "KB36419072", "Hotfix for 2503", "5.00.9135.1019"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2503/KB36419072_9135.1019/KB36419072_FileList.txt
        ]
    },
    "9132": {
        "BaseName": "SCCM 2409",
        "Stack": [
            ("5.00.9132.1011", "Base", "SCCM 2409 Release", "5.00.9132.1000"),
            ("5.00.9132.1013", "KB30833053", "Hotfix KB30833053", "5.00.9132.1013"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB30833053_9132.1013/UploadContent/KB30833053_FileList.txt
            ("5.00.9132.1023", "KB30385346", "Hotfix Rollup KB30385346", "5.00.9132.1023"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB30385346_9132.1023/UploadContent/KB30385346_FileList.txt
            ("5.00.9132.1027", "KB33177653", "Hotfix Rollup KB33177653", "5.00.9132.1027"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB33177653_9132.1027/KB33177653_FileList.txt
            ("5.00.9132.1027", "KB33926600", "Hotfix Rollup KB33926600", "5.00.9132.1028"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB33926600_9132.1028/KB33926600_FileList.txt
            ("5.00.9132.1027", "KB34503768", "Hotfix Rollup KB34503768", "5.00.9132.1029"), # KB34503790 ? https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB34503768_9132.1029/KB34503768_FileList.txt
            ("5.00.9132.1027", "KB35360093", "Hotfix Rollup KB35360093", "5.00.9132.1031"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB35360093_9132.1031/KB35360093_FileList.txt
            ("5.00.9132.1027", "KB35958849", "Hotfix Rollup KB35958849", "5.00.9132.1032"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB35958849_9132.1032/KB35958849_FileList.txt
            ("5.00.9132.1027", "KB36419072", "Hotfix Rollup KB36419072", "5.00.9132.1034"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2409/KB36419072_9132.1034/KB36419072_FileList.txt

        ]
    },
    "9128": {
        "BaseName": "SCCM 2403",
        "Stack": [
            ("5.00.9128.1005", "Base", "SCCM 2403 Release", "5.00.9128.1000"),
            ("5.00.9128.1005", "KB28290310", "Hotfix KB28290310", "5.00.9128.1012"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB28290310_9128.1012/UploadContent/KB28290310_FileList.txt
            ("5.00.9128.1014", "KB28458746", "Hotfix KB28458746", "5.00.9128.1014"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB28458746_9128.1014/UploadContent/KB28458746_FileList.txt
            ("5.00.9128.1014", "KB29166583", "Hotfix KB29166583", "5.00.9128.1024"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB29166583_9128.1024/UploadContent/KB29166583_FileList.txt
            ("5.00.9128.1030", "KB28204160", "Rollup KB28204160", "5.00.9128.1030"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB28204160_9128.1030/UploadContent/KB28204160_FileList.txt
            ("5.00.9128.1033", "KB33177653", "Hotfix KB33177653", "5.00.9128.1033"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB33177653_9128.1033/KB33177653_FileList.txt
            ("5.00.9128.1033", "KB33926600", "Hotfix KB33926600", "5.00.9128.1034"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB33926600_9128.1034/KB33926600_FileList.txt
            ("5.00.9128.1033", "KB34503768", "Hotfix KB34503768", "5.00.9128.1035"), # KB34503790 ? # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB34503768_9128.1035/KB34503768_FileList.txt
            ("5.00.9128.1033", "KB35360093", "Hotfix KB35360093", "5.00.9128.1037"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2403/KB35360093_9128.1037/KB35360093_FileList.txt
        ]
    },
    "9122": {
        "BaseName": "SCCM 2309",
        "Stack": [
            ("5.00.9122.1002", "Base", "SCCM 2309 Release", "5.00.9122.1000"),
            ("5.00.9122.1007", "KB26129847", "Hotfix KB26129847", "5.00.9122.1007"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2309/KB26129847_9122.1007/KB26129847_FileList.txt
            ("5.00.9122.1018", "KB25858444", "Original Hotfix KB25858444", "5.00.9122.1018"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2309/KB25858444_9122.1018/KB25858444_FileList.txt
            ("5.00.9122.1019", "KB27863823", "Revised Hotfix KB27863823", "5.00.9122.1019"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2309/KB27863823_9122.1019/UploadContent/KB27863823_FileList.txt
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9122.1033"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2309/KB29166583_9122.1033/UploadContent/KB29166583_FileList.txt
        ]
    },
    "9106": {
        "BaseName": "SCCM 2303",
        "Stack": [
            ("5.00.9106.1000", "Base", "SCCM 2303 Release", "5.00.9106.1000"),
            ("5.00.9106.1015", "KB21010486", "Original release", "5.00.9106.1015"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2303/KB21010486_9106.1015/KB21010486_FileList.txt
            ("5.00.9106.1015", "KB24721208", "Hotfix KB24721208", "5.00.9106.1018"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2303/KB24721208_9106.1018/KB24721208_FileList.txt
            ("5.00.9106.1022", "KB24719670", "Revised release", "5.00.9106.1022"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2303/KB24719670_9106.1022/KB24719670_FileList.txt
            ("5.00.9106.1027", "KB25073607", "Hotfix", "5.00.9106.1027"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2303/KB25073607_9106.1027/KB25073607_FileList.txt
            ("5.00.9122.1019", "KB29166583", "MP Hotfix", "5.00.9106.1037"), # https://configmgrbits.cdn.manage.microsoft.com/qfe/2303/KB29166583_9106.1037/UploadContent/KB29166583_FileList.txt
            
        ]
    },
    "9096": {
        "BaseName": "SCCM 2211",
        "Stack": [
            ("5.00.9096.1000", "Base", "SCCM 2211 Release", "5.00.9096.1000"),
            ("5.00.9096.1024", "KB16643863", "Hotfix KB16643863", "5.00.9096.1000"),
        ]
    },
    "9088": {
        "BaseName": "SCCM 2207",
        "Stack": [
            ("5.00.9088.1007", "Base", "SCCM 2207 Release", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB14978429", "Hotfix KB14978429", "5.00.9088.1000"),
            ("5.00.9088.1007", "KB15498768", "Hotfix KB15498768", "5.00.9088.1012"),
            ("5.00.9088.1007", "KB15599094", "Hotfix KB15599094", "5.00.9088.1013"),
            ("5.00.9088.1010", "KB14959905", "Hotfix KB14959905", "5.00.9088.1010"),
            ("5.00.9088.1025", "KB15152495", "Hotfix KB15152495", "5.00.9088.1025"),
        ]
    },
    "9078": {
        "BaseName": "SCCM 2203",
        "Stack": [
            ("5.00.9078.1006", "Base", "SCCM 2203 Release", "5.00.9078.1000"),
            ("5.00.9078.1006", "KB13953025", "Hotfix KB13953025", "5.00.9078.1007"),
            ("5.00.9078.1006", "KB14480034", "Hotfix KB14480034", "5.00.9078.1007"),
            ("5.00.9078.1025", "KB14244456", "Hotfix KB14244456", "5.00.9078.1025"),
        ]
    },
    "9068": {
        "BaseName": "SCCM 2111",
        "Stack": [
            ("5.00.9068.1005", "Base", "SCCM 2111 Release", "5.00.9068.1000"),
            ("5.00.9068.1008", "KB12709700", "Hotfix KB12709700", "5.00.9068.1000"),
            ("5.00.9068.1012", "KB12959506", "Hotfix KB12959506", "5.00.9068.1000"),
            ("5.00.9068.1026", "KB12896009", "Hotfix KB12896009", "5.00.9068.1000"),
        ]
    },
}

def get_cves_for_kb(kb_id):
    addressed_cves = [cve for cve, kbs in CVE_MAP.items() if kb_id in kbs]
    return ", ".join(addressed_cves) if addressed_cves else "-"

def audit_build(detected_ver):
    RED = "\033[31m"
    ORANGE = "\033[33m" 
    GREEN = "\033[32m"
    RESET = "\033[0m"
    # Find which build this version belongs to
    target_build = None
    for b_id, data in BUILD_MAP.items():
        if any(detected_ver in item[0] for item in data["Stack"]):
            target_build = b_id
            break
    
    if not target_build:
        print(f"[-] Version {detected_ver} not found in build database.")
        return

    data = BUILD_MAP[target_build]
    print(f"\n[!] MATCHED BUILD: {target_build} ({data['BaseName']})")
    print(f"{'Status':<11} | {'KB / Update':<12} | {'Client Version':<14} | {'Full Version':<14} | {'Security Info'}")
    print("-" * 85)

    found_current = False
    for client_v, kb, name, full_v in data["Stack"]:
        cve_list = get_cves_for_kb(kb)
        
        is_match = (detected_ver == client_v or detected_ver.replace(".00.", ".0.") == client_v.replace(".00.", ".0."))

        if is_match:
            status = f"{ORANGE}[CURRENT*]{RESET}"
            found_current = True
        elif not found_current:
            status = f"{GREEN}[INSTALLED]{RESET}"
        else:
            status = f"{RED}[MISSING]{RESET}"

        print(f"{status:<20} | {kb:<12} | {client_v:<14} | {full_v:<14} | {cve_list}")

    print("\n*Note: If multiple updates are marked as current, it is because they share")
    print("\tthe same client version and cannot be distinguished using ccmsetup.exe alone.")

def fingerprint_sccm(url):
    if url.lower().startswith("https"):
        print("[-] Error: HTTPS is not possible for the moment.")
        return

    full_url = f"{url.rstrip('/')}/CCM_CLIENT/ccmsetup.exe"
    try:
        r = requests.get(full_url, headers={'Range': 'bytes=5000000-'}, timeout=10)
        pattern = rb'5\x00\.\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00\.\x00\d\x00\d\x00\d\x00\d\x00'
        matches = re.findall(pattern, r.content)
        
        if matches:
            detected = matches[0].decode('utf-16le')
            print(f"[+] Extracted Client Version: {detected}")
            audit_build(detected)
        else:
            print("[-] No SCCM string found.")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        fingerprint_sccm(sys.argv[1])
    else:
        print("Usage: python script.py http://<target>")