"""Batch-author primary-source + attribution-sentence on every
walkthrough step across scenarios/. One-shot tool."""
import os, re, sys, yaml
sys.stdout.reconfigure(encoding='utf-8')

SENTENCE_LIB = {
    "LogonSessionId": ("ms-event-4624",
        "Event 4624 records a successful account logon and emits TargetLogonId, a hex LUID that uniquely identifies the session until the matching 4634 logoff closes it, threading every in-session event through a single session scope (Microsoft, n.d.)."),
    "MFTEntryReference": ("ms-ntfs-on-disk-format-secure-system-f",
        "Every NTFS file is uniquely addressed by a file reference combining a 48-bit MFT record number and a 16-bit sequence number, and the USN Journal and $LogFile record every lifecycle change keyed on this reference (Microsoft, 2025)."),
    "UserSID": ("ms-event-4624",
        "Event 4624 records TargetUserSid alongside TargetDomainName and TargetUserName; the SID is the persistent machine-unique account identifier that threads session events to ProfileList, SAM, and NTDS-dit records for the same account (Microsoft, n.d.)."),
    "ProcessId": ("ms-event-4688",
        "Event 4688 records every successful process creation with NewProcessId (a system-wide unique PID for the lifetime of the process) and SubjectLogonId, threading the process back to a specific user session (Microsoft, n.d.)."),
    "HandleId": ("ms-advanced-audit-policy",
        "Windows Advanced Audit Policy object-access events record HandleId, a per-process handle identifier that correlates matching 4656 (open), 4663 (access), and 4658 (close) events to bracket the object's handle-lifetime within a process (Microsoft, n.d.)."),
    "DeviceSerial": ("aboutdfir-nd-usb-devices-windows-artifact-r",
        "USBSTOR contains an entry for every USB device connected to the system keyed on the device's instance ID (which includes the vendor-assigned serial number), threading device identity across MountedDevices, EMDMgmt, WindowsPortableDevices, and PartitionDiagnostic-1006 (AboutDFIR, n.d.)."),
    "ExecutablePath": ("ms-event-4688",
        "Event 4688 records every successful process creation with NewProcessName (full executable path) and SubjectLogonId, chaining a program launch to both a specific account and a specific session (Microsoft, n.d.)."),
    "ExecutableHash": ("mitre-t1574",
        "Amcache-InventoryApplicationFile records the SHA-1 hash of every executable that has run on the host under the InventoryApplicationFile subkey; BAM and 4688 events citing the same executable path cross-verify the hash-to-path binding (MITRE ATT&CK, n.d.)."),
    "VolumeGUID": ("ms-shllink",
        "A Shell Link (.LNK) file's LinkTargetIDList carries a VolumeID shell item encoding the volume's drive-type, serial number, and label, preserving volume-identity-to-file binding across sessions (Microsoft, 2024)."),
    "AppID": ("mitre-t1204",
        "Windows AppIDs uniquely identify installed applications; Jump List entries, BAM records, and UserAssist are all keyed by AppID, enabling per-application execution evidence to be aggregated across artifacts (MITRE ATT&CK, n.d.)."),
    "URL": ("ms-background-intelligent-transfer-ser",
        "The Background Intelligent Transfer Service records each queued URL in qmgr.db, preserving the attacker-chosen endpoint as evidence even after the downloaded file is cleaned from the filesystem (Microsoft, 2022)."),
    "FilesystemVolumeSerial": ("ms-shllink",
        "A Shell Link (.LNK) file's VolumeID shell item encodes the Volume Serial Number read from the VBR (NTFS offset 0x43, FAT32 offset 0x27), binding the referenced file to the specific filesystem instance it was opened from (Microsoft, 2024)."),
    "PIDL": ("libyal-libfwsi",
        "Windows Shell Items (PIDL segments) encode every step of a navigation path with ItemType, typed data, and a FILETIME; ShellBags persist these sequences keyed by folder so shell navigation history can be reconstructed (Metz, 2021)."),
    "TaskName": ("ms-task-scheduler-1-0-legacy-format-re",
        "Each scheduled task registered with Task Scheduler 2.0 is stored as an XML file under %WINDIR%\\System32\\Tasks\\ with a canonical path that is the TaskName, and Task Scheduler events 106 / 140 / 141 cite that same TaskName at register, update, and delete (Microsoft, n.d.)."),
    "MachineNetBIOS": ("ms-event-4624",
        "Event 4624 records WorkstationName (the NetBIOS name of the originating host) for network logons, threading remote authentication events back to the specific source workstation (Microsoft, n.d.)."),
    "FirewallRuleName": ("mitre-t1562-004",
        "Adversaries may disable or modify system firewalls to bypass controls limiting network usage; Windows Firewall audit events cite the FirewallRuleName, making rule-level modifications individually attributable (MITRE ATT&CK, n.d.)."),
    "IPAddress": ("ms-event-5156",
        "Windows Filtering Platform event 5156 records a permitted connection with SourceAddress, SourcePort, DestAddress, DestPort, and ProcessId, providing per-connection attribution keyed on IPAddress pairs (Microsoft, n.d.)."),
    "MBRDiskSignature": ("hale-2018-partition-diagnostic-p1",
        "PartitionDiagnostic event 1006 captures the full partition-table byte layout at connection time, including the MBR DiskSignature and GPT partition GUIDs, establishing the device-to-volume binding authoritatively at the moment of connection (Hale, 2018)."),
}

OVERRIDES = {
    ("usb-convergence-chain.md", 2): ("hedley-2024-usbstor-install-first-install",
        "USBSTOR Properties 0064 and 0065 record install and first-install timestamps, but driver uninstall plus reinstall of the same vendor-product-serial combination overwrites these on-disk values; UserPnp event 20001 fires exactly once per first-install and is therefore the canonical first-connection source when available (Hedley, 2024)."),
    ("usb-convergence-chain.md", 10): ("casey-2002-error-uncertainty-loss-digital-evidence",
        "Digital evidence can at most attribute activity to an account; converting account-level attribution to person-level attribution requires evidence from outside the digital domain (physical access logs, video, biometrics, admissions), a boundary that cannot be closed by additional digital corroboration (Casey, 2002)."),
}

root = r'C:\Users\mondr\Documents\ProgFor\DFIRCLI\scenarios'
total_written = 0
for fn in sorted(os.listdir(root)):
    if not fn.endswith('.md'): continue
    fp = os.path.join(root, fn)
    with open(fp,'r',encoding='utf-8') as f: txt = f.read()
    m = re.match(r'^---\n(.*?)\n---\n', txt, re.DOTALL)
    if not m: continue
    try: fm = yaml.safe_load(m.group(1))
    except: continue
    steps = fm.get('steps') or []
    if not steps: continue
    for s in steps:
        if s.get('primary-source') and s.get('attribution-sentence'):
            continue
        n = s.get('n')
        jk = s.get('join-key') or {}
        concept = jk.get('concept')
        ps_sent = OVERRIDES.get((fn, n)) or SENTENCE_LIB.get(concept)
        if not ps_sent:
            print(f'  SKIP {fn} step{n} concept={concept!r}')
            continue
        ps, sent = ps_sent
        step_pat = re.compile(
            r'(  - n:\s*' + str(n) + r'\n(?:    [^\n]*\n)+?    join-key:\n      concept:\s*' + re.escape(concept or '?') + r'\n      role:\s*[^\n]+\n)',
            re.MULTILINE
        )
        mm = step_pat.search(txt)
        if not mm:
            print(f'  NO-MATCH {fn} step{n}')
            continue
        sent_escaped = sent.replace('\\','\\\\').replace('"','\\"')
        insertion = '    primary-source: ' + ps + '\n    attribution-sentence: "' + sent_escaped + '"\n'
        tail = txt[mm.end():mm.end()+200]
        if 'primary-source:' in tail[:120] or 'attribution-sentence:' in tail[:200]:
            continue
        txt = txt[:mm.end()] + insertion + txt[mm.end():]
        total_written += 1
    with open(fp,'w',encoding='utf-8') as f: f.write(txt)

print(f'\nTotal step-citations inserted: {total_written}')
