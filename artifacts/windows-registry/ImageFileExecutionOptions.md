---
name: ImageFileExecutionOptions
aliases:
- IFEO
- IFEO Debugger hijack
- Accessibility debugger trick
link: persistence
tags:
- system-wide
- tamper-hard
- persistence-primary
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: XP
    max: '11'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\Image File Execution Options
  sub-paths: IFEO\<executable-name.exe> — per-binary subkey
  addressing: hive+key-path
fields:
- name: Debugger
  kind: path
  location: per-binary subkey → Debugger value
  type: REG_SZ
  note: executable launched in place of the original when the named binary is invoked — classic hijack primitive
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
- name: GlobalFlag
  kind: flags
  location: per-binary subkey → GlobalFlag value
  type: REG_DWORD
  note: when set to 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT) combined with SilentProcessExit key elsewhere, triggers external program launch on process exit
- name: MitigationOptions
  kind: flags
  location: per-binary subkey → MitigationOptions value
  type: REG_QWORD
  note: per-process EMET/Defender exploit-guard overrides; attacker use is to DISABLE protections for a target binary
- name: key-last-write
  kind: timestamp
  location: per-binary subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  update-rule: on any IFEO write for that binary
observations:
- proposition: PERSISTED
  ceiling: C3
  note: IFEO Debugger redirects execution of a named binary — classic 'sticky keys' / 'accessibility' replacement attack. Accessible even to admin without service-creation privileges.
  qualifier-map:
    object.process: subkey name
    object.persistence.executable: field:Debugger
    time.created: field:key-last-write
anti-forensic:
  write-privilege: admin
  known-cleaners:
  - tool: manual reg delete
    typically-removes: full
  detection-signals:
  - presence of Debugger value for system binaries (osk.exe, sethc.exe, utilman.exe, magnify.exe, narrator.exe) is almost-always malicious
  - GlobalFlag=0x200 paired with a SilentProcessExit key under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<binary>
provenance:
  - ms-configuring-automatic-debugging-aed
  - mitre-t1546-012
---

# Image File Execution Options

## Forensic value
IFEO is a Windows feature allowing per-binary debug/launch options. Its `Debugger` value is an **execution-hijack primitive**: when `notepad.exe` is invoked and an IFEO key for it specifies `Debugger = C:\evil.exe`, Windows launches `C:\evil.exe notepad.exe` instead of notepad.

Two classic attacks:
1. **Accessibility replacement** — set `Debugger` on `sethc.exe` or `utilman.exe` so that hitting Shift 5× at the logon screen (or clicking Utility Manager) launches attacker-chosen code with SYSTEM privilege.
2. **SilentProcessExit** — GlobalFlag + SilentProcessExit subkey pair triggers external program launch when a named process dies. Used as cleanup triggers or persistence via long-running target crashes.

## Forensic detection
- Enumerate IFEO subkeys for Debugger values. Filter against a known-benign list (SECURITY SOFTWARE may legitimately set Debugger — e.g., some AV).
- Cross-reference subkey names against %WINDIR%\System32\*.exe — IFEO keys naming system binaries should be rare and investigated.
- Check key last-write timestamps for clustering around suspected compromise window.

## Cross-references
- **Security-4657** (registry value modified, if auditing enabled) captures IFEO writes
- **Sysmon-13** (registry value set) — more practical for real-time detection
- **AutoLogon** / **Winlogon-Userinit-Shell** — sibling persistence mechanisms worth enumerating together

## Practice hint
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object { $p = $_.PSChildName; $d = (Get-ItemProperty $_.PSPath -EA 0).Debugger; if ($d) { "$p => $d" } }
```
