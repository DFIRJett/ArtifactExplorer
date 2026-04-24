---
name: Shell-COM-Hooks
title-description: "Shell CLSID-list persistence (ShellExecuteHooks / ShellServiceObjects / ShellIconOverlayIdentifiers / SharedTaskScheduler)"
aliases:
- ShellExecuteHooks
- ShellServiceObjectDelayLoad
- ShellIconOverlayIdentifiers
- SharedTaskScheduler
link: persistence
tags:
- persistence-primary
- itm:PR
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT5.1
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path: "Microsoft\\Windows\\CurrentVersion\\Explorer"
  addressing: hive+key-path
  note: "Four sibling CLSID-list subkeys under the Explorer key, each of which Explorer reads at startup and treats as 'DLLs to load into my process space.' Each is a different hook point but the forensic logic is identical: any entry → a DLL loaded into explorer.exe (or a shared svchost.exe) on next user logon. Adding an entry requires admin (HKLM) unless the HKCU Classes equivalent is used."
fields:
- name: shell-execute-hooks
  kind: identifier
  location: "Explorer\\ShellExecuteHooks\\<CLSID> value names"
  type: REG_SZ
  note: "Each value name is a CLSID of a COM object implementing IShellExecuteHook. Explorer invokes the hook on every ShellExecute call (every file/URL launch through the shell). On stock Windows 10/11 this key contains one well-known CLSID ({AEB6717E-7E19-11d0-97EE-00C04FD91972} — URL and shortcut handling). Any additional CLSID = potential hijack; resolve the CLSID under HKLM\\SOFTWARE\\Classes\\CLSID to find the backing DLL."
- name: shell-service-objects
  kind: identifier
  location: "Explorer\\ShellServiceObjectDelayLoad value names"
  type: REG_SZ
  note: "Each value name (arbitrary string) maps to a CLSID (value data). COM objects listed here are loaded into explorer.exe on logon. Stock Windows has entries like 'WebCheck', 'PostBootReminder', 'SysTray'. Extra entries pointing to non-Microsoft CLSIDs = persistence plant."
- name: shell-icon-overlays
  kind: identifier
  location: "Explorer\\ShellIconOverlayIdentifiers\\<name>\\(Default) value"
  type: REG_SZ
  note: "Each subkey's Default value is a CLSID of an IShellIconOverlayIdentifier COM object. Loaded into explorer.exe to render overlay icons (OneDrive/Dropbox sync-status icons, TortoiseGit state badges). Stock Windows has a handful; cloud-sync apps add more. Subkeys prefixed with leading spaces are a known abuse pattern to win the load-order race (Windows loads only the first ~15 overlay providers)."
- name: shared-task-scheduler
  kind: identifier
  location: "Explorer\\SharedTaskScheduler value names"
  type: REG_SZ
  note: "Each value name is a CLSID. COM objects listed here are loaded by a shared-scheduler service early in session startup. Stock Win10/11 usually has only one (Browseui preloader, {438755C2-A8BA-11D1-B96B-00A0C90312E1}). Extra entries = persistence."
- name: resolved-dll
  kind: path
  location: "HKLM\\SOFTWARE\\Classes\\CLSID\\<CLSID>\\InprocServer32\\(Default)"
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "Each CLSID referenced above resolves to a DLL via the standard COM registration path. THIS is the backing file that actually loads into explorer.exe. Validate that the DLL path is under %SystemRoot%\\System32 (or a signed vendor directory for legitimate cloud/shell integrations). Paths in %APPDATA% / %PROGRAMDATA% / user-writable locations = hijack."
- name: key-last-write
  kind: timestamp
  location: "<any of the four> key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on any of these four keys post-dating the OS install AND falling outside a known legit-software install window = candidate persistence write. Correlate with System-7045 / Security-4697 service events and software install logs."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'Shell CLSID-list persistence is one of the most durable and
    broadly-triggered mechanisms on Windows because the load condition
    is simply "explorer.exe starts" — which happens on every interactive
    user logon. Combined with the fact that most incident responders
    check Run keys and Scheduled Tasks but skip these four Explorer
    subkeys, CLSID-list persistence is under-detected in real
    investigations. Each of the four keys has a known stock content;
    anything outside that baseline warrants investigation.'
  qualifier-map:
    setting.registry-path: "Microsoft\\Windows\\CurrentVersion\\Explorer\\<ShellExecuteHooks|ShellServiceObjectDelayLoad|ShellIconOverlayIdentifiers|SharedTaskScheduler>"
    setting.dll: field:resolved-dll
    time.start: field:key-last-write
anti-forensic:
  write-privilege: unknown
  survival-signals:
  - Value-name / subkey-name under ShellIconOverlayIdentifiers using leading spaces = load-order race abuse
  - CLSID backing DLL path outside System32 / Program Files for a shell hook = almost always malicious
  - Key LastWrite on any of the four keys without a corresponding installer event in System-7045/Security-4697 = drive-by persistence write
  - ShellExecuteHooks with more than the single stock entry on Win10/11 = hijack candidate
provenance:
  - ms-ishellexecutehook-interface-and-reg
  - mitre-t1546
---

# Shell CLSID-list persistence (four-key family)

## Forensic value
Four sibling registry keys under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\` instruct Explorer to load COM objects into its process (or into a shared scheduler service) on every user logon:

1. **`ShellExecuteHooks`** — fires on every ShellExecute call (file / URL launch)
2. **`ShellServiceObjectDelayLoad`** — loaded once on logon; long-running in explorer.exe
3. **`ShellIconOverlayIdentifiers`** — icon overlay providers (max ~15 loaded, first wins)
4. **`SharedTaskScheduler`** — shared scheduler COM objects on session startup

All four resolve entries through `HKLM\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32\(Default)` — the standard COM registration path — to a backing DLL.

## Why these four get grouped
Identical forensic logic across all four:
- Read the CLSID list from the Explorer subkey
- Resolve each CLSID to a DLL path
- Validate the DLL path against the known stock set for the Windows build
- Anything outside stock = candidate hijack

A malicious DLL in any of these keys loads into explorer.exe (a trusted, always-running process) on every interactive logon. This is why modern EDRs enumerate and baseline all four — missing any one leaves a visible persistence gap.

## Stock baseline (Windows 10/11)
- `ShellExecuteHooks` — typically 1 entry: `{AEB6717E-7E19-11D0-97EE-00C04FD91972}` (URL handling)
- `ShellServiceObjectDelayLoad` — a few Microsoft CLSIDs (WebCheck, PostBootReminder, SysTray, CDBurn on systems with the feature)
- `ShellIconOverlayIdentifiers` — OneDrive subkeys on stock Win11, plus a few stock providers
- `SharedTaskScheduler` — generally one entry (Browseui preloader)

Cloud sync apps (OneDrive, Dropbox, Box) legitimately add entries to `ShellIconOverlayIdentifiers`. All other keys getting non-Microsoft additions is rare enough that each addition warrants triage.

## Concept reference
- ExecutablePath (one per resolved backing DLL)

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler"
```

For each CLSID returned, resolve the backing DLL:
```cmd
reg query "HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}\InprocServer32" /ve
```

Validate each DLL path against known-good (signed, in System32 or vendor Program Files directory).

## Practice hint
Autoruns.exe (Sysinternals) enumerates all four keys on its "Explorer" tab. Run on a clean Windows 11 VM and snapshot the baseline. Then run on the investigation target and diff — any deltas not attributable to installed applications are persistence candidates to investigate further.
