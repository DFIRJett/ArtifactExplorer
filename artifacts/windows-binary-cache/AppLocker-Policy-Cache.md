---
name: AppLocker-Policy-Cache
title-description: "AppLocker effective-policy cache (SRP / AppLocker / WDAC on-disk rule store)"
aliases:
- AppLocker policy files
- SrpV2 effective policy
- AppLocker rule cache
- Application Identity policy
link: persistence
link-secondary: system
tags:
- application-allowlist
- tamper-signal
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: AppLocker-Policy-Cache
platform:
  windows:
    min: '7'
    max: '11'
    note: "AppLocker introduced with Windows 7 Enterprise / Server 2008R2. WDAC (Windows Defender Application Control) shipped as the successor for Windows 10+, with AppLocker remaining for compatibility. Both stored as on-disk policy caches consulted by the Application Identity (AppIDSvc) service."
  windows-server:
    min: '2008R2'
    max: '2022'
location:
  path-applocker: "%WINDIR%\\System32\\AppLocker\\*.applocker (effective-policy XML files)"
  path-applocker-mdm: "%WINDIR%\\System32\\AppLocker\\MDM\\*.xml (MDM-pushed AppLocker policy)"
  path-wdac-ci: "%WINDIR%\\System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip (WDAC code-integrity policies)"
  path-wdac-legacy: "%WINDIR%\\System32\\CodeIntegrity\\SiPolicy.p7b (legacy Secure-Integrity-Policy — Win10 1903 and earlier)"
  registry-config: "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2 (AppLocker rules under this GPO path)"
  addressing: file-path
  note: "AppLocker's effective policy — the rules currently enforced — is cached on-disk in System32\\AppLocker\\ as XML files (one per rule collection: Exe, Msi, Script, Dll, Appx). The Application Identity service (AppIDSvc) reads these at boot. WDAC's successor mechanism uses binary .cip files (Windows 10 version 1903+) that are code-signed and more tamper-resistant than AppLocker's plain XML. For DFIR, comparing the file-cache against the registry-policy baseline exposes tampering — an attacker who wants to allow their binary may modify the local effective-policy cache, but the mismatch with registry / SYSVOL-source policy is detectable."
fields:
- name: applocker-rule-xml
  kind: content
  location: "System32\\AppLocker\\*.applocker — XML effective policy"
  encoding: utf-8 XML
  references-data:
  - concept: ExecutablePath
    role: configuredPersistence
  note: "XML rule collection. Each rule allows or denies execution of Exe / Msi / Script / Dll / AppX based on: Publisher (cert signer), Product Name, File Version range, Hash, or File Path. Attacker-modified AppLocker rule adding an Allow-Path for an attacker-controlled directory = effective AV-bypass on AppLocker-enforced hosts. Check for Allow rules targeting %TEMP% / %APPDATA% / user-writable paths."
- name: applocker-enforcement-mode
  kind: flags
  location: "<RuleCollection> element Type attribute + EnforcementMode attribute in XML"
  encoding: text enum
  note: "EnforcementMode: NotConfigured / AuditOnly / Enabled. NotConfigured = rule collection not active. AuditOnly = logs to AppLocker EVTX but does not block. Enabled = actively blocks. Attacker downgrading Enabled → AuditOnly silently disables enforcement without removing the policy (appears configured in GPMC)."
- name: wdac-policy-cip
  kind: content
  location: "System32\\CodeIntegrity\\CiPolicies\\Active\\*.cip"
  encoding: binary + Authenticode signature
  note: "WDAC policy binary (signed, PKCS#7 + custom payload). Each .cip = one active policy. Multiple policies allowed in 'Multiple Policy Format'. Signed tamper = .cip replacement requires valid signing cert — attackers who want to disable WDAC can't just edit the file; they disable via enforcement-flag registry or unsigned policy replacement (Win10 1903+ enforces signed policies in Enforced mode)."
- name: wdac-legacy-sipolicy
  kind: content
  location: "System32\\CodeIntegrity\\SiPolicy.p7b (legacy)"
  encoding: binary WDAC policy
  note: "Legacy single-policy WDAC format (Win10 1803 and earlier). Still present on upgraded systems. Replaced in-place by attackers who want to downgrade code-integrity posture on older systems."
- name: applocker-sysvol-source
  kind: path
  location: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{<GPO-GUID>}\\Machine\\Preferences\\AppLocker\\*.xml"
  note: "For domain-deployed AppLocker, the SOURCE policy lives in SYSVOL. Diff local %WINDIR%\\System32\\AppLocker against SYSVOL source — mismatch indicates local tamper OR refresh failure."
- name: file-mtime
  kind: timestamp
  location: per-AppLocker-file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "NTFS mtime = last policy-refresh write. Compare against domain-side SYSVOL mtime + gpt.ini version for refresh-state sanity. Local mtime much newer than SYSVOL = local tamper."
- name: appid-service-state
  kind: flags
  location: "Services\\AppIDSvc and Services\\AppIDSvcGroup — service state + Start value"
  note: "AppLocker relies on the Application Identity service (AppIDSvc) being running. Start=4 (Disabled) on AppIDSvc while AppLocker policy is deployed = enforcement is inactive regardless of policy content. Classic attacker technique: disable the service rather than tamper with rules."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'AppLocker / WDAC are application-allowlisting controls meant to
    prevent attacker binaries from running. The on-disk policy cache
    is what the Application Identity service actually enforces —
    tamper here directly weakens execution-control defenses. Because
    enterprise AppLocker deployments rely on consistent policy
    across every client, diff against SYSVOL source OR against
    policy baseline surfaces the tamper. WDAC''s signed-.cip format
    is more tamper-resistant — attackers targeting WDAC typically
    disable enforcement via registry flags rather than modify .cip
    files directly. Always check both the policy content AND the
    enforcement-mode registry values AND the AppIDSvc service state.'
  qualifier-map:
    setting.file: "System32\\AppLocker\\*.applocker / CodeIntegrity\\*.cip"
    time.start: field:file-mtime
anti-forensic:
  write-privilege: admin
  integrity-mechanism: WDAC .cip files are signed (Authenticode); AppLocker XML is plain text
  known-cleaners:
  - tool: "Set-AppLockerPolicy <empty-policy>"
    typically-removes: effective AppLocker policy (requires admin; leaves Security-4678 policy-change event)
  - tool: "Stop-Service AppIDSvc + Set-Service -StartupType Disabled"
    typically-removes: AppLocker enforcement (AppLocker rules still present but not acted upon)
  survival-signals:
  - AppLocker XML with Allow rules targeting user-writable paths (%TEMP%, %APPDATA%, Downloads) = bypass-allowlist plant
  - Enforcement mode downgraded to AuditOnly without documented admin approval = silent disable
  - AppIDSvc Start=4 (Disabled) on a host with AppLocker policy deployed = enforcement disabled
  - Local AppLocker XML mtime post-dating SYSVOL source XML mtime = local-tamper OR refresh-lag
  - WDAC .cip missing on a host whose policy baseline expected WDAC = code-integrity mitigation removed
provenance: [ms-applocker-policy-storage-and-enforc, ms-wdac-policy-file-format-and-enforce, mitre-t1562-001]
---

# AppLocker / WDAC Policy Cache

## Forensic value
Application-allowlisting controls cache their effective policy on disk:

- **AppLocker**: `%WINDIR%\System32\AppLocker\*.applocker` (XML files, one per rule collection)
- **WDAC (modern)**: `%WINDIR%\System32\CodeIntegrity\CiPolicies\Active\*.cip` (signed binary)
- **WDAC (legacy)**: `%WINDIR%\System32\CodeIntegrity\SiPolicy.p7b`

These files ARE what the Application Identity service (AppIDSvc) reads at boot and enforces. Attacker tamper here directly weakens the allowlisting defense.

## Two attack classes
1. **Rule addition** — append Allow rule targeting attacker-controlled path (%TEMP%, %APPDATA%)
2. **Enforcement downgrade** — Enabled → AuditOnly (logs but doesn't block) OR disable AppIDSvc
3. **Policy deletion** — remove .applocker or .cip files (WDAC .cip is signed on modern Win10/11 so replacement requires valid signing cert)

## Concept reference
- None direct — policy configuration artifact.

## Triage
```cmd
dir /a %WINDIR%\System32\AppLocker\
dir /a %WINDIR%\System32\CodeIntegrity\CiPolicies\Active\

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v Start

Get-AppLockerPolicy -Effective -Xml  :: PowerShell — live effective policy
```

## Diff workflow
Compare local cache against domain SYSVOL source:
```powershell
# Local policy
$local = Get-AppLockerPolicy -Effective -Xml

# SYSVOL source (if domain-deployed)
$sysvol = Get-Content "\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\Machine\Preferences\AppLocker\SrpPolicy.xml" -Raw

# Diff
if ($local -ne $sysvol) { "TAMPER OR REFRESH-LAG" }
```

## Cross-reference
- **Microsoft-Windows-AppLocker/*** EVTX channels — per-rule-collection enforcement events (Exe, Msi, Script, Dll, Appx)
  - Event IDs 8001 / 8002 / 8003 = allow/audit/deny execution
- **Microsoft-Windows-CodeIntegrity/Operational** — WDAC enforcement events
- **System-7036** — AppIDSvc state changes (stop/start events)
- **Security-4678 / 4712** — policy change events
- **Registry.pol + SYSVOL** — GPO-source of policy for diff

## Attack-chain example
Ransomware operator needs to run an unsigned binary on an AppLocker-enforced host:
1. Domain Admin context
2. Edit Default Domain GPO AppLocker rules → add Allow-Path `%TEMP%\*`
3. Force gpupdate on target host (or wait 90 min)
4. Local `%WINDIR%\System32\AppLocker\Exe.applocker` XML refreshes with new rule
5. Drop ransomware to `%TEMP%\ransom.exe`
6. Execution allowed — AppLocker effective policy includes the attacker rule

DFIR recovery: diff current `Exe.applocker` against pre-intrusion backup OR against SYSVOL source. The added Allow-Path rule for %TEMP% is the visible tamper.

## Practice hint
On a lab VM with AppLocker enabled: use `Get-AppLockerPolicy -Effective` to inspect current policy. Modify a rule in Local Security Policy, observe the XML file in `%WINDIR%\System32\AppLocker\` update. The file mtime + XML-rule content reveal the change.
