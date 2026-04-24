---
name: GPP-SYSVOL-XML
title-description: "Group Policy Preferences XML files in SYSVOL — Groups.xml (cpassword!), ScheduledTasks.xml, Services.xml, Drives.xml"
aliases:
- GPP XML
- SYSVOL Preferences
- Groups.xml cpassword
- GPP password recovery
link: persistence
link-secondary: user
tags:
- enterprise-persistence
- credential-material
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-binary-cache
substrate-instance: GPP-SYSVOL-XML
platform:
  windows-server:
    min: '2008'
    max: '2022'
    note: "Domain-side — files live on Domain Controllers. Client-side reads them during GPO refresh via SYSVOL replication."
  windows:
    min: '7'
    max: '11'
location:
  path-sysvol: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{<GPO-GUID>}\\Machine\\Preferences\\*\\*.xml"
  path-sysvol-user: "\\\\<domain>\\SYSVOL\\<domain>\\Policies\\{<GPO-GUID>}\\User\\Preferences\\*\\*.xml"
  companion: "Registry.pol (separate artifact, registry-settings side)"
  addressing: file-path
  note: "Group Policy Preferences (GPP) XML files under SYSVOL define policy operations beyond plain registry settings — create local users, schedule tasks, install services, map drives, place shortcuts, copy files. Each file class lives in its own Preferences subdirectory (Groups, ScheduledTasks, Services, Drives, Shortcuts, Files, Registry, etc.). For DFIR, these files are AUTHORITATIVE domain-side evidence of what policy was pushed — complementing the client-side Registry.pol cache. CRITICALLY: legacy Groups.xml files contain the cpassword attribute — a weakly-encrypted password for a local account the GPP creates/modifies on every client. Microsoft's published decryption key means ANY authenticated domain user can decrypt cpassword (KB2962486, 2014). Historically-authored Groups.xml files surviving in SYSVOL are a standing credential exposure."
fields:
- name: groups-xml-cpassword
  kind: content
  location: "SYSVOL\\...\\Preferences\\Groups\\Groups.xml — cpassword attribute on User / Group elements"
  encoding: base64(AES-CBC-encrypted-with-public-key)
  note: "THE MS14-025 CRITICAL FINDING. Attribute format: cpassword=\"<base64-encrypted-value>\". Microsoft published the AES key in KB2962486 after the 2014 disclosure — decryption is trivial with tools like gpp-decrypt, SharpGPPass, Invoke-GppDecrypt. Result is the plaintext password. Recovered plaintext is the LOCAL ACCOUNT PASSWORD that every machine covered by this GPP now has set. Classic lateral-movement primitive: any authenticated domain user enumerates SYSVOL, finds Groups.xml, decrypts cpassword, authenticates to every managed host with the recovered local admin password."
- name: scheduled-tasks-xml
  kind: content
  location: "SYSVOL\\...\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
  encoding: UTF-16LE XML
  references-data:
  - concept: TaskName
    role: scheduledTask
  note: "GPP-deployed scheduled tasks. Every task definition includes: target executable, arguments, trigger, run-as context, creation timestamp. Attacker-modified ScheduledTasks.xml in SYSVOL deploys ransomware-execution tasks to every client — classic T1053.005 mass-execution vector. ALSO subject to cpassword in some legacy versions (run-as passwords for tasks that need to run with a specific credential)."
- name: services-xml
  kind: content
  location: "SYSVOL\\...\\Preferences\\Services\\Services.xml"
  encoding: UTF-16LE XML
  note: "GPP-deployed service modifications (start/stop/restart/configure services on clients). Can include cpassword for services-that-run-as a specific user."
- name: drives-xml
  kind: content
  location: "SYSVOL\\...\\Preferences\\Drives\\Drives.xml"
  encoding: UTF-16LE XML
  note: "GPP-deployed network drive mappings. Each entry: drive letter, UNC path, credentials to connect. CPASSWORD vector — credentials stored alongside mapping. Attacker uses: enumerate Drives.xml → recover authentication material for the mapped-share credentials → access those shares directly."
- name: shortcuts-xml
  kind: content
  location: "SYSVOL\\...\\Preferences\\Shortcuts\\Shortcuts.xml"
  encoding: UTF-16LE XML
  note: "GPP-deployed shortcut deployments. Each entry: shortcut target path, arguments, icon. Attacker-authored Shortcuts.xml places .lnk files on every client's Desktop / Start Menu pointing at attacker payload — persistence via shortcut-execution chain."
- name: policy-ref-datetime
  kind: timestamp
  location: "XML attribute — changed='YYYY-MM-DD HH:MM:SS' on each element"
  encoding: ISO-ish datetime string
  clock: DC when the GPP was authored
  resolution: 1s
  note: "When the GPP item was last authored / modified. Pair with GPO's gpt.ini version for policy-edit timeline."
- name: file-mtime
  kind: timestamp
  location: each .xml file $SI modified time on SYSVOL
  encoding: filetime-le
  clock: DC system
  resolution: 100ns
  note: "NTFS mtime on SYSVOL = when the XML was last written / replicated. DFSR propagates changes across DCs; inconsistent mtimes across replicas = DFS-replication lag or selective-DC tamper."
observations:
- proposition: CONFIGURED_BY_POLICY
  ceiling: C4
  note: 'GPP SYSVOL XML files are one of the most-impactful enterprise-
    persistence AND credential-exposure artifacts. Groups.xml
    specifically is a standing DOMAIN-WIDE credential leak for any
    environment that ever deployed local-account-management via GPP
    before Microsoft''s KB2962486 deprecation — the cpassword
    attribute can be decrypted by any authenticated domain user with
    Microsoft''s published key, yielding the local account password
    deployed to every client. For DFIR: always audit SYSVOL\\...\\
    Preferences\\Groups\\*.xml on every DC for cpassword presence
    regardless of current GPP state (old GPOs never cleaned up
    survive indefinitely on SYSVOL). Attacker-modified
    ScheduledTasks.xml / Shortcuts.xml is a canonical mass-deploy
    ransomware primitive (Ryuk, Conti, LockBit all use this).'
  qualifier-map:
    setting.file: "SYSVOL\\...\\Preferences\\*\\*.xml"
    time.start: field:file-mtime
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: DFSR replication consistency across DCs; no per-file signing
  known-cleaners:
  - tool: GPMC (Group Policy Management Console) — delete the GPP item / GPO
    typically-removes: the XML file from SYSVOL (and the refs from gpt.ini)
  survival-signals:
  - ANY cpassword attribute in ANY Groups.xml in SYSVOL = standing credential leak — decrypt and treat as domain-wide exposure
  - ScheduledTasks.xml with Command attribute matching attacker binary / staged path = mass-deploy primitive
  - Shortcuts.xml with targetPath pointing to attacker payload = user-session persistence for every logon
  - file-mtime on SYSVOL XMLs matching compromised-DC-admin timeframe = DC-side GPP tamper
provenance:
  - ms-kb2962486-ms14-025-vulnerability-in
  - mitre-t1552-006
  - schroeder-2016-get-gpppassword-powershell-one
  - robbins-2022-group-policy-preferences-and-t
---

# Group Policy Preferences XML (SYSVOL)

## Forensic value
Group Policy Preferences (GPP) define policy operations beyond plain registry values. Each operation class has its own XML file under a GPO's SYSVOL tree:

```
\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\
    Machine\Preferences\
        Groups\Groups.xml              ← local account management (HAS cpassword!)
        ScheduledTasks\ScheduledTasks.xml
        Services\Services.xml
        Drives\Drives.xml              ← network drive mappings (cpassword on map credentials)
        Shortcuts\Shortcuts.xml
        Files\Files.xml
        Registry\Registry.xml
    User\Preferences\<same classes>
```

## The Groups.xml cpassword disaster
Pre-MS14-025 (2014), GPP stored credentials — notably local account passwords for Groups operations — in the `cpassword` XML attribute as AES-CBC-encrypted text. **Microsoft published the decryption key.**

Any authenticated domain user can:
1. Read SYSVOL (it's readable to Authenticated Users by design)
2. Find any Groups.xml (or older Services.xml / ScheduledTasks.xml / Drives.xml)
3. Extract cpassword attribute
4. Decrypt with the published key (gpp-decrypt, PowerSploit Get-GPPPassword)
5. Recover the local account password

**Every client covered by that GPP has this local password set.** Instant domain-wide lateral movement.

Even though the KB2962486 patch deprecated password-containing GPP, **old XMLs are NOT cleaned up** — they survive on SYSVOL indefinitely. A domain that used GPP for local-admin-management in 2012 still has that cpassword in SYSVOL today, decryptable by any attacker with low-priv foothold.

## Other attacker uses
- **ScheduledTasks.xml** — mass-deploy attacker-scheduled tasks to every domain client (Ryuk / Conti / LockBit standard pre-encryption technique)
- **Shortcuts.xml** — mass-place .lnk on every Desktop / Start Menu pointing at attacker payload
- **Services.xml** — stop EDR services / start attacker services domain-wide
- **Drives.xml** — force every user to connect to attacker-controlled UNC share

## Concept reference
- None direct — configuration-substrate artifact.

## Triage (as domain-member analyst)
```powershell
# Get-GPPPassword (PowerSploit)
Get-GPPPassword
# Any result = standing domain-wide credential exposure

# Manual enumeration
Get-ChildItem -Path "\\<domain>\SYSVOL\<domain>\Policies" -Recurse -Include Groups.xml, Services.xml, ScheduledTasks.xml, Drives.xml | ForEach-Object {
    Select-String -Path $_.FullName -Pattern 'cpassword="[^"]+"'
}
```

## Offline (from DC image)
Mount SYSVOL from the DC image. Walk `Policies\{GUID}\Machine\Preferences\` and `User\Preferences\`. Scan each .xml for `cpassword=` attributes. Decrypt each with `gpp-decrypt` or Invoke-GppDecrypt.

## Cross-reference
- **Registry.pol** — sibling registry-settings side of the same GPO
- **gpt.ini** — GPO version + name metadata
- **Security-5136 / 5137 / 4739** — AD object modification events for GPO changes
- **Microsoft-Windows-GroupPolicy/Operational** EVTX — client-side refresh events

## Practice hint
Do NOT run Get-GPPPassword against a production domain without authorization — it produces forensic noise (SYSVOL reads are logged). On an isolated lab DC, create a test GPO with a Groups Preference that sets a password. Observe the resulting `cpassword` attribute in Groups.xml. Decrypt with gpp-decrypt to confirm the recovered password matches what you set. This is the exact attack chain — foundational muscle memory for domain-security work.
