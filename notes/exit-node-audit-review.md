# Exit-node audit — single-source attribution (FINAL review)

**Status**: 37 artifact exit-nodes evaluated. KEEP / CULL / PENDING verdicts below.

**Summary counts**:
- **24 KEEP** with clean primary-source + attribution-sentence
- **11 CULL** — no defensible single-source sentence found in existing `sources.yaml`
- **2 PENDING** — single-source candidates exist but URL is unreachable (Swapfile, CrashDump-MEMDMP)

**Cull rate: 30%** (11/37) — matches user expectation of substantial culling.

---

## KEEP (24)

### Credential stores (8)
```yaml
# NTDS-dit
primary-source: mitre-t1003-003
attribution-sentence: "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights."

# SAM
primary-source: mitre-t1003-002
attribution-sentence: "The SAM is a database file that contains local accounts for the host, typically those found with the `net user` command."

# LSA-Secrets
primary-source: mitre-t1003-004
attribution-sentence: "Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts."

# Credentials-cached
primary-source: mitre-t1003-005
attribution-sentence: "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable."

# LSA-Cached-Logons
primary-source: mitre-t1003-005
attribution-sentence: "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable."

# Credential-Manager-Vault
primary-source: mitre-t1555-004
attribution-sentence: "The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers."

# DPAPI-MasterKeys
primary-source: mitre-t1555
attribution-sentence: "Adversaries may search for common password storage locations to obtain user credentials."

# Windows-Hello-NGC
primary-source: mitre-t1555
attribution-sentence: "Adversaries may search for common password storage locations to obtain user credentials."

# Kerberos-Tickets-Cache
primary-source: mitre-t1558
attribution-sentence: "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket."
```

### Memory / snapshot captures (3)
```yaml
# Hiberfil
primary-source: ms-hibernate-the-system-hiberfil-sys-f  # URL corrected in sources.yaml
attribution-sentence: "In a hibernate transition, all the contents of memory are written to a file on the primary system drive, the hibernation file."

# Pagefile
primary-source: ms-manage-virtual-memory-paging-file-m
attribution-sentence: "Page files enable the system to remove infrequently accessed modified pages from physical memory to let the system use physical memory more efficiently for more frequently accessed pages."

# VSS-Shadow-Copies
primary-source: ms-volume-shadow-copy-service-vss-arch
attribution-sentence: "VSS coordinates the actions that are required to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up."
```

### Filesystem / disk (2)
```yaml
# Boot
primary-source: libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
attribution-sentence: "The $Boot metadata file contains the volume signature, the BIOS parameter block, and the boot loader."

# Secure-SDS
primary-source: libyal-libfsntfs-libfsntfs-ntfs-extended-attrib
attribution-sentence: "The $Secure metadata file contains the security descriptors used for access control."
```

### Persistence / configuration (5)
```yaml
# BitLocker-FVE
primary-source: ms-bitlocker-registry-configuration-re
attribution-sentence: "BitLocker is a Windows security feature that provides encryption for entire volumes, addressing the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned devices."

# BCD-Store
primary-source: mitre-t1542-003
attribution-sentence: "Adversaries may use bootkits to persist on systems."

# Scheduled-Tasks
primary-source: mitre-t1053-005
attribution-sentence: "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code."

# Services
primary-source: mitre-t1543-003
attribution-sentence: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence."

# WMI-CIM-Repository
primary-source: mitre-t1546-003
attribution-sentence: "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription."
```

### Network / remote-access (2)
```yaml
# FirewallRules
primary-source: mitre-t1562-004
attribution-sentence: "Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage."

# RDP-Bitmap-Cache
primary-source: mitre-t1021-001
attribution-sentence: "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP)."
```

### Email stores (2)
```yaml
# Outlook-PST
primary-source: mitre-t1114-001
attribution-sentence: "Adversaries may target user email on local systems to collect sensitive information."

# Outlook-OST
primary-source: mitre-t1114-001
attribution-sentence: "Adversaries may target user email on local systems to collect sensitive information."
```

### Security logging (1)
```yaml
# Audit-Policy
primary-source: mitre-t1562-002
attribution-sentence: "Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits."
```

### Credential migration (1)
*(already in KEEP list above)*

---

## CULL (11)

**Rationale per entry**: no single source in current `sources.yaml` contains a verbatim sentence defensible as exit-node attribution. Per user direction, `is-terminus: true` gets removed. Artifact retains its observations + concept-refs — this is specifically removing the exit-node flag.

### ProfileList
- Only sources: 3 analyst-writeups + Carvey blogspot. No Microsoft Learn page for ProfileList registry key. No MITRE technique for SID→ProfileImagePath lookup.
- → **CULL**

### MBR
- Only source: `carrier-2005-file-system-forensic-analysis`. The book's landing page doesn't contain extractable MBR content; textbook itself is paywalled for direct quote.
- No Microsoft Learn page specifically on MBR structure. No MITRE.
- → **CULL**

### ComputerName
- No authoritative source at artifact level beyond `libyal-libregf` (generic registry-format spec, doesn't describe ComputerName-specific semantics).
- → **CULL**

### OS-Version
- Only source: `ms-windows-install-registry-values-cur` (install-registry page) — describes install values but not OS-version-specific authoritative terminus claim.
- → **CULL**

### Registered-Owner
- Same source as OS-Version — same limitation.
- → **CULL**

### TimeZoneInformation
- No MITRE technique. Only generic `libyal-libregf`. No Microsoft Learn page specifically about TZI registry semantics with the required depth.
- → **CULL**

### Cortana-CoreDb
- Sources: libyal-libesedb (generic ESE format) + singh-2017-cortana-forensics-windows-10 (analyst paper).
- Neither yields a single-sentence defensible claim about Cortana database content being a Tier-3 terminus.
- → **CULL**

### RunMRU
- No MITRE technique. Registry-specific sources cover usage patterns, not authoritative terminus claim.
- → **CULL**

### TypedURLs
- Same as RunMRU — user-activity registry, no authoritative single-source.
- → **CULL**

### UserAssist
- Same — user-activity registry, analyst-writeups only.
- → **CULL**

### PartitionDiagnostic-1006
- Niche Microsoft-Windows-Partition event. No MITRE technique. Hale 2018 blog posts are analyst-writeup class.
- Per existing exit-node sweep this was endorsed as a "time-anchor bridge" artifact, but the single-source rule requires something authoritative. Absent that → **CULL**.

---

## PENDING (2) — registry gap, needs resolution before final verdict

### Swapfile
- `ms-uwp-app-lifecycle-suspend-resume-sw` URL 404'd (MS retired the page).
- `forensics-2019-the-windows-swapfile-what-it-c` — already marked UNVERIFIED in source registry.
- **Options**:
  - (a) Find + register a new MS Learn URL for swapfile semantics; use that as primary-source
  - (b) CULL if no replacement found
  
### CrashDump-MEMDMP
- `foundation-2021-volatility-hibernate-address-s` returns nothing on the specific crashdump content claim.
- BUT: `https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files` has a clean sentence: *"The Complete Memory Dump is the largest and contains the most information, including some User-Mode memory."*
- This URL **not currently registered** in sources.yaml.
- **Options**:
  - (a) Register this as new source `ms-varieties-of-kernel-mode-dump-files`; use as primary-source → **KEEP**
  - (b) CULL per strict existing-sources-only rule

---

## Post-audit action items

**Apply phase**:
1. Add `primary-source` + `attribution-sentence` to the 24 KEEP entries' `exit-node:` blocks
2. Remove `is-terminus: true` (or flip to `false`) on the 11 CULL entries
3. Resolve 2 PENDING per user direction (register new source OR CULL)
4. Schema update: optional — make `primary-source` + `attribution-sentence` new required fields when `is-terminus: true`
5. Validator: enforce primary-source resolves in `sources.yaml` AND appears in `sources[]`

**Final count after apply**:
- Before audit: 37 artifact exit-nodes
- After audit (strict, PENDING → CULL): **24 exit-nodes** (35% cull)
- After audit (lenient, PENDING → register+KEEP): **26 exit-nodes** (30% cull)

**Concept exit-nodes (14)**: not yet audited — deferred to Phase 2. Different approach needed since concepts don't have exit-node frontmatter blocks. Could either add blocks during Phase 2 or define a narrower schema for concept-level attribution.

---

## Schema notes

**One registry correction applied during audit**: `ms-hibernate-the-system-hiberfil-sys-f` URL updated in `schema/sources.yaml` from Modern Standby page (didn't describe hiberfil content) to System Power States page (authoritative sentence extractable).

**Potential new sources to register** (if lenient path chosen for PENDING):
- `ms-varieties-of-kernel-mode-dump-files` — Microsoft Learn kernel-mode dump file docs; serves CrashDump-MEMDMP
- Swapfile replacement — TBD
