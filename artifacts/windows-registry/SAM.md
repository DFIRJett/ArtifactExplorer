---
name: SAM
aliases:
- Security Account Manager
- local user accounts
- SAM hive
link: user
tags:
- tamper-hard
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SAM
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SAM
  path: SAM\Domains\Account\Users\<RID-hex>
  addressing: hive+key-path
  machine-sid-at: SAM\Domains\Account — V value contains machine SID
fields:
- name: rid
  kind: identifier
  location: <RID-hex> subkey name
  encoding: hex
  note: Relative Identifier — the low 32 bits of the full SID (machine SID + RID = full SID)
- name: full-user-sid
  kind: identifier
  location: 'derived: machine-SID + rid'
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: identitySubject
- name: username
  kind: identifier
  location: V value — parsed from binary structure
  encoding: utf-16le-in-binary
  note: user account name (sAMAccountName on domain-joined machines)
- name: full-name
  kind: identifier
  location: V value — separate field
  encoding: utf-16le-in-binary
- name: account-comment
  kind: identifier
  location: V value — comment field
  encoding: utf-16le-in-binary
- name: password-hash
  kind: hash
  location: V value — LM/NTLM hash blobs (encrypted with system key)
  encoding: AES/DES-encrypted per hive bootkey
  note: NOT directly readable — requires bootkey from SYSTEM hive to decrypt. Offline cracking is the common attack path.
- name: last-logon-time
  kind: timestamp
  location: F value — last logon timestamp
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: last-password-set-time
  kind: timestamp
  location: F value — password-change timestamp
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: account-expiry-time
  kind: timestamp
  location: F value
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: last-incorrect-password-time
  kind: timestamp
  location: F value
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: account-flags
  kind: flags
  location: F value — account control bitfield
  encoding: uint32
  note: 0x0001=disabled, 0x0010=locked, 0x0200=pw-never-expires, 0x8000=domain-trust, etc.
- name: login-count
  kind: counter
  location: F value
  encoding: uint16
- name: bad-password-count
  kind: counter
  location: F value
  encoding: uint16
observations:
- proposition: EXISTS
  ceiling: C3
  note: 'Canonical local-account registry. Establishes that a given SID

    corresponds to a named local user, with password-related metadata.

    On domain-joined machines, domain accounts DO NOT appear here — SAM

    only covers local accounts (including built-in Administrator/Guest).

    '
  qualifier-map:
    entity.user-sid: field:full-user-sid
    entity.username: field:username
    entity.flags: field:account-flags
    time.start: field:last-logon-time
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: password-hash encryption tied to bootkey (SYSTEM hive)
  known-cleaners:
  - tool: net user /delete <name>
    typically-removes: partial
    note: removes account from ProfileList and SAM but leaves NTUSER.DAT on disk unless profile is also deleted
  - tool: direct SAM hive edit offline
    typically-removes: selective
    note: sticky-keys attack variant deletes SAM entries; detectable by missing RID ranges
  survival-signals:
  - Orphan NTUSER.DAT directories (SID in ProfileList but not in SAM) = account deleted but profile remains
  - Non-contiguous RID values = accounts deleted (SAM doesn't recycle RIDs)
provenance:
  - gentilkiwi-2020-mimikatz-lsadump-cache-extract
  - mitre-t1003-002
exit-node:
  is-terminus: true
  primary-source: mitre-t1003-002
  attribution-sentence: 'The SAM is a database file that contains local accounts for the host, typically those found with the `net user` command (MITRE ATT&CK, n.d.).'
  terminates: []
  sources:
    - gentilkiwi-2020-mimikatz-lsadump-cache-extract
    - mitre-t1003-002
  reasoning: >-
    SAM hive is the machine-local authoritative store for user principal data — every local SID-to-account binding originates here. For local accounts, UserSID resolution terminates at SAM; no downstream artifact provides a more authoritative mapping.
  implications: >-
    Defensible citation for local-account SID-to-username resolution. Complementary to NTDS.dit (domain): the pair lets analysts disambiguate whether a SID observed in an event log is local or domain-scoped by looking up in both stores and checking which returns a match.
  preconditions: "Offline extraction recommended; registry transaction logs replayed."
  identifier-terminals-referenced:
    - UserSID
---

# Security Account Manager (SAM)

## Forensic value
Canonical store for local user accounts. Each account has an RID subkey under `SAM\Domains\Account\Users\`; the RID combined with the machine SID (also stored in SAM) gives the full SID used everywhere else in Windows forensic artifacts. Without SAM's username lookup, user-SIDs from event logs and per-user artifacts are anonymous hex strings.

## Concept reference
- UserSID — derived combination of machine-SID + RID

## Known quirks
- **Password hashes are encrypted.** V value contains LM/NTLM hashes encrypted with a key derived from SYSTEM hive. Offline analysis tools (secretsdump.py, samdump2) use the SYSTEM hive's bootkey to decrypt.
- **Domain accounts absent.** SAM only covers LOCAL accounts. For domain accounts, pair with NTDS.dit (AD database) or cached credentials in SECURITY hive.
- **RIDs don't recycle.** Deleted accounts leave gaps in the RID sequence — visible evidence of deletion even if the account's other registry/hive traces are scrubbed.
- **F and V values are binary structures.** Offsets within the blobs differ by Windows version. Use version-aware parsers (RegRipper `samparse`, secretsdump.py, Impacket utilities).

## Anti-forensic caveats
SAM is ACL-protected on live systems (SYSTEM-token required), making it hard to tamper without admin. Offline attacks via raw-disk access are possible but leave timing evidence in SAM's key LastWrite timestamps.

The classic "sticky-keys" attack used Utilman.exe hijacking to gain SYSTEM-context command prompt at logon screen — then modifications to SAM. Detection: compare SAM hive LastWrite against SYSTEM hive LastWrite for the same account boundary.

## Practice hint
Copy SAM + SYSTEM hives from a test VM. Use `secretsdump.py -sam SAM -system SYSTEM LOCAL` to extract accounts + LM/NTLM hashes. Cross-reference RIDs to ProfileList SIDs for full account/profile mapping.
