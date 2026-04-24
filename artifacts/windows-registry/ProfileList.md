---
name: ProfileList
aliases:
- user profile list
- ProfileImagePath map
- SID registry
link: user
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: NT4
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE
  path: Microsoft\Windows NT\CurrentVersion\ProfileList\<user-SID>
  addressing: hive+key-path
fields:
- name: user-sid
  kind: identifier
  location: <user-SID> subkey name
  encoding: sid-string
  references-data:
  - concept: UserSID
    role: identitySubject
  note: authoritative SID for this local or cached domain account
- name: profile-image-path
  kind: path
  location: ProfileImagePath value
  type: REG_EXPAND_SZ
  encoding: utf-16le
  note: "e.g., C:\\Users\\alice or %SystemDrive%\\Users\\alice — resolves SID → disk profile location. Corrected 2026-04-23 from REG_SZ to REG_EXPAND_SZ per Psmths forensic-artifacts writeup + live-registry evidence. Parser-impact: values may contain unexpanded environment variables (%SystemDrive%, %SystemRoot%) that REG_SZ parsers will not resolve. Always treat as REG_EXPAND_SZ and call ExpandEnvironmentStrings (or equivalent) before path-comparing."
- name: flags
  kind: flags
  location: Flags value
  type: REG_DWORD
- name: state
  kind: flags
  location: State value
  type: REG_DWORD
  note: "Profile state bitfield. Canonical values per Precedence Wiki / MS Windows 2000 Resource Kit: 0x001 = PROFILE_MANDATORY, 0x002 = PROFILE_USE_CACHE, 0x004 = PROFILE_NEW_LOCAL, 0x008 = PROFILE_NEW_CENTRAL, 0x010 = PROFILE_UPDATE_CENTRAL, 0x020 = PROFILE_DELETE_CACHE, 0x040 = PROFILE_UPGRADE, 0x080 = PROFILE_GUEST_USER, 0x100 = PROFILE_ADMIN_USER (using admin privileges), 0x200 = DEFAULT_NET_READY, 0x400 = SLOW_LINK, 0x800 = TEMP_ASSIGNED. Corrected 2026-04-23 — prior annotations (0x100=temporary, 0x200=mandatory, 0x400=roaming) were all wrong (temporary is 0x800, mandatory is 0x001, roaming is a SEPARATE ProfilePath/RUP mechanism not encoded in State). Forensically interesting bits: 0x001 (mandatory enforcement), 0x800 (TEMP_ASSIGNED — profile used this session but will not persist), 0x100 (admin-privileged profile load)."
- name: sid-binary
  kind: identifier
  location: Sid value
  type: REG_BINARY
  note: binary encoding of the SID — redundant with subkey name; useful for verification
- name: profile-load-time
  kind: timestamp
  location: ProfileLoadTimeHigh (upper 32) + ProfileLoadTimeLow (lower 32) values
  encoding: filetime split across two REG_DWORDs
  clock: system
  resolution: 100ns
  note: last time this profile was loaded
- name: local-profile-load-time
  kind: timestamp
  location: LocalProfileLoadTimeHigh/Low values
  encoding: filetime-split
  clock: system
  resolution: 100ns
- name: local-profile-unload-time
  kind: timestamp
  location: LocalProfileUnloadTimeHigh/Low values
  encoding: filetime-split
  clock: system
  resolution: 100ns
observations:
- proposition: EXISTS
  ceiling: C3
  note: canonical mapping from SID to profile path; foundational for per-user artifact attribution
  qualifier-map:
    entity.user-sid: field:user-sid
    entity.profile-path: field:profile-image-path
    time.start: field:profile-load-time
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: profile-deletion via Windows UI
    typically-removes: full
    note: removes the SID subkey AND the NTUSER.DAT hive directory
  - tool: manual reg-delete
    typically-removes: surgical
  survival-signals:
  - NTUSER.DAT directory present + no ProfileList entry for that SID = profile manually detached from registry (detached-hive
    analysis warranted)
provenance: [psmths-windows-forensic-artifacts-profilelist, inceptionsecurity-profilelists, carvey-windowsir-users-on-system, precedence-wiki-windows-profilestates]
exit-node:
  is-terminus: false
  terminates:
    - USED
    - AUTHENTICATED_AS
  sources:
    - psmths-windows-forensic-artifacts-profilelist
    - inceptionsecurity-profilelists
    - carvey-windowsir-users-on-system
  reasoning: >-
    ProfileList is the per-machine authoritative binding between a UserSID and its profile state (ProfileImagePath, Flags, LoadTime). When SAM establishes the SID-to-account mapping and NTDS.dit covers domain accounts, ProfileList closes the last gap — has-this-SID-loaded-a-profile-on-this-machine. For USED (at the per-user context) and AUTHENTICATED_AS (profile-actually-loaded), the ProfileList entry is the terminus; no downstream artifact refines it. Exit-node source list corrected 2026-04-23 — prior cite of ms-ntfs-on-disk-format-secure-system-f was an unrelated NTFS $Secure/$SDS article; swapped for Psmths (byte-layout primary), Inception-Security (.bak survival behavior), and Carvey (DFIR-canon provenance).
  implications: >-
    Defensible citation for user-activity localization. Proves a SID had a profile instantiated on the subject machine; distinguishes 'ambient domain-user SID that merely appeared in log data' from 'user with active session state here.' Flags the ProfileImagePath rename pattern used by some anti-forensic tools to decouple an SID from its original user folder.
  identifier-terminals-referenced:
    - UserSID
---

# ProfileList

## Forensic value
The authoritative mapping from Windows SID to on-disk user profile path. Without this lookup, per-user artifacts (MountPoints2, UserAssist, shellbags, LNK files under AppData) can't be attributed to a specific human account with confidence — you'd only know "some user" from an anonymous hive.

Minimal schema, high leverage: the user-SID subkey name resolves to a profile directory containing NTUSER.DAT + UsrClass.dat + AppData, which unlocks the full per-user artifact surface.

## Known quirks
- **Split-FILETIME timestamps** (`*TimeHigh` + `*TimeLow` as separate REG_DWORDs). Parsers must reassemble: `full = (high << 32) | low`.
- **ProfileImagePath is REG_EXPAND_SZ, not REG_SZ.** Values may contain `%SystemDrive%` / `%SystemRoot%`. Parsers that treat it as literal REG_SZ will fail to match real disk paths until ExpandEnvironmentStrings is applied.
- **State flags** (canonical bitmask per Precedence Wiki / Win2K Resource Kit): `0x001` PROFILE_MANDATORY, `0x080` PROFILE_GUEST_USER, `0x100` PROFILE_ADMIN_USER, `0x200` DEFAULT_NET_READY, `0x400` SLOW_LINK, `0x800` TEMP_ASSIGNED. Prior corpus listing (0x100=temporary, 0x200=mandatory, 0x400=roaming) was wrong; rewritten 2026-04-23.
- **Deleted profiles sometimes leave `ProfileList\<SID>.bak`** subkeys with the original entry renamed. Check for `.bak` suffix variants — per Inception-Security, these survive past profile deletion and extend the ProfileList terminus beyond active profiles.

## Practice hint
On a multi-user Windows box, parse ProfileList. Match each SID's ProfileImagePath to directories under `C:\Users\`. Confirm no disk-only directories without ProfileList entries (orphan profiles are investigative signals).
