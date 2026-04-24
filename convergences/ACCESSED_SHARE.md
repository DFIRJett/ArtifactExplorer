---
name: ACCESSED_SHARE
summary: "Network-share access proposition — a user / host accessed a remote SMB share. Joins share-audit events (Security-5140), user-intent LNK artifacts (NetworkShare-LNK, TypedPaths), and offline-cached share content (Offline-Files-CSC) via UNCPath + UserSID + TimeWindow pivots."
yields:
  mode: new-proposition
  proposition: ACCESSED_SHARE
  ceiling: C3
inputs:
  - ACCESSED_SHARE
  - USER_ACCESSED_SHARE
  - HAD_FILE
input-sources:
  - proposition: ACCESSED_SHARE
    artifacts:
      - Security-5140
  - proposition: USER_ACCESSED_SHARE
    artifacts:
      - NetworkShare-LNK
      - TypedPaths
  - proposition: HAD_FILE
    artifacts:
      - Offline-Files-CSC
join-chain:
  - concept: RegistryKeyPath
    join-strength: moderate
    sources:
      - ms-event-5140
      - windowsir-2013-file-access-typedpaths
    primary-source: ms-event-5140
    description: |
      UNC-path pivot (modeled as RegistryKeyPath because the
      corpus uses that concept for stringy paths). Security-5140
      emits ShareName + ShareLocalPath in the event payload
      (\\\\SERVER\\Share + \\??\\C:\\Path); NetworkShare-LNK
      stores the resolved UNC in the .lnk target + LinkInfo
      NetworkShareName; TypedPaths stores whatever UNC path the
      user typed into Explorer's address bar; Offline-Files-CSC
      stores per-file path under %SystemRoot%\\CSC\\<hash>\\.
      Joining on the UNC path binds audit-fact (5140) to user-
      intent (NetworkShare-LNK, TypedPaths) to offline-evidence
      (Offline-Files-CSC). The disagreement test: a path typed
      into TypedPaths but with no matching 5140 indicates
      attempted-but-refused share access (worth investigating).
    artifacts-and-roles:
      - artifact: Security-5140
        role: sharePath
      - artifact: NetworkShare-LNK
        role: sharePath
      - artifact: TypedPaths
        role: sharePath
      - artifact: Offline-Files-CSC
        role: sharePath
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-event-5140
    primary-source: ms-event-5140
    description: |
      Actor-attribution pivot. Security-5140 emits SubjectUserSid
      (the account that accessed the share); NetworkShare-LNK and
      TypedPaths live under HKU\\<SID>\\ — per-user hive anchored
      (each user has their own Typed-paths + their own
      Recent-items LNK collection); Offline-Files-CSC is technically
      system-scope but per-file FILE_SECURITY metadata preserves
      the owner SID. Joining on UserSID converts a generic share-
      access observation into "THIS account accessed THIS share"
      — the attribution grade claim needed for insider-threat or
      lateral-movement reconstructions.
    artifacts-and-roles:
      - artifact: Security-5140
        role: actingUser
      - artifact: NetworkShare-LNK
        role: actingUser
      - artifact: TypedPaths
        role: actingUser
  - concept: TimeWindow
    join-strength: moderate
    sources:
      - ms-event-5140
    primary-source: ms-event-5140
    description: |
      Temporal-bracketing pivot. Security-5140 carries the
      per-event TimeCreated; NetworkShare-LNK carries MAC
      timestamps + LinkModifiedTime; TypedPaths is indirect
      (the RegistryKeyPath LastWrite approximates when an entry
      was added — but MRU shift-and-evict obscures per-entry
      timing); Offline-Files-CSC carries per-file-cache
      modification timestamps. Joining on TimeWindow brackets
      "THIS user accessed THIS share between time A and time B"
      — the substrate for session-level reconstruction when
      paired with Security-4624 logon window.
    artifacts-and-roles:
      - artifact: Security-5140
        role: timeAnchor
      - artifact: NetworkShare-LNK
        role: timeAnchor
      - artifact: Offline-Files-CSC
        role: timeAnchor
exit-node:
  - Security-5140
  - Offline-Files-CSC
notes:
  - 'Security-5140: network-share-object-access audit event (File Share subcategory of Object Access). Emits SubjectUserSid + IpAddress + ShareName + ShareLocalPath. Exit-node for server-side share-access-fact.'
  - 'NetworkShare-LNK: .lnk file on the CLIENT pointing to a UNC target. Carries the resolved UNC, the server NetBIOS name, and MAC timestamps. Exit-node for client-side user-intent evidence.'
  - 'TypedPaths: HKCU\\...\\Explorer\\TypedPaths — addresses the user typed into Explorer. MRU of typed paths, not link-click paths. UNC entries here indicate the user intentionally accessed a share.'
  - 'Offline-Files-CSC: cached copies of SMB share content for offline use. Presence of cached content proves the user''s host accessed the share and chose to cache the file locally. Exit-node for cached-content-fact.'
provenance:
  - ms-event-5140
  - windowsir-2013-file-access-typedpaths
  - ms-offline-files-client-side-caching-o
  - for500-2022-offline-files-forensics-csc-na
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — ACCESSED_SHARE

Tier-2 convergence yielding proposition `ACCESSED_SHARE`.

Binds four network-share-access artifacts covering server-side audit (Security-5140), user-intent LNK records (NetworkShare-LNK, TypedPaths), and offline-cached share content (Offline-Files-CSC). UNC-path + UserSID + TimeWindow pivots resolve which user accessed which share and when.

Participating artifacts: Security-5140, NetworkShare-LNK, TypedPaths, Offline-Files-CSC.
