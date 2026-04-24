---
name: EXECUTED_FROM
summary: "Execution-path proposition — where a binary actually ran from. Joins process-creation event sources (Sysmon-1, Security-4688) with per-user execution caches (UserAssist, BAM, DAM, RecentApps, Prefetch) via ExecutablePath + UserSID + TimeWindow pivots. Distinguishes execution-from-profile / execution-from-removable / execution-from-temp patterns."
yields:
  mode: new-proposition
  proposition: EXECUTED_FROM
  ceiling: C3
inputs:
  - EXECUTED
input-sources:
  - proposition: EXECUTED
    artifacts:
      - Prefetch
      - Amcache-InventoryApplicationFile
      - Sysmon-1
      - Security-4688
      - UserAssist
      - BAM
      - DAM
      - RecentApps
join-chain:
  - concept: ExecutablePath
    join-strength: strong
    sources:
      - libyal-libscca
      - ms-event-4688
      - lagny-2019-anssi-analysis-amcache
    primary-source: ms-event-4688
    description: |
      Binary-identity pivot. Prefetch stores the exact resolved
      path inside the .pf file (including the \VOLUME{guid}\ prefix
      that maps to MountedDevices for removable-media detection);
      Amcache-InventoryApplicationFile stores LowerCaseLongPath with
      SHA1 hash; Sysmon-1 carries Image in the EventData payload;
      Security-4688 carries NewProcessName; UserAssist stores the
      ROT13-encoded full path; BAM + DAM store per-SID executable
      paths with last-execute timestamps. Joining on ExecutablePath
      converts a vague "this EXE ran" into "this EXE at THIS
      specific path, on THIS volume, ran" — the substrate for
      EXECUTED_FROM claims about removable media, temp directories,
      or user-profile locations attackers prefer.
    artifacts-and-roles:
      - artifact: Prefetch
        role: executableLocation
      - artifact: Amcache-InventoryApplicationFile
        role: executableLocation
      - artifact: Sysmon-1
        role: executableLocation
      - artifact: Security-4688
        role: executableLocation
      - artifact: UserAssist
        role: executableLocation
      - artifact: BAM
        role: executableLocation
      - artifact: DAM
        role: executableLocation
      - artifact: RecentApps
        role: executableLocation
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-event-4688
      - suhanov-2020-dfir-ru-bam-internals
    primary-source: ms-event-4688
    description: |
      Actor-attribution pivot. UserAssist + RecentApps live in
      HKU\<SID>\…\Explorer\UserAssist / \Search\RecentApps — per-user
      hive-scoped; BAM stores exe-paths under
      HKLM\SYSTEM\…\bam\State\UserSettings\<SID>\… indexed by SID;
      DAM mirrors the same pattern. Sysmon-1 + Security-4688 emit
      SubjectUserSid in EventData. Prefetch has no user attribution
      directly but links via ProcessId/TimeCreated to the emitting
      event. Joining on UserSID converts "this EXE ran on this host"
      into "this user account executed this EXE" — an attribution
      chain that often survives even when live authentication logs
      have been cleared (because the per-user registry caches
      persist independently of Security log retention).
    artifacts-and-roles:
      - artifact: UserAssist
        role: actingUser
      - artifact: RecentApps
        role: actingUser
      - artifact: BAM
        role: actingUser
      - artifact: DAM
        role: actingUser
      - artifact: Sysmon-1
        role: actingUser
      - artifact: Security-4688
        role: actingUser
  - concept: TimeWindow
    join-strength: moderate
    sources:
      - libyal-libscca
      - suhanov-2020-dfir-ru-bam-internals
    primary-source: libyal-libscca
    description: |
      Temporal-bracketing pivot. Prefetch's LastRun timestamps
      (up to 8 historical runs in Win10+ .pf format); Amcache's
      FirstSeen / LastSeen; Sysmon-1 + Security-4688 UtcTime /
      TimeCreated; UserAssist FocusCount + LastExecutedTime; BAM +
      DAM SequenceNumber + timestamp. Joining on TimeWindow lets
      an analyst correlate simultaneous evidence across caches:
      "Sysmon-1 at 14:23:07 + Prefetch LastRun at 14:23:08 +
      UserAssist LastExecutedTime at 14:23:09" is strong evidence
      of a single real execution event (Prefetch can lag by
      ~10s as the flush trigger fires on unload). Cross-cache
      time agreement is the primary disagreement-exposure test —
      conflicting timestamps expose timestomping or delayed
      Amcache inventory scans.
    artifacts-and-roles:
      - artifact: Prefetch
        role: timeAnchor
      - artifact: Amcache-InventoryApplicationFile
        role: timeAnchor
      - artifact: Sysmon-1
        role: timeAnchor
      - artifact: Security-4688
        role: timeAnchor
      - artifact: UserAssist
        role: timeAnchor
      - artifact: BAM
        role: timeAnchor
      - artifact: DAM
        role: timeAnchor
exit-node:
  - Prefetch
  - Amcache-InventoryApplicationFile
  - Sysmon-1
notes:
  - 'Prefetch: .pf file carries volume-device-path + full EXE path + up to 8 LastRun timestamps + loaded DLL list. Exit-node for EXECUTED_FROM(removable-media) when volume-device-path resolves via MountedDevices to a USB volume-GUID.'
  - 'Amcache-InventoryApplicationFile: Amcache.hve / AmCache.hve — LowerCaseLongPath + SHA1 + FirstSeen. Exit-node for binary identity (SHA1 survives even if the file is deleted from disk).'
  - 'Sysmon-1: authoritative per-execution event with full Image + CommandLine + ParentImage + IntegrityLevel + Hashes. Exit-node for live-response / incident reconstruction when Sysmon is deployed.'
  - 'Security-4688: Windows native per-process-create event. Weaker than Sysmon-1 (no hashes, CommandLine requires audit policy bit, truncated at 4KB) but universal when Sysmon is absent.'
  - 'UserAssist: per-user Explorer-launched GUI-app counter + timestamp. Strong for interactive-GUI user-launched-EXE claims; useless for headless / service-account / cmd-line-only executions.'
  - 'BAM: HKLM\SYSTEM\...\bam per-SID recently-executed-apps cache. Survives logoff. Pairs with Security-4624 logon events for full per-session execution reconstruction.'
  - 'DAM: sibling of BAM for desktop-activity moderator. Same structure, different service, same forensic role.'
  - 'RecentApps: HKCU per-user recent-apps list (Win10 Start-menu telemetry). LastAccessedTime per app.'
provenance:
  - ms-event-4688
  - libyal-libscca
  - lagny-2019-anssi-analysis-amcache
  - suhanov-2020-dfir-ru-bam-internals
  - carvey-2022-windows-forensic-analysis-tool
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — EXECUTED_FROM

Tier-2 convergence yielding proposition `EXECUTED_FROM`.

Binds eight execution-evidence artifacts across process-creation events (Sysmon-1, Security-4688), per-user registry caches (UserAssist, BAM, DAM, RecentApps), and file-system caches (Prefetch, Amcache). ExecutablePath + UserSID + TimeWindow pivots resolve the binary's identity, the acting user, and the execution moment.

Participating artifacts: Prefetch, Amcache-InventoryApplicationFile, Sysmon-1, Security-4688, UserAssist, BAM, DAM, RecentApps.
