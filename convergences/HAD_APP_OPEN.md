---
name: HAD_APP_OPEN
summary: "App-in-memory proposition — a specific application had open state at the time of memory capture / hibernate / swap. Joins volatile-memory artifacts (Swapfile, Hiberfil, Pagefile) with per-app telemetry (Cortana-IndexedDB, Cortana-CoreDb, Notifications-wpnidm) via AppIdentifier + UserSID + TimeWindow pivots."
yields:
  mode: new-proposition
  proposition: HAD_APP_OPEN
  ceiling: C3
inputs:
  - HAD_CONTENT
input-sources:
  - proposition: HAD_CONTENT
    artifacts:
      - Swapfile
      - Hiberfil
      - Pagefile
      - Cortana-IndexedDB
      - Cortana-CoreDb
      - Notifications-wpnidm
join-chain:
  - concept: AppIdentifier
    join-strength: strong
    sources:
      - ms-uwp-app-lifecycle-suspend-resume-sw
      - forensics-2019-the-windows-swapfile-what-it-c
    primary-source: ms-uwp-app-lifecycle-suspend-resume-sw
    description: |
      Application-identity pivot. Swapfile carries package-family
      name fragments for UWP apps at suspend points; Notifications-
      wpnidm indexes per-package notification records by PackageID;
      Cortana-IndexedDB stores per-app search query context keyed
      on originating AppID; Cortana-CoreDb mirrors that with
      conversational-agent entries. Hiberfil + Pagefile carry raw
      process-memory blobs that resolve to a specific AppID when
      parsed for PEB / module list. Joining on AppIdentifier binds
      "some app was open" to "THIS specific app (by package-family-
      name / AppID) was open at the capture moment" — the claim
      needed to assert forensic-relevant application state for
      insider-threat reconstructions (was the messaging app open
      when the exfil occurred? was the screenshot tool running?).
    artifacts-and-roles:
      - artifact: Swapfile
        role: appIdentity
      - artifact: Notifications-wpnidm
        role: appIdentity
      - artifact: Cortana-IndexedDB
        role: appIdentity
      - artifact: Cortana-CoreDb
        role: appIdentity
      - artifact: Hiberfil
        role: appIdentity
      - artifact: Pagefile
        role: appIdentity
  - concept: UserSID
    join-strength: moderate
    sources:
      - ms-uwp-app-lifecycle-suspend-resume-sw
    primary-source: ms-uwp-app-lifecycle-suspend-resume-sw
    description: |
      Actor-attribution pivot. Cortana-IndexedDB + Cortana-CoreDb
      are per-user (%LOCALAPPDATA%\Packages\Microsoft.Windows.Cortana\
      LocalState). Notifications-wpnidm is per-user
      (%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpnidm\).
      Swapfile.sys / Hiberfil.sys / Pagefile.sys are system-wide
      but the process-memory they contain carries SID tags on
      token objects. Joining on UserSID answers "which account
      had this app open?" — critical in multi-user contexts
      (terminal-server, shared workstation) where the app
      identity alone doesn't resolve attribution.
    artifacts-and-roles:
      - artifact: Cortana-IndexedDB
        role: actingUser
      - artifact: Cortana-CoreDb
        role: actingUser
      - artifact: Notifications-wpnidm
        role: actingUser
      - artifact: Swapfile
        role: actingUser
      - artifact: Hiberfil
        role: actingUser
      - artifact: Pagefile
        role: actingUser
  - concept: TimeWindow
    join-strength: moderate
    sources:
      - forensics-2019-the-windows-swapfile-what-it-c
    description: |
      Temporal-bracketing pivot. Swapfile last-write approximates
      suspend moment; Hiberfil last-write approximates hibernate
      moment; Pagefile last-write reflects paging-activity
      (less precise); Cortana-IndexedDB + Cortana-CoreDb carry
      per-record timestamps for query events; Notifications-
      wpnidm carries Created / Expiry per entry. Joining on
      TimeWindow lets an analyst bracket "this app was open
      sometime between 14:00 and 14:05" based on converging
      evidence (notification timestamp at 14:02 + Cortana query
      at 14:03 + suspend-to-swapfile at 14:05) — not point-in-
      time, but within a windowed claim strong enough to
      correlate with session-level evidence.
    artifacts-and-roles:
      - artifact: Swapfile
        role: timeAnchor
      - artifact: Hiberfil
        role: timeAnchor
      - artifact: Pagefile
        role: timeAnchor
      - artifact: Notifications-wpnidm
        role: timeAnchor
      - artifact: Cortana-IndexedDB
        role: timeAnchor
      - artifact: Cortana-CoreDb
        role: timeAnchor
exit-node:
  - Hiberfil
  - Swapfile
notes:
  - 'Swapfile: UWP app suspend/resume memory dump. Volatile — overwritten on next suspend cycle. Exit-node for per-app mid-session state when hibernate has not been performed.'
  - 'Hiberfil: full-RAM snapshot on hibernate — includes every process active at hibernate moment. Exit-node for comprehensive app state at hibernate time.'
  - 'Pagefile: paged-out process memory — fragments of app state from processes under memory pressure. Weaker than Swapfile/Hiberfil but broader coverage.'
  - 'Cortana-IndexedDB: per-user Cortana query + response cache. Binds app-identity (Cortana) to content (queries) for the user.'
  - 'Cortana-CoreDb: conversational-agent record — sibling of IndexedDB.'
  - 'Notifications-wpnidm: Win10+ notification database. Per-package-family-name toast notifications with Created/Expiry timestamps. Evidence that a package existed and received notifications on this machine in recent time.'
provenance:
  - ms-uwp-app-lifecycle-suspend-resume-sw
  - forensics-2019-the-windows-swapfile-what-it-c
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — HAD_APP_OPEN

Tier-2 convergence yielding proposition `HAD_APP_OPEN`.

Binds six volatile-memory + per-app-telemetry artifacts across Swapfile / Hiberfil / Pagefile (memory-capture) and Cortana / Notifications (per-app telemetry). AppIdentifier + UserSID + TimeWindow pivots resolve which application was in memory for which user in which time window.

Participating artifacts: Swapfile, Hiberfil, Pagefile, Cortana-IndexedDB, Cortana-CoreDb, Notifications-wpnidm.
