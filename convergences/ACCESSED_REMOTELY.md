---
name: ACCESSED_REMOTELY
summary: "Per-session remote-access proposition — RDP / AnyDesk / remote-desktop class sessions. Joins RDP-family + AnyDesk artifacts via SessionId + PeerAddress + UserSID pivots. TerminalServerClient-Default + TS-Client-MRU anchor outgoing intent; RDP-Bitmap-Cache + TS-LSM-21 anchor connection fact; AnyDesk-Logs is the cross-tool peer for non-RDP remote sessions."
yields:
  mode: new-proposition
  proposition: ACCESSED_REMOTELY
  ceiling: C3
inputs:
  - COMMUNICATED
  - VIEWED_REMOTE
  - CONNECTED_VIA_RDP
  - CONNECTED
  - AUTHENTICATED
input-sources:
  - proposition: COMMUNICATED
    artifacts:
      - AnyDesk-Logs
  - proposition: VIEWED_REMOTE
    artifacts:
      - RDP-Bitmap-Cache
  - proposition: CONNECTED_VIA_RDP
    artifacts:
      - TerminalServerClient-Default
  - proposition: CONNECTED
    artifacts:
      - TS-Client-MRU
  - proposition: AUTHENTICATED
    artifacts:
      - TS-LSM-21
join-chain:
  - concept: PeerAddress
    join-strength: strong
    sources:
      - velociraptor-nd-windows-registry-rdp-artifact
      - anydesk-2023-anydesk-log-file-locations-and
      - ms-remote-desktop-protocol-bitmap-cach
    primary-source: ms-remote-desktop-protocol-bitmap-cach
    description: |
      Remote-peer pivot. TerminalServerClient-Default stores the
      MRU list of typed host names (mstsc /v:host); TS-Client-MRU
      stores the post-connect entries; AnyDesk-Logs records the
      peer AnyDesk-ID in the connection trace; TS-LSM-21 carries
      the remote ClientName/ClientAddress in the event payload;
      RDP-Bitmap-Cache stores the peer host implicitly in the
      per-session tile files. Joining on PeerAddress binds intent
      (I typed this hostname into mstsc) → connection fact (the
      session authenticated) → viewing evidence (tiles cached
      this peer's screen). A mismatch between MRU and TS-LSM-21
      authenticated peers is an indicator of attempted-but-refused
      connections.
    artifacts-and-roles:
      - artifact: TerminalServerClient-Default
        role: peerTyped
      - artifact: TS-Client-MRU
        role: peerTyped
      - artifact: AnyDesk-Logs
        role: peerConnected
      - artifact: TS-LSM-21
        role: peerConnected
      - artifact: RDP-Bitmap-Cache
        role: peerViewed
  - concept: LogonSessionId
    join-strength: strong
    sources:
      - ms-event-4624
      - thedfirspot-nd-lateral-movement-rdp-artifacts
    primary-source: ms-event-4624
    description: |
      Session-window pivot. TS-LSM-21 carries the SessionID field
      (Terminal Services session identifier, NOT the logon LUID);
      RDP-Bitmap-Cache tiles are written per-session to a GUID-
      keyed directory that maps to the Terminal Services session;
      AnyDesk-Logs tracks its own per-trace session-id but shares
      the Windows session context. Joining on the Terminal Services
      SessionID links the session-authenticate event (TS-LSM-21)
      to the visual evidence (RDP-Bitmap-Cache) to the typed-intent
      (TerminalServerClient-Default LastWrite timestamp proximity).
    artifacts-and-roles:
      - artifact: TS-LSM-21
        role: sessionWindow
      - artifact: RDP-Bitmap-Cache
        role: sessionWindow
      - artifact: AnyDesk-Logs
        role: sessionWindow
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-event-4624
      - velociraptor-nd-windows-registry-rdp-artifact
    primary-source: ms-event-4624
    description: |
      Actor-attribution pivot. TerminalServerClient-Default lives
      under HKU\<SID>\…\Terminal Server Client and is bound to a
      specific user hive; TS-Client-MRU is per-user; RDP-Bitmap-Cache
      is written under %LOCALAPPDATA% of the connecting user;
      TS-LSM-21 carries the acting user SID in the event payload;
      AnyDesk-Logs records the Windows user running the AnyDesk
      process. Joining on UserSID converts "someone RDP'd out from
      this host" into "this specific user account initiated the
      remote session" — the attribution-grade claim needed for
      insider-threat / lateral-movement reconstructions.
    artifacts-and-roles:
      - artifact: TerminalServerClient-Default
        role: actingUser
      - artifact: TS-Client-MRU
        role: actingUser
      - artifact: RDP-Bitmap-Cache
        role: actingUser
      - artifact: TS-LSM-21
        role: actingUser
      - artifact: AnyDesk-Logs
        role: actingUser
exit-node:
  - AnyDesk-Logs
  - TS-LSM-21
  - RDP-Bitmap-Cache
notes:
  - 'AnyDesk-Logs: per-session connection_trace with peer AnyDesk-ID + file-transfer list. Exit-node for non-RDP remote-access sessions.'
  - 'TS-LSM-21: Terminal Services Local Session Manager event on successful RDP session establishment. Exit-node for RDP connection-fact.'
  - 'RDP-Bitmap-Cache: per-session tile store written under %LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache. Exit-node for visual-viewing evidence (tiles reconstruct the screen content shown during the session).'
  - 'TerminalServerClient-Default: HKCU MRU of typed mstsc hostnames. Intent artifact — "user typed this hostname into mstsc" — not connection-fact.'
  - 'TS-Client-MRU: post-connect HKCU entries (10-entry MRU0..MRU9, shift-and-evict). Captures the RECENT outbound RDP targets specifically.'
provenance:
  - velociraptor-nd-windows-registry-rdp-artifact
  - ms-event-4624
  - thedfirspot-nd-lateral-movement-rdp-artifacts
  - anydesk-2023-anydesk-log-file-locations-and
  - aa24-131a-2024-anydesk-in-ransomware-incident
  - research-2023-blackbasta-lockbit-use-of-anyd
  - ms-remote-desktop-protocol-bitmap-cach
  - thedfirspot-nd-lateral-movement-rdp-artifacts
  - velociraptor-nd-windows-registry-rdp-artifact
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — ACCESSED_REMOTELY

Tier-2 convergence yielding proposition `ACCESSED_REMOTELY`.

Binds five remote-access artifacts across the RDP + AnyDesk surfaces. Outgoing-intent (TerminalServerClient-Default, TS-Client-MRU) joins to connection-fact (TS-LSM-21, AnyDesk-Logs) joins to visual-evidence (RDP-Bitmap-Cache) via PeerAddress + LogonSessionId + UserSID pivots.

Participating artifacts: AnyDesk-Logs, RDP-Bitmap-Cache, TerminalServerClient-Default, TS-Client-MRU, TS-LSM-21.
