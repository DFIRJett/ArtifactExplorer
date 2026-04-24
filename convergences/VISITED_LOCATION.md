---
name: VISITED_LOCATION
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: VISITED_LOCATION
  ceiling: C3
inputs:
  - COMMUNICATED
  - HAD_CONTENT
input-sources:
  - proposition: COMMUNICATED
    artifacts:
      - NLA-Signatures-Unmanaged
  - proposition: HAD_CONTENT
    artifacts:
      - Cortana-CoreDb
join-chain:
  - concept: Location
    join-strength: weak
    sources:
      - ms-network-list-service-and-the-signat
      - ms-cortana-privacy-speech-data-retenti
      - singh-2017-cortana-forensics-windows-10
    primary-source: ms-network-list-service-and-the-signat
    description: |
      Two very different location models force a weak pivot. NLA-Signatures-
      Unmanaged binds a unique gateway MAC address to a network-profile
      entry with DateCreated / DateLastConnected timestamps — the host
      was physically close to THAT access point at that window.
      Cortana-CoreDb reminder trigger-location entries carry a
      geolocation (lat/lon / named-place) for user-designated geofences —
      the user deliberately marked a location of interest. Neither system
      shares a coordinate or identifier; both represent "place" at
      different abstractions (network-local vs. semantic geography). Weak
      pivot because matching requires human interpretation (e.g. "home
      router MAC" ↔ "home" reminder). Strengthens forensically when
      NLA timestamps bracket a Cortana reminder trigger — concurrent
      evidence the user was at the named place when the reminder fired.
    artifacts-and-roles:
      - artifact: NLA-Signatures-Unmanaged
        role: connectedNetwork
      - artifact: Cortana-CoreDb
        role: geolocatedTarget
exit-node: Location
notes:
  - 'Cortana-CoreDb: Reminder trigger-location entries are direct evidence the user designated / visited that geolocation.'
  - 'NLA-Signatures-Unmanaged: A unique gateway MAC is effectively a physical-location anchor. A network-history entry places the host at the router''s location at the time window bracketed by DateCreated / DateLastConnected.'
provenance:
  - ms-network-list-service-and-the-signat
  - carvey-2013-recentfilecache-bcf-parser-and
  - for508-2023-hibernation-file-analysis-in-i
  - ms-cortana-privacy-speech-data-retenti
  - singh-2017-cortana-forensics-windows-10
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - regripper-plugins
---

# Convergence — VISITED_LOCATION

Tier-2 convergence yielding proposition `VISITED_LOCATION`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Cortana-CoreDb, NLA-Signatures-Unmanaged.
