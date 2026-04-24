---
name: VIEWED
summary: "Visual-content observation proposition — user saw / displayed / captured specific visual content. Joins thumbnail cache (Thumbcache-Entry), RDP visual tiles (RDP-Bitmap-Cache), and explicit screen captures (Snipping-Tool-Captures) via UserSID + TimeWindow + ExecutableHash pivots."
yields:
  mode: new-proposition
  proposition: VIEWED
  ceiling: C3
inputs:
  - VIEWED_REMOTE
  - VIEWED_OR_INDEXED
  - CAPTURED_SCREEN
input-sources:
  - proposition: VIEWED_REMOTE
    artifacts:
      - RDP-Bitmap-Cache
  - proposition: VIEWED_OR_INDEXED
    artifacts:
      - Thumbcache-Entry
  - proposition: CAPTURED_SCREEN
    artifacts:
      - Snipping-Tool-Captures
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - anssi-fr-2016-bmc-tools-python-tool-to-recon
      - libyal-libfwnt-job-file-format-libwrc-reverse
    primary-source: libyal-libfwnt-job-file-format-libwrc-reverse
    description: |
      Actor-attribution pivot. RDP-Bitmap-Cache lives under
      %LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache —
      per-user. Thumbcache-Entry is per-user at
      %LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db.
      Snipping-Tool-Captures writes under %LOCALAPPDATA%\Packages\
      Microsoft.ScreenSketch_8wekyb3d8bbwe\LocalState. Joining on
      UserSID (inferred from the containing profile path) resolves
      "this user saw / captured this visual content" — attribution-
      grade for insider-threat + incident reconstruction involving
      screenshotted sensitive content.
    artifacts-and-roles:
      - artifact: RDP-Bitmap-Cache
        role: actingUser
      - artifact: Thumbcache-Entry
        role: actingUser
      - artifact: Snipping-Tool-Captures
        role: actingUser
  - concept: FILETIME100ns
    join-strength: moderate
    sources:
      - libyal-libfwnt-job-file-format-libwrc-reverse
      - anssi-fr-2016-bmc-tools-python-tool-to-recon
    primary-source: libyal-libfwnt-job-file-format-libwrc-reverse
    description: |
      Temporal-bracketing pivot. RDP-Bitmap-Cache .bmc file mtimes
      advance per-session; Thumbcache-Entry each cached thumbnail
      carries a ModifiedTime at index-time (FILETIME). Snipping-
      Tool-Captures writes MAC timestamps per PNG / clip file.
      Joining on time brackets "what visual content was surfaced
      around T" — cross-reference with Security-4624 session window
      + file-access audit events to corroborate user presence.
    artifacts-and-roles:
      - artifact: RDP-Bitmap-Cache
        role: absoluteTimestamp
      - artifact: Thumbcache-Entry
        role: absoluteTimestamp
      - artifact: Snipping-Tool-Captures
        role: absoluteTimestamp
  - concept: ExecutableHash
    join-strength: moderate
    sources:
      - libyal-libfwnt-job-file-format-libwrc-reverse
    primary-source: libyal-libfwnt-job-file-format-libwrc-reverse
    description: |
      Content-identity pivot. Thumbcache-Entry keys on a 64-bit
      hash of the source-file path; Snipping-Tool-Captures stores
      PNG content (hashable); RDP-Bitmap-Cache stores 64x64 tile
      content (tile-hash). Joining on content-hash ties a cached
      thumbnail to a specific source file, or a snipping-tool PNG
      to a specific remote-tile rendering. Useful for "attacker-
      captured screenshot of THIS document" claims where content
      hashes match known-sensitive material.
    artifacts-and-roles:
      - artifact: Thumbcache-Entry
        role: artifactContent
      - artifact: Snipping-Tool-Captures
        role: artifactContent
      - artifact: RDP-Bitmap-Cache
        role: artifactContent
exit-node:
  - RDP-Bitmap-Cache
  - Snipping-Tool-Captures
  - Thumbcache-Entry
notes:
  - 'RDP-Bitmap-Cache: per-session tile store — definitive record of what the user saw over RDP. Exit-node for remote-session visual evidence.'
  - 'Thumbcache-Entry: Explorer-generated thumbnail cache — records thumbnails for every file-preview-capable file the user BROWSED (even without opening). Exit-node for "what files existed in the users view" inference; survives file deletion (thumbnail persists after source deleted).'
  - 'Snipping-Tool-Captures: explicit user-driven screenshots. Exit-node for intentional capture evidence — the PNG IS the content.'
provenance:
  - anssi-fr-2016-bmc-tools-python-tool-to-recon
  - ms-remote-desktop-protocol-bitmap-cach
  - libyal-libfwnt-job-file-format-libwrc-reverse
  - matrix-nd-dt061-detect-text-authored-in
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — VIEWED

Tier-2 convergence yielding proposition `VIEWED`.

Binds three visual-content artifacts covering remote-desktop session tiles (RDP-Bitmap-Cache), Explorer thumbnail cache (Thumbcache-Entry), and explicit screen captures (Snipping-Tool-Captures). UserSID + FILETIME + ExecutableHash pivots resolve which user saw what visual content and when.

Participating artifacts: RDP-Bitmap-Cache, Thumbcache-Entry, Snipping-Tool-Captures.
