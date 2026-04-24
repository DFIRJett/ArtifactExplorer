---
name: STAGED
summary: "Content-staging proposition — user set aside content for subsequent movement (paste, sync, delete). Joins clipboard history (Windows-Clipboard) with deletion-staging (Recycle-Bin-INFO2) and cloud-sync pre-commit (OneDrive-SafeDelete) via UserSID + FILETIME pivots."
yields:
  mode: new-proposition
  proposition: STAGED
  ceiling: C3
inputs:
  - HAD_CONTENT
  - DELETED
input-sources:
  - proposition: HAD_CONTENT
    artifacts:
      - Windows-Clipboard
  - proposition: DELETED
    artifacts:
      - Recycle-Bin-INFO2
      - OneDrive-SafeDelete
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-windows-clipboard-history-feature-r
      - ms-how-the-recycle-bin-stores-files-in
    primary-source: ms-windows-clipboard-history-feature-r
    description: |
      Actor-attribution pivot. Windows-Clipboard History lives
      under %LOCALAPPDATA%\Microsoft\Windows\Clipboard — per-user.
      Recycle-Bin-INFO2 records the deleting-user SID (each $I
      file under $RECYCLE.BIN\<SID>\ is per-SID). OneDrive-
      SafeDelete mirrors the per-user OneDrive staging pre-
      commit to cloud. Joining on UserSID identifies which
      account staged content — attribution grade for insider-
      threat exfil-staging pattern detection: same user copies
      sensitive data to clipboard + deletes source file + syncs
      clipboard content to another channel.
    artifacts-and-roles:
      - artifact: Windows-Clipboard
        role: actingUser
      - artifact: Recycle-Bin-INFO2
        role: actingUser
      - artifact: OneDrive-SafeDelete
        role: actingUser
  - concept: FILETIME100ns
    join-strength: moderate
    sources:
      - ms-windows-clipboard-history-feature-r
    primary-source: ms-windows-clipboard-history-feature-r
    description: |
      Temporal-bracketing pivot. Windows-Clipboard entries carry
      per-entry timestamps. Recycle-Bin-INFO2 $I files store
      the deletion timestamp. OneDrive-SafeDelete tracks pre-
      commit staging times. Joining on FILETIME reconstructs the
      staging SEQUENCE: clipboard-copy at T1 + source delete at
      T2 + cloud-sync at T3 within seconds = coordinated exfil
      staging pattern. Time ordering distinguishes exfil-prep
      staging from routine content rearrangement.
    artifacts-and-roles:
      - artifact: Windows-Clipboard
        role: absoluteTimestamp
      - artifact: Recycle-Bin-INFO2
        role: absoluteTimestamp
      - artifact: OneDrive-SafeDelete
        role: absoluteTimestamp
exit-node:
  - Windows-Clipboard
  - Recycle-Bin-INFO2
notes:
  - 'Windows-Clipboard: Windows 10+ clipboard history store (Win+V). Cleartext or ciphertext content depending on app. Exit-node for clipboard-staging evidence — content IS in the store.'
  - 'Recycle-Bin-INFO2: $I sidecar files under $RECYCLE.BIN\<SID>\. Records original path + deletion timestamp + file size. Exit-node for deletion-as-staging evidence (attacker deletes source after copying elsewhere).'
  - 'OneDrive-SafeDelete: cloud-sync pre-commit staging. Records files marked-for-delete before cloud-side deletion fires. Useful for recovering briefly-staged-then-deleted evidence.'
provenance:
  - ms-windows-clipboard-history-feature-r
  - ms-how-the-recycle-bin-stores-files-in
  - forensics-2019-the-windows-swapfile-what-it-c
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — STAGED

Tier-2 convergence yielding proposition `STAGED`.

Binds three staging-evidence artifacts: clipboard history (Windows-Clipboard), recycle-bin deletion records (Recycle-Bin-INFO2), and OneDrive sync-staging (OneDrive-SafeDelete). UserSID + FILETIME pivots resolve which user staged what content when.

Participating artifacts: Windows-Clipboard, Recycle-Bin-INFO2, OneDrive-SafeDelete.
