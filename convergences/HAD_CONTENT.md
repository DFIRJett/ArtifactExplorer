---
name: HAD_CONTENT
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: HAD_CONTENT
  ceiling: C3
inputs:
  - CAPTURED_SCREEN
  - DRAFTED
  - PRINTED
input-sources:
  - proposition: CAPTURED_SCREEN
    artifacts:
      - Snipping-Tool-Captures
  - proposition: DRAFTED
    artifacts:
      - Notepad-TabState
  - proposition: PRINTED
    artifacts:
      - Print-Spool-Files
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-windows-notepad-restore-session-tab
      - hammond-2022-notepad-tabstate-bin-files-uns
      - aboutdfir-com-2023-windows-11-snipping-tool-foren
      - ms-print-spooler-architecture-spl-and
    primary-source: ms-windows-notepad-restore-session-tab
    description: |
      User-authored / user-captured content pivot. All three witnesses are
      per-user artifacts: Notepad-TabState lives in %LOCALAPPDATA%\Packages\
      Microsoft.WindowsNotepad (bound to NTUSER); Snipping-Tool-Captures
      lives in %LOCALAPPDATA%\Microsoft\Windows\Captures (same binding);
      Print-Spool-Files are attributed via the print job's submitting
      SID on the spooler service. Joining on UserSID attributes the
      authored/captured/printed content to a specific user. Memory exits
      (Hiberfil / Pagefile / Swapfile / CrashDump-MEMDMP) corroborate
      the content's live-memory presence but do not add user-attribution
      on their own — they inherit attribution from this user-scoped pivot.
    artifacts-and-roles:
      - artifact: Notepad-TabState
        role: identitySubject
      - artifact: Snipping-Tool-Captures
        role: identitySubject
      - artifact: Print-Spool-Files
        role: actingUser
exit-node:
  - Hiberfil
  - Pagefile
  - Swapfile
  - CrashDump-MEMDMP
notes:
  - 'Notepad-TabState: The buffer-content is direct proof the user authored the text. Pairs with logon-session data to attribute to a specific user.'
  - 'Print-Spool-Files: The SPL is a second copy of the printed document outside the source location — evidence the user possessed the content at print-submit time.'
  - 'Snipping-Tool-Captures: The PNG / MP4 is proof of prior possession of whatever was on screen at capture time.'
provenance:
  - ms-cortana-privacy-speech-data-retenti
  - matrix-nd-dt061-detect-text-authored-in
  - aboutdfir-com-2023-windows-11-snipping-tool-foren
  - ms-windows-notepad-restore-session-tab
  - hammond-2022-notepad-tabstate-bin-files-uns
  - ms-print-spooler-architecture-spl-and
  - 13cubed-2020-print-job-forensics-recovering
  - project-2023-windowsbitsqueuemanagerdatabas
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — HAD_CONTENT

Tier-2 convergence yielding proposition `HAD_CONTENT`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: Notepad-TabState, Print-Spool-Files, Snipping-Tool-Captures.
