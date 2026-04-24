---
name: windows-text-log
kind: plaintext-log
substrate-class: Text Log
aliases: [Windows plaintext log, rotating system log]

format:
  storage: plaintext (UTF-16LE or UTF-8 depending on source)
  rotation: size-based (old file renamed with numeric suffix, new file started)
  authoritative-spec: "no single spec — each log format is defined by the writing component"

persistence:
  known-instances:
    "setupapi.dev.log":    "%WINDIR%\\INF\\setupapi.dev.log"
    "setupapi.setup.log":  "%WINDIR%\\INF\\setupapi.setup.log"
    "dism.log":            "%WINDIR%\\Logs\\DISM\\dism.log"
    "cbs.log":             "%WINDIR%\\Logs\\CBS\\CBS.log"
    "wlansvc":             "%WINDIR%\\Logs\\WMI\\*.etl (binary, not this class)"
  rotation-scheme: "<name>.log.<N> numbered sibling files; oldest dropped when new rotation triggered"
  locked-on-live-system: partial — tail-reading possible while service writes
  acquisition: standard file copy (all numbered variants)

parsers:
  - name: grep / ripgrep / PowerShell Select-String
    strengths: [line-oriented, fast for large logs]
  - name: Plaso / log2timeline
    strengths: [timeline integration, per-log parsers]
  - name: custom regex pipelines
    strengths: [flexible, log-specific]

forensic-relevance:
  - rotation-risk: "small log files rotate fast under load; acquire all numbered variants"
  - line-order-vs-timestamps: "lines are timestamp-ordered within a file but mixed between rotations; concat all rotations and re-sort by timestamp for canonical timeline"
  - embedded-identifiers: "some plaintext logs embed device serials, SIDs, file paths in free-form log messages; require log-specific regex to extract cleanly"

integrity:
  signing: none
  tamper-vectors:
    - direct file edit (any plaintext editor; no checksum)
    - selective line deletion
    - log-rotation-race (fill to force rotation out of a target window)
  audit-trail: "none — text logs have no integrity guard"

known-artifacts:
  # Plaintext-log substrate. Each artifact is a specific named log file with
  # its own schema, produced by a distinct Windows subsystem or third-party tool.
  authored:
    - Defender-MPLog           # Defender per-scan trace log
    - PSReadline-history       # interactive PowerShell command history
    - YARA-hits                # YARA tool scan output
    - firewall-log             # generic Windows Firewall pfirewall.log
    - proxy-log                # generic on-host/gateway proxy log
    - setupapi-dev-log         # SetupAPI device install history
  unwritten:
    - name: WindowsUpdate-log
      location: "%WINDIR%\\Logs\\WindowsUpdate (Win10+ ETL, decoded to text) or %WINDIR%\\WindowsUpdate.log (Win7)"
      value: update install/failure history; anomalies indicate tampered WU state
    - name: CBS-log
      location: "%WINDIR%\\Logs\\CBS\\CBS.log"
      value: component-based servicing (DISM/SFC) log — package installs, system-file-check output
    - name: DISM-log
      location: "%WINDIR%\\Logs\\DISM\\dism.log"
      value: image-servicing operations; traces OS imaging and feature enable/disable
    - name: CMD-History-Doskey
      location: in-memory only per cmd.exe session (not persisted by default)
      value: F7/doskey history — present only in memory forensics, not disk
    - name: WSL-BashHistory
      location: "\\\\wsl$\\<distro>\\home\\<user>\\.bash_history"
      value: Linux shell history on WSL installs — commonly forgotten by attackers
    - name: IIS-access-log
      location: "%SystemDrive%\\inetpub\\logs\\LogFiles\\W3SVC*\\u_ex*.log"
      value: W3C-format web-server access log — webshell/post-exploit traffic source
    - name: HTTPERR-log
      location: "%WINDIR%\\System32\\LogFiles\\HTTPERR\\*.log"
      value: HTTP.sys kernel-driver error log — connection-level evidence IIS missed
    - name: PowerShell-TranscriptLog
      location: "%USERPROFILE%\\Documents\\PowerShell_transcript.*.txt (if transcript logging enabled)"
      value: full-session PowerShell transcript when Transcription policy is on
    - name: SchedLgU
      location: "%WINDIR%\\Tasks\\SchedLgU.txt (legacy pre-Vista; sometimes lingers)"
      value: legacy Task Scheduler text log; occasionally present on upgraded systems
    - name: DHCP-Client-log
      location: "%WINDIR%\\System32\\winevt\\Logs\\Microsoft-Windows-Dhcp-Client%4Operational (EVTX, crossref) / legacy dhcpcli"
      value: DHCP lease assignment history — ties IP to MAC over time (mostly EVTX on modern Windows)
    - name: CrashDump-MEMDMP
      location: "%WINDIR%\\MEMORY.DMP + %WINDIR%\\Minidump\\*.dmp"
      value: kernel-crash memory dump — not text but commonly handled in log-acquisition workflows
    - name: PanGPS-log
      location: GlobalProtect / VPN client log paths (vendor-specific)
      value: VPN client session and endpoint-posture telemetry
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - ms-print-spooler-architecture-spl-and
---

# Windows Text Log

## Forensic value
Catch-all container for rotating plaintext logs Windows components write to disk. Individually of varying value, collectively important because they often capture events the structured event logs (EVTX) don't: early-boot hardware enumeration, install failures, OS update internals.

The setupapi.dev.log is the flagship of this class for DFIR: every PnP device enumeration / driver install writes a line, giving timestamped device-history evidence that survives some cleanup tools that target binary artifacts.

## Acquisition checklist
For a target text log, always acquire:
- The current file (`<name>.log`)
- All numbered rotations (`<name>.log.1`, `.log.2`, ...)
- The directory listing to confirm no gaps in rotation numbering

A gap in rotation sequence = a rotation file was deleted. Worth documenting.
