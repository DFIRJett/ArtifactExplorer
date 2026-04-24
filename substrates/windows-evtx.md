---
name: windows-evtx
kind: binary-structured-file
substrate-class: Event Log
aliases: [EVTX, Windows Event Log, binary XML event log]

format:
  magic: "ElfFile"
  endianness: little
  version: "3.x (Vista–11)"
  authoritative-spec:
    - title: "Windows XML Event Log (EVTX) format specification"
      author: Joachim Metz
      url: https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc

structure:
  header:
    name: ELF file header
    size-bytes: 4096
    key-fields:
      - name: first-chunk-number
      - name: last-chunk-number
      - name: next-record-identifier
      - name: header-block-size
      - name: checksum
  body:
    unit: chunk
    chunk-size: 65536
    cell-contents: [record-templates, event-records, template-definitions]
    event-record-format: binary-XML (BXML) — compressed with template substitution
  addressing:
    scheme: "chunk-number + record-identifier"
    channel-scope: "one channel per file, channel name encoded in filename"

persistence:
  live-system-location:
    root: "%WINDIR%\\System32\\winevt\\Logs"
    filename-encoding: "channel name with '/' encoded as '%4'"
    example-instances:
      Security:                                   "Security.evtx"
      System:                                     "System.evtx"
      Application:                                "Application.evtx"
      "Microsoft-Windows-Partition/Diagnostic":   "Microsoft-Windows-Partition%4Diagnostic.evtx"
      "Microsoft-Windows-DriverFrameworks-UserMode/Operational": "Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx"
      "Microsoft-Windows-Sysmon/Operational":     "Microsoft-Windows-Sysmon%4Operational.evtx"
      "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
  locked-on-live-system: true
  acquisition:
    methods:
      - wevtutil export-log <channel> <path>
      - VSC-based copy
      - raw-disk read (FTK Imager, dd)

retention:
  policy: "per-channel circular buffer (default sizes vary: Security ~20MB, Operational channels smaller)"
  configuration-path: HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\<channel>
  rotation-risk: "high-value forensic events roll off frequently on busy systems; acquire early"

parsers:
  - name: Event Log Explorer (commercial)
    strengths: [GUI, channel-aware search, XPath queries]
  - name: EvtxECmd (Eric Zimmerman)
    strengths: [bulk CSV export, signature-detection, free]
  - name: python-evtx (Willi Ballenthin)
    strengths: [programmatic access, research-grade]
  - name: wevtutil (built-in)
    strengths: [native Windows, scriptable]
    weaknesses: [requires live system access]
  - name: libevtx (Joachim Metz)
    strengths: [format-correct, dirty-file recovery]

forensic-relevance:
  - channel-specificity: |
      Each channel carries a distinct investigative scope. Security.evtx covers
      authentication; Microsoft-Windows-Partition/Diagnostic covers device mount
      events; Sysmon covers detailed process/network telemetry. An artifact's
      substrate-instance must name the specific channel, not just "evtx".
  - dirty-file-recovery: |
      EVTX chunks can be recovered from unallocated space on a volume — event
      records often survive after the log file itself rolls over or is deleted.
      EvtxECmd has a --dirty option.
  - event-id-granularity: |
      One evtx channel typically generates many event IDs. Each event ID with
      distinct forensic meaning is its own artifact — Security 4624 is not the
      same artifact as Security 4625, even though they share the container.

integrity:
  signing: "event record checksums; chunk CRCs"
  audit: "events are append-only at the API level; offline edit possible with admin + raw-disk access"
  tamper-vectors:
    - EventLog service stop + file modification
    - offline edit via evtx parser libraries
    - wevtutil clear-log (audit event emitted to Security 1102)
    - selective chunk overwrite (leaves integrity-check failures detectable by libevtx)

anti-forensic-concerns:
  - Clearing a channel emits Security event 1102 ("audit log cleared") — clearers often leave this trace unless they also wipe Security.evtx.
  - Log rotation happens naturally on busy systems; attackers sometimes flood with noise events to accelerate rotation of incriminating entries ("log-evict" technique).
  - Kernel-logged channels (Partition/Diagnostic, Kernel-PnP) are harder to edit without detection than service-logged channels.

known-artifacts:
  # Roster of forensically-documented per-channel EVTX artifacts.
  # Naming convention: `<ChannelShort>-<EventID>` for per-event artifacts,
  # or `<ChannelShort>-Operational` for multi-event channel summaries.
  # Seed source: existing authored set, cross-verified against Ultimate Windows
  # Security event reference, stuhli/awesome-event-ids, SANS Hunt Evil poster,
  # and the EvtxECmd Map Repository conventions.
  authored:
    - Security-1102           # audit log cleared
    - Security-4624           # successful logon
    - Security-4625           # failed logon
    - Security-4634           # account logoff
    - Security-4648           # explicit-credentials logon
    - Security-4688           # process creation
    - Security-4720           # local account created
    - PowerShell-4104         # script block logging
    - Sysmon-1                # process create
    - Sysmon-3                # network connection
    - Sysmon-7                # image/DLL load
    - Sysmon-11               # file create
    - Sysmon-13               # registry value set
    - Sysmon-22               # DNS query
    - DriverFrameworks-Operational  # UMDF device lifecycle (2003/2004/2100/2101/2102/2105 as a set)
    - PartitionDiagnostic-1006      # volume mount
    - TS-LSM-21               # RDP session logon
    - DeviceSetup-20001
    - DeviceSetup-20003
    - Firewall-2004
    - Firewall-2006
    - Firewall-2033
    - Security-4647
    - System-7036
    - TaskScheduler-201
  unwritten:
    - WPD-MTPClassDriver-1005      # USB-event sibling (Carvey 2022 USB Redux)
    - DeviceSetupManager-112        # USB-event sibling
    - StorageSpaces-Driver-207      # USB-event sibling
    - Ntfs-Operational-145          # NTFS event
    - Ntfs-Operational-142          # NTFS event
provenance:
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - hartong-2024-sysmon-modular-a-repository-of
  - libyal-libevtx
  - libyal-libfwevt-libfwevt-windows-xml-event-log
  - ms-advanced-audit-policy
  - ms-sysmon-system-monitor
--- Security channel (auditing-dependent) ---
    - name: Security-4672
      location: Security.evtx
      value: special privileges assigned at logon — admin/SYSTEM elevation marker
    - name: Security-4697
      location: Security.evtx
      value: service installed — Cobalt Strike/lateral-movement indicator (complement to System-7045)
    - name: Security-4698
      location: Security.evtx
      value: scheduled task created — persistence
    - name: Security-4699
      location: Security.evtx
      value: scheduled task deleted — cleanup signal
    - name: Security-4663
      location: Security.evtx
      value: object-access-attempted — file/registry SACL hits (noisy without scoped auditing)
    - name: Security-4726
      location: Security.evtx
      value: local account deleted
    - name: Security-4732
      location: Security.evtx
      value: member added to security-enabled local group — privilege-granting
    - name: Security-4740
      location: Security.evtx
      value: account locked out — brute-force/password-spray signal
    - name: Security-4768
      location: Security.evtx
      value: Kerberos TGT request — DC-side authentication origination
    - name: Security-4769
      location: Security.evtx
      value: Kerberos TGS request — service-ticket request; Kerberoasting detection
    - name: Security-4776
      location: Security.evtx
      value: NTLM authentication attempt — legacy auth fallback marker
    - name: Security-5140
      location: Security.evtx
      value: network share accessed
    - name: Security-5145
      location: Security.evtx
      value: network share object accessed with requested permissions — granular share I/O
    # --- System channel (no auditing required) ---
    - name: System-7045
      location: System.evtx
      value: service installed — always-on counterpart to Security-4697
    - name: System-104
      location: System.evtx
      value: non-Security log cleared — complement to Security-1102
    - name: System-1074
      location: System.evtx
      value: system shutdown/restart initiated, with initiator process
    - name: System-6005
      location: System.evtx
      value: event-log service started — system-boot marker
    - name: System-6006
      location: System.evtx
      value: event-log service stopped — shutdown marker
    - name: System-41
      location: System.evtx
      value: kernel-power unexpected shutdown (power loss or crash)
    # --- Sysmon/Operational additional ---
    - name: Sysmon-2
      location: Microsoft-Windows-Sysmon/Operational
      value: file creation time changed — timestomp indicator
    - name: Sysmon-5
      location: Microsoft-Windows-Sysmon/Operational
      value: process terminated
    - name: Sysmon-6
      location: Microsoft-Windows-Sysmon/Operational
      value: driver loaded — kernel-level persistence or BYOVD
    - name: Sysmon-8
      location: Microsoft-Windows-Sysmon/Operational
      value: CreateRemoteThread — classic process-injection signal
    - name: Sysmon-10
      location: Microsoft-Windows-Sysmon/Operational
      value: process accessed — credential theft / LSASS read detection
    - name: Sysmon-12
      location: Microsoft-Windows-Sysmon/Operational
      value: registry object create/delete
    - name: Sysmon-15
      location: Microsoft-Windows-Sysmon/Operational
      value: FileCreateStreamHash — ADS and downloaded-file hash capture
    - name: Sysmon-17
      location: Microsoft-Windows-Sysmon/Operational
      value: named pipe created — IPC persistence
    - name: Sysmon-18
      location: Microsoft-Windows-Sysmon/Operational
      value: named pipe connected — C2 pipe-connection trace
    - name: Sysmon-19
      location: Microsoft-Windows-Sysmon/Operational
      value: WMI event filter registered — persistence
    - name: Sysmon-20
      location: Microsoft-Windows-Sysmon/Operational
      value: WMI event consumer registered — persistence
    - name: Sysmon-21
      location: Microsoft-Windows-Sysmon/Operational
      value: WMI filter-to-consumer binding — completes the WMI persistence triangle
    - name: Sysmon-23
      location: Microsoft-Windows-Sysmon/Operational
      value: file delete with archival — attacker cleanup with recoverable artifact
    - name: Sysmon-25
      location: Microsoft-Windows-Sysmon/Operational
      value: process image tampering — process hollowing / herpaderping
    # --- PowerShell/Operational ---
    - name: PowerShell-4103
      location: Microsoft-Windows-PowerShell/Operational
      value: pipeline execution details (per-command module logging)
    - name: PowerShell-400
      location: Windows PowerShell (legacy channel)
      value: engine state changed — fallback when modern PS logging disabled
    # --- TerminalServices channels ---
    - name: TS-LSM-23
      location: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      value: RDP session logoff
    - name: TS-LSM-24
      location: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      value: RDP session disconnect (session remains, client gone)
    - name: TS-LSM-25
      location: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      value: RDP session reconnect
    - name: TS-RCM-1149
      location: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
      value: successful RDP connection established (pre-authentication)
    - name: TS-RDPClient-1024
      location: Microsoft-Windows-TerminalServices-RDPClient/Operational
      value: outbound RDP initiated by this host — lateral-movement origin
    # --- TaskScheduler/Operational ---
    - name: TaskScheduler-106
      location: Microsoft-Windows-TaskScheduler/Operational
      value: task registered
    - name: TaskScheduler-140
      location: Microsoft-Windows-TaskScheduler/Operational
      value: task updated
    - name: TaskScheduler-141
      location: Microsoft-Windows-TaskScheduler/Operational
      value: task deleted
    - name: TaskScheduler-200
      location: Microsoft-Windows-TaskScheduler/Operational
      value: task action started
    # --- Kernel-PnP/Configuration ---
    - name: KernelPnP-400
      location: Microsoft-Windows-Kernel-PnP/Configuration
      value: device node configured — USB/device-insertion timeline
    - name: KernelPnP-410
      location: Microsoft-Windows-Kernel-PnP/Configuration
      value: device node started
    # --- WMI-Activity/Operational ---
    - name: WMIActivity-5857
      location: Microsoft-Windows-WMI-Activity/Operational
      value: provider started — WMI-using process trace
    - name: WMIActivity-5861
      location: Microsoft-Windows-WMI-Activity/Operational
      value: permanent WMI subscription created — persistence
    # --- Windows Defender/Operational ---
    - name: Defender-1116
      location: Microsoft-Windows-Windows Defender/Operational
      value: malware detected
    - name: Defender-1117
      location: Microsoft-Windows-Windows Defender/Operational
      value: action taken on detected malware
    - name: Defender-5001
      location: Microsoft-Windows-Windows Defender/Operational
      value: real-time protection disabled — attacker tampering
    # --- AppLocker ---
    - name: AppLocker-8004
      location: Microsoft-Windows-AppLocker/EXE and DLL
      value: execution blocked by AppLocker policy
    # --- CodeIntegrity/Operational ---
    - name: CodeIntegrity-3077
      location: Microsoft-Windows-CodeIntegrity/Operational
      value: unsigned/untrusted image blocked — driver-signing or WDAC policy hit
    # --- BITS-Client/Operational ---
    - name: BITS-59
      location: Microsoft-Windows-Bits-Client/Operational
      value: BITS job started — living-off-the-land download
    - name: BITS-60
      location: Microsoft-Windows-Bits-Client/Operational
      value: BITS job transferred — completed out-of-band transfer
    # --- DNS-Client/Operational ---
    - name: DNSClient-3006
      location: Microsoft-Windows-DNS-Client/Operational
      value: DNS query initiated — telemetry for C2 domain resolution
    # --- PrintService/Operational ---
    - name: PrintService-307
      location: Microsoft-Windows-PrintService/Operational
      value: document printed — insider-threat exfiltration signal
    # --- NetworkProfile/Operational ---
    - name: NetworkProfile-10000
      location: Microsoft-Windows-NetworkProfile/Operational
      value: network connected — SSID / profile change timeline
    # --- UserProfile Service/Operational ---
    - name: UserProfileService-1
      location: Microsoft-Windows-User Profile Service/Operational
      value: user profile loaded — logon timeline complement
    - name: UserProfileService-4
      location: Microsoft-Windows-User Profile Service/Operational
      value: user profile unloaded — logoff timeline complement
---

# Windows Event Log (EVTX)

## Forensic value
The primary Windows audit substrate. Channels are organized by functional area — security, system, application, and hundreds of Microsoft-Windows-<component> channels for specific subsystems. Modern forensic value increasingly comes from the operational/diagnostic channels, which kernel-level components write with structured payloads far richer than the top-level Security channel.

## Addressing within an EVTX file
An artifact in this container identifies itself by the combination of (channel, event-id). Example: `Microsoft-Windows-Partition/Diagnostic` + event 1006. Within that scope, the artifact's fields are the event payload fields.

## Collection notes
Every EVTX file on a live system is locked by the EventLog service. Use `wevtutil export-log <channel> <path>` for scriptable export, or acquire via VSS/raw-disk for a full offline copy. For dirty-file recovery of deleted or rolled-over events, use libevtx/EvtxECmd's recovery modes.

## Channel rotation is a silent data-loss risk
Most operational channels have a default max size in the low MB — 20MB for Security, smaller for most Microsoft-Windows-* channels. On busy systems, events can roll off within hours. Acquire early; check the channel's retention config under `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<channel>` to know what's expected vs. missing.
