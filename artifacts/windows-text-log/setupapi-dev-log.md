---
name: setupapi-dev-log
aliases:
- setupapi.dev.log
- PnP install log
- driver install log
link: device
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: setupapi.dev.log
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  path: '%WINDIR%\INF\setupapi.dev.log'
  also: '%WINDIR%\INF\setupapi.dev.log.<N> (rotations)'
  addressing: filesystem-path-plus-rotations
fields:
- name: entry-timestamp
  kind: timestamp
  location: per-section header line starting with '>>>'
  encoding: '''YYYY/MM/DD HH:MM:SS.mmm'' local-time with TZ annotation'
  clock: system
  resolution: 1ms
  note: local-time in log; use the trailing '+/-<offset>' marker (when present) for UTC normalization
- name: device-class
  kind: identifier
  location: '''Device Install (...)'' heading'
  encoding: ascii
- name: device-instance-id
  kind: identifier
  location: '''Install'' and ''AddDevice'' lines, ''Device ID:'' prefix'
  encoding: ascii
  note: USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\<SERIAL> form — matches USBSTOR registry instance id
  references-data:
  - concept: DeviceSerial
    role: usbDevice
- name: hardware-id
  kind: identifier
  location: '''HardwareID:'' lines'
  encoding: ascii
- name: compatible-ids
  kind: identifier
  location: '''CompatibleIDs:'' lines'
  encoding: ascii
- name: driver-inf
  kind: path
  location: '''INF'' lines — path to loaded .inf file'
  encoding: ascii
  note: '''oem*.inf'' or ''Windows\INF\<class>.inf'''
- name: driver-binary
  kind: path
  location: '''Copying file'' lines — driver .sys files copied'
  encoding: ascii
- name: install-status
  kind: enum
  location: terminal '<<<  Section end <timestamp>' + '[0x00000000]' code
  encoding: hex-return-code
  note: 0x00000000 = success; non-zero = install error
observations:
- proposition: CONNECTED
  ceiling: C3
  note: 'Gives first-install timestamp for a USB device even on pre-Win8 systems

    that lack the USBSTOR Properties subkey. Crucial historical-coverage

    role — this is often the only source of install-time evidence.

    '
  qualifier-map:
    peer.serial: field:device-instance-id
    time.start: field:entry-timestamp
  preconditions:
  - log file not rotated past the install event
  - no manual edits (check line-number continuity)
corroborates:
- with: USBSTOR
  proposition: CONNECTED
  via: device-instance-id substring match
- with: PartitionDiagnostic-1006
  proposition: CONNECTED
  via: device serial substring match within the ~same install window
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: manual delete + recreate with empty content
    typically-removes: full
  - tool: PrivaZer, some privacy cleaners
    typically-removes: full
    note: some pro cleaners target setupapi.dev.log specifically
  - tool: log-rotation-force (flood with driver installs)
    typically-removes: partial
  survival-signals:
  - USBSTOR entries exist for devices NOT in setupapi.dev.log = log rotated past device install, or log was selectively edited
    (gap in timestamps diagnostic)
  - Monotonically increasing timestamps WITH a gap = selective line-deletion attempt
provenance:
  - ms-setupapi-logging-file-locations-and
  - aboutdfir-nd-usb-devices-windows-artifact-r
  - matrix-dt025-setupapi-dev-log
  - cowen-2013-hecfblog-daily-66-setupapi
  - fortuna-2018-andreafortuna-usb-devices-in-windows
  - ms-setupapi-text-logs-format
  - kape-files-repo
---

# setupapi.dev.log

## Forensic value
Plaintext log of PnP device installs. For each device attached to the system, writes a `>>>` header + block of details + `<<<` footer block. Crucial role as the pre-Win8 source of device first-install timestamps (before USBSTOR Properties subkey existed).

On modern Windows, setupapi.dev.log is still written and still useful as a corroborator to USBSTOR Properties and Partition/Diagnostic 1006 — often the only artifact that captures the DRIVER install details (which .inf, which .sys files, what exit code).

## Known quirks
- **Rotating log** — `.log`, `.log.1`, etc. Always acquire all numbered variants.
- **Timestamps are local time with a trailing timezone hint.** Normalize to UTC before cross-artifact correlation.
- **`>>>` blocks are sometimes nested** for complex installs involving multiple driver packages. Parser must respect nesting or misattribute lines to the wrong event.
- **Free-form middle lines.** The block content is informal prose; extract identifiers with log-specific regex, don't expect structured fields.

## Anti-forensic caveats
Plaintext file with zero integrity guarantees. Edits are undetectable by the file itself. Detection relies on cross-artifact discrepancy (USBSTOR entries without matching setupapi lines, timestamp gaps, etc.).

## Practice hint
On a Win10 VM, plug a known USB. Grep setupapi.dev.log for the device's serial — you'll see a `>>> [Device Install (Hardware initiated)...]` block with full timestamps, hardware IDs, and the copied driver files. Compare timestamp to USBSTOR Properties `first-install-time` — should match within seconds.
