---
name: firewall-log
aliases:
- Windows Firewall log
- pfirewall.log
- WF log
link: network
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: pfirewall.log
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  path: '%WINDIR%\System32\LogFiles\Firewall\pfirewall.log'
  also: '%WINDIR%\System32\LogFiles\Firewall\pfirewall.log.old (rotation)'
  note: disabled by default — requires enabling per-profile via netsh or GPO
fields:
- name: timestamp
  kind: timestamp
  location: space-separated first two columns (date + time)
  encoding: local time 'YYYY-MM-DD HH:MM:SS'
  clock: system
  resolution: 1s
- name: action
  kind: enum
  location: 3rd column
  encoding: '''ALLOW'' / ''DROP'''
- name: protocol
  kind: enum
  location: 4th column
  encoding: '''TCP'' / ''UDP'' / ''ICMP'' / etc.'
- name: src-ip
  kind: identifier
  location: 5th column
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: sourceIp
- name: dst-ip
  kind: identifier
  location: 6th column
  encoding: ip-address-string
  references-data:
  - concept: IPAddress
    role: destinationIp
- name: src-port
  kind: counter
  location: 7th column
  encoding: uint16
- name: dst-port
  kind: counter
  location: 8th column
  encoding: uint16
- name: bytes-transferred
  kind: counter
  location: size column (when logging bytes enabled)
  encoding: uint64
observations:
- proposition: CONNECTED
  ceiling: C3
  note: 'Kernel-level record of TCP/UDP/ICMP packets matching enabled-log

    firewall rules. Captures ALL traffic (in/out, allowed/dropped) when

    logging is on — including traffic that bypasses the proxy.

    '
  qualifier-map:
    peer.ip: field:dst-ip
    local-endpoint: field:src-ip
    via.port: field:dst-port
    via.protocol: field:protocol
    direction: derived from src/dst vs. local IPs
    time.start: field:timestamp
  preconditions:
  - firewall logging enabled via `netsh advfirewall set <profile> logging ...` — NOT on by default
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  known-cleaners:
  - tool: manual file delete + restart firewall service
    typically-removes: full
  survival-signals:
  - firewall log present but empty lines starting at a gap = active truncation
provenance: [ms-windows-defender-firewall-registry]
---

# Windows Firewall Log

## Forensic value
Low-level packet log from the Windows Firewall. Plaintext space-separated format capturing every ALLOW/DROP action that matched a logged rule. Disabled by default — when enabled, provides kernel-scope network visibility complementary to (not replacement of) proxy logs.

## Concept reference
- IPAddress (src + dst)

## Known quirks
- **Off by default.** Absence of the file or zero size doesn't mean "no traffic" — likely means "logging wasn't enabled."
- **Local-time timestamps.** Convert to UTC for cross-artifact alignment.
- **Dropped vs. allowed.** The `ALLOW` entries are what actually happened; `DROP` entries reveal attempted but prevented traffic — both forensically interesting.
- **Rule name not always logged.** Depending on config, you can't always tell which firewall rule matched.

## Practice hint
Enable firewall logging: `netsh advfirewall set allprofiles logging filename %WINDIR%\System32\LogFiles\Firewall\pfirewall.log`. Generate traffic (ping, browser). Parse the log — verify ALLOW entries for your test connections. Note timestamp granularity (1-second) is coarser than Sysmon's millisecond precision.
