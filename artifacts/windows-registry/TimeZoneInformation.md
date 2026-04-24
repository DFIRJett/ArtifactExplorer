---
name: TimeZoneInformation
aliases:
- TZI
- system time zone
- Windows TZ configuration
link: system-state-identity
tags:
- timestamp-carrying
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: XP
    max: '11'
  windows-server:
    min: '2003'
    max: '2022'
location:
  hive: SYSTEM
  path: CurrentControlSet\Control\TimeZoneInformation
  addressing: hive+key-path
fields:
- name: time-zone-key-name
  kind: identifier
  location: TimeZoneKeyName value
  type: REG_SZ
  encoding: utf-16le
  note: e.g., 'Pacific Standard Time', 'UTC', 'Central European Standard Time'
- name: standard-name
  kind: identifier
  location: StandardName value
  type: REG_SZ
  encoding: utf-16le
  note: user-facing name for the standard (non-DST) time-zone
- name: daylight-name
  kind: identifier
  location: DaylightName value
  type: REG_SZ
  encoding: utf-16le
  note: user-facing name during DST
- name: active-time-bias
  kind: counter
  location: ActiveTimeBias value
  type: REG_DWORD
  encoding: int32
  note: minutes OFFSET from UTC (positive = west of UTC). Negative for east, positive for west. Doesn't distinguish standard
    vs. DST — that's inferred from the effective bias.
- name: bias
  kind: counter
  location: Bias value
  type: REG_DWORD
  encoding: int32
  note: standard-time bias
- name: daylight-bias
  kind: counter
  location: DaylightBias value
  type: REG_DWORD
  encoding: int32
  note: usually -60 during DST season
- name: daylight-start
  kind: identifier
  location: DaylightStart value
  type: REG_BINARY
  note: SYSTEMTIME-ish struct defining when DST starts
- name: daylight-end
  kind: identifier
  location: DaylightEnd value
  type: REG_BINARY
- name: dynamic-daylight-time-disabled
  kind: flags
  location: DynamicDaylightTimeDisabled value
  type: REG_DWORD
observations:
- proposition: CONFIGURED
  ceiling: C3
  note: 'Authoritative system time-zone configuration. Critical for interpreting

    any local-time timestamp elsewhere in the corpus — setupapi.dev.log

    uses local time; firewall log uses local time; most user-facing times

    are local. Without knowing the TZ, you can''t reconcile cross-artifact

    timelines.

    '
  qualifier-map:
    setting.tz-name: field:time-zone-key-name
    setting.utc-offset-minutes: field:active-time-bias
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - TimeZone changed shortly before the investigation window = possible forensic-evasion technique (shifts local-time timestamps)
  - TimeZone set to UTC on a desktop machine = unusual; machines usually reflect user's physical TZ
provenance: []
exit-node:
  is-terminus: false
  terminates:
    - ANTI_FORENSIC_TIMELINE_BREAK
  sources:
    - libyal-libregf
  reasoning: >-
    HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation holds the
    authoritative timezone + DST rule at the moment of acquisition.
    Every local-time timestamp on the host (MFT $SI when interpreted
    as local, some event-log fields on legacy systems, registry writes
    via GUI tools) is meaningful only when mapped to this TZ. No
    upstream: the registry IS the machine's TZ truth. Terminus for
    "what TZ interpretation applies to this evidence?"
  implications: >-
    TZ changed shortly before or during the incident window is an
    anti-forensic pattern — shifting TZ shifts every local-time
    timestamp's meaning without modifying the underlying bytes.
    Forensic timeline reconstruction MUST lock the TZ snapshot to
    the moment-of-acquisition value; any analysis that assumes a
    different TZ is defective. Cross-reference with ActiveTimeBias
    + StandardBias / DaylightBias fields to detect DST-aware
    tampering.
  preconditions: >-
    Read access to HKLM\SYSTEM\CurrentControlSet\Control\
    TimeZoneInformation. Value directly readable; no crypto chain.
  identifier-terminals-referenced: []
provenance: [libyal-libregf]
---

# TimeZoneInformation

## Forensic value
Authoritative system time-zone setting. Necessary for normalizing every local-time timestamp elsewhere in the corpus (setupapi.dev.log local time, firewall log local time, many event-log display-time fields).

Investigative checklist item #1 for any multi-artifact timeline: record the system time zone. Timestamps in subsequent artifacts must be interpreted through this configuration.

## No concept reference (yet)
Time-zone is currently modeled as a system-state field. Could get a TimeZone concept if future artifacts need to cross-reference (e.g., different log sources on the same host should agree on TZ).

## Known quirks
- **ActiveTimeBias changes during DST transitions.** For a captured point-in-time hive, ActiveTimeBias reflects whatever it was at shutdown/acquisition — not necessarily the correct bias for an arbitrary past timestamp. Use Bias + DaylightBias + transition rules to compute historical bias.
- **Registry value naming confusing.** `Bias` = standard-time offset (positive = west of UTC). `DaylightBias` = ADDITIONAL offset during DST (usually -60). Effective offset = Bias + (DaylightBias if in DST else 0).
- **Windows 10+ uses time-zone names** (`Pacific Standard Time`); older Windows used numeric IDs.

## Practice hint
On your test system, note the current TZ: `Get-TimeZone`. Then `reg query "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"`. Map the PowerShell output to the registry values. Convert Bias from minutes to hours — should match your offset from UTC.
