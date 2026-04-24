---
name: Windows-Firewall-Profiles
title-description: "Windows Firewall profile enable state + logging config (Domain / Private / Public profiles)"
aliases:
- WFP profile state
- MpsSvc registry
- firewall enable flags
link: system
link-secondary: persistence
tags:
- tamper-signal
- network-defense-state
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: Vista
    max: '11'
  windows-server:
    min: '2008'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
  sub-paths:
    - "FirewallPolicy\\DomainProfile"
    - "FirewallPolicy\\StandardProfile (Private)"
    - "FirewallPolicy\\PublicProfile"
    - "FirewallPolicy\\FirewallRules (individual rule registrations)"
  gpo-path: "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\<profile>\\EnableFirewall (GPO override)"
  addressing: hive+key-path
  note: "Windows Firewall (MpsSvc / Windows Defender Firewall) maintains per-profile state. Three profiles — DomainProfile, StandardProfile (Private), PublicProfile — each with independent EnableFirewall flag, inbound/outbound default action, and logging configuration. The profile applied to any given network interface depends on NLA's classification of the connected network (domain-authenticated / private-marked / public). Attacker-disabled firewall profile = the entire firewall for that network class is off. Separate artifact from FirewallRules (which covers individual rules) and Firewall-log (which covers pfirewall.log); this one focuses on the profile-level ENABLE and DEFAULT-ACTION state."
fields:
- name: enable-firewall
  kind: flags
  location: "<profile>\\EnableFirewall value"
  type: REG_DWORD
  note: "1 = firewall profile active; 0 = DISABLED. DomainProfile / StandardProfile / PublicProfile checked independently. Attacker-set 0 on any profile silently disables enforcement on networks matching that profile — e.g., Private=0 disables firewall on home-network-classified connections. Microsoft baseline + CIS / DISA STIG: all three profiles = 1."
- name: default-inbound-action
  kind: flags
  location: "<profile>\\DefaultInboundAction value"
  type: REG_DWORD
  note: "0 = Allow; 1 = Block. Microsoft baseline: 1 (Block). Attacker changing DomainProfile DefaultInboundAction to 0 allows all inbound traffic on domain networks without explicit rule — broad exposure."
- name: default-outbound-action
  kind: flags
  location: "<profile>\\DefaultOutboundAction value"
  type: REG_DWORD
  note: "0 = Allow; 1 = Block. Windows default: 0 (allow outbound). Rare to change — defense-hardened environments sometimes force 1 (block outbound) with explicit allow-rules. Attacker rarely touches this because legitimate posture is already Allow."
- name: disable-notifications
  kind: flags
  location: "<profile>\\DisableNotifications value"
  type: REG_DWORD
  note: "1 = suppress firewall block notifications. Attackers may set this to hide the popup toast a user would see when firewall blocks the attacker's inbound / outbound attempt."
- name: log-dropped-packets
  kind: flags
  location: "<profile>\\Logging\\LogDroppedPackets value"
  type: REG_DWORD
  note: "1 = log drops to pfirewall.log; 0 = don't log. Attacker clearing this hides evidence of blocked attacker traffic. Microsoft baseline: 1."
- name: log-successful-connections
  kind: flags
  location: "<profile>\\Logging\\LogSuccessfulConnections value"
  type: REG_DWORD
  note: "1 = log successful connections; 0 = don't log. Microsoft baseline: 1 for at least one profile (usually all)."
- name: log-file-size
  kind: counter
  location: "<profile>\\Logging\\LogFileSize value"
  type: REG_DWORD
  note: "Max log size in KB. Default 4096 (4 MB). Attacker reducing to very small value = force rapid rollover that loses evidence window."
- name: key-last-write
  kind: timestamp
  location: per-profile subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on each profile subkey advances when EnableFirewall / DefaultAction / Logging values change. Pair with System EVTX events for tamper timeline."
- name: mpssvc-state
  kind: flags
  location: "CurrentControlSet\\Services\\MpsSvc\\Start value"
  type: REG_DWORD
  references-data:
  - concept: ServiceName
    role: persistedService
  note: "MpsSvc (Windows Firewall service) startup type. 2 = Automatic (default baseline). 4 = Disabled. Attacker setting Start=4 + reboot disables the entire firewall service — profile-level EnableFirewall becomes moot because the service doesn't start. Broader tamper than profile-level disable."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'Windows Firewall profile enable/action/logging state is the
    configuration ground truth for the host''s network-defense posture.
    Attacker-disabled profile OR reduced logging OR permissive default-
    action = visible baseline drift. Because enterprise baselines (CIS /
    DISA / Microsoft) uniformly enable all profiles + Block-inbound +
    log-everything, any deviation on a baselined endpoint is candidate
    tamper. Combined with FirewallRules registry tampering (rule
    additions / removals), this gives the full firewall-configuration
    forensic picture.'
  qualifier-map:
    setting.registry-path: "Services\\SharedAccess\\Parameters\\FirewallPolicy\\<profile>"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none
  survival-signals:
  - EnableFirewall=0 on DomainProfile or PublicProfile on a modern endpoint = baseline tamper
  - DefaultInboundAction=0 (Allow) on any profile = inbound surface broadened
  - LogDroppedPackets=0 on all profiles = drop-event logging disabled
  - MpsSvc Start=4 with no documented admin reason = full firewall service disabled
  - Key LastWrite on FirewallPolicy\<profile> within incident window = tamper timeline anchor
provenance: [ms-windows-defender-firewall-registry, mitre-t1562-004]
---

# Windows Firewall Profile State

## Forensic value
`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` holds three per-profile subkeys:

- `DomainProfile` — applied to domain-authenticated networks
- `StandardProfile` — applied to Private / home networks
- `PublicProfile` — applied to public / unknown networks

Each profile has independent `EnableFirewall`, `DefaultInboundAction`, `DefaultOutboundAction`, and `Logging\*` values. The profile applied at any moment depends on NLA's classification of the currently-connected network.

## Three tamper classes (T1562.004)
1. **Profile disable** — `<profile>\EnableFirewall = 0`
2. **Default-action flip** — `<profile>\DefaultInboundAction = 0` (allow all inbound)
3. **Logging disable** — `<profile>\Logging\LogDroppedPackets = 0`

Plus the nuclear option — `Services\MpsSvc\Start = 4` disables the whole firewall service.

## Concept reference
- None direct — configuration artifact.

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" /s

netsh advfirewall show allprofiles
netsh advfirewall show allprofiles state
Get-NetFirewallProfile  :: PowerShell
```

Validate each profile: `EnableFirewall=1`, `DefaultInboundAction=1`, `DefaultOutboundAction=0` (default allow is OK), `Logging\LogDroppedPackets=1`.

## Cross-reference
- **FirewallRules** artifact — per-rule registrations
- **firewall-log** — pfirewall.log drop / allow entries
- **Microsoft-Windows-Windows Firewall With Advanced Security/Firewall** EVTX — events 2003 (profile change), 2009 (rule added/modified/deleted)
- **System-7036** — MpsSvc service state changes

## Practice hint
On a lab VM: `netsh advfirewall set domainprofile state off` (admin required). Observe `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\EnableFirewall` = 0. Re-enable: `netsh advfirewall set domainprofile state on`. Check EVTX event 2003 — profile state-change is logged. Key LastWrite timestamp brackets the change.
