---
name: Intune-PolicyManager
title-description: "Intune / MDM PolicyManager registry — cached cloud-pushed policies for managed Windows endpoints"
aliases:
- Intune PolicyManager
- MDM CSP cache
- PolicyManager current
link: system
link-secondary: persistence
tags:
- enterprise-policy
- cloud-management
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SOFTWARE
platform:
  windows:
    min: '10'
    max: '11'
    note: "MDM management introduced broadly in Windows 10. Enterprise / Education / Pro SKUs support Intune enrollment. Home SKU supports limited MDM via Azure AD join."
  windows-server:
    min: '2016'
    max: '2022'
location:
  hive: SOFTWARE (HKLM)
  path-current: "Microsoft\\PolicyManager\\current\\device\\<Area>\\<Policy>"
  path-providers: "Microsoft\\PolicyManager\\providers\\<enrollment-id>\\default\\device\\<Area>\\<Policy>"
  path-admx-ingested: "Microsoft\\PolicyManager\\AdmxInstalled\\<vendor>\\<product>"
  addressing: hive+key-path
  note: "When a Windows host is enrolled in Intune (or other MDM), the MDM client (dmwappushservice / DmClient) receives CSP (Configuration Service Provider) policy directives from the cloud and caches them in this registry tree. Policies are grouped into Areas (Defender, BitLocker, Wifi, Browser, Update, etc.) each holding specific policy values. For DFIR: PolicyManager is the forensic ground truth for cloud-pushed settings — complements Group Policy Preferences (domain-side) with MDM (cloud-side). Attacker compromise of an Intune tenant can push malicious policies to every enrolled endpoint — same mass-deploy primitive as GPO, different authorization path. Registry trace of recent unusual PolicyManager writes = candidate Intune-tenant compromise evidence."
fields:
- name: policy-value
  kind: content
  location: "PolicyManager\\current\\device\\<Area>\\<PolicyName> value"
  type: REG_DWORD / REG_SZ / REG_BINARY (per-CSP)
  note: "Cached policy value. Example Areas: Defender (DisableRealtimeMonitoring, ExcludedPaths), BitLocker (EncryptionMethodByDriveType), Wifi (profile blobs), Update (WUfBPolicy overrides), Browser (Edge config), LocalPoliciesSecurityOptions (wide range of security settings). Each Area's policies are CSP-documented. Attacker-authored policies pushing AV-disable or adding Defender exclusions = ransomware tenant-compromise TTP."
- name: policy-area
  kind: label
  location: "PolicyManager\\current\\device\\<Area> subkey name"
  encoding: utf-16le
  note: "CSP Area (policy group). Known set published by Microsoft — Microsoft-intent Areas all prefixed with standard names (Defender, BitLocker, ConnectivityProfiles, Update, Browser, etc.). Unknown / misspelled Area names = fabricated plant."
- name: enrollment-id
  kind: identifier
  location: "PolicyManager\\providers\\<enrollment-id> subkey name"
  encoding: guid-string
  note: "Each MDM enrollment creates a provider-id GUID. Multiple enrollments possible (rare outside test scenarios). The active enrollment's provider subkey holds the authoritative cached policy. Cross-reference to HKLM\\SOFTWARE\\Microsoft\\Enrollments\\<enrollment-id>\\ for enrollment metadata (tenant ID, Azure AD device ID, enrollment time)."
- name: last-policy-refresh
  kind: timestamp
  location: "PolicyManager\\current\\device key metadata — LastWrite"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "When the policy cache was last refreshed from the MDM server. Typical refresh cadence: every 8 hours default, configurable per-tenant. Recent LastWrite on specific Area subkeys = recent policy-push from tenant."
- name: admx-ingested
  kind: identifier
  location: "PolicyManager\\AdmxInstalled\\<vendor>\\<product> subkeys"
  note: "ADMX-backed policies ingested into the MDM policy channel (via the Ingest MDM ADMX feature). Covers Microsoft's own ADMX backlog + third-party vendor ADMX files. A vendor\\product subkey that doesn't match documented enterprise software deployment = candidate attacker injection."
- name: parent-dm-client-state
  kind: identifier
  location: "HKLM\\SOFTWARE\\Microsoft\\Enrollments"
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Parent MDM enrollment metadata. Each enrollment has a subkey under Enrollments with TenantID, UPN (user principal name), enrollment type, discovery URL. Start here to identify what tenant the host is enrolled in."
observations:
- proposition: CONFIGURED_BY_POLICY
  ceiling: C4
  note: 'Intune / MDM PolicyManager is the cloud-side equivalent of
    Group Policy Registry.pol. For Azure-AD-joined / Intune-enrolled
    endpoints, enterprise policy flows through this registry.
    Attacker compromise of an Intune tenant = same mass-enforcement
    primitive as compromised Domain Admin pushing Registry.pol.
    Defensive teams often audit GPO-source policy but skip Intune-
    source policy because it lives in a different registry tree and
    different operational tool (Intune portal vs GPMC). For
    ransomware / defense-tamper investigations on enrolled
    endpoints, always diff PolicyManager against expected tenant
    baseline.'
  qualifier-map:
    setting.registry-path: "Microsoft\\PolicyManager\\current\\device"
    time.start: field:last-policy-refresh
anti-forensic:
  write-privilege: unknown
  integrity-mechanism: MDM sync protocol signature (server-side; not verified on local registry)
  known-cleaners:
  - tool: "Unenroll device from Intune via Settings → Accounts → Access work or school"
    typically-removes: clears the enrollment + PolicyManager cache (visible enrollment-change event)
  survival-signals:
  - PolicyManager\current\device\Defender\ExcludedPaths containing unexpected paths = possible tenant-compromise or legitimate admin action
  - AdmxInstalled subkeys for unknown vendor\product pairs = candidate attacker ADMX injection
  - LastWrite on sensitive Area subkeys (Defender / BitLocker / Update) outside normal MDM refresh cadence = out-of-band policy push
provenance:
  - ms-configuration-service-provider-csp
---

# Intune / MDM PolicyManager Registry

## Forensic value
`HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>\<Policy>` holds the cached value of every policy pushed from an MDM (Intune or other) to this endpoint. Each Area groups related CSP policies — Defender, BitLocker, Wifi, Browser, Update, etc. The registry is the forensic ground truth for cloud-pushed configuration.

For Azure-AD-joined / Intune-enrolled endpoints, this is the equivalent of GPO-sourced Registry.pol but with a different management plane and threat model (tenant compromise vs Domain Admin compromise).

## Concept reference
- None direct — policy-state artifact.

## Triage
```cmd
reg query "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device" /s > intune-policy.txt
reg query "HKLM\SOFTWARE\Microsoft\PolicyManager\providers" /s
reg query "HKLM\SOFTWARE\Microsoft\Enrollments" /s
```

Diff against the tenant's expected policy baseline (Intune portal → Devices → Policies assigned to device).

## Cross-reference
- **GroupPolicy-Registry-Pol** — domain-side equivalent for comparison
- **Defender-Exclusions** — if MDM pushed exclusions, they land here AND in the standard Defender-Exclusions path
- **BitLocker-FVE** — MDM-configured BitLocker settings visible in both places
- **Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational** EVTX — MDM sync events

## Practice hint
On a lab VM with an Intune test tenant: enroll. Push a test policy via Intune portal. Wait for MDM sync (8h or force via Settings → Access work or school → Info → Sync). Inspect `HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>\` — the policy value appears. This cached state IS the artifact.
