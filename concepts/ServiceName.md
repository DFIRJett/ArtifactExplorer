---
name: ServiceName
kind: identifier
lifetime: persistent
link-affinity: persistence
description: 'Windows service name — the SCM-level short identifier for a service

  (e.g., "PSEXESVC", "Spooler", "W32Time"). Distinct from DisplayName

  (human-readable) and from ServiceDll/ImagePath (the binary).

  '
canonical-format: ASCII string, conventionally < 256 chars; case-preserved but case-insensitive match
aliases:
- service-short-name
- SCM-service-name
roles:
- id: identitySubject
  description: Service's canonical short name — Services registry subkey name and System-7045 ServiceName field both carry this
- id: stateChangeTarget
  description: Service name recorded on state-change events (start / stop / fail) — System-7036
- id: installedService
  description: Service name recorded at install-time — Security-4697, System-7045
- id: persistedService
  description: Service name captured via its persistence footprint (ETW autologger provider subkey, Windows Firewall profile service state, other registry-resident service references) — not from a live
    state-change or install event
known-containers:
- Services
- System-7045
- System-7036
- Security-4697
provenance:
- ms-learn-hklm-services-tree
- regripper-plugins
- libyal-libregf
---

# Service Name

## What it is
Short, SCM-canonical identifier for a Windows service. Used as the subkey name under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`, as the `ServiceName` field in System-7045 ("new service installed") and Security-4697, and as the `param1` field in System-7036 ("service state change") events.

## Why it's a forensic join key
When a service is created then later modified (classic Cobalt Strike / ransomware persistence), the Registry shows only the CURRENT ImagePath. System-7045 preserves the ImagePath as it was AT INSTALL. Joining on ServiceName across these sources reveals post-install tampering — the EVTX says "installed with path X," the Registry now says "points at path Y" — X and Y should match.

## Anti-forensic corollary
An attacker deleting a service after lateral movement leaves System-7045 as the only surviving record of the service's existence. The Registry subkey is gone; the evtx entry with its ServiceName persists until log rotation.
