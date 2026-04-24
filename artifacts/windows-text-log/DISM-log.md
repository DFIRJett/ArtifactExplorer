---
name: DISM-log
aliases: [DISM service log, image-servicing log]
link: system-state-identity
tags: [system-wide, install-history]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: DISM.log
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%WINDIR%\\Logs\\DISM\\dism.log"
  addressing: filesystem-path
fields:
- name: log-line
  kind: record
  location: text line
  encoding: "YYYY-MM-DD HH:MM:SS, LEVEL DISM COMPONENT: message"
- name: command
  kind: command
  location: lines beginning with 'Command:' recording invocation
  note: "every dism.exe or DISM-cmdlet invocation logged with full argv"
- name: timestamp
  kind: timestamp
  location: leading timestamp
  encoding: YYYY-MM-DD-HH:MM:SS-ms
  clock: system
  resolution: 1ms
observations:
- proposition: IMAGE_SERVICING_OPERATION
  ceiling: C3
  note: "DISM (Deployment Image Servicing and Management) log. Captures enable/disable-feature, add/remove-package, restorehealth, apply-image, and other DISM invocations."
  qualifier-map:
    object.command: field:command
    time.observed: field:timestamp
anti-forensic:
  write-privilege: unknown
provenance: []
provenance: [kape-files-repo]
---

# DISM.log

## Forensic value
Image-servicing operations. DISM invocations are often admin-level and sometimes attacker-relevant — e.g., `DISM /online /disable-feature /featurename:<defender>` to weaken the host. Every command with its full argv lands here.

## Cross-references
- **CBS-log** — lower-level servicing (DISM calls into CBS)
- **WindowsUpdate-log** — higher-level update timeline
