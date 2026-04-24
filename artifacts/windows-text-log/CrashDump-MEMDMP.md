---
name: CrashDump-MEMDMP
aliases: [MEMORY.DMP, kernel crash dump, minidump]
link: system-state-identity
tags: [system-wide, forensic-gold]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: MEMORY.DMP
platform:
  windows: {min: XP, max: '11'}
location:
  path: "%WINDIR%\\MEMORY.DMP (kernel/full dump) + %WINDIR%\\Minidump\\*.dmp (minidumps)"
  addressing: filesystem-path
fields:
- name: dump-type
  kind: flag
  location: DUMP_HEADER at offset 0
  note: "1 = full, 2 = kernel, 3 = small/minidump, 5 = triage"
- name: bsod-bugcheck-code
  kind: identifier
  location: DUMP_HEADER → BugCheckCode
  note: "0x7E = system thread exception, 0x1E = unhandled kernel exception, 0x3B = system service exception, etc."
- name: crash-timestamp
  kind: timestamp
  location: DUMP_HEADER → SystemTime
  encoding: filetime-le
  clock: system
  resolution: 100ns
- name: machine-info
  kind: identifier
  location: DUMP_HEADER → MachineImageType + version info
- name: kernel-memory-body
  kind: content
  location: body of dump file
  note: "kernel memory (or subset) at crash time — analyzable with WinDbg or Volatility. Contains live credentials, registry in memory, process list, loaded modules."
- name: crashing-process-path
  kind: path
  location: derived from kernel-memory-body — !process command in WinDbg or Volatility psscan walks the EPROCESS list to recover the crashing-context image path
  note: Not a DUMP_HEADER field — derived by walking the captured EPROCESS / PSACTIVE_PROCESS_LINKS during post-mortem analysis. Names the process that was current on the CPU when the crash happened (relevant when analyzing driver-triggered BSODs like 0x7E or 0x3B).
  references-data:
  - concept: ExecutablePath
    role: ranProcess
- name: crashing-process-pid
  kind: identifier
  location: derived from kernel-memory-body — the UniqueProcessId of the current-thread's EPROCESS
  note: Not stored in the DUMP_HEADER — derived the same way as crashing-process-path. Correlates with concurrent Security-4688 / Sysmon-1 events to bracket the crash into a session window.
  references-data:
  - concept: ProcessId
    role: targetProcess
observations:
- proposition: MEMORY_SNAPSHOT_AT_CRASH
  ceiling: C4
  note: "A kernel dump is a memory snapshot at the moment of crash. Forensic gold for post-mortem of rootkits, credential theft (lsass contents), and timeline reconstruction around the crash."
  qualifier-map:
    object.bugcheck: field:bsod-bugcheck-code
    time.crash: field:crash-timestamp
anti-forensic:
  write-privilege: unknown
provenance: [foundation-2021-volatility-hibernate-address-s]
exit-node:
  is-terminus: true
  primary-source: ms-varieties-of-kernel-mode-dump-files
  attribution-sentence: 'The Complete Memory Dump is the largest and contains the most information, including some User-Mode memory (Microsoft, 2025).'
  terminates:
    - RAN_PROCESS
    - HAD_CONTENT
    - HAS_CREDENTIAL
  sources:
    - foundation-2021-volatility-hibernate-address-s
  reasoning: >-
    Full kernel memory dump (MEMORY.DMP) or user-mode minidump captures system state at crash moment — every running process, every loaded module, full kernel structures, and user-process VAS at time of bugcheck. For point-in-time RAN_PROCESS, HAD_CONTENT, or HAS_CREDENTIAL evidence at the crash timepoint, the dump IS the answer; Volatility / WinDbg extraction against it is terminus-level analysis.
  implications: >-
    Often the only memory evidence available on systems that don't hibernate. WER-uploaded dumps can reveal pre-cleanup state weeks after a compromise. Credential extraction (mimikatz-offline) against LSASS sections within a full dump yields plaintext creds + tickets present at crash moment. Key anti-forensic survival mode: attackers rarely clear %SystemRoot%\Minidump or the configured DedicatedDumpFile path.
  preconditions: "CrashDumpEnabled != 0 ; dump file not zeroed by attacker"
  identifier-terminals-referenced:
    - ProcessId
    - ExecutablePath
    - UserSID
---

# MEMORY.DMP

## Forensic value
Kernel memory dump triggered by BSOD or manually captured via NotMyFault / LiveKD. Analyzable with WinDbg (!analyze -v) or Volatility (modern Volatility3 supports Microsoft crash-dump format). Contains:
- Process list at crash time
- Loaded kernel modules (drivers)
- Portions of LSASS memory (on full dumps) — credential theft target
- Registry hives mounted in kernel memory

## Cross-references
- **System-41** (kernel power) — often paired with an involuntary crash
- **Amcache-InventoryDriverBinary** — cross-reference loaded drivers visible in the dump
- **Sysmon-6** — driver load events that may appear just before a crash
