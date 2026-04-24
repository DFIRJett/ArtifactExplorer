# Data Exfiltration — USB Storage Device

## Investigative question
Did user `U` move file `F` onto removable storage device `D` from system `S` within window `T`?

## Target composite proposition
`EXFILTRATED_REMOVABLE(object=F, destination=D, actor=U, system=S, time=T)`

## Decomposition — what must be provable
| # | Primitive | What it establishes | If missing |
|---|---|---|---|
| 1 | `AUTHENTICATED_AS(U, S, T)` | session anchor — user was logged in | every other claim degrades to "some user on this box" |
| 2 | `CONNECTED(D, S, T)` | device was plugged in during window | investigation ends — no exfil without device |
| 3 | `POSSESSED(D, U, T)` | device tied to this user, not another logged-in account | device attribution collapses to host-level |
| 4 | `ACCESSED(F, U, T)` | user opened/read source file | no evidence of interest in F |
| 5 | `EXECUTED_BY(U, copy-tool, T)` | copy mechanism ran — implicit if Explorer drag-drop | drops to "file was accessible" only |
| 6 | `CREATED(F' on D, T)` | **smoking gun — copy appeared on destination** | ceiling capped at C2 regardless of everything else |

## Artifact inventory

Class column: **V** = verifier, **C** = converger. Ceiling is the **solo** Casey C-level this artifact can independently reach; corroboration raises it.

---

### A. Device connection — `CONNECTED(D, S)`

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| [USBSTOR](../artifacts/windows-registry/USBSTOR.md) | `SYSTEM\CurrentControlSet\Enum\USBSTOR\<class-id>\<instance-id>` | vendor, product, revision, serial, ContainerID; first-install, first/last-arrival, last-removal times (Win8+) | C | C3 |
| MountedDevices | `SYSTEM\MountedDevices` | drive letter ↔ volume GUID ↔ device signature mapping | C | C2 |
| setupapi.dev.log | `%WINDIR%\INF\setupapi.dev.log` | plaintext first-install timeline; only pre-Win8 source of install time | C | C3 |
| Partition/Diagnostic evt 1006 | `%WINDIR%\System32\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx` | kernel-logged mount with user SID, model, serial, VBR hash, capacity (Win10 1803+) | **C** | **C4** |
| DriverFrameworks-UserMode/Operational | `...\Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx` | evt 2003/2100/2101/2105 — driver lifecycle, per-device install/attach/detach | C | C3 |
| Kernel-PnP/Configuration | `...\Microsoft-Windows-Kernel-PnP%4Configuration.evtx` | PnP enumeration, driver binding | C | C3 |
| Storage-ClassPnP/Operational | `...\Microsoft-Windows-Storage-ClassPnP%4Operational.evtx` | storage stack binding events | C | C3 |
| Ntfs/Operational evt 98 | `...\Microsoft-Windows-Ntfs%4Operational.evtx` | volume mount events for NTFS-formatted removables | V | C3 |
| Windows Portable Devices | `SOFTWARE\Microsoft\Windows Portable Devices\Devices\<id>` | friendly name, last drive letter for MTP/PTP cameras, phones, tablets | C | C3 |
| EMDMgmt | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt\<id>` | legacy ReadyBoost device enumeration — still populated even when device isn't used for ReadyBoost | C | C2 |

**Anchor artifact:** Partition/Diagnostic 1006. Kernel-signed, user SID embedded, survives most consumer cleaners. If present, it drives the CONNECTED ceiling to C4 without corroboration.

---

### B. User-device binding — `POSSESSED(D, U)`

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| [MountPoints2](../artifacts/windows-registry/MountPoints2.md) | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | per-user volume GUIDs; LastWrite = last mount under this profile | C | C2–C3 |
| Shellbags | `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` + `Bags` | folder navigation history; entries for removable-volume paths prove user browsed the device | C | C3 |
| LastVisitedPidlMRU | `NTUSER.DAT\...\Explorer\ComDlg32\LastVisitedPidlMRU` | last-browsed locations per app, includes removable paths | C | C2 |
| OpenSavePidlMRU | `NTUSER.DAT\...\Explorer\ComDlg32\OpenSavePidlMRU` | dialog-box history per file extension | C | C2 |
| Automatic Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms` | per-app MRU with volume GUID embedded; preserves historical mounts MountPoints2 loses | C | C3 |
| Custom Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*` | user-pinned items with volume references | C | C3 |

**Key point:** MountPoints2 is user-writable (no admin required). Solo it's C2. The convergence chain (MountPoints2 GUID ↔ MountedDevices signature ↔ USBSTOR serial) is what drives it to C3.

---

### C. Source file access — `ACCESSED(F, U)` / `MODIFIED(F)`

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| $MFT ($STANDARD_INFO) | NTFS metadata | atime (if enabled — usually off modern Win); mtime, ctime, btime | C | C2 |
| $MFT ($FILE_NAME) | NTFS metadata | harder-to-forge timestamp set; updated by fewer operations | C | C3 |
| $LogFile | NTFS journal | recent transactions (~64MB rolling buffer) | C | C3 |
| $UsnJrnl:$J | NTFS journal | file-op journal within retention (default 32MB) | C | C3 |
| LNK files in Recent | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | target path + volume serial + volume label + original filename + MAC times at capture + machine NetBIOS + MAC address | **C** | C3 |
| RecentDocs | `NTUSER.DAT\...\Explorer\RecentDocs` | per-extension MRU, ordered | C | C2 |
| Office File MRU | `NTUSER.DAT\Software\Microsoft\Office\<ver>\<app>\File MRU` | per-app recent files with full path, last-access | C | C2 |
| Office Reading Locations | `NTUSER.DAT\Software\Microsoft\Office\<ver>\Word\Reading Locations` | last cursor position in each Word doc — proves read, not just open | C | C2 |
| Thumbnail cache | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db` | rendered thumbnails of images/PDFs viewed — proves content access even after file deletion | **C** | C3 |
| IconCache | `%LOCALAPPDATA%\IconCache.db` | cached icons of launched programs | V | C2 |
| Prefetch for Explorer.exe | `C:\Windows\Prefetch\EXPLORER.EXE-*.pf` | referenced-files list — includes files Explorer opened handles on | C | C2 |

**LNK files are converger-gold.** A single LNK carries enough data to prove access AND identify the source volume AND timestamp the access. Always parse every LNK in Recent\.

---

### D. Execution of copy mechanism — `EXECUTED_BY(U, P)`

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| BAM | `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\<exe-path>` | per-user execution last-run timestamp (FILETIME value data) | **C** | **C4** |
| DAM | `SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>\<exe-path>` | desktop-activity-moderator equivalent of BAM | C | C4 |
| UserAssist | `NTUSER.DAT\...\Explorer\UserAssist\<GUID>\Count` | GUI launches, run count, last-run, focus time; names ROT13'd | **C** | C3 |
| Amcache.hve | `%WINDIR%\AppCompat\Programs\Amcache.hve` | first-seen, SHA1, PE metadata, binary origin volume, last-modified | **C** | C3 |
| ShimCache / AppCompatCache | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` | execution evidence; Win10+ semantics disputed between parsers | V | C2 |
| SRUM | `%WINDIR%\System32\sru\SRUDB.dat` | per-process network bytes, disk bytes, user SID, hourly buckets | **C** | **C4** |
| Security.evtx evt 4688 | `%WINDIR%\System32\winevt\Logs\Security.evtx` | process creation with parent PID + command line (if cmdline auditing on) | C | C4 |
| Sysmon evt 1 | `...\Microsoft-Windows-Sysmon%4Operational.evtx` | process creation with full command line, image hash, parent | **C** | C4 |
| PowerShell/Operational evt 4104 | `...\Microsoft-Windows-PowerShell%4Operational.evtx` | decoded script blocks (if ScriptBlockLogging enabled) | C | C4 |
| PSReadline history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | plaintext typed PowerShell history | V | C2 |
| Prefetch | `C:\Windows\Prefetch\<exe>-<hash>.pf` | execution + last-8 run times + referenced files + run count | C | C3 |
| RecentFileCache.bcf | `%WINDIR%\AppCompat\Programs\RecentFileCache.bcf` (Win7 only) | recently executed binaries | V | C2 |

**Two anchor artifacts for execution:** BAM (per-user, kernel-service-written, user SID embedded) and SRUM (per-process byte counts — tells you how much data a process moved). Both survive most cleaners.

---

### E. Destination evidence — `CREATED(F' on D)` — **usually unavailable**

Only achievable if the device was seized and imaged.

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| $MFT on D | NTFS metadata on removable volume | CREATED entries for copied files; filename, size, MAC times, parent directory | **C** | **C5** |
| $LogFile on D | NTFS journal on removable volume | transaction log of writes to D | C | C4 |
| FAT directory entries on D | FAT32/exFAT volume structures | file creation order, cluster chains | C | C3 |
| Carved deleted files on D | slack + unallocated on D | recovery of stage-then-delete patterns | V | C3 |
| VBR / volume serial on D | first sector of D | matches MountedDevices signature / USBSTOR DiskID — proves this is the right device | V | C3 |

**Hash match between F on S and F' on D is the single most powerful evidentiary element available in this entire topic.** If available, composite ceiling reaches C5.

---

### F. Session context — `AUTHENTICATED_AS(U, S)`

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| Security.evtx 4624 | `...\Security.evtx` | logon with type (2=interactive, 3=network, 10=RDP), user SID, source IP, logon ID | **C** | C4 |
| Security.evtx 4634/4647 | `...\Security.evtx` | logoff with logon ID — anchors session end | V | C4 |
| Security.evtx 4648 | `...\Security.evtx` | explicit credential use (runas) | C | C4 |
| TerminalServices-LSM/Operational | `...\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | evt 21/22/24/25 — interactive + RDP session lifecycle | C | C4 |
| TerminalServices-RCM/Operational evt 1149 | `...\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | RDP authenticated connection | C | C3 |
| ProfileList | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` | SID ↔ profile path ↔ last-use | C | C3 |
| SAM `V` value | `SAM\SAM\Domains\Account\Users\<RID>\V` | last-logon timestamp per local account | V | C3 |

---

### G. Endpoint telemetry — if deployed

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| Defender AH `DeviceFileEvents` | cloud — Advanced Hunting | file copy/move/delete with source path, destination path, hash, user, initiating process | **C** | C4 |
| Defender AH `DeviceEvents` (USB) | cloud | PnP events with device ID, user | C | C4 |
| Sysmon evt 11 | `...\Microsoft-Windows-Sysmon%4Operational.evtx` | FileCreate events with process, user, full path | C | C4 |
| Carbon Black `filemod` | EDR backend | file modification with process lineage | C | C4 |

---

### H. Volume Shadow Copies — historical state on S

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| VSC snapshots | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>` | historical file state on source; may preserve F before or after copy; may preserve prior USBSTOR/MountPoints2 state | C | C3 |

---

### I. Content-bound metadata on F

| Artifact | Path | Forensically relevant data | Class | Ceiling |
|---|---|---|---|---|
| Office DocumentProperties | inside .docx/.xlsx/.pptx | author, last-edited-by, template, last-saved timestamp, revision number | C | C2 |
| EXIF | inside .jpg/.tiff/.heic | camera, timestamps, GPS | C | C2 |
| PDF `/Info` + XMP | inside .pdf | producer, author, creation/mod times | C | C2 |
| Zone.Identifier ADS | `<file>:Zone.Identifier` | origin URL / referrer / zone ID if downloaded | V | C3 |

---

## Convergence map (canonical exfil chain)

```
AUTHENTICATED_AS ──┐
                   │
CONNECTED(D, S) ───┼──[USED(U, D, S)]──┐
                   │                    │
POSSESSED(D, U) ───┘                    │
                                        ├──▶ EXFILTRATED_REMOVABLE
ACCESSED(F, U)    ─────────────────────┤
                                        │
EXECUTED_BY(U, P) ─────────────────────┤
                                        │
CREATED(F' on D)  ─────────────────────┘    ← the C4→C5 lever
```

## Missed-convergence checklist — resolve each before reporting

| # | Check | What's lost if absent | Fallback |
|---|---|---|---|
| 1 | Was device `D` acquired? | all of §E — ceiling capped at C2 | SRUM bytes + hash match is next-best |
| 2 | Partition/Diagnostic 1006 retained? | kernel-anchored CONNECTED (C4) | degrade to USBSTOR + DriverFrameworks (C3) |
| 3 | Security.evtx covers window? | `AUTHENTICATED_AS` direct | BAM + UserAssist imply active session |
| 4 | atime enabled on source volume? | direct `ACCESSED(F)` | LNK in Recent + OfficeMRU + thumbcache |
| 5 | Process creation auditing (4688 / Sysmon)? | direct `EXECUTED_BY` | BAM + UserAssist + Prefetch |
| 6 | PowerShell ScriptBlockLogging on? | scripted-copy content | PSReadline (user-editable, C2) |
| 7 | Anti-forensic cleaner detected? | USBSTOR, MountPoints2, setupapi | Partition/Diag 1006, Jump Lists, Kernel-PnP, Storage-ClassPnP |
| 8 | Profile hive dirty / not replayed? | per-user artifacts may be stale | replay NTUSER.LOG1/LOG2 before analysis |
| 9 | Roaming profile? | POSSESSED may be from a different host | cross-check `ProfileList` ProfileType |
| 10 | VSS snapshots available? | historical state on S | mount each snapshot as readonly, re-run §A–§D |

## Minimum evidentiary thresholds

| Claim level | Required evidence |
|---|---|
| **C2** (likely) | §A any + §B any + §C any — temporal coincidence only |
| **C3** (probable) | §A (≥2 sources) + §B (MountPoints2 + jump lists or shellbags) + §C (LNK or Office MRU) + §F |
| **C4** (strong) | above + §D (BAM or Sysmon or 4688) + either Partition/Diag 1006 OR SRUM byte match |
| **C5** (near-certain) | all above + §E with hash match between source file and destination file on acquired device |

## Training exercise

Lone Wolf scenario image (AboutDFIR) or a self-constructed lab:
1. On a clean Win10 VM: log in as User A, plug in known USB, copy a file with a known hash, safely remove, log off.
2. Acquire SYSTEM, NTUSER.DAT, Security.evtx, Partition/Diagnostic, Microsoft-Windows-DriverFrameworks, SRUDB.dat, Prefetch, LNK directory, Amcache, `%WINDIR%\AppCompat\Programs\`.
3. Reconstruct each row in §A–§F independently. For each, note which propositions it emits and what ceiling it reaches solo.
4. Now acquire the USB and pull §E. Compute composite ceiling before and after §E. Observe the C3 → C5 jump.
5. Run USBOblivion on a duplicate VM and re-acquire. Which rows survive? (Hint: Partition/Diagnostic, Jump Lists, and Kernel-PnP typically do.)
