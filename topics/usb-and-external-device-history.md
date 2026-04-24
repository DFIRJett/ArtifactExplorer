# USB and External Device History — Registry Tree (Scoped)

**Scope constraint:** only the four artifacts stipulated for this training pass.

| Artifact | Hive | Path |
|---|---|---|
| USBSTOR | SYSTEM | `CurrentControlSet\Enum\USBSTOR\` |
| MountedDevices | SYSTEM | `MountedDevices\` |
| MountPoints2 | NTUSER.DAT | `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\` |
| Windows Portable Devices | SOFTWARE | `Microsoft\Windows Portable Devices\Devices\` |

## Registry Tree

```
REGISTRY
│
├── SYSTEM  [hive]
│   │
│   ├── CurrentControlSet\Enum\USBSTOR\                              ┐
│   │   │                                                            │ USBSTOR
│   │   └── <class-id>\                                              │
│   │       │   ← format: Disk&Ven_<VENDOR>&Prod_<PRODUCT>&Rev_<REV> │
│   │       │                                                        │
│   │       └── <instance-id>\                                       │
│   │           │   ← device serial OR OS-synthesized (see A0)       │
│   │           │                                                    │
│   │           ├── [key.LastWrite]                          ─── A1  │
│   │           ├── FriendlyName             REG_SZ          ─── A2  │
│   │           ├── ContainerID              REG_SZ / GUID   ─── A3  │
│   │           ├── DeviceDesc               REG_SZ          ─── A4  │
│   │           ├── HardwareID               REG_MULTI_SZ    ─── A5  │
│   │           ├── CompatibleIDs            REG_MULTI_SZ    ─── A6  │
│   │           ├── Service                  REG_SZ          ─── A7  │
│   │           ├── Driver                   REG_SZ          ─── A8  │
│   │           ├── ClassGUID                REG_SZ / GUID   ─── A9  │
│   │           ├── Class                    REG_SZ          ─── A10 │
│   │           ├── Mfg                      REG_SZ          ─── A11 │
│   │           ├── Capabilities             REG_DWORD       ─── A12 │
│   │           ├── ConfigFlags              REG_DWORD       ─── A13 │
│   │           │                                                    │
│   │           ├── Device Parameters\  (subkey, rarely forensic)    │
│   │           ├── LogConf\            (subkey, rarely forensic)    │
│   │           │                                                    │
│   │           └── Properties\                                      │
│   │               └── {83da6326-97a6-4088-9453-a1923f573b29}\      │
│   │                   │   ← DEVPKEY property class (Win8+)         │
│   │                   │                                            │
│   │                   ├── 0064   REG_BINARY/FILETIME      ─── A14  │
│   │                   ├── 0065   REG_BINARY/FILETIME      ─── A15  │
│   │                   ├── 0066   REG_BINARY/FILETIME      ─── A16  │
│   │                   └── 0067   REG_BINARY/FILETIME      ─── A17  ┘
│   │
│   └── MountedDevices\                                              ┐
│       │                                                            │ MountedDevices
│       ├── [key.LastWrite]                                 ─── B1   │
│       ├── \DosDevices\<letter>:         REG_BINARY        ─── B2   │
│       │      ├── (MBR case)  disk-sig(4B) + offset(8B)             │
│       │      ├── (GPT case)  partition GUID (16B)                  │
│       │      └── (USB case)  symbolic-link string to \??\USBSTOR#…#│
│       └── \??\Volume{<GUID>}             REG_BINARY        ─── B3  │
│              └── (same three encoding cases as B2)                 ┘
│
├── NTUSER.DAT  [hive — one per user profile]
│   │
│   └── Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\   ┐
│       │                                                                  │ MountPoints2
│       │                                                                  │
│       ├── {<volume-GUID>}\      ← local/removable volume subkey          │
│       │   ├── [key.LastWrite]                              ─── C1        │
│       │   ├── BaseClass            REG_SZ                  ─── C2        │
│       │   ├── _LabelFromReg        REG_SZ                  ─── C3        │
│       │   ├── Data                 REG_BINARY (optional)   ─── C4        │
│       │   └── Shell\AutoRun\command    REG_SZ (optional)   ─── C5        │
│       │                                                                  │
│       ├── #<server>#<share>\   ← SMB share subkey (# encodes \)          │
│       │   ├── [key.LastWrite]                              ─── C6        │
│       │   └── _LabelFromReg        REG_SZ                  ─── C7        │
│       │                                                                  │
│       └── CPC\...             ← namespace-extension entries (non-mount)  ┘
│
└── SOFTWARE  [hive]
    │
    └── Microsoft\Windows Portable Devices\Devices\                    ┐
        │                                                              │ Windows Portable
        │                                                              │ Devices
        └── <WPD-device-id>\                                           │
            │   ← format: WPDBUSENUMROOT#UMB#…#USBSTOR#…#<SERIAL>…     │
            │                                                          │
            ├── [key.LastWrite]                             ─── D1     │
            └── FriendlyName           REG_SZ               ─── D2     ┘
```

## Leaf annotations

### A. USBSTOR

| Leaf | Encoding | Semantics | Availability | Tamper class | Proposition |
|---|---|---|---|---|---|
| A0 | path-segment | `<instance-id>` IS the serial. Char-pos 2 = `&` means OS-synthesized (not device-reported) — do NOT treat as unique identity. | always | — | — |
| A1 | FILETIME | Key LastWrite — "last touched" semantics, not "last connected." Updated on any value change. | always | admin-writable indirectly | weak time bound |
| A2 | UTF-16LE | Friendly name from USB descriptor. Missing on generic thumb drives. | device-dependent | admin-editable | identifier for `CONNECTED(peer)` |
| A3 | REG_SZ/GUID | **ContainerID** — stable device identity. Survives format/repartition. Does NOT survive controller replacement / crypto-erase. | Win7+ | admin-editable | primary `CONNECTED(peer)` identifier |
| A4 | REG_SZ (`@<dll>,-<resid>`) | Localized string resource indirection. Corroboration only. | always | admin-editable | — |
| A5 | REG_MULTI_SZ | Hardware IDs, most-specific first. | always | admin-editable | identifier corroboration |
| A6 | REG_MULTI_SZ | Compatible IDs (generic). | always | admin-editable | identifier corroboration |
| A7 | REG_SZ | Usually `"disk"` or `"USBSTOR"`. | always | admin-editable | — |
| A8 | REG_SZ | Driver node path → pivots to `SYSTEM\...\Class\<ClassGUID>\`. | always | admin-editable | cross-hive pivot |
| A9 | REG_SZ/GUID | Standard disk class GUID. | always | admin-editable | — |
| A10 | REG_SZ | Human class name (`"DiskDrive"`). | always | admin-editable | — |
| A11 | REG_SZ (indirection) | Manufacturer resource. | always | admin-editable | — |
| A12 | REG_DWORD | Capability bitfield (ejectable, removable, lockable). | always | admin-editable | "is removable" corroboration |
| A13 | REG_DWORD | Config flags set by PnP manager. | always | admin-editable | — |
| A14 | FILETIME | **First install** — set once on first enumeration. | Win8+ | admin-editable | `CONNECTED.time.start` anchor |
| A15 | FILETIME | **First arrival** — first plug-in after driver install. | Win8+ | admin-editable | `CONNECTED` corroboration |
| A16 | FILETIME | **Last arrival** — updated every reconnect. | Win8+ | admin-editable | `CONNECTED.time.end` |
| A17 | FILETIME | **Last removal** — updated ONLY on Safely-Remove. Yank does not update. Stale A17 + recent A16 = behavior indicator. | Win8+ | admin-editable | `CONNECTED` corroboration + behavior |

### B. MountedDevices

| Leaf | Encoding | Semantics | Availability | Tamper class | Proposition |
|---|---|---|---|---|---|
| B1 | FILETIME | Key LastWrite. Set on any value change (new mount / remount). | always | admin-writable | weak time anchor |
| B2 | REG_BINARY (by disk type) | Drive-letter binding. For USB: UTF-16LE symlink string `\??\USBSTOR#Disk&...#<SERIAL>#{...}`. Serial pivots back to A0. | always | admin-editable | bridges drive-letter ↔ USBSTOR |
| B3 | REG_BINARY | Volume-GUID-keyed binding; same data encodings as B2. **This is what MountPoints2 resolves through.** | always | admin-editable | bridges volume-GUID ↔ USBSTOR |

### C. MountPoints2 (per user)

| Leaf | Encoding | Semantics | Availability | Tamper class | Proposition |
|---|---|---|---|---|---|
| C1 | FILETIME | **Last mount of this volume under THIS user.** No history — only most recent. | Vista+ | **user-writable** (HKCU, no elevation) | `POSSESSED.time` |
| C2 | REG_SZ | `"Drive"` for local/removable. Absent/different for network/virtual. | commonly present | user-writable | volume classification |
| C3 | REG_SZ | Volume label as user saw it in Explorer. | when label set | user-writable | device identity corroboration |
| C4 | REG_BINARY | Opaque Shell namespace data. Sometimes contains drive letter / volume serial. | variable | user-writable | opportunistic |
| C5 | REG_SZ | AutoPlay command for this volume. Presence suggests user opened AutoPlay UI. | when interacted | user-writable | weak `ACCESSED` indicator |
| C6 | FILETIME | Last mount of this SMB share under this user. | when share mounted | user-writable | `ACCESSED(remote-share, user)` |
| C7 | REG_SZ | Share label/name. | variable | user-writable | identifies share |

### D. Windows Portable Devices

| Leaf | Encoding | Semantics | Availability | Tamper class | Proposition |
|---|---|---|---|---|---|
| D1 | FILETIME | Last enumeration or friendly-name update (often when Explorer refreshes device). | Vista+ | admin-writable | `CONNECTED.time` corroboration |
| D2 | UTF-16LE | Volume label as seen by WPD subsystem — filesystem label written at format or by `label.exe`. **Frequently survives anti-forensic cleanup** that hits USBSTOR/MountedDevices. | variable | admin-writable | device identity + anti-forensic survivor |

## Cross-artifact convergence map

```
   A0 / A3          B2 / B3                 C1
 (device serial  ← bridges drive-letter →  (user ties
    + ContainerID)    and volume-GUID       to volume-GUID
                     to USBSTOR serial       via per-user LastWrite)
        ▲                                         ▲
        │                                         │
        └──────── same device identity ───────────┘
                           ▲
                           │
                           D2
               (volume label corroborates
                even when USBSTOR wiped)
```

### Canonical pivot chain (using only the four artifacts in scope)

1. **A0/A3** — start at USBSTOR instance: vendor, product, serial, ContainerID.
2. **B3** — find MountedDevices value whose data contains that serial; value-name yields the volume-GUID.
3. **C1** — find that volume-GUID as a subkey under MountPoints2 in a specific NTUSER.DAT; proves *that user* saw the volume mounted; C1 timestamp dates the last mount under that profile.
4. **D2** — corroborate with Windows Portable Devices: volume label carries across even when USBSTOR has been cleaned.

### Timestamp triangulation within scope

Combining A14–A17 (device lifecycle on SYSTEM) with C1 (user-scoped last-mount on NTUSER) gives:
- When the device was first known to this system (A14)
- When a user first plugged it in (A15)
- When it was last connected (A16)
- When it was last safely removed (A17) — or whether the user yanked it (A17 stale vs. A16 recent)
- When that specific user last mounted it (C1)

### Missed-convergence signals

| Pattern | Likely cause | Forensic value |
|---|---|---|
| A0/A3 present, B2/B3 for same serial absent | MountedDevices cleaned; USBSTOR survived | partial anti-forensic — cleaner missed SYSTEM\MountedDevices |
| B2/B3 refs serial with no matching A0 | USBSTOR cleaned; MountedDevices survived | opposite partial cleanup — cleaner hit USBSTOR\Enum but not root \MountedDevices |
| C1 exists under GUID with no matching B3 | Targeted cleanup of SYSTEM\MountedDevices; NTUSER untouched | user-scope evidence survives host-scope cleanup |
| D2 exists without USBSTOR or MountedDevices | Thorough cleanup of SYSTEM hive; WPD in SOFTWARE hive missed | most telling anti-forensic signature — WPD rarely hit by cleaners |

## Training observations

- The four-artifact scope is enough to answer "did device `D` connect to system `S`, and did user `U` see it" at **C3** ceiling (device identity + user binding + two corroborating sources across two hives).
- It is NOT enough to answer "did user `U` *copy files to* device `D`" — that requires `ACCESSED`, `EXECUTED_BY`, and (ideally) destination-side `CREATED` evidence from artifacts outside scope.
- The single most anti-forensic-resistant leaf in scope is **D2** (WPD FriendlyName). Most USB cleaners ignore the WPD path.
- The single weakest leaf in scope is **C1** (MountPoints2 LastWrite) — user-writable, no audit, no history.
- The single most information-dense leaf is **A0/A3** combined — one value + one path-segment parse gives you unique device identity and reveals OS-synthesized-serial warnings.
