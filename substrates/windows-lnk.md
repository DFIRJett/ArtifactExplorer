---
name: windows-lnk
kind: binary-structured-file
substrate-class: Filesystem/Artifact
aliases: [LNK, Shell Link, Shortcut file]

format:
  magic: "4C 00 00 00 (0x0000004C header-size signature)"
  clsid: "00021401-0000-0000-C000-000000000046"
  endianness: little
  authoritative-spec:
    - title: "[MS-SHLLINK]: Shell Link (.LNK) Binary File Format"
      publisher: Microsoft
      url: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
    - title: "Windows Shortcut File (LNK) format"
      author: Joachim Metz
      url: https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc

structure:
  header:
    size-bytes: 76
    key-fields:
      - { name: HeaderSize, offset: 0x00, encoding: uint32 }
      - { name: LinkCLSID, offset: 0x04, encoding: guid }
      - { name: LinkFlags, offset: 0x14, encoding: uint32-bitfield }
      - { name: FileAttributes, offset: 0x18, encoding: uint32-bitfield }
      - { name: CreationTime, offset: 0x1C, encoding: filetime }
      - { name: AccessTime, offset: 0x24, encoding: filetime }
      - { name: WriteTime, offset: 0x2C, encoding: filetime }
      - { name: FileSize, offset: 0x34, encoding: uint32 }
      - { name: IconIndex, offset: 0x38, encoding: int32 }
      - { name: ShowCommand, offset: 0x3C, encoding: uint32 }
      - { name: HotKey, offset: 0x40, encoding: uint16 }
  body:
    sections-in-order:
      - LinkTargetIDList         # optional — shell item list of target components
      - LinkInfo                 # optional — volume / local-path / network-path info
      - StringData               # optional — NAME_STRING / RELATIVE_PATH / WORKING_DIR / ARGS / ICON
      - ExtraData                # optional — TrackerDB, PropertyStore, SpecialFolder, etc.

persistence:
  live-system-locations:
    auto-created-by-Explorer:
      - "%APPDATA%\\Microsoft\\Windows\\Recent"                # file-open history (auto)
      - "%APPDATA%\\Microsoft\\Office\\Recent"                 # Office MRU
    user-maintained:
      - "%USERPROFILE%\\Desktop"
      - "%APPDATA%\\Microsoft\\Windows\\Start Menu"
      - "%USERPROFILE%\\Links"
    embedded-in-other-containers:
      - AutomaticDestinations (jump lists) — .automaticDestinations-ms files
      - CustomDestinations (jump lists) — .customDestinations-ms files
  locked-on-live-system: false
  acquisition: standard file copy; individual .lnk files can be read without special tools

parsers:
  - name: LECmd (Eric Zimmerman)
    strengths: [CSV/JSON bulk export, TrackerDB parsing, well-maintained]
  - name: liblnk / lnkinfo (Joachim Metz)
    strengths: [format-correct, research-grade]
  - name: Windows File Analyzer
    strengths: [GUI]
  - name: Explorer shell API (on live systems)
    weaknesses: [does NOT expose TrackerDataBlock; forensically inadequate]

forensic-relevance:
  - MAC times at capture: |
      LNK preserves the target file's MAC timestamps at the moment the LNK
      was created. Subsequent modifications to the target don't update these.
      LNK MAC times are a time-frozen snapshot.
  - volume-identity capture: |
      LinkInfo preserves drive type, drive serial (FS-level), and volume
      label at the moment of access. Comparing LNK volume serial to current
      volume serial reveals whether the volume has been reformatted since.
  - cross-host attribution: |
      TrackerDataBlock carries the NetBIOS name of the machine that stamped
      the LNK. Preserves cross-host provenance even when the LNK is copied.

integrity:
  signing: none
  mac: none
  tamper-vectors:
    - open/save via LNK-aware tool re-writes fields
    - direct hex-edit of binary
    - target-file modification after LNK creation does NOT update LNK MAC times (this is a feature, not a vuln — but means LNK timestamps can look stale without being tampered)

anti-forensic-concerns:
  - Clearing "Recent items" via Explorer UI deletes files in %APPDATA%\\Microsoft\\Windows\\Recent but leaves jump list .automaticDestinations-ms files intact. Partial cleanup is the norm.
  - LNK carving from unallocated is productive — LNK files have a fixed header signature and are self-describing.

known-artifacts:
  # LNK artifacts are semantic uses of the same binary format at different
  # filesystem locations. Each location has distinct forensic interpretation.
  # Seed source: authored set + Magnet Forensics LNK analysis +
  # Nasreddine Bencherchali Windows Artifacts series.
  authored:
    - ShellLNK           # generic format — fields common to any LNK instance
  unwritten:
    - name: Recent-LNK
      location: "%APPDATA%\\Microsoft\\Windows\\Recent\\*.lnk"
      value: auto-populated file-access history; survives target deletion
    - name: Desktop-LNK
      location: "%USERPROFILE%\\Desktop + %PUBLIC%\\Desktop\\*.lnk"
      value: user-placed shortcuts; intentional accessibility signal
    - name: StartMenu-LNK
      location: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\*.lnk"
      value: installed/placed app launchers; baseline for unauthorized additions
    - name: Startup-LNK
      location: "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.lnk (+ All Users variant)"
      value: LNK-based autorun persistence; common malware drop site
    - name: OfficeRecent-LNK
      location: "%APPDATA%\\Microsoft\\Office\\Recent\\*.lnk"
      value: per-Office-app recent-document tracking, distinct from system Recent
    - name: NetworkShare-LNK
      location: any *.lnk with UNC-target
      value: accessed network share + volume/MachineID pivot for lateral attribution
    - name: BrowserDownload-LNK
      location: "%USERPROFILE%\\Downloads\\*.lnk and adjacent"
      value: downloaded shortcut files (phishing/supply-chain); Mark-of-the-Web via Zone-Identifier ADS
provenance:
  - libyal-libfwsi
  - libyal-liblnk
  - ms-shllink
---

# Windows Shell Link (LNK) file

## Forensic value
LNK files are the single richest per-user file-access evidence on Windows. Each LNK captures:
- Full target path, including volume identity
- Target's MAC timestamps at the moment of access
- Volume label and filesystem serial number
- Source machine NetBIOS name (cross-host attribution)
- Network share path if the target was remote

The LNK format is older than Windows NT and remains forensically rich because Explorer writes one automatically for virtually every file the user opens. `%APPDATA%\Microsoft\Windows\Recent` is a time-ordered history of user file access, one LNK per recently-opened target.

## Addressing within a LNK
An artifact in this container identifies by (role, location). "ShellLNK" as a general class refers to any .lnk file's internal structure. Specific artifact variants (Recent LNK vs. Desktop LNK vs. embedded-in-jump-list) share the same format but live in different containers and carry slightly different investigative propositions.

## Parser disagreements
- Tracker MachineID: 15 vs. 16 bytes of the field returned by different parsers.
- Shell-item decoding in the LinkTargetIDList varies — some parsers fully resolve the chain (ComputerFolder → drive → folder → file), others stop at the first unrecognized item type.
- String encoding (ASCII vs. UTF-16LE) in the optional StringData sections depends on the `IsUnicode` LinkFlags bit; parsers that don't honor the flag produce garbled paths.
