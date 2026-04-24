---
name: windows-prefetch
kind: binary-structured-file
substrate-class: Filesystem/Artifact
aliases: [prefetch, .pf file, SuperFetch trace]

format:
  storage-scheme:
    pre-win10-1709: "raw binary, signature 'SCCA' at offset 4"
    win10-1803-plus: "MAM-compressed (XPRESS Huffman) wrapping the raw SCCA content"
  magic-compressed: "4D 41 4D 04  ('MAM\\x04')"
  magic-decompressed: "53 43 43 41  ('SCCA')"
  endianness: little
  authoritative-spec:
    - title: "Windows Prefetch File (PF) format"
      author: Joachim Metz
      url: https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
  versions:
    17: "Windows XP / Server 2003"
    23: "Windows Vista / 7 / Server 2008"
    26: "Windows 8 / 8.1 / Server 2012"
    30: "Windows 10 (all builds)"
    31: "Windows 11"

structure:
  outer: |
    On Win10 1803+, the file begins with a 4-byte 'MAM\x04' signature followed
    by a 4-byte uncompressed size and then XPRESS-Huffman-compressed data.
    Decompress to access the SCCA content.
  header:
    size-bytes: 84
    key-fields:
      - { name: Version, offset: 0x00, encoding: uint32 }
      - { name: Signature, offset: 0x04, encoding: "'SCCA' FOURCC" }
      - { name: FileSize, offset: 0x0C, encoding: uint32 }
      - { name: Executable-name, offset: 0x10, size: 60, encoding: utf-16le }
      - { name: Path-hash, offset: 0x4C, encoding: uint32-le }
  body:
    file-information-struct: "contains run-count and last-run-times array"
    volumes-information-array: "per-volume device-path + 32-bit serial + creation-time + file-ref list"
    metrics-array: "one per file referenced during loading (win10+ includes MFT segment ref)"
    trace-chains-array: "sequential file-IO trace"
    filename-strings: "UTF-16LE list of all referenced files"

persistence:
  live-system-locations:
    root: "%WINDIR%\\Prefetch"
    file-format: "<EXENAME>-<8-char-hex-path-hash>.pf"
  max-entries: "varies by OS — typically 1024 on consumer Windows; can be disabled via registry"
  locked-on-live-system: partial — the active OS holds some .pf files briefly
  acquisition: standard file copy from %WINDIR%\\Prefetch\\*.pf

parsers:
  - name: PECmd (Eric Zimmerman)
    strengths: [bulk CSV, all versions, transparent MAM decompression]
  - name: libscca / scca_info (Joachim Metz)
    strengths: [format-correct, research-grade]
  - name: WinPrefetchView (NirSoft)
    strengths: [GUI, live-system friendly]

forensic-relevance:
  - up-to-8-run-timestamps: "Win10+ preserves last 8 run times per executable — rich temporal evidence"
  - file-loading-trace: "filenames referenced during execution identify DLL-loads, config-file reads, etc. — execution context"
  - per-executable-per-path: "two prefetch entries with same exe name but different path hashes = same name run from two locations"
  - hash-collisions: "Path hash is 32-bit, collisions possible but rare; use path string for disambiguation"

integrity:
  signing: none
  tamper-vectors:
    - deletion (common cleanup; detectable via $MFT carving in some cases)
    - in-place edit after decompression (requires recompression to restore valid file)
  audit-trail: "deletion of a .pf file is not audited by default; changes to the Prefetch directory are visible in $MFT"

anti-forensic-concerns:
  - "Prefetch can be disabled via 'EnablePrefetcher' = 0 in SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters. Forensic absence of Prefetch on a Windows box is itself suspicious."
  - "Anti-forensic tools may delete individual .pf files for specific targets while leaving the directory populated — selective cleanup detectable by timing pattern."

known-artifacts:
  # Prefetch-substrate artifacts cover the .pf file itself plus sibling
  # optimisation structures in the same directory. Superfetch/ReadyBoot
  # telemetry DBs live adjacent but in different formats.
  authored:
    - Prefetch                 # <Name>-<Hash>.pf — full execution metadata
  unwritten:
    - name: Prefetch-Layout
      location: "%WINDIR%\\Prefetch\\Layout.ini"
      value: defragmenter hint file listing all prefetched binaries in boot order; enumerates executed programs even when individual .pf files are purged
    - name: Prefetch-ReadyBoot
      location: "%WINDIR%\\Prefetch\\ReadyBoot\\ReadyBoot.etl + Trace*.fx"
      value: ETL-format boot trace; alternate evidence of early-boot execution sequence
    - name: Prefetch-AgAppLaunch
      location: "%WINDIR%\\Prefetch\\AgAppLaunch.db"
      value: legacy Superfetch app-launch telemetry DB (Vista–8.1); rolls into SRUM on Win10+
    - name: Prefetch-AgGlFaultHistory
      location: "%WINDIR%\\Prefetch\\AgGlFaultHistory.db"
      value: Superfetch page-fault history; historical application behavior
    - name: Prefetch-Compressed-MAM
      location: "*.pf with MAM header (Win10+)"
      value: XPress/MAM-compressed prefetch variant; requires decompression before parsing
provenance:
  - libyal-libscca
---

# Windows Prefetch

## Forensic value
Per-executable execution history with up to 8 run timestamps (Win10+), run count, path hash, and the set of files loaded during execution. One of the foundational execution-evidence artifacts. Survives most consumer anti-forensic tools.

## Addressing
An artifact here identifies as `<executable>-<path-hash>.pf`. The filename is the artifact name. Multiple prefetch files for the same executable imply execution from multiple paths.

## MAM compression gotcha (Win10+)
Attempting to read a Win10+ .pf file as raw binary yields `MAM\x04` followed by garbage. Parsers must recognize the MAM header, read the uncompressed size, and XPRESS-Huffman decompress before parsing the SCCA content. Old parsers (pre-2018) fail on modern prefetch.

## Collection notes
Acquire the entire `%WINDIR%\Prefetch\` directory. Individual files are small (kilobytes); the directory usually fits in under 100 MB total. Preserving all .pf files is the standard forensic acquisition approach.
