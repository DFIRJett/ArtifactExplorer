---
name: ExecutableHash
kind: value-type
lifetime: permanent
link-affinity: application
link-affinity-secondary: file
description: |
  Cryptographic hash of a PE file's contents (SHA1, SHA256, MD5, or IMPHASH).
  The canonical way to identify the same executable across artifacts
  regardless of path or filename. Primary pivot against threat-intel feeds.
canonical-format: "hex string — 32 chars (MD5), 40 chars (SHA1), 64 chars (SHA256)"
aliases: [file-hash, image-hash, SHA1, SHA256, MD5, IMPHASH, PE-hash]
roles:
  - id: ranHash
    description: "Hash of an executable observed at the moment of execution"
  - id: detectedHash
    description: "Hash of a file flagged by security tooling"
  - id: scannedHash
    description: "Hash observed during a scan without necessarily being flagged"
  - id: contentHash
    description: "Hash captured as content of the artifact itself — certificate thumbprint, signed-binary catalog hash, file-hash embedded in a log line — not tied to an execution / detection / scan event"

known-containers:
  - Amcache-InventoryApplicationFile
  - Sysmon-1
  - Sysmon-7
  - Defender-MPLog
  - YARA-hits
  - Prefetch
provenance: [nist-fips-180-4, ms-sysinternals-autoruns]
---

# Executable Hash

## What it is
Cryptographic fingerprint of a PE file. Unlike ExecutablePath (which is a location claim), a hash is an *identity* claim — two files with the same SHA256 are the same file regardless of path, name, or machine.

## Forensic value
- **Cross-machine and cross-artifact identity.** Match a hash in your corpus against VirusTotal, Defender logs, threat feeds.
- **Path-independent deduplication.** `powershell.exe` at `C:\Windows\System32\` and the same binary at `C:\Users\X\Temp\` produce the same hash — evidence of relocation or impersonation.
- **Tamper detection.** A PE that no longer hashes to its known-good value was modified or replaced.

## Encoding variations

| Artifact | Field / location | Algorithm |
|---|---|---|
| Amcache | `Root\InventoryApplicationFile\<Id>\FileId` | SHA1 (first byte = "0" prefix then 40-hex) |
| Sysmon-1 | `Hashes` event field | "MD5=...,SHA1=...,SHA256=...,IMPHASH=..." compound string |
| Defender-MPLog | detection entry | SHA256 most common |
| Prefetch | PE loaded during exec — hash not stored directly, resolvable via path + live disk |
