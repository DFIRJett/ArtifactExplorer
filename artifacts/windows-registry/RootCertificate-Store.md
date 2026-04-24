---
name: RootCertificate-Store
title-description: "Trusted Root Certification Authority store — attacker-installed roots enable silent TLS MITM"
aliases:
- Root CA store
- SystemCertificates\ROOT
- Trusted Root Certification Authorities
- Certificate Store
link: persistence
tags:
- tls-mitm
- tamper-signal
- itm:ME
volatility: persistent
interaction-required: user-session
substrate: windows-registry-hive
substrate-instance: SOFTWARE and NTUSER.DAT
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SOFTWARE (HKLM) — machine-wide certs
  path-machine: "Microsoft\\SystemCertificates\\ROOT\\Certificates\\<thumbprint>"
  hive-user: NTUSER.DAT (HKCU) — per-user certs
  path-user: "Software\\Microsoft\\SystemCertificates\\ROOT\\Certificates\\<thumbprint>"
  addressing: hive+key-path
  note: "Each subkey name is the SHA-1 thumbprint of an installed root certificate. The (Default) Blob value under each subkey contains the DER-encoded certificate. Windows also maintains an AuthRoot store (Microsoft-managed auto-update list), a CA store (intermediate CAs), and others — this artifact focuses on the ROOT store because it is the trust anchor for TLS / code-signing verification. An attacker-installed root cert enables the attacker to: (1) sign TLS certificates that appear valid to Windows apps, enabling silent MITM of HTTPS traffic; (2) sign code that passes Authenticode verification; (3) issue sub-CAs for broader downstream trust abuse."
fields:
- name: certificate-blob
  kind: content
  location: "ROOT\\Certificates\\<thumbprint>\\Blob value"
  type: REG_BINARY
  encoding: Microsoft SystemCertificates binary wrapper containing DER-encoded X.509
  note: "The raw certificate. Binary-format wrapper (SystemCertificate property bag) with the DER-encoded X.509 certificate embedded. Tools: certutil -store ROOT; PowerShell Get-ChildItem Cert:\\LocalMachine\\Root; or parse the Blob directly via CertParseCertificateContext."
- name: cert-subject
  kind: label
  location: "Certificate blob — Subject DN field"
  encoding: X.509 / ASN.1 encoded Distinguished Name
  note: "Subject of the root CA. Well-known legit roots: DigiCert, Let's Encrypt ISRG, VeriSign, Microsoft, GlobalSign, Sectigo, etc. A Subject that is NOT on the Microsoft Trusted Root Program list AND not on the enterprise's documented internal-CA list = investigation target."
- name: cert-issuer
  kind: label
  location: "Certificate blob — Issuer DN field"
  note: "For a true root CA, Issuer == Subject (self-signed). For intermediates mistakenly placed in ROOT store, Issuer differs from Subject. Presence of an intermediate-looking cert in ROOT store is either misconfiguration or deliberate cert-chain-pinning by an attacker."
- name: cert-validity
  kind: timestamp
  location: "Certificate blob — NotBefore / NotAfter"
  encoding: X.509 UTC time
  clock: certificate-issuer
  resolution: 1s
  note: "Validity window. Attacker-generated roots often have very long validity (50+ years, 9999-12-31) to outlive detection; excessive far-future NotAfter = signal. Also: a NotBefore matching the suspected intrusion timeline is a direct pivot."
- name: cert-serial
  kind: identifier
  location: "Certificate blob — Serial Number field"
  encoding: X.509 integer
  note: "Serial number is certificate-issuer-scoped. For an attacker-generated root this is an arbitrary value set at cert generation; no lookup against external registries possible, but pairs with Subject / Thumbprint for cert-identity confirmation."
- name: cert-thumbprint
  kind: hash
  location: "ROOT\\Certificates\\<thumbprint> subkey NAME"
  encoding: sha-1 hex
  references-data:
  - concept: ExecutableHash
    role: contentHash
  note: "SHA-1 hash of the DER-encoded certificate. Join key across the whole certificate ecosystem — use this to cross-reference against certutil output, Event Viewer CAPI2 events, Microsoft's Trusted Root list, and any EDR cert-inventory data."
- name: key-last-write
  kind: timestamp
  location: "ROOT\\Certificates\\<thumbprint> key metadata"
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on the subkey = cert-install time. Correlate with Microsoft-Windows-CAPI2/Operational event 4097 (cert installed) when CAPI2 operational logging is enabled. Bonus: CAPI2 channel logs the SID of the installing user."
- name: per-user-vs-machine
  kind: flags
  location: "HKLM (machine-wide) vs HKCU (per-user installation)"
  references-data:
  - concept: RegistryKeyPath
    role: subjectKey
  note: "Machine-wide root installs (HKLM) affect every user and require admin; per-user installs (HKCU) affect only that user but do NOT require admin. Low-privilege attackers use HKCU to install rogue roots in their own session silently. Always enumerate BOTH scopes; an unprivileged attacker's cert may only be in HKCU."
observations:
- proposition: CONFIGURED
  ceiling: C4
  note: 'The Windows root certificate store is the trust anchor for all
    TLS validation and Authenticode code-signing checks performed by
    Windows applications. An attacker-installed root allows: silent
    MITM of HTTPS traffic (issue server certs valid for any domain),
    bypass of SmartScreen / WDAC / AppLocker signer-based rules
    (sign malicious binaries with the rogue root-chained cert), and
    issuance of sub-CAs for ecosystem-wide trust abuse. Per-user
    root install requires NO admin — one of the most dangerous
    user-scope capabilities because most defensive assumptions
    presume root certs require admin to install. Always enumerate
    BOTH HKLM\\...\\SystemCertificates\\ROOT and HKCU\\...\\
    SystemCertificates\\ROOT, diff against Microsoft Trusted Root
    Program list + documented enterprise internal-CA inventory,
    investigate any delta.'
  qualifier-map:
    setting.registry-path: "Microsoft\\SystemCertificates\\ROOT\\Certificates\\<thumbprint>"
    setting.cert: field:cert-subject
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: "Windows AuthRoot update mechanism does NOT remove manually-installed roots — attacker roots persist through Windows Update CTL refreshes. Tamper Protection does not cover this store."
  known-cleaners:
  - tool: certutil -delstore ROOT <thumbprint>
    typically-removes: the single cert (leaves subkey LastWrite on sibling subkeys unchanged)
  - tool: Certificates MMC snap-in → right-click → Delete
    typically-removes: same; produces CAPI2-4098 event
  survival-signals:
  - Subject DN not on Microsoft Trusted Root Program list and not on enterprise internal-CA list = candidate rogue root
  - Issuer == Subject (self-signed) with unusual Subject fields (CN=localhost, CN=test, CN=attacker-issued-name) = attacker-generated
  - NotAfter very far in the future (9999-12-31 or 50+ years out) = generated without compliance with CA/Browser Forum norms
  - HKCU\\Software\\Microsoft\\SystemCertificates\\ROOT entries on a non-admin user's profile = user-scope rogue install
  - Key LastWrite within incident window AND cert Subject contains attacker-suggestive names = direct plant
provenance:
  - ms-windows-certificate-stores-registry
  - ms-microsoft-trusted-root-program-list
  - mitre-t1553-004
  - labs-2019-dangers-of-installing-root-cer
---

# Trusted Root Certificate Store

## Forensic value
Every Windows system maintains a Trusted Root Certificate Authorities store at `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\<thumbprint>` (machine-wide) and `HKCU\Software\Microsoft\SystemCertificates\ROOT\Certificates\<thumbprint>` (per-user). Certificates here are the trust anchor for:

- **TLS server-certificate validation** — Edge, Chrome (Enterprise policy), curl.exe, PowerShell Invoke-WebRequest, and all Windows apps using WinHTTP / WinINet / Schannel
- **Authenticode code-signing verification** — signed executables / drivers / scripts
- **S/MIME email signature validation**

An attacker-installed root enables:

1. **Silent TLS MITM** — attacker generates server certs for any domain, signed by the rogue root; the client validates them as trusted
2. **Authenticode bypass** — attacker-signed binaries appear Microsoft-trusted; SmartScreen / WDAC / AppLocker signer-rules are bypassed
3. **Sub-CA issuance** — the rogue root can be used to issue intermediates that issue leaf certs, enabling ecosystem-wide trust abuse

## The per-user scope
Per-user root installs do **not require admin**. A low-privilege attacker with only user-scope writes can install a rogue root in HKCU and immediately MITM their own session's HTTPS traffic or bypass user-scope code-signing. This is one of the highest-impact unprivileged persistence capabilities on Windows, and most defensive baselines wrongly assume "root certs need admin."

Always enumerate BOTH HKLM and HKCU scopes. For HKCU, sweep every user profile's NTUSER.DAT.

## Concept reference
- None direct — cert-content artifact. Thumbprint serves as the unique identifier for cross-reference.

## Triage
```cmd
:: Machine-wide
certutil -store ROOT
:: Per-user (current user)
certutil -user -store ROOT

:: Registry-direct enumeration
reg query "HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"
reg query "HKCU\Software\Microsoft\SystemCertificates\ROOT\Certificates"
```

PowerShell:
```powershell
Get-ChildItem Cert:\LocalMachine\Root | Format-List Subject, Issuer, NotAfter, Thumbprint
Get-ChildItem Cert:\CurrentUser\Root | Format-List Subject, Issuer, NotAfter, Thumbprint
```

## Baseline-comparison
Compare enumerated thumbprints against Microsoft's Trusted Root Program published list. Cert-thumbprint match to published list = known-good. Non-match = investigation candidate (may still be legitimate enterprise CA — check against enterprise PKI inventory).

## Cross-reference
- `Microsoft-Windows-CAPI2/Operational` event 4097 — root cert installation (when CAPI2 op logging enabled)
- `Microsoft-Windows-CAPI2/Operational` event 4098 — root cert removal
- PKI audit logs for enterprise internal CAs (validate documented internal roots against what's actually present)
- Prefetch / Security-4688 for `certutil.exe` with `-addstore` / `-user -addstore` arguments = install evidence

## Practice hint
On a lab VM: `certutil -user -addstore ROOT <path-to-self-signed-cert.cer>`. Note that this succeeds WITHOUT admin elevation. Open Internet Explorer / Edge and visit an HTTPS site served by that self-signed cert — no warning. Now `certutil -user -delstore ROOT <thumbprint>` and repeat — warning returns. That unprivileged install capability is exactly what makes rogue-root persistence dangerous.
