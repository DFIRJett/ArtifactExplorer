---
name: SChannel-TLS-Config
title-description: "SChannel TLS / cipher / protocol registry — attacker-downgrade surface for Windows TLS stack"
aliases:
- SChannel registry
- TLS downgrade
- Schannel Ciphers
- Schannel Protocols
link: system
link-secondary: network
tags:
- tls-downgrade
- tamper-signal
- itm:AF
volatility: persistent
interaction-required: none
substrate: windows-registry-hive
substrate-instance: SYSTEM
platform:
  windows:
    min: NT5.0
    max: '11'
  windows-server:
    min: '2000'
    max: '2022'
location:
  hive: SYSTEM
  path: "CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
  sub-paths:
    - "SCHANNEL\\Protocols\\<protocol>\\Client (Enabled, DisabledByDefault)"
    - "SCHANNEL\\Protocols\\<protocol>\\Server (Enabled, DisabledByDefault)"
    - "SCHANNEL\\Ciphers\\<cipher-name> (Enabled)"
    - "SCHANNEL\\Hashes\\<hash-name> (Enabled)"
    - "SCHANNEL\\KeyExchangeAlgorithms\\<kx> (Enabled)"
  addressing: hive+key-path
  note: "Schannel is Windows' TLS / SSL stack. Every Windows app using WinHTTP / WinINet / Schannel direct — Edge, Outlook, Windows Update, Windows Defender, built-in PowerShell Invoke-WebRequest — consults these registry keys. Attacker-tampered values downgrade TLS security on the entire host: re-enable SSL 2.0 / 3.0 / TLS 1.0, re-enable RC4 / 3DES, weaken key-exchange to enable passive MITM or accept weakly-signed certs. Enterprise hardening baselines (CIS, DISA STIG) explicitly configure these; drift from baseline = either misconfigured IT OR deliberate tamper."
fields:
- name: protocol-enabled
  kind: flags
  location: "Protocols\\<SSL 2.0|SSL 3.0|TLS 1.0|TLS 1.1|TLS 1.2|TLS 1.3>\\Client\\Enabled + DisabledByDefault values"
  type: REG_DWORD
  note: "Enabled: 0xFFFFFFFF / 1 = protocol enabled, 0 = disabled. DisabledByDefault: 1 = negotiation skips unless app explicitly requests, 0 = negotiated normally. MS baseline on Win10/11: TLS 1.2 / 1.3 enabled+default-on; all others disabled+default-off. Attacker re-enabling SSL 2.0 / 3.0 / TLS 1.0 = downgrade surface for passive capture / MITM. Check BOTH Client and Server subkeys."
- name: cipher-enabled
  kind: flags
  location: "Ciphers\\<cipher-name>\\Enabled value"
  type: REG_DWORD
  note: "0xFFFFFFFF = enabled; 0 = disabled. Cipher-name examples: 'AES 128/128', 'AES 256/256', 'DES 56/56', 'RC2 40/128', 'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168', 'NULL'. MS baseline disables: NULL, DES, RC2, RC4 variants. Attacker re-enabling RC4 / 3DES / DES = cryptographic-weakness reintroduction."
- name: hash-enabled
  kind: flags
  location: "Hashes\\<hash-name>\\Enabled value"
  type: REG_DWORD
  note: "Values per hash: MD5, SHA, SHA256, SHA384, SHA512. Enabled: 0xFFFFFFFF = on, 0 = off. MS baseline disables MD5. Attacker re-enable of MD5 = weak-signature acceptance for cert chains."
- name: key-exchange-enabled
  kind: flags
  location: "KeyExchangeAlgorithms\\<kx-name>\\Enabled value"
  type: REG_DWORD
  note: "Values: Diffie-Hellman, ECDH, PKCS, RSA, etc. Attacker manipulation of these keyexchange settings enables downgrade to weaker key agreement."
- name: fips-algorithm-policy
  kind: flags
  location: "Control\\Lsa\\FipsAlgorithmPolicy value"
  type: REG_DWORD
  note: "Cross-key sibling: 1 = FIPS mode (restricts SChannel to FIPS-approved algorithms), 0 = non-FIPS. Attacker clearing FIPS mode weakens the entire cryptographic posture. MS baseline on regulated-environment hosts: 1."
- name: event-logging
  kind: flags
  location: "SCHANNEL\\EventLogging value"
  type: REG_DWORD
  note: "Controls SChannel event-log verbosity. 1 = errors, 2 = warnings, 4 = informational, 7 = all. Attacker setting 0 (or very low) suppresses SChannel errors from System-channel / Microsoft-Windows-Schannel/Operational EVTX, hiding cert-validation failures / downgrade-negotiation warnings."
- name: key-last-write
  kind: timestamp
  location: per-SChannel-subkey metadata
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "LastWrite on protocol / cipher / hash subkeys updates when the Enabled or DisabledByDefault value changes. Diff against enterprise hardening-baseline snapshot: any subkey with LastWrite post-dating the baseline deploy = drift candidate."
observations:
- proposition: CONFIGURED_DEFENSE
  ceiling: C3
  note: 'SChannel registry controls the TLS / SSL posture of every
    Windows application that uses the OS crypto stack. Browsers
    (Edge), email clients (Outlook), built-in Windows components
    (Windows Update, Windows Defender update channel, BITS,
    PowerShell Invoke-WebRequest) all trust Schannel for TLS.
    Attacker-enabled SSL 2.0 / 3.0 / TLS 1.0 + attacker-enabled
    RC4 / 3DES / DES + attacker-enabled MD5 hash = downgrade attack
    surface. Passive network capture + MITM becomes viable against
    previously-secured traffic. Enterprise baselines (CIS / DISA STIG)
    explicitly configure these values — drift from baseline is either
    misconfigured IT OR deliberate tamper. DFIR: diff live registry
    against known-good policy baseline.'
  qualifier-map:
    setting.registry-path: "Control\\SecurityProviders\\SCHANNEL"
    time.start: field:key-last-write
anti-forensic:
  write-privilege: admin
  integrity-mechanism: none (not signed)
  survival-signals:
  - SSL 2.0 / SSL 3.0 / TLS 1.0 / TLS 1.1 Enabled=1 on a modern Windows endpoint = downgrade surface
  - RC4 / DES / 3DES / NULL cipher Enabled=1 on a modern endpoint = weak-cipher surface
  - FipsAlgorithmPolicy changed from 1 → 0 without documented reason = FIPS posture broken
  - EventLogging=0 on SChannel = deliberate error-suppression
  - Key LastWrite on SChannel subkeys within incident window = TLS posture tamper during intrusion
provenance: [ms-tls-registry-settings-schannel-conf, mitre-t1562-001, stig-2023-windows-10-11-security-technic]
---

# SChannel TLS / Cipher Configuration

## Forensic value
Windows' TLS / SSL stack (Schannel) reads its configuration from the registry on every TLS handshake. Every app that uses Schannel (Edge, Outlook, Windows Update, BITS, PowerShell Invoke-WebRequest, etc.) inherits this posture.

Four key subtrees under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\`:

- `Protocols\<SSL 2.0|SSL 3.0|TLS 1.0|TLS 1.1|TLS 1.2|TLS 1.3>\{Client,Server}` — enable/disable per protocol version and direction
- `Ciphers\<cipher-name>` — enable/disable symmetric ciphers
- `Hashes\<hash-name>` — enable/disable hash algorithms
- `KeyExchangeAlgorithms\<kx-name>` — enable/disable key-exchange algorithms

## Attacker-target posture changes
- **Re-enable SSL 3.0 / TLS 1.0** → passive network capture of supposedly-secure traffic
- **Re-enable RC4 / 3DES / DES** → weak cipher suites acceptable to negotiation
- **Re-enable MD5 hash** → weakly-signed cert chain acceptance
- **Set FipsAlgorithmPolicy=0** → remove FIPS-mode constraints
- **Set EventLogging=0** → suppress Schannel error events in Event Log

Any of these on a modern, baseline-hardened endpoint = potential tamper.

## Concept reference
- None direct — configuration state artifact.

## Triage
```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes" /s
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v FipsAlgorithmPolicy
```

PowerShell enterprise-scan:
```powershell
# Use IISCrypto / Nartac / custom script to render the current cipher suite state vs baseline
```

## Diff workflow
Diff live registry against a baseline enterprise-hardened snapshot:
- Expected enabled: TLS 1.2, TLS 1.3, AES 128/256, SHA 256/384/512
- Expected disabled: SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1, RC4 (all variants), DES, 3DES, RC2, NULL, MD5

Any enabled from the "expected disabled" set on a baselined endpoint = tamper / drift.

## Cross-reference
- **Microsoft-Windows-Schannel/Operational** EVTX channel — TLS-negotiation events
- **System-36887 / 36888** — Schannel fatal-alert events
- **Security-4688 / Sysmon-1** — reg.exe / PowerShell registry-write process-creation at tamper moment
- **Network captures** — pcap evidence of weak-cipher negotiation post-tamper

## Practice hint
On a test VM: inspect baseline Schannel state with `reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s`. Then enable SSL 3.0: `reg add "...\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 1 /f` + `reg add ... /v DisabledByDefault /t REG_DWORD /d 0 /f`. Use `nmap --script ssl-enum-ciphers` against a local TLS service to confirm SSL 3.0 is now negotiable. Restore by setting back to defaults. This drift is exactly what DFIR compares against baseline.
