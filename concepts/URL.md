---
name: URL
kind: value-type
lifetime: permanent
link-affinity: network
link-affinity-secondary: application
description: |
  Full URL — scheme + host + path + query. Captured by browser histories,
  cache artifacts, file-download provenance markers (Zone.Identifier),
  and web-proxy logs. Contains a `DomainName` as a substring.
canonical-format: "RFC-3986 form (e.g., 'https://example.com/path?q=1')"
aliases: [web-url, resource-locator]
roles:
  - id: visitedUrl
    description: "URL the user browsed to"
  - id: downloadedFromUrl
    description: "URL that served a downloaded file"
  - id: referrerUrl
    description: "The page that referenced a subsequent navigation or download"
  - id: proxyRequestUrl
    description: "URL recorded in a web-proxy access log entry"
  - id: embeddedReferenceUrl
    description: "URL embedded in another artifact's content (email body, file metadata)"

known-containers:
  - Chrome-History
  - Firefox-places
  - Zone-Identifier-ADS
  - proxy-log
  - Outlook-PST
provenance:
  - rfc-3986-uri-generic-syntax
---

# URL

## What it is
Full web-resource identifier. Superset of `DomainName` — the URL contains the domain but also path and query-string information that reveal *what* was requested, not just where.

## Forensic value
- **Specific-content tracking.** `http://example.com/payload.exe` vs just `example.com` — the URL tells you which file was downloaded.
- **Query-string exfiltration.** Long query strings with base64-encoded parameters are a classic covert-channel.
- **Phishing-link attribution.** Precise URL can be matched against known-bad campaigns.

## Relationship to DomainName
Every URL contains exactly one DomainName in its authority section. The build pipeline does NOT automatically derive DomainName from URL — artifacts that record URLs should reference both if the investigator should be able to pivot on either.

## Encoding variations

| Artifact | Where |
|---|---|
| Chrome-History | `urls.url` column (full URL, percent-encoded) |
| Zone-Identifier-ADS | `ReferrerUrl=` and `HostUrl=` fields in the `[ZoneTransfer]` section |
| proxy-log | per-entry URL field |
