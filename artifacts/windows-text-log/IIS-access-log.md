---
name: IIS-access-log
aliases: [IIS W3C log, u_ex access log]
link: network
tags: [server-only, web-traffic]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: IIS-W3C
platform:
  windows-server: {min: '2003', max: '2025'}
location:
  path: "%SystemDrive%\\inetpub\\logs\\LogFiles\\W3SVC<siteId>\\u_ex<yymmdd>.log"
  addressing: filesystem-path
fields:
- name: log-line
  kind: record
  location: W3C-format text line
  encoding: "configurable field list; default includes date/time, s-ip, cs-method, cs-uri-stem, cs-uri-query, s-port, cs-username, c-ip, cs(User-Agent), cs(Referer), sc-status, sc-substatus, sc-win32-status, time-taken"
- name: c-ip
  kind: address
  location: c-ip field
  references-data:
  - {concept: IPAddress, role: sourceIp}
- name: cs-uri-stem
  kind: url
  location: cs-uri-stem field
  references-data:
  - {concept: URL, role: proxyRequestUrl}
- name: cs-username
  kind: label
  location: cs-username field
  note: "authenticated-only; '-' for anonymous"
- name: cs(User-Agent)
  kind: label
  location: user-agent field
  note: "signature for scanner identification — sqlmap, Nikto, curl, ..."
- name: sc-status
  kind: status
  location: HTTP status code field
- name: timestamp
  kind: timestamp
  location: date + time fields
  encoding: UTC (ISO-8601)
  clock: system (UTC)
  resolution: 1s
observations:
- proposition: HTTP_REQUEST_SERVED
  ceiling: C3
  note: "Per-request IIS access log. Gold source for webshell / post-exploit analysis, SQL-injection probing, credential-stuffing, data-exfil-via-HTTP."
  qualifier-map:
    actor.ip: field:c-ip
    object.url: field:cs-uri-stem
    object.status: field:sc-status
    time.observed: field:timestamp
anti-forensic:
  write-privilege: unknown
  known-cleaners:
  - {tool: direct file delete, typically-removes: full (but IIS keeps log handle, often fails on active day)}
provenance: []
provenance: [kape-files-repo]
---

# IIS-access-log

## Forensic value
Per-request log for every web request IIS processes. W3C format; field set configurable per site. Primary forensic interest:
- Webshell activity (unusual cs-uri-stem + POST patterns)
- Data exfil (large time-taken or repeated large-response patterns)
- Credential stuffing (many 401 events from few IPs)
- Injection probing (SQL/XSS patterns in cs-uri-query + cs(User-Agent))

## Cross-references
- **HTTPERR-log** — requests that failed at the HTTP.sys kernel level
- **firewall-log** — network-layer corroboration (source IP, byte counts)
- **Security-4624** — if cs-username is populated, matches against a logon event
