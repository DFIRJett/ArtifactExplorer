---
name: HTTPERR-log
aliases: [HTTP.sys error log, kernel HTTP driver error log]
link: network
tags: [system-wide, connection-level]
volatility: persistent
interaction-required: none
substrate: windows-text-log
substrate-instance: HTTPERR
platform:
  windows: {min: XP, max: '11'}
location:
  path: "%WINDIR%\\System32\\LogFiles\\HTTPERR\\httperr*.log"
  addressing: filesystem-path
fields:
- name: log-line
  kind: record
  location: text line
  encoding: "YYYY-MM-DD HH:MM:SS srcip srcport dstip dstport protocol verb url statuscode siteId reason queuename"
- name: src-ip
  kind: address
  location: third field in the line
  references-data:
  - {concept: IPAddress, role: sourceIp}
- name: dst-ip
  kind: address
  location: fifth field
  references-data:
  - {concept: IPAddress, role: destinationIp}
- name: verb
  kind: label
  location: HTTP method field
- name: url
  kind: url
  location: URL field
  references-data:
  - {concept: URL, role: proxyRequestUrl}
- name: status-code
  kind: status
  location: HTTP status code field
- name: reason
  kind: label
  location: trailing reason field
  note: "Timer_ConnectionIdle, Connection_Dropped_List_Full, Forbidden, BadRequest, URL_ProcessingFailed, ..."
- name: timestamp
  kind: timestamp
  location: leading timestamp
  encoding: ISO-8601
  clock: system
  resolution: 1s
observations:
- proposition: HTTP_KERNEL_ERROR
  ceiling: C3
  note: "HTTP.sys kernel-driver error log. Captures requests IIS never processed — timeouts, connection drops, URL-parser failures, forbidden requests. Useful for DoS attribution and scanner identification (unusual URL patterns that IIS rejects pre-application)."
  qualifier-map:
    actor.ip: field:src-ip
    object.url: field:url
    object.status: field:status-code
    time.observed: field:timestamp
anti-forensic:
  write-privilege: unknown
provenance: []
---

# HTTPERR-log

## Forensic value
HTTP.sys (kernel HTTP driver) error log. Captures requests that never reached IIS — connection-level failures, URL-parser rejections, timeouts, forbidden patterns. Complement to IIS-access-log (which only records what IIS processed).

Value for DFIR: scanner / attacker activity often trips HTTPERR before IIS sees it. Unusual URL patterns, malformed verbs, or "URL_ProcessingFailed" lines cluster around reconnaissance traffic.

## Cross-references
- **IIS-access-log** — successful / application-layer requests
- **firewall-log** — network-layer corroboration
