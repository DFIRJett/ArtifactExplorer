---
name: EXFILTRATED_NETWORK
summary: "Data-exfiltration-over-network proposition — user/process moved content off-host via HTTP / HTTPS / BITS / proxy channels. Joins browser history (Chrome / Edge / Firefox), silent-transfer artifacts (BITS-QueueManager), proxy-log, and firewall-log via URL + DomainName + PeerAddress pivots."
yields:
  mode: new-proposition
  proposition: EXFILTRATED_NETWORK
  ceiling: C3
inputs:
  - ACCESSED
  - COMMUNICATED
  - CONNECTED
input-sources:
  - proposition: ACCESSED
    artifacts:
      - Chrome-History
      - Edge-History
  - proposition: COMMUNICATED
    artifacts:
      - Chrome-History
      - Firefox-places
      - BITS-QueueManager
      - proxy-log
  - proposition: CONNECTED
    artifacts:
      - firewall-log
join-chain:
  - concept: URL
    join-strength: strong
    sources:
      - chromium-history-schema
    description: |
      Destination-URL pivot. Chrome-History, Edge-History,
      Firefox-places each store visited URLs (including cloud-
      storage upload endpoints — dropbox.com/upload, drive.google
      .com/upload, onedrive.live.com). BITS-QueueManager stores
      the RemoteUrl for each enqueued transfer. proxy-log emits
      request-URL per line. firewall-log doesn't carry URL (only
      IP + port). Joining on URL converts a generic "content
      left the host" claim into "content was POSTed to THIS
      specific cloud-storage endpoint" — the attribution-grade
      evidence prosecutors / HR / internal investigations need.
    artifacts-and-roles:
      - artifact: Chrome-History
        role: destinationURL
      - artifact: Edge-History
        role: destinationURL
      - artifact: Firefox-places
        role: destinationURL
      - artifact: BITS-QueueManager
        role: destinationURL
      - artifact: proxy-log
        role: destinationURL
  - concept: DomainName
    join-strength: strong
    sources:
      - chromium-history-schema
    description: |
      DNS-resolvable-peer pivot. All URL-carrying artifacts
      implicitly carry the destination DomainName (host portion
      of the URL). firewall-log + proxy-log also emit domain
      when DNS resolution happens before the connection. Joining
      on DomainName groups exfil across protocols (browser
      upload + BITS + proxy all hitting the same dropbox.com
      domain within minutes = coordinated multi-vector exfil,
      not one-off). Also the pivot for cloud-storage-provider
      classification (DomainName → CloudProvider taxonomy).
    artifacts-and-roles:
      - artifact: Chrome-History
        role: peerDomain
      - artifact: Edge-History
        role: peerDomain
      - artifact: Firefox-places
        role: peerDomain
      - artifact: BITS-QueueManager
        role: peerDomain
      - artifact: proxy-log
        role: peerDomain
      - artifact: firewall-log
        role: peerDomain
  - concept: IPAddress
    join-strength: moderate
    sources:
      - chromium-history-schema
    description: |
      Peer-IP pivot. firewall-log emits src/dst IP per flow;
      proxy-log emits client + upstream IP; BITS-QueueManager
      stores the resolved peer IP at transfer-enqueue time.
      Browser histories don't directly carry IP. Joining on
      IPAddress is the fallback when DomainName is unreliable
      (fast-flux DNS, direct-IP URLs, cloud-CDN IP reuse).
      Also the primary pivot when cross-referencing against
      threat-intel IP blocklists.
    artifacts-and-roles:
      - artifact: firewall-log
        role: peerIp
      - artifact: proxy-log
        role: peerIp
      - artifact: BITS-QueueManager
        role: peerIp
  - concept: TimeWindow
    join-strength: moderate
    sources:
      - chromium-history-schema
    description: |
      Temporal-bracketing pivot. Chrome-History.visits.visit_time
      (microseconds since 1601); Edge-History similar; Firefox-
      places.history.visit_date (microseconds since epoch);
      BITS-QueueManager per-transfer timestamps; proxy-log
      per-line timestamps; firewall-log per-flow timestamps.
      Joining on TimeWindow lets an analyst correlate
      simultaneous exfil signals across channels: a browser
      upload-URL visit at 14:02 + a firewall flow to the same
      CIDR at 14:02 + BITS transfer to same provider at 14:03
      = high-confidence exfil burst.
    artifacts-and-roles:
      - artifact: Chrome-History
        role: timeAnchor
      - artifact: Edge-History
        role: timeAnchor
      - artifact: Firefox-places
        role: timeAnchor
      - artifact: BITS-QueueManager
        role: timeAnchor
      - artifact: proxy-log
        role: timeAnchor
      - artifact: firewall-log
        role: timeAnchor
exit-node:
  - BITS-QueueManager
  - proxy-log
notes:
  - 'Chrome-History: visits table + downloads table. "/upload" or large POST-likely URLs in History. Exit-node for browser-mediated exfil.'
  - 'Edge-History: Chromium-family history (identical SQLite schema to Chrome post-Chromium-adoption).'
  - 'Firefox-places: places.sqlite history database. Different schema from Chrome/Edge (moz_places + moz_historyvisits tables) but same forensic role.'
  - 'BITS-QueueManager: Background Intelligent Transfer Service queue state. QMGR database carries JobID + RemoteUrl + LocalFilename + transfer state. Exit-node for silent-exfil via BITS (attacker-favorite because BITS uses Windows-trusted svchost.exe).'
  - 'proxy-log: enterprise HTTP proxy log. Per-request URL + user + destination + bytes-transferred. Exit-node for the server-side view of HTTP-based exfil.'
  - 'firewall-log: pfirewall.log — per-flow src/dst/protocol/bytes. No URL visibility. Complements proxy-log for HTTPS flows where proxy sees URL (if MITM) but firewall sees the SNI-absent CONNECT.'
provenance:
  - chromium-history-schema
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — EXFILTRATED_NETWORK

Tier-2 convergence yielding proposition `EXFILTRATED_NETWORK`.

Binds seven network-exfil-evidence artifacts covering browser histories (Chrome / Edge / Firefox), silent-BITS transfers, enterprise proxy logs, and host firewall logs. URL + DomainName + IPAddress + TimeWindow pivots resolve where content went, via which channel, to which peer, at which time.

Participating artifacts: Chrome-History, Edge-History, Firefox-places, BITS-QueueManager, proxy-log, firewall-log.
