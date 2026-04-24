---
name: DOWNLOADED
summary: "Extracted from artifact extends-to rules. join-chain and exit-node require authorship."
yields:
  mode: new-proposition
  proposition: DOWNLOADED
  ceiling: C3
inputs:
  - COMMUNICATED
input-sources:
  - proposition: COMMUNICATED
    artifacts:
      - BITS-QueueManager
      - CryptnetUrlCache
join-chain:
  - concept: URL
    join-strength: strong
    sources:
      - ms-background-intelligent-transfer-ser
      - project-2023-windowsbitsqueuemanagerdatabas
      - zimmerman-2021-cryptneturlcacheparser-forensi
      - hull-2020-the-cryptnet-url-cache-an-over
    primary-source: ms-background-intelligent-transfer-ser
    description: |
      URL is the direct shared object across both download witnesses. BITS-
      QueueManager qmgr.db RemoteURL field records the source for every
      queued / completed transfer. CryptnetUrlCache stores the fetched
      content keyed by the URL that requested it (path-hash of the URL
      string as the cache-file name). Same URL observed in both = strong
      corroboration the content was requested AND delivered. URL is strong
      for this convergence because both artifacts are content-addressed by
      it — unlike IPAddress which can be shared across requests.
    artifacts-and-roles:
      - artifact: BITS-QueueManager
        role: sourceUrl
      - artifact: CryptnetUrlCache
        role: sourceUrl
  - concept: ExecutableHash
    join-strength: moderate
    sources:
      - zimmerman-2021-cryptneturlcacheparser-forensi
      - ms-working-with-certificate-revocation
      - anssi-fr-2018-bits-parser-jobs-jdb-qmgr-dat
    primary-source: ms-working-with-certificate-revocation
    description: |
      Content-identity pivot for offline verification. CryptnetUrlCache's
      Content\<hash> file IS the downloaded bytes; BITS local-destination
      file's SHA-256 should match if the download succeeded. Joining on
      hash establishes "these two witnesses agree on what came back" —
      critical when URL matches but content differs (e.g. redirect, MITM,
      cached-vs-live). Moderate strength because hash availability depends
      on BITS destination still being on disk; weak otherwise.
    artifacts-and-roles:
      - artifact: BITS-QueueManager
        role: contentIdentity
      - artifact: CryptnetUrlCache
        role: contentIdentity
exit-node:
  - URL
  - ExecutableHash
notes:
  - 'BITS-QueueManager: A completed BITS download job with a local destination path is direct evidence of file delivery to disk.'
  - 'CryptnetUrlCache: The Content\<hash> file IS the downloaded bytes — use it for offline verification of what came back.'
provenance:
  - ms-background-intelligent-transfer-ser
  - mitre-t1197
  - project-2023-windowsbitsqueuemanagerdatabas
  - anssi-fr-2018-bits-parser-jobs-jdb-qmgr-dat
  - zimmerman-2021-cryptneturlcacheparser-forensi
  - hull-2020-the-cryptnet-url-cache-an-over
  - ms-working-with-certificate-revocation
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — DOWNLOADED

Tier-2 convergence yielding proposition `DOWNLOADED`.

Extracted from `extends-to:` rules across the artifact corpus. The `join-chain` and `exit-node` fields are left empty during initial extraction — authorship of the explicit concept-role chain is a manual pass.

Participating artifacts: BITS-QueueManager, CryptnetUrlCache.
