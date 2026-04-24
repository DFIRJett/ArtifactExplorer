---
name: ACCESSED_SERVICE
summary: "Service-ticket / service-authentication proposition — user authenticated to a specific Kerberos service principal or Windows service. Joins Kerberos ticket cache with RDP session auth (TS-LSM-21) + service installation/execution records (Services, Security-4697) via ServiceName + UserSID pivots."
yields:
  mode: new-proposition
  proposition: ACCESSED_SERVICE
  ceiling: C3
inputs:
  - AUTHENTICATED
  - PERSISTED
input-sources:
  - proposition: AUTHENTICATED
    artifacts:
      - Kerberos-Tickets-Cache
      - TS-LSM-21
  - proposition: PERSISTED
    artifacts:
      - Services
      - Security-4697
join-chain:
  - concept: ServiceName
    join-strength: strong
    sources:
      - ietf-2005-rfc-4120-the-kerberos-network
      - ms-event-4624
    primary-source: ms-event-4624
    description: |
      Service-principal pivot. Kerberos-Tickets-Cache TGS tickets
      bind to a specific SPN (HTTP/server, CIFS/server, MSSQLSvc/
      server:port). TS-LSM-21 binds a session to the Terminal
      Services service principal. Services registry names the
      service (MpsSvc, LanmanServer, etc.); Security-4697 emits
      ServiceName on installation. Joining on ServiceName answers
      "which specific service did THIS user access / is configured
      on this host?" — the pivot for Kerberoasting detection
      (anomalous SPN-ticket requests) + service-abuse detection
      (legit user's TGT used to request unusual service tickets).
    artifacts-and-roles:
      - artifact: Kerberos-Tickets-Cache
        role: identitySubject
      - artifact: TS-LSM-21
        role: identitySubject
      - artifact: Services
        role: identitySubject
      - artifact: Security-4697
        role: identitySubject
  - concept: UserSID
    join-strength: strong
    sources:
      - ietf-2005-rfc-4120-the-kerberos-network
      - ms-event-4624
    primary-source: ms-event-4624
    description: |
      Actor-attribution pivot. Kerberos-Tickets-Cache entries are
      per-LSA-session (accessible via the session's LUID → owning
      SID mapping). TS-LSM-21 emits the authenticating UserSID in
      the event payload. Security-4697 emits SubjectUserSid of the
      account that installed the service. Joining on UserSID
      converts "some account accessed this service" into "THIS
      specific account accessed this service" — foundational for
      service-account-abuse and Golden-Ticket / Silver-Ticket
      forgery detection (forged tickets appear with anomalous or
      privileged SIDs for services the user shouldn't access).
    artifacts-and-roles:
      - artifact: Kerberos-Tickets-Cache
        role: actingUser
      - artifact: TS-LSM-21
        role: actingUser
      - artifact: Security-4697
        role: actingUser
exit-node:
  - Kerberos-Tickets-Cache
notes:
  - 'Kerberos-Tickets-Cache: cryptographically-bound proof of service-authentication. Exit-node for HAS_CREDENTIAL + ACCESSED_SERVICE — ticket bytes terminate replay-attack attribution (you CANT have this ticket unless authentication happened or the key material was forged).'
  - 'TS-LSM-21: RDP session authenticate event. Binds Terminal Services session to UserSID + ClientName. Specific to interactive remote-access service.'
  - 'Services: HKLM\SYSTEM\CurrentControlSet\Services registry — service identity configuration. Paired with Security-4697 (install event) for per-service lifecycle.'
  - 'Security-4697: service-installation event. Emits ServiceName + ImagePath + installer SubjectUserSid. Requires Security System Extension audit.'
provenance:
  - ietf-2005-rfc-4120-the-kerberos-network
  - ms-event-4624
  - mitre-t1558
  - mitre-t1543-003
  - gentilkiwi-2020-mimikatz-vault-cred-modules-ex
  - foundation-2021-volatility-hibernate-address-s
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
---

# Convergence — ACCESSED_SERVICE

Tier-2 convergence yielding proposition `ACCESSED_SERVICE`.

Binds four service-access artifacts: Kerberos TGS tickets (Kerberos-Tickets-Cache), RDP session auth (TS-LSM-21), service registry (Services), and service-install audit (Security-4697). ServiceName + UserSID pivots resolve which user accessed which service when.

Participating artifacts: Kerberos-Tickets-Cache, TS-LSM-21, Services, Security-4697.
