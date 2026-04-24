---
name: AUTHENTICATION_ATTEMPTED
summary: "Authentication-event proposition — any logon attempt (success or failure) across interactive / network / explicit / Kerberos / NTLM surfaces. Joins Security-462x/4776 authentication events with Kerberos + NTLM residuals via UserSID + LogonSessionId + MachineNetBIOS pivots. The broadest auth-observation convergence."
yields:
  mode: new-proposition
  proposition: AUTHENTICATION_ATTEMPTED
  ceiling: C3
inputs:
  - AUTHENTICATED
input-sources:
  - proposition: AUTHENTICATED
    artifacts:
      - Security-4624
      - Security-4625
      - Security-4634
      - Security-4648
      - Security-4776
      - TS-LSM-21
      - Kerberos-Tickets-Cache
      - Credentials-cached
join-chain:
  - concept: UserSID
    join-strength: strong
    sources:
      - ms-event-4624
      - ms-event-4776
      - mitre-t1110-003
    primary-source: ms-event-4624
    description: |
      Acting-identity pivot. Security-4624 / 4625 / 4634 / 4648
      all carry TargetUserSid (the account being authenticated) +
      SubjectUserSid (the account invoking the auth for 4648).
      Security-4776 carries only the account name (no SID — NTLM
      validator cannot resolve SID for unknown-domain attempts —
      making 4776 the canonical source for invalid-username
      claims). TS-LSM-21 carries the authenticated-user SID in
      the RDP-session payload. Kerberos-Tickets-Cache is keyed by
      the per-user TGT principal. Credentials-cached is per-user
      vault. Joining on UserSID binds the full auth cluster to
      an account — including failures, which 4625 + 4776 are the
      only events that capture (success-only views miss brute-
      force and spray attempts).
    artifacts-and-roles:
      - artifact: Security-4624
        role: actingUser
      - artifact: Security-4625
        role: actingUser
      - artifact: Security-4634
        role: actingUser
      - artifact: Security-4648
        role: actingUser
      - artifact: Security-4776
        role: actingUser
      - artifact: TS-LSM-21
        role: actingUser
      - artifact: Kerberos-Tickets-Cache
        role: actingUser
      - artifact: Credentials-cached
        role: actingUser
  - concept: LogonSessionId
    join-strength: strong
    sources:
      - ms-event-4624
    primary-source: ms-event-4624
    description: |
      Session-binding pivot. Security-4624 emits TargetLogonId
      (LUID of the new session); 4634 emits LogonId at logoff;
      4648 emits SubjectLogonId (the calling session, not the
      one being created); TS-LSM-21 binds the Terminal-Services
      SessionID to a Windows LUID. Kerberos-Tickets-Cache entries
      (when recovered from KerbTicket cache) carry the LSA session
      LUID that owned them. Joining on LogonSessionId lets an
      analyst bracket all activity that happened within this
      specific login session — the pivot that unlocks cross-source
      reconstruction (4624 + 4663 file-access + 4688 process-create
      + 4634 logoff under the same LUID is a complete session
      reconstruction).
    artifacts-and-roles:
      - artifact: Security-4624
        role: sessionBind
      - artifact: Security-4625
        role: sessionBind
      - artifact: Security-4634
        role: sessionBind
      - artifact: Security-4648
        role: sessionBind
      - artifact: TS-LSM-21
        role: sessionBind
      - artifact: Kerberos-Tickets-Cache
        role: sessionBind
  - concept: MachineNetBIOS
    join-strength: moderate
    sources:
      - ms-event-4624
      - ms-event-4776
    primary-source: ms-event-4624
    description: |
      Origin-machine pivot. Security-4624 / 4625 emit
      WorkstationName + IpAddress — the client from which the
      authentication was attempted (may differ from the host
      the event fires on in network-logon scenarios). Security-
      4776 emits Workstation — the client that submitted the NTLM
      challenge. TS-LSM-21 emits ClientName (NetBIOS of the RDP
      client). Joining on MachineNetBIOS lets an analyst answer
      whether THIS host got authenticated to from THAT host —
      the lateral-movement reconstruction primitive. Also the
      source for impossible-travel / geographically-inconsistent
      origin detections when the name resolves to an IP the
      user's profile does not explain.
    artifacts-and-roles:
      - artifact: Security-4624
        role: originMachine
      - artifact: Security-4625
        role: originMachine
      - artifact: Security-4776
        role: originMachine
      - artifact: TS-LSM-21
        role: originMachine
exit-node:
  - Security-4624
  - Security-4625
  - Security-4776
notes:
  - 'Security-4624: successful logon. Exit-node for positive authentication-fact. LogonType codes: 2=interactive / 3=network / 4=batch / 5=service / 7=unlock / 8=networkCleartext / 10=remoteInteractive / 11=cachedInteractive.'
  - 'Security-4625: failed logon. Exit-node for failed-authentication-fact. Status + SubStatus codes distinguish bad-password vs bad-username vs disabled-account vs expired-password. The only way to distinguish username-existed-but-bad-password from username-did-not-exist.'
  - 'Security-4776: NTLM credential validation (succeeded + failed). Exit-node for pre-Kerberos / legacy-protocol authentication-fact. Often the ONLY record when an NTLM attempt hits a domain-joined workstation.'
  - 'Security-4634: logoff event. Pairs with 4624 via LogonId for session-duration calculation.'
  - 'Security-4648: explicit credential logon (runas.exe, scheduled-task with credentials, DCOM over different creds). Distinguishes user-typed-credentials-for-different-account from passive auth.'
  - 'TS-LSM-21: RDP session establish event. Terminal Services Local Session Manager. Specific to LogonType=10 interactive remote desktop sessions.'
  - 'Kerberos-Tickets-Cache: residual of Kerberos authentication — recovered TGT / TGS tickets prove historic authentication. Not an event record; a state record extractable from memory or the LSA cache.'
  - 'Credentials-cached: Credential Manager vault — per-user DPAPI-protected secrets including saved RDP credentials. Evidence that the user supplied credentials for specific target hosts in the past.'
provenance:
  - ms-event-4624
  - ms-event-4776
  - mitre-t1110-003
  - casey-2002-error-uncertainty-loss-digital-evidence
  - casey-2020-standardization-evaluative-opinions
  - forensicartifacts-repo
  - kape-files-repo
  - insiderthreatmatrix-repo
  - ms-advanced-audit-policy
---

# Convergence — AUTHENTICATION_ATTEMPTED

Tier-2 convergence yielding proposition `AUTHENTICATION_ATTEMPTED`.

Binds eight authentication-observation artifacts covering NTLM + Kerberos + interactive + RDP + cached-credential surfaces. UserSID + LogonSessionId + MachineNetBIOS pivots resolve who, which session, and from where — the three dimensions of a complete authentication reconstruction.

Participating artifacts: Security-4624, Security-4625, Security-4634, Security-4648, Security-4776, TS-LSM-21, Kerberos-Tickets-Cache, Credentials-cached.
