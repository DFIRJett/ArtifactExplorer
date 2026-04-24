# Schema — Composition Rules

Derived propositions. Each rule specifies:
- **inputs:** primitives (from `primitives.md`) that must be present
- **constraints:** unification rules across the inputs
- **derives:** the new proposition
- **strength formula:** how the derived proposition's C-ceiling is computed
- **preconditions:** case-time conditions that must hold

A composition rule is a template. At case time, the schema traverses each artifact's `extends-to` edges, checks whether inputs are available and preconditions hold, and emits the derived proposition. If an input is absent but would have satisfied all preconditions, the schema flags a **missed convergence**.

---

## `USED(user, device, system)`
User connected and used a removable/peripheral device on a system.

**Inputs:**
- `CONNECTED(peer=device=D, local-endpoint=system=S, time=T1)`
- `POSSESSED(entity=device=D, actor=user=U, scope=user-profile, time=T2)`

**Constraints:**
- Device identity unifies between inputs (serial, ContainerID, or volume-GUID chain).
- Time windows overlap: `T1 ∩ T2 ≠ ∅`.

**Derives:**
```
USED(actor=U, entity=D, system=S, time=T1 ∩ T2)
```

**Strength formula:**
- `min(ceiling(CONNECTED), ceiling(POSSESSED))`
- `-1` if device identity chain depends on an OS-assigned serial (USB `&0` suffix) with no ContainerID corroboration.

**Preconditions:**
- User profile for `U` was loadable during `T1` (NTUSER.DAT available + user existed at that time).
- No evidence of profile-hive transplant (`ProfileList` SID vs. hive SID mismatch).

---

## `EXECUTED_BY(user, process, system)`
A specific user account ran a process.

**Inputs (Path A — direct):**
- `EXECUTED(process=P, actor=U, time=T)` — artifact asserts user directly (e.g., UserAssist, ShimCache with user context, EVTX 4688 with SubjectUserName)

**Inputs (Path B — session-chained):**
- `EXECUTED(process=P, on=system=S, time=T)`
- `AUTHENTICATED(principal=U, target=S, result=success, time=Ta)` where `Ta ≤ T` and `Ta` is the most recent successful interactive logon for any principal on `S` before `T`
- No intervening `logoff` event between `Ta` and `T`

**Derives:**
```
EXECUTED_BY(actor=U, process=P, system=S, time=T)
```

**Strength formula:**
- Path A: `ceiling(EXECUTED)`.
- Path B: `min(ceiling(EXECUTED), ceiling(AUTHENTICATED)) - 1`. Capped at C3 unless session had cryptographic integrity (Kerberos + PAC + signed events).

**Preconditions:**
- Single-user session on `S` during window `[Ta, T]`. Multi-user systems (RDP, Terminal Server, fast-user-switch) require session-ID correlation and escalate strength penalty.
- Process was not launched by a scheduled task or service (which would reassign the actor).

**Common missed convergence:** Security.evtx rotation. If logon events rolled over before examination but UserAssist still carries the execution record, Path A survives where Path B dies.

---

## `EXFILTRATED(object, peer, system)`
Data was moved off the system to an external destination.

**Inputs (minimal):**
- `ACCESSED(object=O, on=system=S, time=T1)` OR `MODIFIED(object=O, on=S, time=T1)`
- `CONNECTED(peer=P, local-endpoint=S, direction=outbound, time=T2)` where `T2` is within a tunable window `Δ` of `T1` (default `Δ = 5 min`)

**Inputs (strengthened):**
- Add `COMMUNICATED(direction=sent, peer=P, actor=?, content-digest ≈ hash(O) OR size(O) ± ε, time=T3)`

**Derives:**
```
EXFILTRATED(entity=O, peer=P, system=S, time=T1 → T2)
```

**Strength formula:**
- Minimal inputs: **C2** maximum. Temporal coincidence is weak.
- With content-digest match: **C3–C4** depending on digest precision (exact hash > size-match > metadata-match).
- With full content capture in PCAP or proxy log: **C4** (still not C5 — content could be decoy).

**Preconditions:**
- Object size > noise floor of normal outbound traffic on `S`.
- Peer `P` is not a sanctioned backup destination (check `CONFIGURED(backup-target)` propositions).

**Design note:** This is intentionally the weakest composite. Exfil claims routinely get overstated from temporal coincidence alone — the rule forces the examiner to declare which strengthening inputs they have.

---

## `PERSISTED(entity, system)`
Entity is configured to execute on future boot/login events.

**Inputs:**
- `CONFIGURED(setting=<persistence-mechanism>, value=<references entity E>, on=system=S, time=Tc)` where `setting` matches a known persistence mechanism (Run key, Scheduled Task, Service, launchd plist, systemd unit, cron, WMI subscription, etc.)
- `EXISTS(entity=E, on=S, time=Te)` where `Te ≥ Tc`

**Derives:**
```
PERSISTED(entity=E, system=S, via=<setting>, time=Tc → present)
```

**Strength formula:**
- `ceiling(CONFIGURED)` — the persistence mechanism's artifact is load-bearing.
- `-1` if persistence mechanism is user-writable without elevation (HKCU Run vs. HKLM Run).

**Preconditions:**
- Entity `E` actually resolvable at path referenced by the setting (dead persistence — file deleted — gets a separate proposition: `PERSISTED_DANGLING`).
- Setting was not created by a known-benign installer (cross-reference software inventory).

---

## `EXECUTED_FROM(process, source-location, system)`
Process ran from a specific source — notably removable media, network share, or staged location.

**Inputs:**
- `EXECUTED(process=P, source=L, on=system=S, time=T)` (direct)

**OR:**
- `EXECUTED(process=P, on=S, time=T)`
- `CONNECTED(peer=device=D, local-endpoint=S, time=T2)` where `T2 ≤ T` and no intervening disconnect
- Process image path references a drive letter or share resolvable to `D`

**Derives:**
```
EXECUTED_FROM(process=P, source=L, system=S, time=T)
```

**Strength formula:**
- Direct: `ceiling(EXECUTED)`.
- Indirect via drive-letter resolution: `min(ceilings) - 1`. Drive letters are ephemeral and reassignable.

**Preconditions:**
- If indirect: drive letter → device mapping stable across `[T2, T]`. A user who unplugs-and-replugs invalidates the chain.

---

## `AUTHENTICATED_AS(user, system)` — the session fact
Establishes that a user had an active session on a system during a window. Required input for most user-attribution compositions.

**Inputs:**
- `AUTHENTICATED(principal=U, target=S, result=success, time=Ta)`
- No `AUTHENTICATED(principal=U, target=S, result=logoff)` between `Ta` and current time OR explicit session-end event

**Derives:**
```
AUTHENTICATED_AS(actor=U, system=S, time=Ta → Tend)
```

**Strength formula:** `ceiling(AUTHENTICATED)`.

**Preconditions:**
- Logoff tracking is reliable on `S` (Security.evtx 4634/4647 retained OR equivalent).
- Session not hijacked (no evidence of process token theft or pass-the-ticket during window).

**Missed convergence pattern:** Truncated Security.evtx frequently obliterates the logon anchor. Fallback artifacts: UserAssist timestamps, Registry transaction logs, cached credentials (registry LSA Secrets), prefetch timestamps on logon scripts.

---

## Composition rule authoring guide

When adding a new derived proposition:

1. **Minimum-input form first.** State the weakest input set that the name implies, not the ideal evidentiary picture. Strengthening inputs go in a separate section.
2. **Strength formula must penalize weak links.** If any input can be forged by a non-elevated user, the composite cannot exceed C3.
3. **Preconditions must be case-time checkable.** "Single-user session" is checkable; "user intended to exfiltrate" is not — that belongs to the factfinder.
4. **Missed-convergence patterns** should be documented. They're the most valuable training content — they teach what to look for when the obvious artifact is gone.
5. **Every rule must be reversible.** Given a composite proposition, it must be possible to decompose it back into its input primitives and name the artifact that sourced each qualifier. No black-box inference.
