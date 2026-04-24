# Schema — Primitive Investigative Propositions

Tier-1 proposition vocabulary. An artifact's `observations:` block must reference one of these primitives (or a rule from `composition-rules.md` that derives from them). Tier-2 `convergences/*.md` files compose these primitives into higher-level claims.

## Design rules

1. A primitive asserts a single, atomic fact about observable activity on a system.
2. Every primitive requires a `time` qualifier (point or window). A proposition without time cannot be corroborated.
3. Every qualifier value carries a `provenance` — the artifact + field(s) that sourced it. Propositions without provenance are claims, not evidence.
4. Two propositions refer to the same event iff same primitive + unifiable qualifiers + overlapping time. Unification rules are per-primitive (below).
5. Qualifiers marked `(req)` must be filled for the proposition to be valid. `(opt)` qualifiers strengthen but are not required.
6. Every proposition carries a `strength-ceiling` — the Casey C-level floor given the artifact(s) asserting it. See `timestamp-semantics.md` for timestamp-induced strength penalties.

## Primitive set

### 1. `EXISTS(entity)`
The entity was present on the system.

| qualifier | req/opt | notes |
|---|---|---|
| entity | req | file, process image, account, device, application, configuration blob |
| location | opt | where on/within the system |
| time | req | point or window |
| frequency | opt | first-seen, last-seen, duration |

Unification: same canonical entity identity + overlapping time.

### 2. `EXECUTED(process)`
A process ran on the system.

| qualifier | req/opt | notes |
|---|---|---|
| process | req | path + hash preferred; name + parent acceptable |
| actor | opt | principal (user / service / SYSTEM) |
| source | opt | origin location (fixed disk, removable, network share, memory) |
| parent | opt | parent process identity |
| invocation | opt | command line, arguments |
| time | req | start; end if known |
| frequency | opt | count, first-run, last-run |

Unification: same process image hash OR same path + overlapping exec window.

### 3. `ACCESSED(object)`
An object was read/opened without modification.

| qualifier | req/opt |
|---|---|
| object | req |
| actor | opt |
| via | opt (app or handle type) |
| time | req |
| frequency | opt |

Unification: same object identity + overlapping time.

### 4. `CREATED(object)`
Object came into existence on this system. Mutually exclusive with pre-existing state.

| qualifier | req/opt |
|---|---|
| object | req |
| actor | opt |
| source | opt (copied-from, synthesized-by) |
| location | req |
| time | req |

### 5. `MODIFIED(object)`
Content of an existing object changed.

| qualifier | req/opt |
|---|---|
| object | req |
| actor | opt |
| change-type | opt (size, content-hash, attribute, metadata) |
| time | req |
| frequency | opt |

### 6. `DELETED(object)`
Object was removed. Soft-delete (recycle) vs. hard-delete (unlinked/overwritten) distinguished via `change-type`.

| qualifier | req/opt |
|---|---|
| object | req |
| actor | opt |
| change-type | opt (soft / hard / secure-wipe) |
| time | req |

### 7. `CONNECTED(peer)`
A network or physical connection occurred.

| qualifier | req/opt |
|---|---|
| peer | req | remote host, removable device, physical bus endpoint |
| local-endpoint | opt (this system / an interface on it) |
| via | opt (interface, transport, port, protocol) |
| direction | opt (inbound / outbound / bidirectional) |
| actor | opt (principal / process) |
| time | req |
| frequency | opt |

Unification: same peer identity (IP+port or device ID) + overlapping time.

### 8. `AUTHENTICATED(principal)`
A credential was evaluated. Captures both successes and failures.

| qualifier | req/opt |
|---|---|
| principal | req |
| target | req (system, realm, resource) |
| result | req (success / failure) |
| method | opt (password, cert, token, biometric, passkey, kerberos, NTLM) |
| source | opt (origin host/device) |
| time | req |
| frequency | opt |

Unification: same (principal, target, result) + overlapping time.

### 9. `POSSESSED(entity)`
Entity was under the control of a principal or within a principal's scope.

| qualifier | req/opt |
|---|---|
| entity | req |
| actor | req |
| scope | opt (user profile, app sandbox, org tenancy) |
| time | req |

Unification: same (entity, actor) + overlapping time.

### 10. `COMMUNICATED(direction, with)`
A message was sent or received.

| qualifier | req/opt |
|---|---|
| direction | req (sent / received) |
| peer | req (email addr, phone, account handle, channel ID) |
| actor | opt (local principal) |
| channel | opt (SMTP, SMS, XMPP, Signal, Slack, Teams, HTTP-POST) |
| content-digest | opt (hash / subject / size — for content-level correlation) |
| time | req |

Unification: same (direction, peer, actor, approx-time) — content-digest strengthens.

### 11. `CONFIGURED(setting, value)`
Persistent state was established on the system.

| qualifier | req/opt |
|---|---|
| setting | req (registry path, config file path, env var, policy name) |
| value | req |
| actor | opt |
| scope | opt (machine / user / application) |
| time | req |
| frequency | opt (if setting is history-preserving) |

Unification: same setting + same scope + overlapping time. Value changes make distinct propositions.

## Strength ceiling

Every supporting artifact declares a `strength-ceiling` for the proposition it asserts. When multiple artifacts assert the same proposition (corroboration), the composite ceiling is:

- **Symmetric-independent corroboration:** `max(ceilings)` if sources are independent AND both are tamper-resistant, else `min(ceilings) + 1` capped at C4.
- **Single-source assertion:** ceiling declared by the artifact.
- **Chained/derived:** see `composition-rules.md`.

A composite can never exceed C5 (multiple independent tamper-protected sources agreeing, per Casey). C6 is reserved.

## Qualifier provenance

Every qualifier value in a filled proposition carries:

```
value: <the value>
from: <artifact-file>#<field-name>
confidence: <C-level for this specific qualifier>
```

This matters because a single proposition's qualifiers may come from multiple artifacts at different C-levels. The proposition's overall strength is the min of its qualifier confidences.

## Time qualifier structure

Time is never a single scalar. Always:

```
time:
  kind: point | window
  start: <ISO-8601>
  end: <ISO-8601>        # == start if kind=point
  clock: <from timestamp-semantics.md>
  resolution: <e.g., 100ns, 1s>
  manipulation-evidence: none | suspected | confirmed
```

Two time qualifiers overlap iff their [start,end] ranges intersect after accounting for clock-skew tolerance declared in `timestamp-semantics.md`.

## What is NOT a primitive

- **Intent** (e.g., "user intended to exfiltrate"). Always a factfinder conclusion.
- **Maliciousness** of an entity. IOC status is analytical overlay, not a proposition.
- **Causation between events.** Sequence can be asserted; causation is inference.
- **Identity of a human behind a principal.** The strongest `AUTHENTICATED` proposition asserts credential use, not keyboard-presence. Human-at-keyboard attribution requires non-digital corroboration outside this schema.
