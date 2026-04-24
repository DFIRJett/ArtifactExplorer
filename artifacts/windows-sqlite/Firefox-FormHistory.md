---
name: Firefox-FormHistory
aliases: [Firefox form autofill history]
link: user
link-secondary: application
tags: [per-user, user-typed-content]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Firefox-FormHistory
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\formhistory.sqlite"
  addressing: sqlite-table-row
fields:
- name: profile-sid
  kind: identifier
  location: derived from path segment `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\` — the owning user's SID resolves via ProfileList's ProfileImagePath match against the Users\<username> parent
  encoding: sid-string
  note: "Not a column in moz_formhistory — derived from the filesystem path's owning-user-profile. Required to attribute form-submission evidence to a specific user account."
  references-data:
  - concept: UserSID
    role: profileOwner
- name: fieldname
  kind: label
  location: moz_formhistory → fieldname
  note: "name of the form field the value was submitted under (e.g. 'email', 'query', 'username')"
- name: value
  kind: label
  location: moz_formhistory → value
  note: "literal value the user typed into the field — search terms, email addresses, usernames, plaintext form data"
- name: firstUsed
  kind: timestamp
  location: moz_formhistory → firstUsed
  encoding: webkit-microseconds
- name: lastUsed
  kind: timestamp
  location: moz_formhistory → lastUsed
  encoding: webkit-microseconds
- name: timesUsed
  kind: counter
  location: moz_formhistory → timesUsed
observations:
- proposition: USER_TYPED_CONTENT
  ceiling: C3
  note: "Every autofill-eligible form submission persists here. Gold for user-intent: literal strings the user typed into websites — search queries, email addresses, usernames, phone numbers."
  qualifier-map:
    actor.user: profile owner
    object.form.field: field:fieldname
    object.form.value: field:value
    time.last_used: field:lastUsed
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: Firefox → Clear History → Form history, typically-removes: full}
provenance: [mozilla-places-schema]
---

# Firefox-FormHistory

## Forensic value
Every string the user typed into an autofill-eligible form across every site. Email addresses, search queries, shipping addresses, usernames, phone numbers — literal text with field context. High user-intent value — what the user was looking for, corresponding with, identifying themselves as.

## Cross-references
- **Firefox-places** — URLs the user visited
- **Chrome-WebData** — Chromium equivalent (autofill table)
