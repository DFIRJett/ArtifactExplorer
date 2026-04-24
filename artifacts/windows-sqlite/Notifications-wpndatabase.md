---
name: Notifications-wpndatabase
aliases: [WNS database, Windows Push Notifications database]
link: user
link-secondary: application
tags: [per-user, notification-history]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Notifications-wpndatabase
platform:
  windows: {min: '10', max: '11'}
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db"
  addressing: sqlite-table-row
fields:
- name: handler-primary-id
  kind: identifier
  location: NotificationHandler → PrimaryId
  note: "PackageFamilyName or AppUserModelID — joins to AppID concept"
  references-data:
  - {concept: AppID, role: muiCachedApp}
- name: notification-payload
  kind: content
  location: Notification → Payload
  note: "XML or JSON content of the toast — title, body, image URLs. Persisted UNTIL the user dismisses, then deleted."
- name: arrival-time
  kind: timestamp
  location: Notification → ArrivalTime
  encoding: filetime-le
- name: expiry-time
  kind: timestamp
  location: Notification → ExpiryTime
  encoding: filetime-le
observations:
- proposition: NOTIFICATION_DELIVERED
  ceiling: C3
  note: "Every toast notification delivered to the host. Shows what apps produced notifications AND the content (often including sender/subject for email, incoming-call contacts, chat senders). Gold for cross-device correspondence context."
  qualifier-map:
    object.app.id: field:handler-primary-id
    object.payload: field:notification-payload
    time.arrived: field:arrival-time
anti-forensic:
  write-privilege: user
  known-cleaners:
  - {tool: Notifications panel → clear, typically-removes: partial (display-only; entries persist until explicit delete)}
provenance: [archaeology-2020-wpndatabase-db-and-wpnidm-noti, ms-notification-platform-wns-on-device]
---

# wpndatabase.db

## Forensic value
Windows Push Notifications database. Every toast the user received — email-arrival summaries, Teams chats, calendar reminders, VoIP incoming-call prompts. The Payload column has the rendered content — often revealing senders, subjects, and chat previews visible to the host without requiring access to the underlying app.

## Cross-references
- **ActivitiesCache** — Timeline activity for apps that also sent notifications
- **TaskbarLayout** / **JumpList-AppID-Mapping** — resolve handler-primary-id to human app names
