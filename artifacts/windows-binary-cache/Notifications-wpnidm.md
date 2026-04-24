---
name: Notifications-wpnidm
title-description: "Notification image cache (wpnidm) — PNG/JPG images referenced by toast notifications"
aliases:
- wpnidm
- notifications image cache
- toast notification images
link: user
link-secondary: application
tags:
- per-user
- notification-trail
volatility: persistent
interaction-required: user-action
substrate: windows-binary-cache
substrate-instance: Notifications-wpnidm
platform:
  windows:
    min: '10'
    max: '11'
  windows-server:
    min: '2016'
    max: '2022'
location:
  path: "%LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpnidm\\"
  addressing: file-path
  note: "Per-user cache of image assets (PNG, JPG) referenced by toast notifications. Each file is named by hash. Sibling to wpndatabase.db which holds the notification metadata (timestamps, app IDs, text content). wpnidm stores the actual graphical payloads — thumbnail images embedded in notifications, app-icon variants, preview images from messaging apps."
fields:
- name: notification-image
  kind: content
  location: "wpnidm\\<hash> file"
  encoding: PNG / JPG image
  references-data:
  - concept: AppID
    role: jumplistApp
  note: "Raw image as delivered by the notifying app. For messaging apps (Teams, Slack, WhatsApp, Signal for Windows), this may include received-message preview images, attachment thumbnails, and profile pictures of senders. Surfaces visual content the user saw without having to recover the full app state."
- name: image-hash-name
  kind: hash
  location: "wpnidm\\<hash> filename"
  encoding: hex hash (content-addressable)
  note: "Filename is a hash of the image content. Unique identifier for the specific image; joins to wpndatabase.db references."
- name: file-mtime
  kind: timestamp
  location: wpnidm\<hash> file $SI modified time
  encoding: filetime-le
  clock: system
  resolution: 100ns
  note: "Cache entry creation time. Brackets the notification event timing. Cross-reference with wpndatabase.db for the notification's full metadata."
- name: companion-database
  kind: identifier
  location: "../wpndatabase.db — Notifications table"
  note: "wpndatabase.db references wpnidm images by hash. Parse wpndatabase to find the image-to-notification mapping including app / sender / text / timestamp."
observations:
- proposition: HAD_CONTENT
  ceiling: C2
  note: 'wpnidm is a secondary / supporting artifact alongside
    wpndatabase.db (already covered). Useful specifically when
    notification image content (attachment thumbnails, sender
    avatars, preview pictures) is forensically relevant. Lower
    C-ceiling (C2) because imagery alone is derivative; combined
    with wpndatabase metadata the pair is stronger.'
  qualifier-map:
    object.content: field:notification-image
    time.start: field:file-mtime
anti-forensic:
  write-privilege: user
  integrity-mechanism: none
  known-cleaners:
  - tool: delete wpnidm directory
    typically-removes: cached images (wpndatabase metadata remains without resolvable image refs)
  survival-signals:
  - wpnidm images depicting relevant content (message previews with sensitive text, attachment thumbnails matching sensitive files) = visual evidence of received notifications
provenance: [ms-notification-platform-wns-on-device, archaeology-2020-wpndatabase-db-and-wpnidm-noti]
---

# Notification image cache (wpnidm)

## Forensic value
`%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpnidm\` holds the image payloads referenced by toast notifications. Companion to `wpndatabase.db` (already covered separately) which has the notification metadata.

Useful when you need the visual content of a notification — message-preview images, attachment thumbnails, sender avatars.

## Triage
```powershell
Get-ChildItem "C:\Users\*\AppData\Local\Microsoft\Windows\Notifications\wpnidm\" -ErrorAction SilentlyContinue | Select FullName, Length, LastWriteTime
```

For any interesting image, cross-reference its hash against wpndatabase.db to find the notification it was attached to.

## Practice hint
On a VM with a messaging app (Teams, Discord): receive a notification with an image attachment. Check wpnidm — the thumbnail appears as a hash-named file within seconds of the toast notification firing.
