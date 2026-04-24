---
name: windows-pst
kind: binary-structured-file
substrate-class: Filesystem/Artifact
aliases: [PST, OST, Outlook storage, MS-PST]

format:
  storage: "MS-PST Personal Folders File (also OST — Offline Storage Table)"
  authoritative-spec:
    - title: "[MS-PST]: Outlook Personal Folders (.pst) File Format"
      publisher: Microsoft
      url: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546
  variants:
    PST:  "Personal Storage Table — user's local mail archive, Outlook-managed"
    OST:  "Offline Storage Table — cached Exchange mailbox, similar format"

known-instances:
  "Outlook PST":      "%LOCALAPPDATA%\\Microsoft\\Outlook\\<account>.pst"
  "Outlook OST":      "%LOCALAPPDATA%\\Microsoft\\Outlook\\<account>.ost"
  "archive.pst":      "user-customized location per Outlook config"

persistence:
  locked-on-live-system: "yes when Outlook running"
  acquisition: "close Outlook or VSS snapshot; readpst / libpst for offline parsing"
  parsers:
    - { name: libpst / readpst, strengths: [OSS, EML export] }
    - { name: Outlook scanpst.exe, strengths: [native, but repairs the file — NOT forensic] }
    - { name: pffexport (Joachim Metz libpff), strengths: [format-correct] }
    - { name: Kernel OST Viewer, strengths: [commercial GUI] }

forensic-relevance:
  - per-message-attachment-extraction: "every message + attachment recoverable as original files"
  - deleted-item-recovery: "Deleted Items folder preserved unless explicitly emptied; even after 'empty' many items recoverable from PST free-space"
  - header-preservation: "full Internet Message Format headers preserved — Received-by chain for source-tracing"

integrity:
  signing: none
  tamper-vectors:
    - "scanpst.exe modifies the file 'to repair' — destructive to forensic integrity"
    - "direct PST edit with tools like Aid4Mail Exporter"

known-artifacts:
  # Outlook personal-store family. PST + OST share the same on-disk format;
  # their siblings (NST/PAB) use parallel conventions. Per-item artifacts
  # (email, calendar, contact, task, attachment) are distinct forensic types
  # within any of these containers.
  # Seed source: authored + Joachim Metz libpff documentation.
  authored:
    - Outlook-PST              # .pst — local personal store (archive/import/export)
  unwritten:
    - name: Outlook-OST
      location: "%LOCALAPPDATA%\\Microsoft\\Outlook\\*.ost"
      value: offline cache of Exchange mailbox; often contains data no longer on server (deleted items, shadow copies)
    - name: Outlook-NST
      location: "%LOCALAPPDATA%\\Microsoft\\Outlook\\*.nst"
      value: Notes-store variant (Groups feature); same PFF format
    - name: Outlook-PAB
      location: legacy locations (pre-Outlook-2007)
      value: Personal Address Book — legacy user-contact store
    - name: PST-Email-Item
      location: per-message nodes in any PST/OST/NST
      value: individual email with sender/recipients/subject/timestamps/body/attachments — primary unit of email forensics
    - name: PST-Calendar-Item
      location: calendar folder nodes in any PST/OST
      value: meeting/appointment records with attendees and reminders
    - name: PST-Contact-Item
      location: contacts-folder nodes
      value: per-contact entries — corroborates social-graph attribution
    - name: PST-Attachment
      location: attachment nodes attached to message items
      value: embedded files (often malware in phishing cases); MIME boundaries and content-type
    - name: PST-DeletedItems-Folder
      location: Deleted Items folder + hidden Recover-Deleted-Items storage
      value: soft-deleted messages often retained past user expectation
provenance:
  - libyal-libpff
  - ms-pst
---

# Outlook PST / OST

## Forensic value
Self-contained binary archive of a user's Outlook mailbox. Every message with full headers, attachments, read/unread state, folder hierarchy. For email-centric investigations (phishing, BEC, insider-threat communications), the PST is the central artifact.

## Acquisition note
DO NOT run scanpst.exe on the evidence file — it rewrites the file in place to 'repair' inconsistencies, destroying forensic integrity. Work on copies; prefer libpst/libpff for read-only parsing.
