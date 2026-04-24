---
name: Firefox-Downloads
aliases: [Firefox downloads (places annotations)]
link: file
link-secondary: application
tags: [per-user]
volatility: persistent
interaction-required: user-action
substrate: windows-sqlite
substrate-instance: Firefox-places
platform:
  windows: {min: '7', max: '11'}
location:
  path: "%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\places.sqlite"
  note: "modern Firefox consolidates downloads into places.sqlite via moz_annos (previous downloads.sqlite is deprecated)"
  addressing: sqlite-table-row
fields:
- name: annotation-content
  kind: content
  location: moz_annos → content (for rows with anno_attribute_id mapping to 'downloads/destinationFileURI' or 'downloads/metaData')
  note: "downloads/destinationFileURI holds the target file URI; downloads/metaData holds a JSON blob with source URL, mime, size, referrer"
- name: place-url
  kind: url
  location: moz_places → url (joined via moz_annos.place_id)
  references-data:
  - {concept: URL, role: downloadedFromUrl}
- name: dateAdded
  kind: timestamp
  location: moz_annos → dateAdded
  encoding: webkit-microseconds
observations:
- proposition: DOWNLOADED
  ceiling: C3
  note: "Firefox download record — consolidated into places.sqlite in modern FF (71+). Parse via SQL joining moz_annos + moz_places + moz_anno_attributes."
  qualifier-map:
    object.source.url: field:place-url
    time.download: field:dateAdded
anti-forensic:
  write-privilege: unknown
provenance: [mozilla-places-schema]
---

# Firefox-Downloads

## Forensic value
Modern Firefox (71+) consolidated the old `downloads.sqlite` into `places.sqlite` via the moz_annos annotation mechanism. Each download becomes multiple moz_annos rows keyed by the source URL's place_id, with attribute-IDs like `downloads/destinationFileURI` and `downloads/metaData`.

## Cross-references
- **Firefox-places** — the visits table (same DB)
- **Zone-Identifier-ADS** — Mark-of-the-Web on the downloaded file
