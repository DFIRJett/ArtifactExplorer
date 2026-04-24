---
name: Location
kind: value-type
lifetime: persistent
link-affinity: user
description: |
  Geographic location — lat/lon coordinate, geofence boundary, place name,
  or cell-tower fix. Captured by Windows location providers (GPS, Wi-Fi
  positioning, cell triangulation) and surfaced in Cortana / Timeline /
  Maps / virtual-assistant artifacts.
canonical-format: "latitude/longitude decimal degrees (WGS84); optional radius (meters) for geofences"
aliases: [Geolocation, GPS, Coordinates, GeoFence, Place]
roles:
  - id: reportedLocation
    description: "Location value recorded by a subsystem at a point in time"
  - id: geofenceBoundary
    description: "Location value defining the edge of a geofence trigger"
  - id: reminderAnchor
    description: "Location attached to a user-created reminder (arrive/leave trigger)"

known-containers:
  - Cortana-CoreDb
provenance:
  - singh-2017-cortana-forensics-windows-10
---

# Location

## What it is
A geographic value — point coordinate, named place, or geofence — recorded by Windows location services and consumed by Cortana, Timeline, Maps, and third-party location-aware apps.

## Forensic value
- **Places user at a specific location at a specific time.** Stronger evidence than most digital artifacts for physical-presence questions in insider-threat, stalking, or corroboration cases.
- **Passive capture.** Unlike phone GPS where the user may explicitly consent per-app, Windows location is often captured opportunistically during Cortana / Timeline use.
- **Not present in most DFIR training canon yet.** Emerging as Windows 10/11 location-integrated features see wider use.

## Encoding variations

| Artifact | Where |
|---|---|
| Cortana-CoreDb | Locations, Geofences, Triggers tables — lat/lon floats + place names + radius |
| Timeline (ActivitiesCache) | `Activity.Payload` embedded location metadata (less systematic) |
| Maps AppData | cached tiles / search history — location via side-channel |

## Anti-forensic notes

Location provider can be disabled per-user (Settings → Privacy → Location) — absence of location records is meaningful signal only when the provider was enabled at the relevant window. Check `Settings.dat` for the toggle state around the time of interest.
