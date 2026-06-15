# Changelog

## v1.1 — 2026-06-15

### Added
- Sidecar package list (aur_pkg_list.txt): checked first by the loader,
  then live HedgeDoc, then embedded fallback. Update independently.
- Brave/Chromium component updater temp dirs and GNU parallel temp
  dirs classified as [INFO] in Module 9 with explanatory [NOTE].

### Changed
- Updated dependencies: removed base64 and gunzip, added find.

### Fixed
- Package list sources comment now reflects sidecar-first priority.

## v1.0 — 2026-06-15

Initial release. 10-module AUR security scanner with embedded
compromised package list (1936 names), HedgeDoc fallback, read-only
operation, and offline support.
