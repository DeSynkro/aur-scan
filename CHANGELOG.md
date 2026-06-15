# Changelog

## v1.2.1 — 2026-06-15

### Changed
- HedgeDoc fetch now takes priority over the sidecar file (online-first).
- `[FAIL]` marker upgraded to `[ALERT]` for compromised packages.
- Tagline changed from Offline-First to Online-Preferred.

## v1.2 — 2026-06-15

### Removed
- Embedded package list (1936 names) from the bottom of aur-scan.sh.
  Script now relies solely on the sidecar file (aur_pkg_list.txt) and
  live HedgeDoc fetch. Single-file offline use requires the sidecar.

### Changed
- References to "embedded fallback" replaced with "sidecar" throughout.

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
