# Changelog

## Unreleased

- Counter series with closed label sets (delete blocked, TXT invalid, pages fetched, read restarts, reconfigure by result, endpoints dropped by reason, changes by operation) now exist at zero from startup, so the first increment is a visible delta for `increase()` and the alert on blocked deletes fires on the first event.

## 0.1.0 (2026-09-15)

- Initial provider: A/AAAA/TXT host overrides, paginated consistent reads, phased apply with TXT-first ordering, pending reconfigure repair, delete guard for alias children.
