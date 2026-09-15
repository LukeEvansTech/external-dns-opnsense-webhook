# Changelog

## Unreleased

- Every mutating OPNsense call (`addHostOverride`, `setHostOverride`, `delHostOverride`) now runs behind one client mutex, whatever `OPNSENSE_APPLY_WORKERS` is set to. OPNsense's config save is not safe under concurrent writes: during the 2026-09-15 cutover, 2 of 282 acknowledged adds were never saved. Concurrency across names is orchestration only; writes reach the firewall one at a time.
- After each apply phase that wrote, the provider re-reads the table and checks every acknowledged write landed: created and updated rows are present and read as written, deleted rows are gone. The rows that did land are still reconfigured; if the verification read itself fails, that is logged and the apply carries on.
- A lost write is logged at error with its name, type and uuid, counted, and treated as that phase's failure, so the existing phase gate holds (no data row is created over a lost registry TXT, no registry row removed over a lost data delete), `ApplyChanges` returns an error naming it, and the next reconcile converges.
- New counter `externaldns_webhook_opnsense_lost_writes_total{provider,operation}` (`create`, `update`, `delete`), pre-created at zero.
- `OPNSENSE_APPLY_WORKERS` now defaults to `1` (range still 1 to 32).
- The fake gains a `Lost` fault mode (acknowledge a write without saving it) and a maximum in-flight write counter; the integration batch test reads the table back after the create and the delete.

## 0.1.1 (2026-09-15)

- Counter series with closed label sets (delete blocked, TXT invalid, pages fetched, read restarts, reconfigure by result, endpoints dropped by reason, changes by operation) now exist at zero from startup, so the first increment is a visible delta for `increase()` and the alert on blocked deletes fires on the first event.

## 0.1.0 (2026-09-15)

- Initial provider: A/AAAA/TXT host overrides, paginated consistent reads, phased apply with TXT-first ordering, pending reconfigure repair, delete guard for alias children.
