# external-dns-opnsense-webhook: design

Date: 2026-09-14. This is the design as approved, kept as the record of why the
provider works the way it does. Where it and the shipped code disagree, the
code and `README.md` are authoritative. The written review log and the
operator-side migration plan are not part of this repository.

## 1. Goal

Replace `ghcr.io/crutonjohn/external-dns-opnsense-webhook` with a webhook
provider built the way `home-operations/external-dns-unifi-webhook` is built,
so that an external-dns deployment can run `policy: sync` with external-dns's
TXT registry, the record ceiling and the daily restart CronJob go away, and
removals propagate to Unbound.

Success looks like:

- The external-dns deployment runs `policy: sync`, `registry: txt`, no CronJob,
  no `upsert-only`, and a removed HTTPRoute removes its A row and its TXT row
  within one reconcile.
- Every row on the operator's reviewed migration allowlist is deleted, every
  name the cluster declares is recreated as an owned A row plus one TXT row,
  and every row outside the allowlist is byte-identical before and after.
- A full read of the override table is paginated, never depends on a single
  response under 64 KiB, and never returns a partial table.
- `GET /records` answers external-dns inside its 5 s default read timeout at
  the current table size, and the deployment raises that timeout anyway.
- A failed write, a lost response or a failed reconfigure converges on a later
  reconcile without manual repair and without touching unrelated rows (the
  invariants in section 6.2).
- Zero fatal log lines from external-dns over a week that are attributable to
  the sidecar.

## 2. Non-goals

- A dnsmasq backend. OPNsense's dnsmasq has its own hosts API with CNAME
  support; upstream PR #37 sketches a backend. Not in this build.
- A Helm chart. The image is consumed through the upstream external-dns chart's
  `provider.webhook` sidecar, as with UniFi.
- MX or SRV writes. MX rows are read so they are visible to external-dns, never
  written.
- CNAME writes in v1. OPNsense has no CNAME record type; a host alias is
  rendered as a copy of its parent's A/AAAA record at the alias name
  (`unbound.inc`, `unbound_add_host_entries`), so it cannot honour a CNAME's
  semantics (address family, multi-target, independent TTL). Aliases are read
  faithfully (section 6.1) and CNAME endpoints are dropped on write (section
  6.4).
- Wildcard writes in v1. A `*` hostname makes OPNsense emit
  `local-zone: "<domain>" redirect`, which answers every name under that domain
  with one address and would shadow every other override in it. Existing
  wildcard rows are read as-is; wildcard endpoints are dropped on write.
- Migrating a consuming cluster's external-dns annotations from the alpha
  prefix to the GA prefix. Separate change.
- An "adopt unowned records" mode. Migration is delete-and-recreate, driven by
  the operator's own migration tooling. Pre-seeding registry TXT rows would
  avoid the outage window and is recorded as the alternative in section 12; it
  was not chosen.
- Upstreaming to crutonjohn. The maintainer has been inactive since 2026-05-23
  and two community PRs conflict; this is a rewrite, credited, not a fork.

## 3. Repository

- `LukeEvansTech/external-dns-opnsense-webhook`, public, Apache-2.0.
- Go module `github.com/LukeEvansTech/external-dns-opnsense-webhook`. Go 1.27
  via mise with a committed `mise.lock`.
- `NOTICE` and `README.md` credit kashalls and onedr0p for the skeleton copied
  from external-dns-unifi-webhook, and crutonjohn for the original OPNsense
  provider idea.

Layout (copied from the UniFi repository, provider package replaced):

```text
cmd/external-dns-opnsense-webhook/main.go   logger, metrics, config, provider, signal ctx, server
internal/config/        SERVER_*, HEALTH_SERVER_ADDR, READINESS_CACHE_TTL, LOG_*, PPROF_ENABLED
internal/dnsprovider/   Init(): env.Parse(opnsense.Config) -> opnsense.NewProvider
internal/opnsense/      types.go, client.go, transport.go, dto.go, snapshot.go, provider.go, apply.go, names.go, errors.go
internal/webhook/       protocol adapter over provider.Provider (unchanged from UniFi)
internal/server/        two http.Servers, middleware, cached readiness (unchanged)
internal/metrics/       registry, provider label "opnsense"
internal/httpx/         response recorder (unchanged)
test/fake/              in-memory OPNsense: config table, "served" table published by reconfigure, fault injection
test/reconcile/         build tag reconcile: real external-dns planner + TXT registry + webhook client against the binary and the fake
test/e2e/               build tag e2e: real binary against the fake, protocol-level
test/integration/       build tag integration: real firewall, extdns-itest-* names
hack/capture-fixtures.sh   read-only capture from a real firewall (no mutating API calls; POST searchHostOverride is allowed), sanitise checklist
docs/design.md          this file
```

## 4. Configuration

Env-only via `caarlos0/env/v11`, validated at startup; misconfiguration exits
non-zero before the server starts.

| Var                                                                                                   | Default                        | Notes                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OPNSENSE_HOST`                                                                                       | required                       | Scheme and host, for example `https://fw.example.com`. Trailing slash stripped.                                                                                                                                            |
| `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`                                                            | required                       | `notEmpty,unset`: removed from the process environment after load. Sent as HTTP basic auth.                                                                                                                                |
| `OPNSENSE_DOMAINS`                                                                                    | required, comma list           | Used twice: returned as the negotiated `DomainFilter` on `GET /`, and as the split boundary for FQDN to hostname+domain (section 6.3). Lower-cased at load.                                                                |
| `OPNSENSE_SKIP_TLS_VERIFY`                                                                            | `false`                        | Deliberately not the UniFi default. `true` logs a WARN.                                                                                                                                                                    |
| `OPNSENSE_CA_CERT`                                                                                    | empty                          | PEM bundle path; wins over skip-verify. TLS 1.2 minimum.                                                                                                                                                                   |
| `OPNSENSE_ADD_PTR`                                                                                    | `false`                        | Value of `addptr` on every managed A/AAAA row.                                                                                                                                                                             |
| `OPNSENSE_OWNER_MARKER`                                                                               | `external-dns`                 | Written into `description` on every managed row (for operators filtering the grid, and for the startup served-state check in section 8). Never used for ownership decisions.                                               |
| `OPNSENSE_PAGE_SIZE`                                                                                  | `150`                          | `rowCount` per `searchHostOverride` page. 1..500.                                                                                                                                                                          |
| `OPNSENSE_READ_ATTEMPTS`                                                                              | `3`                            | Full re-reads allowed when a paginated read is inconsistent (section 6.1).                                                                                                                                                 |
| `OPNSENSE_APPLY_WORKERS`                                                                              | `4`                            | Bounded concurrency across names inside one apply phase. 1..32.                                                                                                                                                            |
| `OPNSENSE_RETRY_ATTEMPTS` / `_INITIAL_DELAY` / `_MAX_DELAY`                                           | `3` / `500ms` / `10s`          | Retry only idempotent calls and any 429 (section 7).                                                                                                                                                                       |
| `OPNSENSE_REQUEST_TIMEOUT`                                                                            | `20s`                          | Per-call context timeout on the firewall API.                                                                                                                                                                              |
| `OPNSENSE_RECONFIGURE_TIMEOUT`                                                                        | `45s`                          | `service/reconfigure` stops and starts Unbound and waits up to 10 s for the pid.                                                                                                                                           |
| `OPNSENSE_APPLY_TIMEOUT`                                                                              | `120s`                         | Budget for one whole `ApplyChanges`, all phases and the reconfigure included. Runs detached from the request context (section 6.2).                                                                                        |
| `SERVER_HOST` / `SERVER_PORT`                                                                         | `localhost` / `8888`           | Webhook API, loopback only; external-dns reaches it inside the pod.                                                                                                                                                        |
| `SERVER_READ_TIMEOUT` / `SERVER_READ_HEADER_TIMEOUT` / `SERVER_WRITE_TIMEOUT` / `SERVER_IDLE_TIMEOUT` | `60s` / `5s` / `180s` / `120s` | Write timeout exceeds the apply budget plus one reconfigure so a long batch is never cut off by the server; the binary refuses to start otherwise. 64 KiB headers, 5 MiB body.                                             |
| `HEALTH_SERVER_ADDR`                                                                                  | `:8080`                        | `/healthz`, `/readyz`, `/metrics` on all interfaces. The external-dns chart's `http-webhook` container port is 8080, so kubelet probes and the ServiceMonitor land here. `/healthz` and `/readyz` are also served on 8888. |
| `READINESS_CACHE_TTL`                                                                                 | `30s`                          |                                                                                                                                                                                                                            |
| `LOG_LEVEL` / `LOG_FORMAT`                                                                            | `info` / `json`                | `text` for humans.                                                                                                                                                                                                         |

Timeout budget, inner to outer (each layer must be shorter than the next):

| Layer                                                | Value |
| ---------------------------------------------------- | ----- |
| One firewall API call                                | 20 s  |
| Reconfigure                                          | 45 s  |
| Whole `ApplyChanges`                                 | 120 s |
| One apply plus its trailing reconfigure (worst case) | 165 s |
| `SERVER_WRITE_TIMEOUT`                               | 180 s |
| external-dns `--webhook-provider-write-timeout`      | 180 s |
| external-dns `--webhook-provider-read-timeout`       | 30 s  |
| Pod `terminationGracePeriodSeconds`                  | 180 s |

The trailing reconfigure runs under its own context, so one apply can take up
to `OPNSENSE_APPLY_TIMEOUT` plus `OPNSENSE_RECONFIGURE_TIMEOUT` (165 s by
default); `main` exits non-zero at startup if that sum exceeds
`SERVER_WRITE_TIMEOUT`. Measured on the firewall on 2026-09-14 by the
integration suite: a 282-row batch took 8.3 s to create and 7.7 s to delete
(three runs within 1 s of each other), so the 120 s apply budget carries more
than a tenfold margin. OPNsense stores an uncompressed IPv6 literal verbatim,
so A/AAAA targets are compared as written.

Startup order: parse config, bind both listeners, then probe the firewall.
external-dns negotiates `GET /` with five retries and exponential backoff
(`provider/webhook/webhook.go`, v0.22.0) and exits fatally if none succeeds, so
the listener must be up within a few seconds of container start regardless of
the firewall. Firewall reachability gates `/readyz`, not the process.

Required OPNsense privileges for the API user:
`Services: Unbound DNS: Edit Host and Domain Override`,
`Services: Unbound (MVC)`, `Status: DNS Overview`.

## 5. Webhook protocol

Unchanged from the UniFi adapter: `GET /` negotiates
`application/external.dns.webhook+json;version=1` and returns the domain
filter; `GET /records`; `POST /records` with `plan.Changes`, 204 on success;
`POST /adjustendpoints`; strict media-type validation (406/415/400/413). Built
against `sigs.k8s.io/external-dns v0.22.x` types only.

## 6. Provider semantics

### 6.1 Records()

- **1.** Page through `POST /api/unbound/settings/searchHostOverride` with
  `{"current": n, "rowCount": PAGE_SIZE, "sort": {"domain": "asc", "hostname": "asc", "rr": "asc", "server": "asc"}}`.
  OPNsense appends each row's uuid to its sort key (`ArrayField::sortedBy`), so
  the order is total and deterministic for an unchanged table. Offset
  pagination gives no snapshot guarantee, so a read is accepted only if all of
  these hold: `total` is identical on every page; no page before the last is
  empty; the page count does not exceed `ceil(total / PAGE_SIZE) + 1`; and the
  number of unique uuids collected, counted before any filtering, equals
  `total`. Otherwise the whole read restarts, up to `OPNSENSE_READ_ATTEMPTS`,
  then `Records()` returns an error. A partial table is never returned and
  never used to plan writes. The read's deadline is the caller's context
  (external-dns's read timeout), and `Records()` returns early on it.
- **2.** Skip rows with `isAlias` true wherever they appear, and rows with
  `enabled == "0"`.
- **3.** Map by `rr`, lower-casing names and trimming trailing dots:
  - `A`, `AAAA`: endpoint
    `{name: hostname+"."+domain, type, target: server, ttl}`; group by (name,
    type) so a multi-target endpoint returns one endpoint with N targets. If
    grouped rows carry different TTLs the smallest wins, with one WARN per name
    per snapshot.
  - `TXT`: target is `txtdata` with surrounding double quotes restored (`"` +
    value + `"`), because the registry expects the quoted form and the provider
    strips it on write (round-tripped against a live firewall on 2026-09-14).
  - `MX`: endpoint with target `"<mxprio> <mx>"`, read-only.
  - anything else: skipped with a debug log.
- **4.** For each A/AAAA row, each `_children` entry with `enabled != "0"`
  becomes an endpoint of the **parent's type** with the parent's target and TTL
  at the alias name, because that is what `unbound.inc` serves. A child with
  empty hostname or domain inherits the parent's. These endpoints carry no
  registry TXT, so external-dns treats them as unowned and leaves them alone; a
  desired endpoint colliding with one is skipped by external-dns with its
  owner-mismatch log, the same as any hand-made row.
- **5.** `ttl` of `""` or `"0"` means unset (`RecordTTL(0)`).

### 6.2 ApplyChanges()

The TXT registry marks a name as owned only while its TXT row exists, so the
provider keeps four invariants:

- **I1** A managed data row never outlives a failed request without its TXT
  row: creates write TXT endpoints before A/AAAA endpoints, deletes remove
  A/AAAA before TXT.
- **I2** An in-place change never removes the TXT row and never leaves a name
  with zero data rows: updates converge the row set (add, set, then remove)
  rather than delete-then-create.
- **I3** Every write is idempotent against the snapshot: a create whose (name,
  type, target) row already exists is a no-op that reconciles
  `ttl`/`description` in place, a delete of a missing row is a no-op, so a lost
  response converges on the next reconcile.
- **I4** The saved configuration and the running Unbound never diverge
  silently: a pending-reconfigure state survives an empty next plan.

Algorithm:

- **1. Single writer.** One `sync.Mutex` serialises `ApplyChanges`;
  external-dns is sequential, so a second request only ever arrives after a
  client timeout, and it waits. The apply runs under
  `context.WithoutCancel(req.Context())` bounded by `OPNSENSE_APPLY_TIMEOUT`,
  so a client disconnect cannot abort a batch half way. Across pods, the
  chart's `deploymentStrategy: Recreate` (its default, stated explicitly in the
  HelmRelease) prevents two controllers from applying stale snapshots during a
  rollout.
- **2. Snapshot** as in 6.1, keeping uuids, raw rows and `_children`, indexed
  by (name, type, target) and by (name, type).
- **3. Desired row sets.** Fold the plan into one desired target set per (name,
  type): `Create` and `UpdateNew` set it to the endpoint's targets, `Delete`
  sets it to empty. `UpdateOld` is not consulted: the snapshot, not the plan,
  is the source of truth for what exists. TXT targets are validated here
  (section 6.4's TXT rule) and an invalid one fails that endpoint before any
  write.
- **4. Phases**, each drained before the next, names inside a phase spread over
  an `errgroup` with `SetLimit(APPLY_WORKERS)`, every step inside a name
  sequential:
  - **1.** create and set TXT rows;
  - **2.** create and set A/AAAA rows (`setHostOverride` on kept rows whose
    `ttl` or `description` differ, `addHostOverride` for missing targets);
  - **3.** remove surplus A/AAAA rows;
  - **4.** remove surplus TXT rows.

  Phases 1 and 3 protect phases 2 and 4: if any TXT write failed in phase 1,
  phase 2 is skipped for this cycle (no data row is created without its
  registry row), and if any data delete failed in phase 3, phase 4 is skipped
  (no registry row is removed while its data row remains). Every key a skipped
  add/set phase would have written is marked failed, so the remove phase keeps
  its existing rows too: a name never loses the rows its new targets were meant
  to replace. The provider cannot pair a TXT row with the data name it covers,
  because the registry's prefix is external-dns's concern, so the gate is per
  phase, not per name; a skipped phase converges on the next reconcile by I3.
  Within a phase, one name's failure never stops another name. Errors are
  collected with `errors.Join`.

- **5. Deletes never cascade silently.** `delHostOverride` deletes the row's
  aliases with it, so a row with any enabled `_children` is never deleted by
  the provider: that endpoint fails with `ErrAliasChildren`,
  `externaldns_webhook_opnsense_delete_blocked_total` increments, and the
  operator re-homes or removes the alias by hand. v1 creates no aliases, so
  every child is hand-made. A target change on such a row uses
  `setHostOverride`, which keeps the uuid and its children.
- **6. Response decoding.** Every write is decoded as
  `{"result": string, "uuid": string, "validations": map[string]StringOrList}`
  where `StringOrList` accepts a string or an array of strings (the base
  controller switches to an array on the second message for a field).
  `addHostOverride` requires `result == "saved"` and a non-empty `uuid`;
  `setHostOverride` requires `"saved"`; `delHostOverride` treats `"deleted"` as
  done and `"not found"` as already gone (not counted as a mutation); anything
  else is an error carrying the validations verbatim.
- **7. Pending reconfigure.** The provider sets `pending = true` before its
  first write in an apply and after any ambiguous write (a timeout after the
  request was sent, since the firewall may have committed it). After the
  phases, if `pending`, it calls `POST /api/unbound/service/reconfigure` under
  a fresh context bounded by `OPNSENSE_RECONFIGURE_TIMEOUT`, requires
  `{"status":"ok"}`, and only then clears `pending`. `Records()` checks
  `pending` first and runs the same reconfigure before reading, so an empty
  next plan still repairs the running service. Write errors and reconfigure
  errors are both returned. `externaldns_webhook_opnsense_pending_reconfigure`
  is a gauge.
- **8. Restart recovery.** `pending` lives in memory. At startup, after the
  listeners are up, the provider runs a served-state check: it fetches
  `diagnostics/listlocaldata` once and compares the enabled rows carrying the
  owner marker in the config snapshot against what Unbound serves; any managed
  row that is saved but not served triggers one reconfigure. The marker is a
  heuristic for this check only, never an ownership signal.
- **9. Return.** Any error becomes a 500 whose body is the joined message (the
  webhook adapter writes it, so it reaches external-dns's log); external-dns
  re-plans on its next cycle and, by I3, converges. A repair reconfigure from
  `Records()` and the trailing reconfigure of an apply share one mutex, so at
  most one reconfigure is in flight.

### 6.3 Names

- Join: `hostname + "." + domain`, both trimmed of trailing dots, lower-cased.
- Split on write: longest suffix in `OPNSENSE_DOMAINS` matched
  case-insensitively at a label boundary (`name == d` or `name` ends with
  `"." + d`); the domain is that suffix and the hostname is the rest.
  `badexample.com` does not match `example.com`. A name matching no configured
  domain is an error for that endpoint; there is no fallback (external-dns's
  own domain filter, negotiated from the same list, makes this unreachable in
  practice).
- A name equal to a configured domain (apex) is rejected with a clear error,
  because the Unbound model requires a hostname.
- Wildcards: read as-is (hostname `*`); rejected on write in v1 (section 2).
- Lookups on write always compare joined FQDNs, never the hostname/domain pair,
  so hand-made rows split differently are still found.
- TTL: the model accepts 0..2147483647. Negative or zero from external-dns
  means unset; larger than the maximum is clamped with a WARN. All rows of one
  endpoint get the endpoint's TTL on write.

### 6.4 AdjustEndpoints()

- Lower-case names, trim trailing dots, clamp TTL as in 6.3.
- Drop endpoints the provider cannot write, with a WARN and
  `externaldns_webhook_opnsense_endpoints_dropped_total{reason}`, so
  external-dns never loops on them. The reason set is fixed: `type` (not
  A/AAAA/TXT), `wildcard`, `set-identifier` (the provider has no set
  identifiers), `apex` (name equals a configured domain), `domain` (outside
  `OPNSENSE_DOMAINS`), `name` (any other split failure), `txt` (a source TXT
  target failing the TXT rule below).
- TXT rule (applied here for source TXT endpoints and again in 6.2 step 3 for
  registry rows, which do not pass through this call): exactly one pair of
  surrounding double quotes, a single character-string (no `"a" "b"`
  concatenation), printable ASCII only, no inner `"` or `\`, and at most 255
  bytes after stripping (the model's `txtdata` limit and RFC 1035's
  character-string limit coincide because the content is ASCII). Violations
  fail the endpoint with an error naming the length and the record, and
  increment `externaldns_webhook_opnsense_txt_invalid_total`; nothing is
  truncated.

## 7. Client and transport

- `http.Client` with a custom `http.Transport`: `ForceAttemptHTTP2: true`,
  `TLSClientConfig` per config, `DialContext` 10 s, `TLSHandshakeTimeout` 10 s,
  `ResponseHeaderTimeout` = request timeout, `IdleConnTimeout` 90 s,
  `MaxConnsPerHost` = workers + 2.
- Every request built with `NewRequestWithContext`; the caller's context
  carries the per-call timeout.
- Response bodies read through a `LimitReader` (8 MiB) and always drained and
  closed.
- Retry: 429 for any method (honouring `Retry-After`); 5xx and network errors
  only for `searchHostOverride`, `getHostOverride`, `listlocaldata`,
  `service/status`, and deletes (a repeated delete is answered `not found`,
  which 6.2 treats as done). Adds, sets and reconfigure are never retried: an
  add may have committed before the error, and I3 converges it next cycle.
- Exponential backoff `initial << attempt` with 0 to 50 % jitter, clamped to
  max delay.
- Startup: listeners first (section 4), then `GET /api/unbound/service/status`
  and the served-state check (6.2 step 8) in the background. Failure there logs
  at ERROR and leaves `/readyz` at 503; it does not exit the process.

## 8. Ops surface

- `/healthz`: static 200.
- `/readyz`: cached (`READINESS_CACHE_TTL`), single-flighted, context-detached
  probe that fetches page 1 of `searchHostOverride` with `rowCount: 1`. 503
  `not ready` with the cause logged once per probe.
- `/metrics`: every metric is registered under the `externaldns_webhook`
  namespace and carries `provider="opnsense"`. Alongside the HTTP, record and
  change metrics inherited from UniFi:
  `externaldns_webhook_opnsense_api_errors_total{operation}`,
  `externaldns_webhook_opnsense_api_duration_seconds{operation}`,
  `externaldns_webhook_opnsense_api_response_size_bytes{operation}`,
  `externaldns_webhook_opnsense_api_retries_total{operation,status}`,
  `externaldns_webhook_opnsense_api_rate_limits_total{operation}`,
  `externaldns_webhook_opnsense_pages_fetched_total`,
  `externaldns_webhook_opnsense_read_restarts_total`,
  `externaldns_webhook_opnsense_rows` (gauge from the last accepted snapshot),
  `externaldns_webhook_opnsense_reconfigure_total{result}`,
  `externaldns_webhook_opnsense_pending_reconfigure` (gauge),
  `externaldns_webhook_opnsense_apply_duration_seconds`,
  `externaldns_webhook_opnsense_delete_blocked_total`,
  `externaldns_webhook_opnsense_endpoints_dropped_total{reason}`,
  `externaldns_webhook_opnsense_txt_invalid_total`. `README.md` lists the whole
  set with its labels.
- Logs: `log/slog` JSON; every write logs name, type, target, uuid and outcome
  at info; the raw table is never logged, even at debug.
- Alerts for the consuming cluster to define: `ExternalDNSStale` (no successful
  sync for 15 min), `OPNsensePendingReconfigure` (gauge 1 for 10 min),
  `OPNsenseDeleteBlocked` (counter increased in the last hour).

## 9. Cluster-side changes

Out of scope for this repository. Swapping a cluster's external-dns deployment
onto this image, moving it to `policy: sync` with the TXT registry, and
clearing the unowned rows an earlier provider left behind are the operator's
work, driven by the operator's own migration tooling against the same API and
credentials.

## 10. Testing

- Unit: table-driven stdlib tests with `httptest.NewServer` standing in for
  OPNsense. Must cover: pagination across three pages with a duplicate uuid on
  the boundary; `total` changing between pages restarts the read and exhausting
  attempts errors; a row deleted between pages is detected by the unique-uuid
  count; `isAlias` and disabled rows skipped; `_children` mapped to parent-type
  endpoints including inherited hostname/domain; differing TTLs in a group; TXT
  quote strip/restore round trip; TXT rule rejections (256 bytes, inner quote,
  backslash, non-ASCII, concatenated strings) and a 255-byte acceptance;
  multi-target grouping and converge (add one target, remove one, change TTL in
  place); name split against configured domains, label-boundary and case rules,
  no-match error, wildcard rejection, apex rejection; response decoding for
  `saved`, `failed` with string and array validations, missing uuid, `deleted`,
  `not found`; delete blocked by children; reconfigure called only after a
  write, after a partial failure, and from `Records()` while pending; retry
  only on idempotent calls; readiness cache and detachment; listeners answer
  `GET /` before the upstream probe has finished.
- Fake (`test/fake`): in-memory config table with the real row shape, a
  separate served table that only `reconfigure` publishes, and fault injection
  per operation (fail once, time out after commit, return `failed`).
- Reconcile suite (`test/reconcile`, runs in CI): imports external-dns
  v0.22.0's `plan`, `registry/txt` and `provider/webhook` client packages and
  drives them against the real binary and the fake, so the planner, the TXT
  registry and the webhook protocol are all the pinned real code. Scenarios:
  create; a second reconcile is a no-op; target change; TTL change;
  multi-target add and remove; delete; an unrelated hand-made row and a
  hand-made alias are untouched throughout; a TXT row with another owner ID is
  ignored; fault injection at each step (TXT create succeeds then A create
  fails; A create committed but response lost; partial update; A delete
  succeeds then TXT delete fails; reconfigure fails and the next plan is empty;
  process restart with a pending reconfigure). Each scenario must reach the
  desired state within three reconciles with no manual step, and both the
  config table and the served table are asserted.
- End-to-end (`-tags e2e`, CI on PRs): protocol level against the fake:
  negotiate, records, apply with a create and a delete, 406/413, readiness
  reflecting upstream failure.
- Integration (`-tags integration`, manual): against a real firewall with
  `extdns-itest-<label>-<rand>` names under a configured domain, sweep
  leftovers at start, cleanup at end. Includes the TXT round trip, the
  local-data-before-cache ordering (query a name, get NXDOMAIN, add it,
  reconfigure, query again), a timed 282-row create-and-delete batch recorded
  in the run log, and a read-only look at what a wildcard row makes Unbound
  serve for the apex, an explicit child and a missing child.
- Known-bad control: every test that asserts "nothing was written" or "nothing
  unrelated changed" is paired with a case that proves the assertion fires.

## 11. Release engineering

- Releases are cut by hand, not by release-please: a `chore(release): X.Y.Z`
  pull request that bumps `CHANGELOG.md`, then a `vX.Y.Z` tag pushed at the
  merge commit.
- `.github/workflows/docker-publish.yml` builds `linux/amd64,linux/arm64` with
  Buildx and attaches an SBOM and provenance, pushing to
  `ghcr.io/lukeevanstech/external-dns-opnsense-webhook`: `X.Y.Z` and `X.Y` from
  a tag, `main` from a push to the default branch, and the short commit SHA for
  every build. Pull requests build without pushing. Distroless static nonroot
  image, `EXPOSE 8888/tcp`.
- CI (`.github/workflows/ci.yaml`): golangci-lint v2, `go test -race` with a
  `go mod tidy` check, the end-to-end and reconcile suites, govulncheck,
  actionlint + zizmor. super-linter runs from `LukeEvansTech/shared-workflows`
  in `.github/workflows/lint.yml` with `soft-launch: false`, its own Go linters
  disabled because the bundled golangci-lint predates this module's Go version
  (house gate: run the real image locally before pushing).
- Renovate via `github>LukeEvansTech/renovate-config`. Digest pinning of the
  image in the consuming cluster is Renovate's job.
- `AGENTS.md` carries the fleet Go conventions; `CLAUDE.md` imports it.

## 12. Risks and open items

- **Alias `_children` shape** is read from 26.1/26.7 source. A future OPNsense
  change to the grid could alter it; the integration suite catches that, and
  `searchHostAlias` remains a fallback path behind a build-time constant.
- **`txtsupport` general option**: when enabled, OPNsense also emits every
  row's `description` as a TXT record. The owner marker would then be visible
  in DNS. Harmless; documented.
- **Registry TXT under 255 bytes**: label strings here are around 105
  characters; a long namespace/name pair could approach the cap. The provider
  refuses rather than truncates, and the metric makes it visible.
- **Hand-made aliases on managed rows** block deletion (6.2 step 5) by design;
  `externaldns_webhook_opnsense_delete_blocked_total` makes it visible and the
  operator re-homes or removes the alias.
- **Pagination is offset-based**; the consistency rules in 6.1 detect a moving
  table and restart, they cannot make a single read atomic. A page can still
  exceed 64 KiB if rows carry many children; that no longer matters on 26.7.1+
  (kTLS disabled by default) and the page size is configurable.
- **Migration outage window** is accepted. The zero-window alternative is to
  pre-seed one registry TXT row per declared name with the exact label string
  external-dns would write, so the new controller finds every row owned on its
  first reconcile; it needs no provider feature, only a script, but it
  duplicates the registry's serialisation and was not chosen. Available if the
  measured window turns out unacceptable.
- **Orphan registry TXT rows are permanent until swept.** If the data row's
  delete succeeds and the TXT delete then fails (phase 3 succeeds, phase 4
  fails), the TXT row stays: external-dns's TXT registry folds registry rows
  into ownership labels and never returns them as endpoints, so no later plan
  deletes them. The reconcile suite pins this behaviour. The rows are harmless
  to DNS; listing and deleting them is the operator's migration tooling's job.
  A provider-side reaper (remembering failed TXT deletes across reconciles) is
  a possible v1.x improvement, not in v1.
- **Unbound restart per apply**: each apply with changes stops and starts
  Unbound (cache preserved unless `cacheflush` is set).
  `--min-event-sync-interval` on the controller bounds the rate if HTTPRoute
  churn ever makes this noisy.
