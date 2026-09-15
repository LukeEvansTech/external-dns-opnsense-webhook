# external-dns-opnsense-webhook

[external-dns](https://github.com/kubernetes-sigs/external-dns) webhook
provider for OPNsense Unbound host overrides. Built on the shape of
[external-dns-unifi-webhook](https://github.com/home-operations/external-dns-unifi-webhook);
see `NOTICE`.

## What it does

- Manages A, AAAA and TXT host overrides under the domains you configure, so
  external-dns's TXT registry and `policy: sync` work: removed workloads remove
  their records.
- Reads the override table in pages and never returns a partial table.
- Writes TXT registry rows before data rows and removes them after, so a
  failure part-way never leaves a record unowned.
- Applies configuration with `service/reconfigure` only when something changed,
  and repairs a failed reconfigure on the next read or at startup.
- Refuses to delete a row that has hand-made aliases attached, and never writes
  CNAME or wildcard records (see [Limitations](#limitations-v1)).

The full design, including the read-consistency rules and the apply invariants,
is in [`docs/design.md`](docs/design.md).

## Deploy with the external-dns chart

```yaml
fullnameOverride: opnsense-dns
provider:
  name: webhook
  webhook:
    image:
      repository: ghcr.io/lukeevanstech/external-dns-opnsense-webhook
      tag: 0.1.1 # pin a release
    env:
      - name: OPNSENSE_HOST
        value: https://fw.example.com
      - name: OPNSENSE_API_KEY
        valueFrom:
          secretKeyRef:
            name: opnsense-dns-secret
            key: api-key
      - name: OPNSENSE_API_SECRET
        valueFrom:
          secretKeyRef:
            name: opnsense-dns-secret
            key: api-secret
      - name: OPNSENSE_DOMAINS
        value: example.com,internal.example.com
    livenessProbe:
      httpGet:
        path: /healthz
        port: http-webhook
      initialDelaySeconds: 10
      timeoutSeconds: 5
    readinessProbe:
      httpGet:
        path: /readyz
        port: http-webhook
      initialDelaySeconds: 10
      timeoutSeconds: 5
deploymentStrategy:
  type: Recreate
terminationGracePeriodSeconds: 180
policy: sync
registry: txt
txtOwnerId: main
txtPrefix: k8s.main.%{record_type}-
sources:
  - gateway-httproute
  - service
domainFilters:
  - example.com
  - internal.example.com
extraArgs:
  - --webhook-provider-read-timeout=30s
  - --webhook-provider-write-timeout=180s
serviceMonitor:
  enabled: true
```

The chart maps `http-webhook` to container port 8080, which is this image's
health and metrics listener; the webhook API on 8888 binds to loopback and is
reached by external-dns inside the pod.

## OPNsense side

API user privileges: `Services: Unbound DNS: Edit Host and Domain Override`,
`Services: Unbound (MVC)`, `Status: DNS Overview`. Tested against OPNsense
26.7.

## Configuration

Environment only, parsed with `caarlos0/env/v11` and validated at startup: a
bad value exits non-zero before either listener is bound.

| Var                                                                                                   | Default                        | Notes                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `OPNSENSE_HOST`                                                                                       | required                       | Scheme and host, for example `https://fw.example.com`. A path is rejected; a trailing slash is stripped.                                                                                                                   |
| `OPNSENSE_API_KEY` / `OPNSENSE_API_SECRET`                                                            | required                       | `notEmpty,unset`: cleared from the process's own environment after parsing (they are never logged). Sent as HTTP basic auth.                                                                                               |
| `OPNSENSE_DOMAINS`                                                                                    | required, comma list           | Used twice: returned as the negotiated `DomainFilter` on `GET /`, and as the split boundary for FQDN to hostname plus domain. Lower-cased and trailing dots trimmed at load; duplicates are rejected.                      |
| `OPNSENSE_SKIP_TLS_VERIFY`                                                                            | `false`                        | Deliberately not the UniFi default. `true` logs a WARN.                                                                                                                                                                    |
| `OPNSENSE_CA_CERT`                                                                                    | empty                          | PEM bundle path; wins over skip-verify. TLS 1.2 minimum.                                                                                                                                                                   |
| `OPNSENSE_ADD_PTR`                                                                                    | `false`                        | Value of `addptr` on every managed A/AAAA row.                                                                                                                                                                             |
| `OPNSENSE_OWNER_MARKER`                                                                               | `external-dns`                 | Written into `description` on every managed row, for operators filtering the grid and for the startup served-state check. Never used for ownership decisions.                                                              |
| `OPNSENSE_PAGE_SIZE`                                                                                  | `150`                          | `rowCount` per `searchHostOverride` page. 1 to 500.                                                                                                                                                                        |
| `OPNSENSE_READ_ATTEMPTS`                                                                              | `3`                            | Full re-reads allowed when a paginated read is inconsistent. At least 1.                                                                                                                                                   |
| `OPNSENSE_APPLY_WORKERS`                                                                              | `1`                            | Goroutines converging names in one apply phase, 1 to 32. Orchestration only: firewall writes are always serialised, as OPNsense's config save is unsafe under concurrent writes (2026-09-15 cutover: 2 of 282 adds lost).  |
| `OPNSENSE_RETRY_ATTEMPTS`                                                                             | `3`                            | 1 to 10. Retries are limited to idempotent calls and any 429.                                                                                                                                                              |
| `OPNSENSE_RETRY_INITIAL_DELAY`                                                                        | `500ms`                        | At least 1ms. Backoff is `initial << attempt` with up to 50% jitter.                                                                                                                                                       |
| `OPNSENSE_RETRY_MAX_DELAY`                                                                            | `10s`                          | Must be at least `OPNSENSE_RETRY_INITIAL_DELAY`.                                                                                                                                                                           |
| `OPNSENSE_REQUEST_TIMEOUT`                                                                            | `20s`                          | Per-call context timeout on the firewall API.                                                                                                                                                                              |
| `OPNSENSE_RECONFIGURE_TIMEOUT`                                                                        | `45s`                          | `service/reconfigure` stops and starts Unbound and waits for the pid.                                                                                                                                                      |
| `OPNSENSE_APPLY_TIMEOUT`                                                                              | `120s`                         | Budget for the converge phases of one `ApplyChanges`. Must exceed `OPNSENSE_RECONFIGURE_TIMEOUT`. Runs detached from the request context.                                                                                  |
| `SERVER_HOST` / `SERVER_PORT`                                                                         | `localhost` / `8888`           | Webhook API, loopback only; external-dns reaches it inside the pod.                                                                                                                                                        |
| `SERVER_READ_TIMEOUT` / `SERVER_READ_HEADER_TIMEOUT` / `SERVER_WRITE_TIMEOUT` / `SERVER_IDLE_TIMEOUT` | `60s` / `5s` / `180s` / `120s` | The write timeout exceeds the apply budget plus one reconfigure so a long batch is never cut off by the server; the binary refuses to start otherwise.                                                                     |
| `SERVER_MAX_HEADER_BYTES` / `SERVER_MAX_BODY_BYTES`                                                   | `65536` / `5242880`            | 64 KiB of headers, 5 MiB of body.                                                                                                                                                                                          |
| `HEALTH_SERVER_ADDR`                                                                                  | `:8080`                        | `/healthz`, `/readyz`, `/metrics` on all interfaces. The external-dns chart's `http-webhook` container port is 8080, so kubelet probes and the ServiceMonitor land here. `/healthz` and `/readyz` are also served on 8888. |
| `READINESS_CACHE_TTL`                                                                                 | `30s`                          | How long a `/readyz` verdict is reused before the upstream is probed again.                                                                                                                                                |
| `PPROF_ENABLED`                                                                                       | `false`                        | Mounts `/debug/pprof/*` on the health server. Logs a WARN when on.                                                                                                                                                         |
| `LOG_LEVEL`                                                                                           | `info`                         | `debug`, `warn` or `error`; anything else is `info`. `debug` also adds the call site to every record.                                                                                                                      |
| `LOG_FORMAT`                                                                                          | `json`                         | `text` for humans.                                                                                                                                                                                                         |

Timeout budget, inner to outer — each layer must be shorter than the next:

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
to `OPNSENSE_APPLY_TIMEOUT` plus `OPNSENSE_RECONFIGURE_TIMEOUT` — 165 s by
default. `main` compares that sum against `SERVER_WRITE_TIMEOUT` at startup and
exits non-zero rather than let the server cut off the reply to an apply that is
still legitimately running. Measured on a firewall on 2026-09-14 by the
integration suite: a 282-row batch took 8.3 s to create and 7.7 s to delete,
three runs within 1 s of each other, so the 120 s apply budget carries more
than a tenfold margin.

Startup order is listeners first, firewall second: both servers bind, then the
provider probes the firewall in the background. external-dns negotiates `GET /`
with a few retries and exits fatally if none succeeds, so the listener has to
answer within seconds of container start regardless of the firewall.
Reachability gates `/readyz`, never the process.

## Ports

| Port | Bind           | Serves                                                                                                 |
| ---- | -------------- | ------------------------------------------------------------------------------------------------------ |
| 8888 | localhost      | webhook API (`GET /`, `GET /records`, `POST /records`, `POST /adjustendpoints`), `/healthz`, `/readyz` |
| 8080 | all interfaces | `/healthz`, `/readyz`, `/metrics` (the chart's `http-webhook` container port)                          |

`/healthz` is a static 200: the process is up. `/readyz` runs one cheap
`searchHostOverride` page of a single row against the firewall, so it reports
not-ready while the API is unreachable or the credentials are wrong. That probe
is cached for `READINESS_CACHE_TTL`, single-flighted so concurrent hits share
one check, detached from the caller's context and separately bounded at 10 s;
the failure cause is logged once per probe rather than returned to the caller.

At startup the provider calls `service/status` and then compares the enabled
rows carrying the owner marker in the saved configuration against what Unbound
is actually serving (`diagnostics/listlocaldata`). Any managed row that is
saved but not served triggers one reconfigure, which is how a reconfigure lost
to a restart repairs itself. Failures there are logged and leave `/readyz`
failing; they never exit the process.

## Limitations (v1)

- No CNAME writes: OPNsense has no CNAME record; an alias is a copy of its
  parent A record, and the provider reads aliases as such. CNAME endpoints are
  dropped with a warning and a metric.
- No wildcard writes: a `*` override makes Unbound redirect the whole domain.
  Existing wildcard rows are read as-is.
- Deleting a row with alias children is refused
  (`externaldns_webhook_opnsense_delete_blocked_total`). Re-home or delete the
  alias by hand.
- MX rows are read, never written.

`AdjustEndpoints` drops what the model cannot hold rather than letting
external-dns retry it forever. The reason set is closed, and it is the `reason`
label on `externaldns_webhook_opnsense_endpoints_dropped_total`: `type` (not A,
AAAA or TXT), `set-identifier`, `wildcard`, `apex` (the name equals a
configured domain), `domain` (outside `OPNSENSE_DOMAINS`), `name` (any other
split failure), `txt` (a TXT target failing the length or character rules).

## Metrics

Everything is registered under the `externaldns_webhook` namespace and carries
`provider="opnsense"`.

HTTP surface:

- `externaldns_webhook_http_requests_total{provider,method,endpoint,status_code}`
- `externaldns_webhook_http_request_duration_seconds{provider,method,endpoint}`
- `externaldns_webhook_http_requests_in_flight{provider}`
- `externaldns_webhook_http_response_size_bytes{provider,method,endpoint}`
- `externaldns_webhook_http_validation_errors_total{provider,header_type}`
- `externaldns_webhook_http_json_errors_total{provider,endpoint}`
- `externaldns_webhook_http_handler_panics_total{provider,endpoint}`

Provider operations:

- `externaldns_webhook_records{provider,record_type}` — gauge, endpoints the
  last read returned for A, AAAA, TXT and MX
- `externaldns_webhook_changes_total{provider,operation}`
- `externaldns_webhook_changes_by_type_total{provider,operation,record_type}`
- `externaldns_webhook_adjust_endpoints_total{provider}`
- `externaldns_webhook_negotiate_total{provider}`

OPNsense API:

- `externaldns_webhook_opnsense_api_errors_total{provider,operation}`
- `externaldns_webhook_opnsense_api_duration_seconds{provider,operation}`
- `externaldns_webhook_opnsense_api_response_size_bytes{operation}`
- `externaldns_webhook_opnsense_api_retries_total{provider,operation,status}`
- `externaldns_webhook_opnsense_api_rate_limits_total{provider,operation}`

Read, apply and reconfigure:

- `externaldns_webhook_opnsense_pages_fetched_total{provider}`
- `externaldns_webhook_opnsense_read_restarts_total{provider}` — paginated
  reads restarted because the table moved
- `externaldns_webhook_opnsense_rows{provider}` — gauge, rows in the last
  accepted snapshot before filtering
- `externaldns_webhook_opnsense_reconfigure_total{provider,result}` — `result`
  is `ok` or `error`
- `externaldns_webhook_opnsense_pending_reconfigure{provider}` — gauge, 1 while
  the saved configuration has not reached the running Unbound
- `externaldns_webhook_opnsense_apply_duration_seconds{provider}`
- `externaldns_webhook_opnsense_delete_blocked_total{provider}`
- `externaldns_webhook_opnsense_endpoints_dropped_total{provider,reason}`
- `externaldns_webhook_opnsense_txt_invalid_total{provider}`
- `externaldns_webhook_opnsense_lost_writes_total{provider,operation}` — writes
  the firewall acknowledged that the re-read after the phase showed were not
  saved; `operation` is `create`, `update` or `delete`
- `externaldns_webhook_opnsense_verify_reads_failed_total{provider}` — verification
  reads that failed, so that apply's writes went unverified

Health of the whole loop:

- `externaldns_webhook_consecutive_errors{provider}` — gauge, counted per
  top-level operation, not per API call
- `externaldns_webhook_last_success_timestamp{provider}`
- `externaldns_webhook_info{version,provider}`

Worth alerting on: `externaldns_webhook_opnsense_pending_reconfigure` stuck at
1, any increase in `externaldns_webhook_opnsense_delete_blocked_total` or
`externaldns_webhook_opnsense_lost_writes_total`, and
`externaldns_webhook_last_success_timestamp` going stale.

## Development

`mise install`, then:

| Task                            | Runs                                                                        |
| ------------------------------- | --------------------------------------------------------------------------- |
| `mise run test`                 | unit tests with the race detector and coverage                              |
| `mise run test-e2e`             | the built binary against the in-memory OPNsense, at protocol level          |
| `mise run test-reconcile`       | external-dns's own planner and TXT registry against the binary and the fake |
| `mise run test-integration`     | against a real firewall, needs `OPNSENSE_*` in the environment              |
| `mise run lint`                 | golangci-lint                                                               |
| `mise run lint-workflows`       | actionlint and zizmor                                                       |
| `mise run vulncheck`            | govulncheck                                                                 |
| `mise run fmt` / `mise run vet` | `go fmt` and `go vet`                                                       |

The integration suite needs a real firewall: see
`test/integration/integration_test.go` for the variables it expects and the
`extdns-itest-*` names it creates and sweeps.

## Releases

Open a `chore(release): X.Y.Z` pull request that only bumps `CHANGELOG.md`,
merge it, then tag the merge commit `vX.Y.Z` and push the tag. The tag push
builds and publishes
`ghcr.io/lukeevanstech/external-dns-opnsense-webhook:X.Y.Z` (and `X.Y`) for
linux/amd64 and linux/arm64, with an SBOM and provenance attached. Pushes to
`main` publish the `main` tag, which is a moving target — pin a released
version in anything that matters.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
