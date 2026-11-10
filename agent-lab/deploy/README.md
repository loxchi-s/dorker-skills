# Remote Audit WSGI resource limits

This is a deployment profile, not a deployed service. The repository still requires a reviewed production identity policy and independent approval-evidence verifier before an application factory can be exposed.

## Runtime limits

Run one synchronous Gunicorn worker and one thread with `gunicorn.conf.py`. The service's WSGI boundary applies:

| Control | Limit |
|---|---:|
| Global request rate | 30/minute, burst 5 |
| Per remote peer | 10/minute, burst 3 |
| Concurrent requests | 1 |
| Application processing deadline | 8 seconds |
| Gunicorn hard worker timeout | 10 seconds |
| PostgreSQL connect timeout | 2 seconds |
| PostgreSQL statement timeout | 3 seconds |
| PostgreSQL lock timeout | 1 second |
| Idle transaction timeout | 5 seconds |
| Request body | 64 KiB |
| Request target | 4 KiB |
| Request headers | 32 fields, 8,190 bytes per field |
| Response body | 256 KiB |

The token buckets are process-local and intentionally bounded to 2,048 peer keys. Therefore the supported deployment topology is exactly one Gunicorn worker and one thread. Do not increase workers or threads without replacing the limiter with a shared, durable rate-limit store and adding multi-process conformance tests.

The application does not trust `X-Forwarded-For`; it uses the socket peer address. If every request arrives through one reverse proxy, they share one per-peer bucket, so the effective ceiling is the conservative 10 requests/minute for that proxy plus the global bucket. Do not accept client-supplied forwarded-IP headers as identity.

The 8-second application deadline is checked after body receipt and service processing. A blocking call cannot be safely pre-empted inside WSGI; the 10-second Gunicorn worker timeout is the hard process boundary. The 2/3-second connection and database timeouts bound the PostgreSQL path. Keep any future network verifier timeout at 3 seconds or less. The reverse proxy must also enforce TLS, a 64 KiB body cap, a 5-second client-header/body timeout, and an 8-second upstream read timeout.

## Start command

After a separately reviewed application factory is implemented and configured:

```sh
cd agent-lab
gunicorn --config deploy/gunicorn.conf.py '<configured_wsgi_module>:app'
```

Do not substitute a test fixture, permissive test policy, fake approval verifier, or owner/service-role DSN. The repository intentionally does not provide a production app factory while authorization and evidence-provider decisions remain unconfigured.

## Supabase Free-plan budget (90% ceiling; 10% reserve)

Supabase Free includes unlimited Data API requests, so there is no monthly API-request quota to set at 90%. The application rate limiter above protects the database and service from bursts; it is not a Supabase billing quota.

| Free-plan resource | Plan allowance | Alert at 80% | Stop/mitigate by 90% |
|---|---:|---:|---:|
| Database size | 500 MB/project | 400 MB | 450 MB |
| Uncached egress | 5 GB/org | 4 GB | 4.5 GB |
| Cached egress | 5 GB/org | 4 GB | 4.5 GB |
| File storage | 1 GB/org | 800 MB | 900 MB |
| Edge Function invocations | 500,000/org | 400,000 | 450,000 |
| Realtime messages | 2,000,000/org | 1,600,000 | 1,800,000 |
| Auth MAU | 50,000/org | 40,000 | 45,000 |
| Realtime peak connections | 200 | 160 | 180 |

These are operating thresholds, not Supabase-enforced caps. The Free-plan quota is shared across projects in the organization for organization-level usage items. Database size is per project. The audit service currently uses PostgreSQL directly; it does not use Edge Functions or Realtime.

The PostgreSQL adapter also checks the live database size inside the write transaction and rejects new audit writes at 450,000,000 bytes. Exact idempotent replays remain readable at the ceiling. This prevents this adapter from intentionally consuming the reserved database headroom; unrelated Supabase services and other tables can still grow the database, so keep the dashboard alert active.

A read-only check on 2026-11-10 measured this project's database at 11,359,923 bytes (about 10.83 MiB, 2.27% of the 500 MB limit), with 14 of 60 PostgreSQL connections open and 1 active. The `remote_audit` tables total about 120 KiB. These are point-in-time database measurements, not monthly egress/storage/MAU usage. Egress and the other service quotas must be checked in Supabase Organization > Usage; database SQL cannot prove those organization-wide totals.

Do not automatically delete audit records to preserve quota. If database usage approaches 450 MB, stop new audit writes through an explicit operational gate and plan an approved archive/retention design. Do not silently prune the hash chain.
