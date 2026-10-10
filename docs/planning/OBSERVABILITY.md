# Observability gaps

**Status: not started.** Already in place: OTLP export of traces, metrics and logs; per-request spans; about 40 `obscura_*` counters, gauges and histograms (grep `src/` for `obscura_`); `obscura_health_status` from `/readyz`.

## Missing

- **Inventory gauges**, from a poller every few minutes rather than per scrape: users, queued messages, live attachments (count and bytes), DB pool connections in use.
- **HTTP RED metrics**: request count by method, route and status, and a duration histogram by route. Only spans exist today.
- **Error classification**: mark spans with OTel exception and status conventions so 4xx and 5xx are distinguishable for alerting.
- **Metric catalogue**: a list of the `obscura_*` metrics and their labels.

## Open questions

- Do counts of users and messages belong in telemetry at all, given the metadata-minimising goal?
