# Portability FAQ

## What is portable today?

The domain and wire contracts, explicit adapter map, working local stack, SDK-free managed
construction and fail-fast on-prem seam are executable with `make portability-demo`.

## What is not proved?

The script does not prove live GCP behavior, a completed on-prem backend or
jurisdiction-selectable PII packs. It also makes no identity, datastore or audit portability
claim because `agent-guardrail-gateway` is a stateless workload service. `agent-registry` owns identity and `agent-observability` owns audit.

## Why not add a platform profile?

`agent-guardrail-gateway` is itself the shared platform guardrail. A vertical delegates to `agent-guardrail-gateway`; `agent-guardrail-gateway` cannot
delegate the same responsibility back to itself.
