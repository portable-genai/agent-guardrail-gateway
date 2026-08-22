# Portability FAQ

## What is portable today?

The domain and wire contracts, explicit adapter map, working local stack, SDK-free managed
construction and fail-fast on-prem seam are executable with `make portability-demo`.

## What is not proved?

The script does not prove live GCP behavior, a completed on-prem backend or
jurisdiction-selectable PII packs. It also makes no identity, datastore or audit portability
claim because Hrz1 is a stateless workload service. Hrz3 owns identity and Hrz5 owns audit.

## Why not add a platform profile?

Hrz1 is itself the shared platform guardrail. A vertical delegates to Hrz1; Hrz1 cannot
delegate the same responsibility back to itself.
