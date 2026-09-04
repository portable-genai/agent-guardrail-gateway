# Security FAQ

## Can a client assert its own user or permissions?

No. `agent-guardrail-gateway` accepts no end-user actor or ACL fields. The service verifies the calling workload
server-side. `agent-registry` owns workforce and agent identity.

## Where is a blocked decision reviewed?

`agent-guardrail-gateway` returns the safety verdict. A workflow that needs an exception or manual decision
routes it to `human-review-console`. Durable security evidence belongs in `agent-observability`.

## Does on-prem mode fail open?

No. Its placeholder adapters raise before processing. They must be replaced and validated
before an institution can claim an on-prem deployment.
