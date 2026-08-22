# Security FAQ

## Can a client assert its own user or permissions?

No. Hrz1 accepts no end-user actor or ACL fields. The service verifies the calling workload
server-side. Hrz3 owns workforce and agent identity.

## Where is a blocked decision reviewed?

Hrz1 returns the safety verdict. A workflow that needs an exception or manual decision
routes it to Hrz7. Durable security evidence belongs in Hrz5.

## Does on-prem mode fail open?

No. Its placeholder adapters raise before processing. They must be replaced and validated
before an institution can claim an on-prem deployment.
