# Compliance FAQ

## Does this repository certify regulatory compliance?

No. It provides technical control evidence. The adopting institution owns legal
interpretation, operating effectiveness and its regulator-specific crosswalk.

## Which evidence belongs here?

Keep adapter behavior, configuration, tests, deployment controls and evaluation evidence
with `agent-guardrail-gateway`. Send durable execution evidence to `agent-observability` and keep model promotion evidence with
`model-quality-gate`.

## Is the PII configuration globally portable?

Not yet. The current offline pack is SG-centric and C4 remains partial. An institution
outside Singapore must not treat the local pack as complete.
