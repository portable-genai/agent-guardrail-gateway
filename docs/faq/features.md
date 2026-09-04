# Features FAQ

## What does `agent-guardrail-gateway` decide?

It screens prompt injection, jailbreak and malicious URLs, and it de-identifies sensitive
text. Its response is a typed verdict, not a human approval or model-quality promotion.

## Which adjacent systems own those decisions?

`model-quality-gate` owns quality promotion gates, `human-review-console` owns human review and `enterprise-knowledge-base` owns governed retrieval.
`agent-guardrail-gateway` remains the runtime safety boundary for their text.

## Does it store prompts?

No. `agent-guardrail-gateway` is stateless and logs no request content. Calling systems send durable,
content-minimised evidence to `agent-observability`.
