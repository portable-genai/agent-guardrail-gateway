# Features FAQ

## What does Hrz1 decide?

It screens prompt injection, jailbreak and malicious URLs, and it de-identifies sensitive
text. Its response is a typed verdict, not a human approval or model-quality promotion.

## Which adjacent systems own those decisions?

Hrz4 owns quality promotion gates, Hrz7 owns human review and Hrz2 owns governed retrieval.
Hrz1 remains the runtime safety boundary for their text.

## Does it store prompts?

No. Hrz1 is stateless and logs no request content. Calling systems send durable,
content-minimised evidence to Hrz5.
