# Adoption FAQ

## Should we consume or fork?

Consume when the contract and release boundary fit. Fork when institutional naming,
ownership or release cadence must differ. See `docs/ADOPTING.md` for the comparison and
rename flow.

## Where should bank policy live?

Use Model Armor and DLP templates, configuration and institution-owned adapter code. Do not
put knowledge policy in `agent-guardrail-gateway`; `enterprise-knowledge-base` owns governed knowledge. Do not put promotion thresholds
here; `model-quality-gate` owns the promotion verdict.

## Can the rename tool damage an existing package?

It previews by default and refuses to apply if the destination package already exists.
Review the diff and run the full gate after applying it in a fork.
