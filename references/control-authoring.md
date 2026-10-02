# Control Authoring

Controls are declarative JSON documents validated by `control/v1`. Evaluator code lives separately.

## Add a control

1. Choose a stable domain ID such as `CI-OPS-011`.
2. Add metadata to the relevant `controls/*.v1.json` catalog: title, description, applicability capabilities, minimum evidence kinds, evaluator name, time/correlation flags, and allowed states.
3. Write the evaluator test first and observe RED.
4. Implement an evaluator that consumes normalized evidence and returns `control-result/v1`.
5. If the control can produce a material canonical problem, add a tested correlation rule. Do not let the collector create findings.
6. Add completeness/error cases: unavailable source, permission denial, partial retention, malformed evidence.
7. Run the complete suite.

## Boundaries

- Collector → facts/evidence only.
- Evaluator → one control decision.
- Correlation → cross-control/cross-source condition.
- Finding materializer → canonical problem representation.
- Renderer → presentation only.

A control must never report PASS when its minimum evidence is inaccessible or incomplete unless the control definition explicitly proves that the observed subset is sufficient.
