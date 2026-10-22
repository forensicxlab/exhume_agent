# Investigator-led execution contract

The shared runtime serves the CLI and Thanatology. A case brief defines the objective, selected evidence and its role, supplied facts, allegations, constraints, and whether external-tool proposals are permitted. Unknown background details can remain empty. An objective and evidence selection are required before approval. Thanatology derives processing destinations from the session's configured AI services when the investigator saves the brief; there is no separate destination editor. The CLI can still supply an explicit processing policy in its JSON brief.

A model can propose a step and record provisional findings. Only the host's human-facing commands can approve a step or accept a finding. Ordinary conversation text does not grant permission.

## A bounded step

Each proposal identifies its question, rationale, evidence IDs, permitted tool names, required source selectors, call/retry/time/output bounds, stop conditions, effort, and limitations. One to three proposals are presented with exactly one recommendation. `source_selectors` restricts required top-level arguments to exact approved values:

```json
{
  "query_index": {
    "sql": ["SELECT COUNT(*) AS indexed_files FROM system_files"]
  }
}
```

An approved step can begin once, on one turn ID. Changing the case brief invalidates pending and approved proposals. Ending a step consumes its approval. Reopening a session interrupts both approved and running steps; prior approval cannot silently resume execution.

Tool calls first reserve a durable execution record. Completion records the full received result, exact parameters, selected evidence identities, toolkit version, timestamps, output digest, status, and coverage before presentation truncation. A source-selector, evidence-selection, or processing-policy violation interrupts the whole step. Failed tool branches have bounded retries; declared dependents require an observed usable result. Independent approved tools can continue within the remaining limits.

The host must enforce physical evidence identity, actual tool time/output bounds, and native tool argument semantics. The store enforces the declared step contract and persistence. Model output cannot override either layer.

## Observations and review

Statuses are `success`, `partial`, `failed`, and `unknown`. Structured tool errors or nonzero exit codes cannot be labeled successful. Truncated or unsuccessful results cannot claim complete coverage.

A material finding cites execution IDs, evidence IDs and source locations. Its source locator must appear in the cited parameters, result or examined coverage, or equal a captured evidence path or execution ID. Its exact source excerpt must appear in the cited raw result or a decoded JSON string. A supplied source digest must appear in captured evidence identities or cited results. Findings automatically receive the exact tool and parameter reproduction instructions. Incomplete negative results must state their limitations.

These checks establish that a cited result was observed. They do not establish that an interpretation is correct. All new findings are provisional regardless of model-supplied review flags. Investigator decisions accept, reject, or request corroboration while preserving the original observation and decision history. Path-confidence scoring is intentionally absent.

## Durable files and recovery

Each session creates:

- `<session-id>-investigation.md`: case brief and revisions, proposed/approved scopes, checkpoints, material findings, reproduction instructions, provider provenance, and investigator decisions.
- `<session-id>-executions.jsonl`: complete received results and execution provenance.

The database is authoritative. Every mutation is written with an optimistic revision check, then both files are atomically replaced and synchronized while a SQLite write transaction serializes exports across processes. Stale revisions are rejected before either file is touched. The exported revision advances only after both writes succeed. If export fails, the API returns an error and subsequent execution is blocked. Fix the underlying storage error and call `repair_exports()`, or reopen the session to retry the export. A caller must not claim a report was saved after an error.

## Processing and missing capabilities

A processing destination includes provider, endpoint, model, authentication mode and optional account identity. Declared account and authentication restrictions are enforced along with the destination. Requested model aliases and resolved model identifiers are retained separately. Provider usage is recorded separately from tool execution and does not imply that an investigative observation succeeded. There is no automatic fallback to another account, provider, or billing mode.

On desktop **Save brief**, the recorded destinations are refreshed from the session's configured reasoning service and its supported image/audio services. This replaces stale or empty destinations from an older saved brief while preserving the external-tools checkbox. Configuration is captured when the session opens; reopen the session after changing Settings, then save the brief. Destinations never expand during execution, and every tool still needs an approved step. Processing provenance remains in the report.

A missing capability can be proposed even when external tools are currently disallowed. Approval of an external-tool proposal requires the investigator to enable **Permit proposals involving external tools** in the case brief first. Capability-gap reports include a reviewable GitHub issue draft with the component, missing behavior, a synthetic example, and developer acceptance criteria. The UI opens an issue form only on an explicit click; it does not publish an issue. Review the draft for case details before sharing it.

## Verification

The module tests exercise one-turn and resume approval boundaries, source-selector violations, failed dependency/retry behavior, export failure and recovery, complete-result retention, contradictory success flags, fabricated excerpts and locators, partial negative findings, account changes, resolved model aliases, stale exports, failed repairs, and external-capability proposals. The tests use synthetic in-memory databases and temporary output directories, not a forensic case image.
