# Investigator-led agent implementation

This change implements the agreed investigation workflow in the reusable `exhume_agent` runtime and its CLI and Thanatology integrations. The later user-authorized [Kali live workflow audit](kali-live-agent-audit.md) records attempts through the desktop agent and their limitations; it does not establish whether the example allegation is true.

## Implemented behavior

- A case brief separates the objective, evidence roles, supplied facts, allegations, constraints and external-tool proposal permission. Thanatology derives processing destinations from the session's AI configuration when saving the brief. Unknown background details can remain unknown.
- Human-facing commands approve a bounded step and major pivots. Model prose cannot approve work. Each approval applies to one execution turn; reopening a session invalidates unfinished approvals.
- Native tools run only within the approved source selectors, tool list, dependencies and resource limits. Failed branches have bounded retries. Source or policy violations interrupt the step.
- Structured tool outcomes are checked before display truncation. The complete received output, exact arguments, source identity, status and provenance are retained. Successful execution verifies an operation, not the truth of a model interpretation.
- Findings require observed excerpts and source locators tied to actual executions. The runtime generates reproduction steps. Human review can accept, reject or request corroboration; new findings remain provisional.
- Checkpoints separate observations, interpretations, contradictions and limitations, then propose up to three paths with one recommendation. Path-confidence scores are intentionally absent.
- Markdown reports and JSONL execution logs are mandatory. The desktop's **Report & decisions** tab renders the persisted Markdown, with revision checks, automatic snapshot refresh and a manual refresh action. Failed exports block execution until repaired; concurrent exports cannot overwrite newer revisions. Conversation clearing preserves the investigation ledger.
- Capability gaps produce reviewable, case-neutral issue/developer briefs. The desktop can open GitHub's issue form on an investigator click; it never publishes an issue automatically.
- Image description and transcription use bounded single-file tools with recorded processing destinations, source hashes and explicit interpretation limits. Desktop destinations come from configured supported services; each investigative tool still requires step approval. Unsupported account/media combinations fail without fallback.

The [execution contract](investigation-contract.md) documents the state model and report guarantees. [Account authentication](account-authentication.md) documents exact provider support and setup.

## Using the workflow

In Thanatology, configure the provider in Settings, open the agent workspace for the selected evidence, complete **Case brief**, and save it. Keep **Permit proposals involving external tools** selected only when those proposals are wanted. Review the proposed question, tools, source restrictions and limits, then choose **Approve and run**. Review the checkpoint and findings before approving another step. Reports and review history are available in **Report & decisions**.

For the CLI, start with an existing source and an explicitly selected backend/model:

```sh
cargo run -p exhume_agent --bin exhume-agent --offline -- \
  --image /path/to/source.E01 --provider ollama --model YOUR_INSTALLED_MODEL
```

This prepares local storage and the interface; it does not automatically index or investigate the source. Describe the objective to get an initial inventory proposal. `/brief` displays the editable JSON brief; `/brief JSON` saves it. `/approve STEP_ID` records a human decision, and `/run` executes the approved scope. `/status`, `/reject STEP_ID`, `/review FINDING_ID accept|reject|corroborate REASON`, `/propose JSON_ARRAY`, and `/repair-report` support review and recovery. `/help` lists these commands.

The CLI can inspect unindexed partitions/directories/files using native offsets and filesystem identifiers after approval. SQLite/media adapters currently require indexed partition/file identifiers. A missing index is a coverage limitation, not evidence that files are absent. Full recursive indexing remains a separate toolkit/desktop operation and is not silently started by the agent.

Embedded callers should use `AgentSession` for decisions, cancellation and lifecycle management. Low-level `ExhumeAgent::chat` still enforces step approval, but dropping its future does not provide the session wrapper's interruption cleanup. An extension tool must declare its processing destinations through `AgentToolProvider::tool_destinations`; an undeclared extension is unavailable.

## Desktop case-brief simplification (2026-10-14)

Removed **Approved processing destinations**, its provider/endpoint/model/account inputs, add/remove controls, and destination-input validation from the desktop case brief. **Permit proposals involving external tools (each step still needs approval)** remains editable and retains its saved value. The approval description now refers to the saved brief and step scope.

Saving the desktop brief derives its recorded destinations from the session's configured reasoning service and supported media tools. This also replaces stale or empty destinations in older briefs without requiring hidden fields to be repaired manually. Each tool still needs an approved step; the runtime's provider/account checks, execution limits and CLI's explicit policies remain in place. The backend does not add destinations during execution.

To reproduce and review: open an agent workspace, choose **Case brief**, enter an objective, toggle the external-tools checkbox, and save. The destination editor is absent, the checkbox's value persists, and the initial step still requires **Approve and run**. Reopen a session after changing AI Settings, then save its brief to use the new configuration. The Markdown report records the resulting destinations and subsequent investigator decisions.

Validation: the TypeScript check and production frontend build passed, with the existing bundle-size warning. `cargo test -p exhume_agent --lib --offline configured_ -- --nocapture` passed all three selected tests, including two new regressions covering available media services, stale destination replacement, both checkbox values, CLI policy preservation, and the need for approval after saving. The desktop `cargo check --manifest-path src-tauri/Cargo.toml --offline` passed. Interactive desktop verification has not been performed for this change.

## Rendered report and live workflow testing (2026-10-14)

The desktop report preview reads the actual exported file via `get_agent_report`, authorizes the requesting session/window, checks revisions before and after a bounded read, and renders headings, lists, tables and code. Stale or incomplete exports are visible errors. HTML and image fetching are disabled. Three backend tests, the frontend build and desktop Rust check passed. Live Tauri inspection verified rendered report revision 27 and manual refresh; a main-window request for the agent window's report was denied.

Live inspection also found ten historical model responses with no tool executions and an empty successful checkpoint. The runtime now requires structured calls for OpenAI subscription requests, retains bounded unverified model diagnostics and checkpoint-validation errors, and interrupts after three consecutive responses without progress. The required-tool payload test passed. A further live retry identified synchronous Keychain access blocking both timeout and cancellation. Credential access in inference now runs on blocking workers with lock retention; 20 authentication tests and 12 focused workflow/cancellation/session tests passed. A live retest returned to idle after its provider deadline and refreshed the rendered report to revision 36, while the OS credential call remained pending in a background worker. No evidence-tool results or forensic findings were obtained. Details, reproduction, remaining UI/authentication follow-ups and the requirement for the user to handle any OS prompt are in the [audit](kali-live-agent-audit.md).

## Authentication support

The credential-access follow-up adds an expiry-aware ChatGPT access-token cache
in backend process memory, with account/directory isolation, concurrent request
coalescing, and generation checks for cross-process credential changes. Account
display reads a non-secret metadata index; explicit **Refresh connections** or
CLI `--auth refresh` loads legacy stored accounts. Normal configuration reads no
longer fetch an API key just to redact it. Credential refresh/persist transactions
survive investigation cancellation without continuing inference. The desktop
release workflow supports a configured Developer ID identity; activating it still
requires the owner's certificate and GitHub Actions configuration. See
[credential behavior](account-authentication.md#credential-reads-and-account-details)
for first-use prompts and custom-auth-directory migration.

This follow-up passed 98 agent tests, including 12 added cache/index regressions,
15 focused desktop tests, the frontend build, desktop Rust check and native debug
build. Signing-workflow YAML and five synthetic configuration checks passed.
Real account cache reuse and a certificate-signed release were not exercised.

| Provider | Account connection | Investigation inference |
| --- | --- | --- |
| OpenAI | Official Sign in with ChatGPT, account model catalog and OS-protected tokens | Direct Responses API with explicit account selection; no API-key fallback |
| Mistral | Official Vibe login, explicit import of its documented provisioned API credential into OS storage | Direct public API; account allowance or enabled pay-as-you-go applies |
| Claude | Official native login/status/logout | API-key mode works. Subscription inference is unavailable until pre-launch managed execution policy can be attested |

The Claude restriction is deliberate: official native controls cannot guarantee that managed startup hooks are suppressed before inference. Account connection alone must not imply that subscription investigation is enabled. The authentication document includes a case-neutral upstream feature brief.

Saved desktop API keys remain behind native IPC. Existing plaintext settings migrate to OS storage. Legacy batch specialists resolve keys in the backend and reject unsupported provider/authentication/endpoint combinations before processing, avoiding implicit routing to another provider.

The browser/model-selection follow-up adds a visible **Sign in with ChatGPT** action using the default system browser, cancellable authorization with window-owned cleanup, automatic subscription catalog loading, and a searchable model selector for every supported provider. Reconnecting the same account refreshes its catalog too. API/local connections expose **Load models**; no model identifier needs manual entry. Stored keys are reused for discovery only when the saved provider and normalized endpoint match. Stale asynchronous results cannot replace the selected connection's catalog.

Follow-up verification passed 12 core authentication tests and seven desktop authentication/catalog tests, plus the production frontend build and final TypeScript check. These cover fragmented callback requests, cancellation/expiry ownership, catalog parsing, pagination, ordering and credential routing without live account access. Interactive browser authorization still requires a live smoke test; no running Tauri app was available for visual verification in this session.

### Browser rejection: unsupported host identifier (2026-10-14)

**Observation:** The user reported the browser returning `invalid_authorize_request` with `param: ext_agent_host_id`. The sign-in implementation generated and persisted `exhume-<random-base64url>`. OpenAI's [host-ID contract](https://developers.openai.com/siwc/token-sharing-open-source#a-client-vs-an-agent-host) accepts specific URI formats, including `urn:uuid:<UUIDv4>`; the generated value did not comply. The earlier callback tests did not exercise the outgoing authorization URL.

**Change:** Generate a random UUIDv4 URN for new installations. Repair empty or legacy `exhume-...` values once, while holding the existing vault lock, and persist before opening authorization. Preserve supported existing IDs and every account registration, token and API key. Extract the URL builder so regression tests inspect the actual emitted parameters for new and returning accounts, including a published PKCE test vector.

**Reproduction and verification:**

1. With the earlier build and no OpenAI connection, select **OpenAI → ChatGPT subscription (browser sign-in)** and click **Sign in with ChatGPT**. The outgoing request contains the unsupported host ID; the user observed the browser rejection above. No investigator evidence is needed.
2. Rebuild and restart the native app with the fix, then click **Sign in with ChatGPT** again. Use the new browser page instead of refreshing the failed URL. The stored legacy ID is repaired automatically; do not delete credentials.
3. Run `cargo test -p exhume_agent --lib --offline auth::` from `exhume/`. All **18 tests passed**, including six added regressions for UUID version/variant and uniqueness, stable persistence, supported-format preservation, lossless legacy migration, and initial/returning authorization URLs. Tests use synthetic vaults and loopback callbacks without reading the real credential store.
4. Run `cargo check --manifest-path src-tauri/Cargo.toml --offline` from `thanatology/`. The desktop Rust check passed against the updated shared agent source.

Live browser authorization after this fix remains to be confirmed by the user. A separate recovery limitation remains: if first-registration token exchange fails with `invalid_grant`, the callback-issued client ID is not retained for the next attempt. Supporting that recovery requires provisional registration state distinct from a validated connected account; it is not the cause of this browser rejection.

## Validation and practical limits

Validation uses synthetic evidence, temporary databases, local mock HTTP responses and injected credential readers. No real case image or provider account is required. The agent tests cover approval boundaries, evidence/index binding, source selectors, retries/dependencies, cancellation, tool outcomes, reproduction, export failure/recovery/concurrency and provider parsing. Desktop validation includes the production frontend build and credential-routing regression tests.

On 2026-10-14, the final agent suite passed **66 tests** (56 library tests and 10 integration tests). The two desktop credential regression tests passed, the desktop Rust check passed, and the production frontend build passed with the existing bundle-size warning. Diff whitespace checks passed for both repositories.

Run from the framework workspace:

```sh
cd exhume
cargo test -p exhume_agent --all-targets --offline
```

```sh
cd thanatology
npm run build
cargo check --manifest-path src-tauri/Cargo.toml --offline
cargo test --manifest-path src-tauri/Cargo.toml --lib --offline specialist_credential_tests
```

The local HTTP integration tests require permission to listen on loopback. Live account login, subscription eligibility, refresh/revocation and OS credential-store behavior still require a sign-in smoke test. Windows and Linux account storage have not been exercised on the macOS development host. Desktop visual interaction has not been verified in a running Tauri window.

Evidence identity checks bind the selected source to its index and session, then compare canonical path, size and modification time before/after tool work. They are not a full acquisition-image hash verification; segmented images and changes within a selected folder require additional acquisition verification. Extracted files receive SHA-256 hashes. Directory/file APIs still perform some synchronous native parsing, so cooperative timeouts are not a hard process-isolation boundary for a stalled parser. Unix shell cancellation terminates ordinary process-group descendants; this is not a sandbox against a command deliberately escaping its group, and Windows cleanup currently covers the immediate process only.

## Keychain and live provider follow-up (2026-10-15)

The user retained the native Keychain backend and resumed testing. Automatic
ChatGPT model discovery now uses only cached access tokens and local generation
metadata; otherwise the model selector offers explicit credential access.
Mistral and stored API-key discovery use the same explicit-action boundary.
Approved inference retains native loading and refresh. Explicit account refresh
and successfully persisted sign-in seed the cache; sign-in releases its vault
lock before waiting for the cache mutex and verifies the generation before
publishing tokens, avoiding stale publication after a concurrent disconnect.

A live bounded workflow test established an OpenAI stream parsing defect:
the stream contained a completed function call while the successful final
response's output array was empty. The adapter now reconstructs that specific
case from whole completed items, with completion, ordering, identity, conflict
and duplicate checks. Deltas and failed/truncated streams remain unusable.
Full reproduction steps, subsequent test outcomes and remaining limitations are
recorded in the [live audit](kali-live-agent-audit.md#resumed-baseline-and-completed-stream-omission-2026-10-15).

Live validation subsequently passed: explicit model loading and filtering,
warm Settings reopening, two exact approved metadata reads, running-state
progress, checkpoint validation/correction and rendered Markdown revision 71.
The run stopped with the next proposal pending approval and two provisional
observations. Both observations include exact reproduction parameters and
execution IDs. No conclusion about exploitation or modifications was made.

The live Settings retest also exposed duplicate automatic requests under React
StrictMode: the second saw a busy cache while the first success was discarded.
Identical pending automatic requests now share one promise, with no automatic
credential retry. Passive legacy-config reads redact without migration; explicit
migration preserves the original settings on failure and checks credential
routing. Final desktop validation passed 14 frontend regressions, nine
configuration/migration tests, 11 agent tests, the frontend build and Rust check.
The final full core suite passed 113 tests (100 library and 13 integration).
The live audit records the remaining browser-login, OS-denial and signing checks.

An opt-in desktop signed-debug helper verifies the certificate team, bundle ID
and designated requirement before declaring an artifact usable for identity
testing. Seven synthetic tests passed. Real signing remains blocked by the
absence of an installed valid Developer ID Application identity. No certificate,
Keychain ACL or credential backend was changed. See the
[signing guide](../../../../thanatology/docs/macos-development-signing.md).

## Coordinated release requirement

Thanatology currently uses the sibling development source at `../../exhume/members/exhume_agent`. This is intentional for validating the changes together. An app-only checkout does not contain that path. Before a standalone desktop release, publish the reviewed agent changes under a **new distinct version** and switch the desktop dependency to that exact registry version, or pin a reviewed immutable source revision with the same code. Regenerate `src-tauri/Cargo.lock` and validate a clean standalone checkout with `--locked` on every release platform. The existing published agent version does not contain these APIs. No package publication, release workflow or remote commit was performed here.
