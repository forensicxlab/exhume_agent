# Kali live agent workflow audit

Date: 2026-10-14. Application: Thanatology development build. Evidence: `9` (`Kali Linux`), session `thanatology-9`. Source: `/Users/fguyard/Downloads/Case3-Kali/workshop-kali.E01`.

The user authorized an investigation attempt through Thanatology's agent using the configured OpenAI connection, and identification of workflow problems. This report separates software observations from forensic conclusions. It does not treat an attacker-side artifact as proof of a victim-side effect.

## Existing run: no tool progress hidden behind a completed turn

**Observed:** On connecting through Tauri MCP, the existing session was idle. Its working report at revision 26 showed ten OpenAI request/response pairs using the configured subscription connection, zero tool executions, zero findings, and a checkpoint stating that the bounded model/tool loop ended without a valid checkpoint. The activity panel showed only turn start and turn completion. The previous approved step allowed `query_index` and `list_partitions`, six calls, and 120 seconds.

**Interpretation:** Model transport completion did not establish investigation progress. The runtime could retry text-only responses or rejected finish payloads ten times without surfacing the reason. The historical response texts and finish-validation errors were not retained, so the exact cause of that historical run cannot be established from its report.

**Reproduction:**

1. Open the Kali evidence's agent workspace and inspect the existing initial inventory checkpoint.
2. Open its persisted report at `<app-data>/evidences/9.extracted/investigations/thanatology-9-investigation.md`.
3. Compare the provider provenance entries with the empty execution/reproduction index and zero material findings.
4. Inspect `run_step` in `src/runtime.rs`: no-tool replies receive the same correction; invalid finish payloads return only an internal tool message; exhaustion saves an empty checkpoint and returns success.

**Implemented correction:** Each round now persists bounded, explicitly unverified diagnostics and rejected checkpoint reasons before UI delivery. Three consecutive responses without executable progress interrupt the step; successful/partial tool progress resets that counter. Overall exhaustion also interrupts instead of returning an empty successful checkpoint. OpenAI subscription requests use `tool_choice: "required"` when the runtime supplies an executable catalog and finish tool. Namespace and replay formats were retained after comparison with the [official SIWC contract](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations). Six workflow regressions and the required-tool payload test passed. A live retry is needed to determine the next concrete failure or successful behavior.

## Report visibility

**Observed:** The original Report & decisions tab exposed a filesystem path and an external-open button, without displaying the report contents.

**Change:** The tab now reads the actual persisted report through session/window-scoped IPC and renders Markdown headings, lists, tables, and code. It refreshes with snapshot revisions and supports manual refresh. Incomplete/stale exports show an error. Reads are bounded to 4 MiB; HTML and image fetching are disabled.

**Reproduction:** Open **Investigation → Report & decisions** and compare the rendered report's session/revision with the persisted Markdown file. Refresh after an approved step or decision. The external report and execution-log actions remain available.

**Verified live:** Tauri DOM inspection confirmed the rendered `Saved investigation report` article at session `thanatology-9`, revision 27, with seven document headings and three code blocks. Manual **Refresh report** returned the same persisted revision without error. Calling the report IPC from the main window was correctly rejected because the agent session belonged to another window. Three backend report tests, the frontend build, and desktop Rust check passed. Screenshot capture failed in the older MCP bridge; no pixel-level visual claim is made.

## Automation observations

The running app uses MCP Bridge 0.11.2. Connection and window discovery worked, but some IPC/JavaScript calls timed out while their operations completed. The first snapshot of an already-open agent window also lacked its accessibility helper; snapshots worked after reopening the window. Treat a timeout as uncertain execution and inspect current state before retrying a mutation. No bridge upgrade was needed for the available interaction tools.

The native development watcher restarts the app when desktop Rust files change, closing auxiliary windows. Changes in the shared agent crate alone did not trigger that watcher. Finish native edits and confirm the rebuilt binary before starting a live run, then reopen the evidence workspace. The later credential-worker rebuild recovered the previously hung step as interrupted, preserving its ledger and requiring fresh approval.

## Live retry: synchronous Keychain access blocks cancellation

**Observed:** A fresh proposal authorized exactly two `query_index` reads (table names and indexed file count), zero retries, 32 KiB output, and 90 seconds. Its explicit decision rationale recorded the assistant's delegated test role. The run started at 13:13:06 UTC and remained running beyond its time bound, without any model response or tool result. Clicking **Cancel the active turn** did not finish the operation.

**Verified cause:** A one-second native stack sample showed `submit_agent_turn → AgentSession::submit → run_step → chatgpt → access_token → load_vault → secret_load → SecItemCopyMatching`, blocked synchronously in macOS SecurityServer credential decryption. The OpenAI request had not been sent. This is credential access blocking the async task, not demonstrated provider latency. A `tokio::time::timeout` cannot interrupt a synchronous OS call inside the future it is polling.

**Reproduction:** Rebuild the development binary, open the existing subscription-backed session, approve a bounded index-read step, and leave any required OS Keychain authorization unresolved. Observe whether the deadline and Cancel remain responsive. Do not record account tokens or passwords. To diagnose a stuck native process, capture `sample <Thanatology PID> 1 10 -file /tmp/thanatology-agent-hang.sample.txt` and inspect only the function stack around `access_token`/`SecItemCopyMatching`.

**Implemented correction:** Blocking credential reads and writes now run on background workers, retaining their file locks for the full OS operation even if the awaiting task is cancelled. An already-requested cancellation has priority over resumed work. Synthetic tests on a single-thread async runtime verify responsive timeout/cancellation and lock retention until the simulated OS operation ends. Keychain security and stored credentials are unchanged. The user was asked to handle a visible OS prompt directly if present; no password was requested. Native automation explicitly refused access to SecurityAgent, so that OS approval cannot be completed by the assistant.

**Verification:** All 20 authentication tests, 12 focused workflow/cancellation/session tests, and the desktop Rust check passed. The background OS operation itself cannot be cancelled; its credential lock remains held until the OS returns, so concurrent attempts fail with lock contention instead of racing a delayed write. After the development app restarted, the previously hung step was visibly `interrupted` and the workspace was idle.

**Live retest:** A fresh, explicitly approved proposal repeated only the two metadata queries, with a 30-second provider/tool budget. The turn started at 13:24:16 UTC and reported `Provider request exceeded the approved step duration; no response was accepted` at 13:24:51 UTC, returning to idle. Total turn time includes setup and report persistence outside the provider-loop timer. The rendered report automatically updated to revision 36. No model response or tool result was received. A second native stack sample confirmed the credential read still waiting in `SecItemCopyMatching`, now on `tokio::runtime::blocking::task::BlockingTask` under `LockedVault::load`, after the investigative turn had ended. Thus timeout recovery is live-verified; cancellation responsiveness is covered by synthetic tests, not a second live cancellation claim.

## Observations and follow-ups at the first live retest

- **Progress display:** During execution, the Steps card still showed `approved` while the footer showed `THINKING`. Reproduce by approving a slow bounded step and inspecting both displays before it ends. The frontend refreshes the full investigation snapshot after submission finishes; `turn_started` only updates session status. Add a lightweight progress snapshot/event with stale-response protection, avoiding repeated full-workspace index counts. This display issue does not grant an additional approval.
- **Report loading during execution:** Opening the report during the retest showed loading until the turn ended. Code review found no execution-held lock in the snapshot/report read path. Measure IPC and database latency before attributing the delay to a lock; its cause remains unproven.
- **Other credential entry points (code review):** Account listing, API-key settings/catalog lookup and Mistral disconnect still have synchronous credential calls in async desktop commands. Apply the blocking-worker boundary consistently and verify a stalled synthetic store does not prevent their deadlines or unrelated UI work.
- **Refresh cancellation (code review, not observed on this account):** Cancellation after a server rotates a refresh token but before local persistence can discard the replacement token. A bounded, owned refresh/validate/persist transaction should retain its lock and finish storing the result while the cancelled investigation stops. Reproduce with a mock token endpoint that signals rotation, cancel before persistence, and verify the replacement is retained without sending an inference request. Do not induce this failure on a real account.

These are developer follow-ups, not forensic findings. No GitHub issue was published.

## Credential caching follow-up

The user subsequently approved reducing repeated Keychain access. The previous
implementation called `access_token → load_vault → secret_load` before every
model request, even when the stored token remained valid. Account listing also
read the secret vault, and desktop configuration display loaded an API key only
to erase it before returning the configuration.

ChatGPT now reuses valid access tokens in backend memory, scoped by account and
authentication directory. Concurrent callers share credential work. A private
metadata index supplies account display details and a generation marker; cache
checks honor credential updates and disconnects from other processes. Explicit
**Refresh connections** or CLI `--auth refresh` reloads the OS store, while normal
status display does not. Legacy connections can populate their metadata on first
authenticated use. Settings/configuration and remaining desktop credential
wrappers use blocking workers where OS access is required.

The refresh cancellation follow-up above is addressed by an owned credential-only
transaction: cancellation stops the investigation while token validation and
persistence finish. There is no overall cancellation deadline that discards a
received token during validation; individual native HTTP operations remain
bounded. Genuine identity/network validation failure still fails without using
unvalidated credentials and may require reconnection.

The desktop release workflow now accepts optional Developer ID signing
configuration instead of requiring ad-hoc signing. No certificate was provisioned,
no release was built or published, and no local Keychain permissions were changed.
Debug builds may still prompt after rebuilds. See
[credential behavior and migration](account-authentication.md#credential-reads-and-account-details)
and the desktop release documentation for setup. This follow-up uses injected
credential stores and synthetic tokens for validation; it does not establish any
additional forensic finding or demonstrate that the pending OS prompt was resolved.

**Verification:** 98 agent tests passed, including 12 new synthetic cache/index
tests; the final 12 were rerun after the last edits. Fifteen focused desktop tests,
the frontend build, Rust check and native debug build passed. Workflow YAML and
five synthetic signing-configuration cases passed. The initial sandboxed full run
could not bind loopback sockets for five callback tests; the authorized rerun with
localhost access passed. The Tauri bridge later reported a connection but could
not list windows, so this follow-up makes no live cache-use claim.

## Evening MCP inspection: empty provider responses and frontend state

**Observed:** The current Kali workspace was idle after its initial inventory
step was interrupted. The approved scope permitted `query_index` and
`list_partitions`, six calls, one retry per tool, 120 seconds and 65,536 output
bytes. The recorded selectors covered table names, partition metadata, indexed
file count and artifact counts by parser/kind. The turn started at 19:43:04 UTC;
rounds at 19:43:22, 19:43:26 and 19:43:30 recorded zero callable actions and no
visible provider text. At 19:43:30 the runtime interrupted after three responses
without executable progress. There were no evidence-tool results or findings.

**Interpretation:** Unlike the earlier Keychain hang, these provider responses
completed. Existing records do not establish whether the final response omitted
calls already present in stream events or contained only reasoning/empty output.
The error is not evidence that the indexed case data is unavailable.

**Reproduction:** Open evidence 9's agent workspace, inspect the latest inventory
step and its activity entries, and compare the recorded provider rounds with the
empty execution list. Review the persisted report rather than treating the
provider's completed transport status as successful investigation progress.

**Diagnostic change:** An empty ChatGPT completion now stops immediately with
bounded protocol metadata: counts of fixed event/item/content/status categories
and the returned tool-choice mode. It records neither raw responses nor text,
arguments, reasoning, identifiers or credentials. Completed stream-call counts
and final-envelope item counts will distinguish the two suspected failure modes
on the next approved attempt. No automatic reconstruction of streamed calls was
introduced without live evidence. All seven focused provider HTTP tests passed.
The cause of this live failure remains unproven.

**Frontend observations and changes:** The live console reported MUI's warning
that an uncontrolled Accordion changed `defaultExpanded`. Step accordions now
use controlled expansion and retain investigator toggles. A lightweight,
window-authorized `get_agent_progress` command updates investigation state while
running without repeatedly loading the full workspace/index counts. Requests do
not overlap, and stale session/revision responses cannot overwrite newer
progress. In-progress report writes display a saving state. Three snapshot
regression tests, the frontend build, desktop Rust check and native debug build
passed. Live verification is recorded below; running-state polling still awaits
a new approved provider attempt.

The full offline agent suite also passed: 88 library tests and 13 integration
tests (101 total). Ten focused desktop authentication, model-catalog and report
tests passed. Those tests use synthetic data and do not establish successful
authorization or inference with the user's account.

**Automation limit:** Window discovery, DOM inspection and console reads worked.
Native screenshot capture failed, its HTML-canvas fallback timed out, and the
screen-capture fallback was left disabled pending the user's preference. The
development binary was not selectable by the computer-use tool. Subsequently
the MCP bridge stopped listening on port 9223 while Vite remained available on
1420. It later became available again with the app at its home screen, permitting
the tests below. There is no screenshot-based visual verification from this
inspection. The older bridge also reports missing accessibility helpers in a
new auxiliary window, so those checks used live DOM reads and MCP interactions.

**Live frontend retest after reconnect:** Navigated through Cases → Kali Linux
→ Review investigation → Open Exhume Agent. The current report rendered session
`thanatology-9`, revision 47, with 34 headings, seven code blocks and no images.
Clicking **Refresh report** returned the same revision without a report error.
Collapsing the first interrupted step, switching to the report and back to
Steps preserved its collapsed state. No changing-`defaultExpanded` warning was
observed in that retest; the console contained an unrelated Emotion
`:first-child` selector warning. The Case brief had no approved-destinations
editor, retained the external-tools checkbox, and Findings showed its empty
state. No case brief, approval or investigative state was changed for these
checks.

The `get_agent_progress` IPC returned revision 47, matching exported revision
47, in 7 ms. A call from the main window was rejected because another window
owned the session. MCP initially reported a script timeout despite completed
execution; a temporary page-side result marker confirmed the actual result and
was then removed. This verifies the command while idle, not running-state
polling during a provider request. No model discovery or sign-in was triggered
against the existing Keychain backend.

**Additional account frontend review:** Cancelling before sign-in setup returned
its request ID previously reported success too early. Cancellation now waits
for that ID and backend cleanup, and concurrent cleanup shares one promise.
Request/lifecycle guards reject obsolete account lists, cancellation notices
and API-key-deletion results. The empty account option now clears the selection.
Reproduce these races with deferred setup/cancellation responses and navigation
away/reopen, without a real account. Three deferred-promise regressions and the
three snapshot regressions passed, as did the final frontend build. Real browser
sign-in/cancellation and account-model selection remain to be tested when live
authentication testing resumes.

## Credential-storage decision: retain Keychain (2026-10-15)

The user initially requested eliminating Keychain access, then paused
implementation to compare Zed and ChatGPT/Codex. After that comparison, the
user explicitly chose to keep Keychain. This supersedes the proposed private
credential-file or memory-only replacement. No replacement, automatic migration,
credential deletion or forced fresh sign-in was implemented.

Zed's [development documentation](https://zed.dev/docs/development#keychain-access)
confirms that normal releases use the system Keychain, while development builds
bypass it because changing binary identity causes repeated prompts. Read-only
`codesign -d --verbose=2` inspection showed Thanatology's local debug binary was
ad-hoc/linker signed with no Team Identifier; installed Zed had a Team Identifier
and signing requirements. Development identity is therefore a candidate cause,
not a proven explanation of every Thanatology prompt. OpenAI's
[authentication documentation](https://learn.chatgpt.com/docs/auth#credential-storage)
describes configurable Codex credential storage; the exact installed ChatGPT
desktop backend was not established by this comparison.

The user subsequently resumed implementation and live testing. The work below
limits automatic Keychain access while retaining the existing cache and
blocking-worker safeguards. No development-only file backend was selected or
implemented. A retained Keychain backend cannot promise that macOS will never
request authorization.

## Resumed baseline and completed-stream omission (2026-10-15)

**Observation:** At 11:16:44–11:17:06 Europe/Amsterdam, a new explicitly approved
workflow-test step failed before any evidence tool executed. The configured
OpenAI subscription model was `gpt-6.1-sol`. The proposal allowed only
`query_index`, two exact metadata queries, two calls, zero retries, 30 seconds
and 32,768 output bytes. The approval rationale identified the assistant's
delegated testing role rather than attributing the decision to the investigator.

The error's bounded protocol counts showed one `response.output_item.added`,
one `response.output_item.done` containing a completed function call, 23 argument
deltas, one argument-done event and one successful `response.completed`.
The final output array was empty and tool choice was `required`. The previous
adapter discarded completed items from the stream and inspected only that empty
final array. This establishes the omission as the cause of this attempt's error;
it does not establish the cause of every earlier empty response.

**Interpretation and fix:** Preserve whole completed stream items, require a
successful final envelope, validate item status/identity/index continuity, and
reject duplicate or conflicting data before normal tool validation. Never
execute text or argument deltas. Preserve reasoning items for full replay.
A populated final output must agree with streamed completed items and is used
only once. Explicit non-completed item statuses are rejected in either path.
An independent review found no blocking fallback defect and identified the
additional final-item-status check, which is now covered by a regression.

**Reproduction:** Open evidence 9 → Exhume Agent → Steps → Propose custom step.
Use the following exact `query_index.sql` selectors:

```sql
SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name
SELECT COUNT(*) AS indexed_files FROM system_files
```

Enter the bounds above, require a checkpoint after the two reads or the first
error, and approve the displayed proposal with a workflow-test rationale. Inspect
Activity, executions and Report. A successful transport with no execution is
not an investigation result. Each retest needs a fresh approval; the interrupted
approval cannot be reused. The post-fix live outcome is recorded below.

**Keychain behavior:** Automatic ChatGPT model discovery now uses only a fresh
in-memory access token and local generation metadata. Cache misses, expiration,
mutation or a busy transaction yield an explicit credential-access action.
Approved inference retains native credential loading and refresh. Successful
explicit account refresh and persisted browser sign-in seed the cache. Synthetic
tests assert zero credential reads, writes and refreshes for automatic misses.
Mistral and stored API-key discovery also require explicit access.

**Signing limit:** The local read-only signing check found zero valid code-signing
identities. A signed-debug helper and guide were added and seven synthetic tests
passed; no certificate was created/imported, no credential ACL was changed, and
no certificate-signed build was produced. The helper verifies the expected team,
bundle identifier and certificate-based designated requirement. The guide notes
that bundled LeechCore libraries still need separate hardened-runtime validation.
Stable-identity Keychain behavior remains unverified until an existing Developer
ID Application certificate is available.

**Validation so far:** All 99 core library tests and 13 integration tests passed
offline, including provider reconstruction and cache regressions. The desktop
native debug build passed. The credential model UI passed its frontend build,
six lifecycle/progress regressions and 11 desktop agent tests. A follow-up review
identified the legacy configuration migration path, addressed separately below.

Native MCP screenshot capture succeeded for the main case window at 11:38 local
without OS screen-sharing fallback. Earlier screenshot failures were therefore
not a persistent inability to capture every window. No pixel verification of the
updated Settings or report is implied by that case-list capture.

## Settings migration and concurrent discovery follow-up

Review found that an older plaintext `api_key` in `ai_config.json` was still
migrated during passive configuration loading. That could open Keychain when
Settings mounted, despite the new model-catalog gate. Display reads now return
redacted configuration and a migration-needed boolean without migrating it.
Explicit Save/model loading secures the retained key first and replaces the file
atomically; failures preserve the original. Model loading checks the original
provider, authentication mode and normalized endpoint before accessing a key.
An empty-key Save cannot silently reassign a pending legacy key to another
endpoint. Unreadable settings surface an error and block Save. Removing saved
keys is disabled while legacy migration is pending, avoiding apparent deletion
followed by automatic restoration from the original file.

Reproduce with a temporary synthetic legacy configuration: passive load must
return an empty key and a migration flag without calling injected credential
functions; failing the injected secure save must leave the file byte-for-byte
unchanged. The focused desktop config/specialist suite passed nine tests and the
desktop agent suite passed 11 tests. No real legacy key was planted or migrated
for this test.

At approximately 11:48 local, the live Settings window showed the explicit
Keychain-access action, then successfully loaded seven account models after the
button was clicked. The existing `gpt-6.1-sol` selection remained intact. Typing
`6.1` filtered the dropdown to that model, and selecting it required no manual
identifier entry. Native capture visually verified the Settings layout.

Reopening Settings exposed a second defect: React StrictMode could start two
identical automatic catalog requests. The first held the cache mutex during its
generation check; the second returned the busy-cache credential marker. The
frontend discarded the first success as obsolete and displayed the second
error. Code review confirmed that index publication was correct and identified
this race. Automatic identical in-flight requests now share a promise; explicit
credential requests bypass it, changed connections/revisions remain separate,
and settled results are neither cached nor retried by this helper. Five
synthetic coalescing regressions passed. A cold cache also keeps the saved model
visible in helper text instead of making the preserved selection appear lost.

**Post-fix live retest:** After the final native edits, explicit catalog loading
succeeded again. Navigating Cases → Settings then automatically loaded the
catalog and displayed `GPT-6.1-Sol`, with no credential-access-required alert.
A page-local marker and unchanged navigation time confirmed the same process
remained active during that retest. This validates warm Settings reuse; it is
not a certificate-signed restart test or a fresh browser-login test. All 14
frontend regressions, 20 focused desktop tests, the frontend build and Rust check
passed after integration. The final cache refinement separately passed all 16
cache regressions, including persistence while the cache mutex is held and a
concurrent disconnect before seeding.

## Successful bounded run and rendered report (2026-10-15)

At 11:56:07–11:56:56 Europe/Amsterdam, the updated app completed a fresh approved
two-query workflow test. The selectors were unchanged from the baseline; the
duration was explicitly increased to 90 seconds to allow both calls and the
checkpoint. Calls remained limited to two, retries to zero, and output to 32,768
bytes. No additional investigative path was approved.

| Execution | Observed result | Scope |
| --- | --- | --- |
| `execution-58-1` | Success; 16 table names, no truncation/error | Exact table-name query above |
| `execution-62-2` | Success; `indexed_files = 461607`, no truncation/error | Exact global `system_files` count above |

The UI showed the step as **running** and updated Activity with both results
while the provider was still preparing its checkpoint. Provider round three
attempted a checkpoint with a source locator that was not observed in the cited
execution; validation rejected it. Round four corrected the references to actual
execution IDs. The saved checkpoint explicitly records that rejection and the
absence of case-specific analysis. No extra evidence reads occurred during the
correction. The proposed next inventory remained **pending approval**, and the
workspace ended in **APPROVAL REQUIRED**.

The two observations remain **provisional**. The Findings UI displays their
execution IDs, excerpts, exact reproduction commands, and Accept/Reject/Needs
corroboration controls. No finding was accepted during this test. The count is
an index-wide row count, not proof of 461,607 files in the acquisition; the query
has no `evidence_id` filter and the table includes indexed entries.

**Report verification:** The persisted Markdown and in-app rendering both showed
session `thanatology-9`, revision **71**. Findings contain exact tool parameters
and execution IDs; the execution index records Success, toolkit version and
full-result SHA-256 hashes. The rendered document had 16 code blocks, semantic
headings and no images. **Refresh report** retained revision 71 without a report
error. Native screenshots verified the running-step view and rendered report;
the OS screen-sharing fallback remained disabled. The console still reports the
existing Emotion `:first-child` server-rendering warning, unrelated to this run.

Reproduce the post-fix run through the custom-step procedure above with a fresh
90-second approval. Inspect Activity before the run ends, then Findings and
Report & decisions. Do not approve the generated next step as part of this
test. The saved report is at:

```text
/Users/fguyard/Library/Application Support/com.thanatology.app/evidences/9.extracted/investigations/thanatology-9-investigation.md
```

## Investigation coverage and remaining validation

Final validation passed **113 core tests** (100 library and 13 integration),
**20 focused desktop tests**, **14 frontend regressions** and **seven synthetic
signing checks**. Frontend build, desktop Rust check and diff whitespace checks
passed. The live desktop run above exercised the rebuilt native provider path.

Two metadata executions and two provisional observations are now recorded. No
exploitation method or system modification has been established, and no case
resolution is claimed. The available image is the suspected attacker's system;
the potentially affected company endpoint was not supplied. Source identity
uses path, segment size and modification time without a recorded full acquisition
hash. The next evidence-specific inventory is proposed for investigator review.

Live model selection, warm cache reuse, approved inference, checkpoint validation
and rendered Markdown succeeded. A fresh browser authorization, real token
expiry/rotation, denial of an OS prompt, and stable Developer ID signing across
rebuilds were not exercised in this follow-up. Synthetic tests cover the relevant
failure/cancellation paths; they do not replace those platform/account checks.
No certificate was available for the signed-build test. The user's Keychain
decision requires no storage migration or forced reconnection of existing
subscription accounts.
