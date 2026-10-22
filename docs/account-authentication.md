# Provider account authentication

Exhume supports an explicit `api_key` or `subscription` authentication mode. The latter means account-based access; it does not promise unlimited usage or that every provider bills exclusively against a consumer subscription. The configured provider, account, destination and actual response model are recorded with each successful model response. Failure never selects another account, provider or billing mode.

Credentials stay out of serialized `AgentConfig`, debug output, reports and model inputs. Exhume-managed credentials use macOS Keychain, Linux Secret Service (`secret-tool` with an unlocked desktop collection), or Windows per-user DPAPI encrypted storage. If secure storage is unavailable, connection fails instead of writing plaintext credentials. Native runtime credentials remain owned by their provider's unmodified runtime.

The 2026-10-15 product decision retains Keychain on macOS. The proposed
replacement with a private credential file or memory-only sign-in was not
implemented; existing connections require no migration because of this decision.
The follow-up limits automatic credential access and provides an opt-in signed
development build for testing stable application identity.

### Credential reads and account details

ChatGPT access tokens are cached in backend process memory, separately for each
account and authentication directory. A valid token is reused for subsequent
model requests and model discovery. During approved inference, near expiration the runtime reads the
protected credentials, refreshes the token and persists any rotation before
using it. Concurrent requests share the credential operation. Credential updates
and disconnects invalidate cached tokens; cache entries are never written to
application settings, reports or the browser renderer.

The private authentication directory also contains `accounts-index.json`, with
account display metadata and a generation marker, but no access, refresh or ID
tokens or API keys. Ordinary account-status display reads this file without
opening Keychain. Credential writes change its generation so other processes
stop using stale cache entries. Missing or invalid generation state cannot be
used to authorize continued use of an existing cached token.

For connections saved by an older build, use **Refresh connections** once to
load their details from the OS credential store. A saved account selection is
preserved even before those details are available. First authenticated use can
also populate the index. The CLI equivalent is:

```sh
exhume-agent --provider openai --auth refresh
```

For OpenAI and Mistral, `--auth status` reads metadata only; it is not a live provider validation.
Explicit refresh may request OS authorization and seeds the in-memory cache
with valid access tokens. Successful browser sign-in seeds that cache only after
native credential persistence succeeds. Automatic ChatGPT model discovery uses
only an existing valid cache entry and the local generation marker. A cold,
expired, invalidated or busy cache returns `credential_access_required` without
opening or renewing credentials. Settings offers **Allow Keychain access and
load models** on macOS; failed access requires another deliberate retry. Mistral
discovery and discovery using a stored API key also require an explicit action.

Normal configuration display redacts legacy embedded keys without accessing
Keychain or modifying the saved file. Settings marks a pending migration.
An explicit save or credential-bearing operation secures the legacy key before
atomically replacing the original configuration. Failed migration leaves the
original file intact; unreadable settings produce a visible error and block
Save. These controls concern automatic Settings reads and model discovery.
Credential-bearing actions, including opening an API-key agent workspace, may
still require native authorization.

Credential operations run outside async runtime workers. Cancelling an
investigation stops inference; a credential refresh already in progress may
finish validating and saving its rotated tokens to avoid losing the account
connection. An OS prompt itself cannot be cancelled by dropping the task, and
its credential lock remains held until the OS operation ends.

The default credential-store identity is preserved. Nondefault
`EXHUME_AUTH_DIR` directories now use separate OS credential identities as well
as separate locks and caches. Older macOS/Linux builds shared one OS vault even
when that directory differed; users of those custom directories must explicitly
reconnect in their selected directory. Existing default-directory credentials
are not moved or deleted.

Caching reduces OS reads during a running process. It cannot remove an initial
Keychain prompt after launch, an expired-token refresh or a changed app identity.
For stable macOS distribution signing, see the desktop
[release configuration](../../../../thanatology/docs/updater.md#stable-macos-application-identity).
For a local certificate-signed debug bundle, see the
[development signing guide](../../../../thanatology/docs/macos-development-signing.md).
It requires an existing Developer ID Application identity; it does not create
certificates, change Keychain permissions or publish the application.

## ChatGPT

In the desktop app:

1. Open **Settings → AI Copilot Configuration** and select **OpenAI (Cloud)**.
2. Set **Authentication** to **ChatGPT subscription (browser sign-in)**.
3. Click **Sign in with ChatGPT**. Exhume opens the operating system's default browser; complete sign-in and authorize subscription access there.
4. Return to Thanatology. The connected account's model catalog loads automatically. Select a model from the searchable **Model** dropdown; a model ID never needs to be typed manually.
5. Click **Save Settings**.

The same browser flow is available from the CLI:

```sh
exhume-agent --provider openai --auth login
exhume-agent --provider openai --auth status
exhume-agent --provider openai --auth models --account-id ACCOUNT_ID
```

Select one of the account's returned model IDs and save the account selection. Start investigations with explicit subscription mode and that account ID. `AGENT_AUTH_MODE=subscription` and `AGENT_ACCOUNT_ID` are the equivalent environment settings. `AGENT_MODEL` selects the model. Login, status and model discovery do not require evidence.

The desktop displays authorization progress and supports **Cancel sign-in**. Closing the settings view or its window cancels pending work; late responses cannot replace another selected account. Browser-launch failures release the callback listener. The callback accepts fragmented browser requests within fixed size/time limits and ignores unrelated local requests without accepting their authorization data. If authorization has already completed when cancellation arrives, refresh connections to inspect the result.

ChatGPT catalogs refresh automatically when the selected account changes or
Settings reopens if a valid token is already cached. Otherwise use the explicit
credential-access button. **Refresh models** retries a failed catalog request.
The provider's ordering and display names are preserved, and selection stores
its actual model identifier. Empty catalogs and unavailable saved models are
visible; Exhume does not silently substitute another model. For Mistral, API-key
and local providers, enter/select the connection, click the model-loading
button, and choose from its returned catalog. Discovery sends no case content.
A stored API key is not reused for an unsaved different provider or endpoint.

The app uses the official public-client Sign in with ChatGPT flow: a loopback browser callback, fresh state/nonce/PKCE per attempt, dynamic registration for new accounts, issued client IDs for returning accounts, verified RS256 ID-token signatures, issuer/audience/expiry/nonce checks, and granted plan-usage scopes. Each account/workspace registration remains separate. The stable host ID and validated account records are protected in the credential store. New host IDs use the documented `urn:uuid:<UUIDv4>` format and are persisted once per host. Refresh-token rotation is serialized across processes. A failed reauthorization preserves the previous connection.

If an older build failed in the browser with `invalid_authorize_request` for `ext_agent_host_id`, rebuild/restart the native app and click **Sign in with ChatGPT** again. The new attempt automatically replaces the unsupported legacy `exhume-...` host ID under the credential-store lock, preserving all account registrations and credentials. Existing supported IDs remain unchanged. Close the old error tab and use the newly opened authorization page; refreshing its old URL cannot apply the fix. Credential deletion is unnecessary.

Only `https://api.openai.com/v1` receives subscription access tokens. Requests use Responses with `store:false`, `stream:true`, full history and namespaced client-side functions. The transport requires a final `response.completed` with successful status. Text deltas, a terminated stream, invalid tool arguments and failed final events are not accepted as successful results.

Some successful streams deliver complete `response.output_item.done` records
but an empty final output array. The adapter retains those complete items in
output-index order, including reasoning needed for replay. It accepts them only
after successful final completion and rejects incomplete, duplicate, conflicting
or gapped output. A populated final array must agree with completed stream
items; the two are never concatenated. Explicit unsuccessful item statuses and
duplicate tool call IDs are rejected. This follows the item-completion contract
in the official [streaming event reference](https://developers.openai.com/api/reference/resources/responses/streaming-events).

Sign-out attempts remote refresh-token revocation and clears the local connection. If remote revocation cannot be confirmed, Exhume reports that distinction; review app access in ChatGPT Settings. API keys are never used as a quota fallback. ChatGPT subscription access does not include the transcription API; select a supported API-key configuration if transcription is needed and approve its investigative step.

Official references: [host identifier formats](https://developers.openai.com/siwc/token-sharing-open-source#a-client-vs-an-agent-host), [registration](https://developers.openai.com/siwc/token-sharing-open-source/sign-in), [sessions](https://developers.openai.com/siwc/token-sharing-open-source/profiles-and-sessions), [inference](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference), [capability limits](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations).

## Mistral

Mistral's official Vibe browser login provisions an ordinary Mistral API credential. Exhume uses that documented credential with the public Mistral API, so the investigator does not need to manually create or paste a key. Included API usage and any enabled pay-as-you-go allowance belong to the Mistral account. Exhume cannot independently identify the plan or guarantee that the provider will not charge enabled pay-as-you-go usage.

Install the official `vibe-acp` runtime, then run:

```sh
exhume-agent --provider mistral --auth login
```

This invokes official onboarding in an Exhume-specific `VIBE_HOME`. The explicit connection action reads only that profile's documented `.env` `MISTRAL_API_KEY`, validates it through `/v1/models`, and imports it into Exhume's OS-protected credential store. It does not search other Vibe profiles, collect account passwords, or copy browser/session tokens. A label identifies the connection; it is an investigator-entered label, not verified account identity.

In desktop settings choose **Mistral → Provider account**, refresh the connections and select the connection. Its model catalog loads automatically into the model selector. The separate **Connect credential from completed Vibe sign-in** button explicitly imports a completed native setup when necessary. Inference then goes directly to `https://api.mistral.ai/v1/chat/completions`; Vibe does not run tools, hooks or agents for the investigation.

Disconnect removes Exhume's imported credential. Vibe's own copy and the provider-side credential are not revoked by that action. Revoke unused credentials in Mistral Studio and manage the original native profile with Vibe. Credential expiry/revocation pauses inference; reconnect explicitly after another native login.

Official references: [browser login and documented credential file](https://docs.mistral.ai/vibe/code/cli/api-keys-profiles), [VIBE_HOME](https://docs.mistral.ai/vibe/code/cli/configuration), [subscription allowances](https://docs.mistral.ai/admin/billing-usage/subscriptions).

### Why inference does not delegate to Vibe ACP

ACP currently does not attest the effective account, destination and tool configuration after organization-managed overrides. Enabling a native ACP investigation without those facts could bypass an approved case scope. The direct API transport avoids that uncertainty.

If native ACP delegation is needed later, propose this case-neutral GitHub issue for investigator review; do not publish automatically:

**Title:** Expose effective execution policy and account provenance over Vibe ACP

**Developer brief:** Add a versioned, read-only capability response containing effective provider origin, opaque account identifier, selected model, native tool allowlist, hook/MCP discovery state and configuration origin after managed overrides. Offer a model-only session profile with all native tools/hooks disabled. Changing that state during a session must invalidate the session before further inference or actions.

**Acceptance criteria:** An ACP client can refuse a session before sending evidence if the approved account or destination differs, any native execution capability is active, configuration cannot be verified, or policy changes. Cover managed overrides, user plugins, tools enabled by default, authentication changes, denial of permission callbacks and truncated/failed final results with synthetic fixtures. No real case data is required.

## Claude

Install the official unmodified Claude Code binary and choose **Claude → Provider account → Connect Claude account only**. If the native login requires a terminal, run:

```sh
exhume-agent --provider claude --auth login
```

Exhume uses a dedicated `CLAUDE_CONFIG_DIR`, checks the native `auth status` result and requires a `claude.ai` identity before subscription inference. Select the returned account connection; a different current native identity pauses inference. Exhume neither implements Claude.ai OAuth nor extracts its credentials. Other native login methods remain available in the official runtime; they are separate from Exhume's subscription mode.

**Claude subscription inference is currently unavailable.** Connecting or saving a native account does not enable investigation requests. Explicit native login, status and logout are supported; the separately selected Claude API-key transport remains available. Exhume stops before launching native inference and never silently changes authentication mode.

The official runtime preserves managed startup hooks and organization plugins even when a host passes `disableAllHooks:true`, `--safe-mode`, empty tools and restricted settings. Initialization/final event checks happen after startup and cannot prevent those side effects. Exhume checks known local managed JSON/drop-ins and macOS preference documents for incompatible settings, but this is insufficient to attest server-managed and other OS policy. It therefore cannot safely implement the shared-tool approval boundary through the current native interface.

The reserved logical destination is `native://claude-code`: the native runtime owns routing, so Exhume does not claim a public API endpoint was used. Cases requiring a verified network endpoint should use an explicitly approved API transport. No native inference is sent to that logical destination in this release.

The installed runtime owns authentication/refresh/logout. Official references: [authentication](https://code.claude.com/docs/en/authentication), [CLI controls](https://code.claude.com/docs/en/cli-reference), [managed-hook limits](https://code.claude.com/docs/en/settings-reference#disableallhooks), [managed policy precedence](https://code.claude.com/docs/en/managed-settings), [third-party hosting conditions](https://code.claude.com/docs/en/legal-and-compliance).

### Suggested upstream issue

Review and open this case-neutral issue in the official Claude Code repository if native subscription investigations are needed. Exhume does not publish it automatically.

**Title:** Provide a native model-only account session with pre-launch execution-policy attestation

**Developer brief:** Add a supported embedding mode that authenticates through the native account while disabling all tools, startup/session hooks, managed plugins/mods, MCP servers and credential/policy helpers before accepting a prompt. Return a versioned capability response with effective account, routing, model and execution controls after every managed-policy source is resolved. A host must be able to reject the session before evidence or startup execution, and policy changes must invalidate the session.

**Acceptance criteria:** Synthetic fixtures cover managed hooks, force-enabled plugins, policy/credential helpers, remote policy refresh, macOS preferences and Windows registry policy. None executes before host acceptance. A successful final result reports actual model/account provenance; unsupported versions, policy changes, tool attempts and truncated/failed events fail closed. Existing investigator approvals remain owned by Exhume.

## Bounded media interpretation

`describe_image` and `transcribe_audio` replace automatic specialist loops in investigation sessions. Each call identifies one indexed source, verifies evidence ownership and actual size before extraction (maximum 20 MiB), hashes the extracted bytes, and returns interpretation with source path/hash and service provenance. HTTP errors, malformed JSON, incomplete image completions and oversized responses fail the tool. An absent reported model remains `null` with an explicit limitation; a requested model is never presented as actual provenance.

Image requests use the explicitly configured OpenAI-compatible model/endpoint, or the selected Copilot image service. Audio uses the explicit audio endpoint, or the public OpenAI transcription endpoint only when the configured API provider already is public OpenAI. Custom audio endpoints must share the configured credential origin. Copilot audio stays on its configured service. Saving a desktop brief records supported media destinations from the session's AI configuration, including the transcription model; the CLI retains explicit destination configuration. Every media tool still requires an approved investigative step, and no provider or subscription fallback occurs. Account-mode media adapters are unavailable in this release. Review descriptions and transcripts against the original source before treating them as findings.

## Verification

Unit tests cover UUIDv4 host-ID generation, stable reuse, legacy repair without account-data loss, initial/returning authorization parameters, callback state/client replacement/duplicate rejection, identity and permission checks, literal-only Mistral imports, refresh-token replacement, pinned authentication origins, failed/truncated provider responses, full Responses replay, native execution-policy rejection, media source ownership and size bounds, and incomplete media responses. Transport and credential parsing tests use synthetic values, without account login or paid model requests.

The caching follow-up passed 98 agent tests (85 library and 13 integration),
including 12 new injected-store/cache tests. They verify one read for concurrent
valid-token requests, one refresh at expiry, account/directory isolation,
credential-generation invalidation using independent cache/store instances,
metadata without secrets, explicit refresh, failed-write recovery, and caller
cancellation before and after a rotated response through persistence. The final
cache/store tests passed again after the last implementation edits. Desktop
validation passed 15 focused auth/catalog/report/config tests, the frontend build,
Rust check and native debug build. Workflow YAML and five synthetic signing
configuration cases passed. Developer ID signing and live account cache reuse
were not exercised; no real credential store was accessed for these tests.

The 2026-10-15 follow-up passed 113 core tests, 20 focused desktop tests, 14
frontend regressions, seven synthetic signing checks, the frontend build and
desktop Rust check. Live testing with the existing OpenAI subscription account
verified explicit model discovery, model filtering/selection, warm Settings
reuse, two approved index reads and a validated checkpoint rendered at report
revision 71. See the [live audit](kali-live-agent-audit.md) for reproduction and
the rejected source locator corrected during that run.

A fresh browser login, real refresh-token expiry/rotation, OS-prompt denial and
certificate-signed rebuild remain untested in this follow-up. Windows DPAPI and
Linux Secret Service cannot be exercised on the macOS host. Provider preview
protocols and native runtime flags can change; unsupported behavior returns a
visible error rather than lowering the controls.
