//! Explicit account sign-in. Secrets never enter AgentConfig, reports or model prompts.
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use fs2::FileExt;
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

mod cache;
mod store;
use store::{CredentialStore, LockedVault};

const SERVICE: &str = "org.forensicxlab.exhume-agent";
const VAULT_ACCOUNT: &str = "chatgpt-accounts-v1";
const ISSUER: &str = "https://auth.openai.com";
const TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
const RESOURCE: &str = "https://api.openai.com/v1";
const REQUIRED_SCOPES: [&str; 2] = ["chatgpt.tokens.use.direct", "resource.invoke"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    ApiKey,
    Subscription,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountStatus {
    pub provider: String,
    pub account_id: String,
    pub email: Option<String>,
    pub subject: String,
    pub connected: bool,
    pub expires_at: Option<u64>,
    pub plan_usage_enabled: bool,
    pub usage_source: String,
}

// Deliberately no Debug: even an error-path log must not reveal these fields.
#[derive(Clone, Serialize, Deserialize)]
struct Credentials {
    access_token: String,
    refresh_token: String,
    id_token: String,
    expires_at: u64,
    scopes: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Registration {
    client_id: String,
    subject: String,
    email: Option<String>,
    credentials: Option<Credentials>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Vault {
    host_id: String,
    accounts: BTreeMap<String, Registration>,
    #[serde(default)]
    mistral_accounts: BTreeMap<String, MistralRegistration>,
    #[serde(default)]
    api_keys: BTreeMap<String, String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct MistralRegistration {
    label: String,
    api_key: Option<String>,
}

pub fn auth_directory() -> Result<PathBuf> {
    if let Some(root) = std::env::var_os("EXHUME_AUTH_DIR") {
        return Ok(PathBuf::from(root));
    }
    let root = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .ok_or_else(|| anyhow!("Cannot locate account configuration directory"))?;
    Ok(PathBuf::from(root).join(".config/exhume-agent"))
}

fn random_secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("Secure randomness unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn new_host_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("Secure randomness unavailable"))?;
    // SIWC accepts a UUIDv4 URN, not an application-prefixed opaque string.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

/// Caller must persist a changed ID under the vault lock before authorization.
fn ensure_host_id(vault: &mut Vault) -> Result<bool> {
    // Repair the unsupported format previously saved even by failed sign-ins.
    // Keep existing supported IDs and all account registrations/credentials intact.
    if vault.host_id.is_empty() || vault.host_id.starts_with("exhume-") {
        vault.host_id = new_host_id()?;
        return Ok(true);
    }
    Ok(false)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn http_client() -> Result<reqwest::Client> {
    // Never forward authorization to a redirect destination. No hidden request retries.
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()?)
}

/// OS credential APIs may wait for a user prompt or an unavailable system service.
/// Keep them off runtime workers so callers can still time out or cancel.
async fn credential_store_task<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| anyhow!("The OS credential-store worker could not complete"))?
}

fn vault_lock_sync(dir: &std::path::Path) -> Result<File> {
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(dir.join("accounts.lock"))?;
    // Fail fast rather than race refresh-token rotation with another process.
    file.try_lock_exclusive()
        .context("Another process is updating account credentials; retry after it finishes")?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn secret_load(_directory: &std::path::Path, account: &str) -> Result<Option<Vec<u8>>> {
    match security_framework::passwords::get_generic_password(SERVICE, account) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.code() == -25300 => Ok(None),
        Err(_) => bail!("Cannot read the OS credential store; unlock Keychain and retry"),
    }
}
#[cfg(target_os = "macos")]
fn secret_save(_directory: &std::path::Path, account: &str, value: &[u8]) -> Result<()> {
    security_framework::passwords::set_generic_password(SERVICE, account, value)
        .map_err(|_| anyhow!("Cannot save account credentials in the OS credential store"))
}
#[cfg(target_os = "linux")]
fn secret_load(_directory: &std::path::Path, account: &str) -> Result<Option<Vec<u8>>> {
    let output = std::process::Command::new("secret-tool")
        .args(["lookup", "service", SERVICE, "account", account])
        .output()
        .context("Install secret-tool and enable an unlocked Secret Service credential store")?;
    if output.status.success() {
        Ok(Some(output.stdout))
    } else if output.status.code() == Some(1) && output.stderr.is_empty() {
        Ok(None)
    } else {
        bail!("Cannot read the OS Secret Service credential store")
    }
}
#[cfg(target_os = "linux")]
fn secret_save(_directory: &std::path::Path, account: &str, value: &[u8]) -> Result<()> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let mut child = Command::new("secret-tool")
        .args([
            "store",
            "--label=Exhume ChatGPT accounts",
            "service",
            SERVICE,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Cannot open Secret Service credential store")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Credential store input unavailable"))?
        .write_all(value)?;
    if !child.wait()?.success() {
        bail!("Cannot save account credentials in Secret Service");
    }
    Ok(())
}
#[cfg(target_os = "windows")]
fn windows_protect(value: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };
    let length =
        u32::try_from(value.len()).map_err(|_| anyhow!("Credential record is too large"))?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: length,
        pbData: value.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // DPAPI binds encryption to the current Windows user. No machine-wide flag is set.
    // Input memory outlives the FFI call; output is OS-allocated and freed with LocalFree.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        bail!("Windows could not protect or unlock account credentials for this user");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}
#[cfg(target_os = "windows")]
fn secret_load(directory: &std::path::Path, _account: &str) -> Result<Option<Vec<u8>>> {
    let path = directory.join("credentials.dpapi");
    match std::fs::read(path) {
        Ok(value) if value.len() <= 16 * 1024 * 1024 => Ok(Some(windows_protect(&value, false)?)),
        Ok(_) => bail!("Encrypted credential record exceeds its limit"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => bail!("Cannot read Windows-protected credential storage"),
    }
}
#[cfg(target_os = "windows")]
fn secret_save(dir: &std::path::Path, _account: &str, value: &[u8]) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(&dir)?;
    let encrypted = windows_protect(value, true)?;
    let mut file = tempfile::NamedTempFile::new_in(&dir)?;
    file.write_all(&encrypted)?;
    file.as_file().sync_all()?;
    file.persist(dir.join("credentials.dpapi"))
        .map_err(|_| anyhow!("Cannot atomically save Windows-protected credential storage"))?;
    Ok(())
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn secret_load(_directory: &std::path::Path, _account: &str) -> Result<Option<Vec<u8>>> {
    bail!("OS-protected subscription credential storage is unavailable on this platform")
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn secret_save(_directory: &std::path::Path, _account: &str, _: &[u8]) -> Result<()> {
    bail!("Subscription credential storage is unavailable on this platform")
}
/// Desktop settings store only the profile label in JSON; API keys live in the OS store.
pub fn save_api_key(profile: &str, key: &str) -> Result<()> {
    if profile.trim().is_empty() || key.trim().is_empty() {
        bail!("Credential profile and API key are required");
    }
    let mut stored = CredentialStore::native()?.load_locked()?;
    stored.vault.api_keys.insert(profile.into(), key.into());
    stored.save_sync()
}
pub fn load_api_key(profile: &str) -> Result<Option<String>> {
    Ok(CredentialStore::native()?
        .load_locked()?
        .vault
        .api_keys
        .get(profile)
        .cloned())
}
pub fn delete_api_key(profile: &str) -> Result<()> {
    let mut stored = CredentialStore::native()?.load_locked()?;
    stored.vault.api_keys.remove(profile);
    stored.save_sync()
}

pub fn account_status() -> Result<Vec<AccountStatus>> {
    CredentialStore::native()?.account_status()
}

/// Explicit user action for legacy credentials or recovery; ordinary status never opens Keychain.
pub async fn refresh_account_status() -> Result<Vec<AccountStatus>> {
    cache::refresh_account_status(CredentialStore::native()?).await
}

/// Stable marker for automatic discovery that needs an explicit credential action.
pub const CREDENTIAL_ACCESS_REQUIRED: &str = "credential_access_required";

fn credential_access_required() -> anyhow::Error {
    anyhow!("{CREDENTIAL_ACCESS_REQUIRED}: Allow credential access to load or renew this account's credentials; automatic model discovery does not open the OS credential store")
}

fn vault_account_status(vault: &Vault) -> Vec<AccountStatus> {
    let mut result: Vec<_> = vault
        .accounts
        .iter()
        .map(|(id, r)| {
            let c = r.credentials.as_ref();
            AccountStatus {
                provider: "openai".into(),
                account_id: id.clone(),
                email: r.email.clone(),
                subject: r.subject.clone(),
                connected: c.is_some(),
                expires_at: c.map(|v| v.expires_at),
                plan_usage_enabled: c.is_some_and(|v| has_plan_scope(&v.scopes)),
                usage_source: "chatgpt_plan".into(),
            }
        })
        .collect();
    result.extend(vault.mistral_accounts.iter().map(|(id, r)| AccountStatus {
        provider: "mistral".into(),
        account_id: id.clone(),
        email: None,
        subject: r.label.clone(),
        connected: r.api_key.is_some(),
        expires_at: None,
        plan_usage_enabled: false,
        usage_source: "mistral_account_api_allowance_or_payg".into(),
    }));
    result
}
fn has_plan_scope(scopes: &[String]) -> bool {
    REQUIRED_SCOPES
        .iter()
        .all(|needed| scopes.iter().any(|v| v == needed))
}

pub struct PendingSignIn {
    /// Open only in the system browser. Do not persist this temporary URL.
    pub authorization_url: String,
    listener: TcpListener,
    redirect_uri: String,
    state: String,
    nonce: String,
    verifier: String,
    selected: Option<(String, Registration)>,
}

pub async fn begin_chatgpt_sign_in(account_id: Option<&str>) -> Result<PendingSignIn> {
    let mut stored = LockedVault::load().await?;
    let changed = ensure_host_id(&mut stored.vault)?;
    let selected = account_id
        .map(|id| {
            stored
                .vault
                .accounts
                .get(id)
                .cloned()
                .map(|r| (id.to_string(), r))
                .ok_or_else(|| anyhow!("Unknown account registration"))
        })
        .transpose()?;
    let host_id = stored.vault.host_id.clone();
    if changed {
        stored.save().await?;
    } else {
        drop(stored);
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/auth/callback",
        listener.local_addr()?.port()
    );
    let state = random_secret()?;
    let nonce = random_secret()?;
    let verifier = random_secret()?;
    let authorization_url = chatgpt_authorization_url(
        &host_id,
        selected.as_ref().map(|(_, registration)| registration),
        &redirect_uri,
        &state,
        &nonce,
        &verifier,
    )?;
    Ok(PendingSignIn {
        authorization_url,
        listener,
        redirect_uri,
        state,
        nonce,
        verifier,
        selected,
    })
}

fn chatgpt_authorization_url(
    host_id: &str,
    registration: Option<&Registration>,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<String> {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let client_id = registration
        .map(|r| r.client_id.as_str())
        .unwrap_or("dynamic_agent_client");
    let mut url = reqwest::Url::parse("https://auth.openai.com/api/accounts/authorize")?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("ext_agent_host_id", host_id),
        ("response_type", "code"),
        ("redirect_uri", redirect_uri),
        (
            "scope",
            "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
        ),
        ("resource", RESOURCE),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge_method", "S256"),
        ("code_challenge", &challenge),
    ]);
    if registration.is_none() {
        url.query_pairs_mut()
            .append_pair("agent_name_hint", "Exhume Agent");
    }
    // Account selection remains explicit; omit retained identity-token hints from URLs.
    Ok(url.into())
}

#[derive(Debug)]
struct Callback {
    code: String,
    client_id: String,
}
fn callback_parameters(target: &str) -> Result<BTreeMap<String, String>> {
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}"))?;
    if url.path() != "/auth/callback" {
        bail!("Unexpected callback path");
    }
    let mut params = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        if params.insert(k.to_string(), v.to_string()).is_some() {
            bail!("Duplicate callback parameter");
        }
    }
    Ok(params)
}

fn validate_callback(
    target: &str,
    expected_state: &str,
    registered: Option<&str>,
) -> Result<Callback> {
    let params = callback_parameters(target)?;
    if params.get("state").map(String::as_str) != Some(expected_state) {
        bail!("Sign-in callback state did not match");
    }
    if params.contains_key("error") {
        bail!("Account authorization was declined or failed; no credentials changed");
    }
    let client_id = match (registered, params.get("client_id")) {
        (Some(old), Some(new)) if old != new => {
            bail!("Sign-in callback attempted to replace the selected account registration")
        }
        (Some(old), _) => old.to_string(),
        (None, Some(new)) if new != "dynamic_agent_client" && !new.is_empty() => new.clone(),
        _ => bail!("Account registration did not return an issued client ID"),
    };
    let code = params
        .get("code")
        .filter(|v| !v.is_empty())
        .cloned()
        .ok_or_else(|| anyhow!("Sign-in callback did not contain an authorization code"))?;
    Ok(Callback { code, client_id })
}

/// TCP reads do not preserve HTTP message boundaries. Accumulate a bounded
/// request header before interpreting its first line; never log its contents.
async fn read_callback_target(stream: &mut tokio::net::TcpStream) -> Result<Option<String>> {
    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let remaining = MAX_HEADER_BYTES.saturating_sub(bytes.len());
        if remaining == 0 {
            bail!("Sign-in callback request headers exceeded the limit");
        }
        let count = stream.read(&mut chunk[..remaining.min(1024)]).await?;
        if count == 0 {
            bail!("Sign-in callback request ended before its headers were complete");
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end])
                .map_err(|_| anyhow!("Invalid sign-in callback request headers"))?;
            let first = headers.split("\r\n").next().unwrap_or_default();
            let mut words = first.split_whitespace();
            let method = words.next();
            let target = words.next();
            let version = words.next();
            if words.next().is_some() || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1")) {
                bail!("Invalid sign-in callback request line");
            }
            return Ok(target
                .filter(|target| method == Some("GET") && target.starts_with("/auth/callback?"))
                .map(str::to_owned));
        }
    }
}

async fn callback_reply(stream: &mut tokio::net::TcpStream, accepted: bool) {
    let (status, body) = if accepted {
        (
            "200 OK",
            "Authorization received. Return to Exhume to confirm completion.",
        )
    } else {
        (
            "400 Bad Request",
            "Authorization was not accepted. Return to Exhume to continue or retry sign-in.",
        )
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}", body.len());
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        stream.write_all(response.as_bytes()),
    )
    .await;
}

async fn receive_callback(
    listener: &TcpListener,
    expected_state: &str,
    registered: Option<&str>,
    overall_timeout: Duration,
    connection_timeout: Duration,
) -> Result<Callback> {
    tokio::time::timeout(overall_timeout, async {
        loop {
            let (mut stream, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            let target =
                match tokio::time::timeout(connection_timeout, read_callback_target(&mut stream))
                    .await
                {
                    Ok(Ok(Some(target))) => target,
                    _ => {
                        callback_reply(&mut stream, false).await;
                        continue;
                    }
                };
            match validate_callback(&target, expected_state, registered) {
                Ok(callback) => {
                    callback_reply(&mut stream, true).await;
                    return Ok(callback);
                }
                Err(error) => {
                    callback_reply(&mut stream, false).await;
                    // An explicit authorization denial with the expected state is
                    // terminal. Unrelated, malformed or stale requests cannot end
                    // the investigator's pending sign-in attempt.
                    if callback_parameters(&target).is_ok_and(|params| {
                        params.get("state").map(String::as_str) == Some(expected_state)
                            && params.contains_key("error")
                    }) {
                        return Err(error);
                    }
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow!("Account sign-in timed out; no credentials changed"))?
}

impl PendingSignIn {
    pub async fn complete(self) -> Result<AccountStatus> {
        let callback = receive_callback(
            &self.listener,
            &self.state,
            self.selected
                .as_ref()
                .map(|(_, registration)| registration.client_id.as_str()),
            Duration::from_secs(300),
            Duration::from_secs(5),
        )
        .await?;
        let response = token_request(&[
            ("grant_type", "authorization_code"),
            ("client_id", &callback.client_id),
            ("code", &callback.code),
            ("code_verifier", &self.verifier),
            ("redirect_uri", &self.redirect_uri),
            ("resource", RESOURCE),
        ])
        .await?;
        let id_token = response
            .id_token
            .as_deref()
            .ok_or_else(|| anyhow!("Sign-in response omitted the ID token"))?;
        let claims = validate_id_token(id_token, &callback.client_id, Some(&self.nonce)).await?;
        if self
            .selected
            .as_ref()
            .is_some_and(|(_, r)| r.subject != claims.sub)
        {
            bail!("Account identity changed; existing credentials were preserved");
        }
        let credentials = credentials_from_response(response, None)?;
        if !has_plan_scope(&credentials.scopes) {
            bail!("ChatGPT plan usage permission was not granted; inference remains disconnected");
        }
        let id = self
            .selected
            .as_ref()
            .map(|(id, _)| id.clone())
            .unwrap_or_else(|| {
                hex::encode(Sha256::digest(callback.client_id.as_bytes()))[..24].to_string()
            });
        let status = AccountStatus {
            provider: "openai".into(),
            account_id: id.clone(),
            email: claims.email.clone(),
            subject: claims.sub.clone(),
            connected: true,
            expires_at: Some(credentials.expires_at),
            plan_usage_enabled: true,
            usage_source: "chatgpt_plan".into(),
        };
        let mut stored = LockedVault::load().await?;
        if let Some(existing) = stored.vault.accounts.get(&id) {
            if existing.client_id != callback.client_id || existing.subject != claims.sub {
                bail!("Account registration collision; credentials were not replaced");
            }
        }
        stored.vault.accounts.insert(
            id,
            Registration {
                client_id: callback.client_id,
                subject: claims.sub,
                email: claims.email,
                credentials: Some(credentials),
            },
        );
        cache::save_and_seed(stored).await?;
        Ok(status)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}
async fn token_request(form: &[(&str, &str)]) -> Result<TokenResponse> {
    let response = http_client()?
        .post(TOKEN_URL)
        .timeout(Duration::from_secs(30))
        .form(form)
        .send()
        .await
        .map_err(|_| anyhow!("Authentication service could not be reached"))?;
    if !response.status().is_success() {
        bail!("Authentication request failed (HTTP {}); reconnect the selected account. No API-key fallback was attempted",response.status().as_u16());
    }
    response
        .json()
        .await
        .map_err(|_| anyhow!("Authentication service returned an invalid token response"))
}
fn credentials_from_response(
    response: TokenResponse,
    old: Option<&Credentials>,
) -> Result<Credentials> {
    if !response.token_type.eq_ignore_ascii_case("bearer")
        || response.access_token.is_empty()
        || response.expires_in == 0
    {
        bail!("Invalid authentication token response");
    }
    let refresh_token = response
        .refresh_token
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("Authentication response omitted the renewable session token"))?;
    let id_token = response
        .id_token
        .or_else(|| old.map(|c| c.id_token.clone()))
        .ok_or_else(|| anyhow!("Authentication response omitted identity"))?;
    let scopes = response
        .scope
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
        .or_else(|| old.map(|c| c.scopes.clone()))
        .ok_or_else(|| anyhow!("Authentication response omitted granted permissions"))?;
    Ok(Credentials {
        access_token: response.access_token,
        refresh_token,
        id_token,
        expires_at: now().saturating_add(response.expires_in),
        scopes,
    })
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Value,
    exp: u64,
    nonce: Option<String>,
    email: Option<String>,
}
fn validate_claims(claims: &IdClaims, client_id: &str, nonce: Option<&str>) -> Result<()> {
    let audience = claims.aud.as_str() == Some(client_id)
        || claims
            .aud
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(client_id)));
    if claims.iss != ISSUER || !audience || claims.exp <= now() || claims.sub.is_empty() {
        bail!("Account identity validation failed");
    }
    if nonce.is_some() && claims.nonce.as_deref() != nonce {
        bail!("Account identity nonce did not match");
    }
    Ok(())
}
async fn discovery() -> Result<Value> {
    let response = http_client()?
        .get(format!("{ISSUER}/.well-known/openid-configuration"))
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("Cannot discover authentication endpoints");
    }
    let v: Value = response.json().await?;
    if v["issuer"].as_str() != Some(ISSUER) {
        bail!("Authentication issuer mismatch");
    }
    Ok(v)
}
fn trusted_auth_url(value: &Value) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(
        value
            .as_str()
            .ok_or_else(|| anyhow!("Authentication endpoint missing"))?,
    )?;
    if url.scheme() != "https"
        || url.host_str() != Some("auth.openai.com")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
    {
        bail!("Untrusted authentication endpoint");
    }
    Ok(url)
}
async fn validate_id_token(token: &str, client_id: &str, nonce: Option<&str>) -> Result<IdClaims> {
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid identity token");
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    if header["alg"].as_str() != Some("RS256") {
        bail!("Unsupported identity token signature algorithm");
    }
    let kid = header["kid"]
        .as_str()
        .ok_or_else(|| anyhow!("Identity token has no signing key"))?;
    let metadata = discovery().await?;
    let response = http_client()?
        .get(trusted_auth_url(&metadata["jwks_uri"])?)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("Cannot obtain identity verification keys");
    }
    let keys: Value = response.json().await?;
    let key = keys["keys"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|k| k["kid"].as_str() == Some(kid) && k["kty"] == "RSA")
        })
        .ok_or_else(|| anyhow!("Unknown identity signing key"))?;
    let n = URL_SAFE_NO_PAD.decode(
        key["n"]
            .as_str()
            .ok_or_else(|| anyhow!("Invalid identity key"))?,
    )?;
    let e = URL_SAFE_NO_PAD.decode(
        key["e"]
            .as_str()
            .ok_or_else(|| anyhow!("Invalid identity key"))?,
    )?;
    signature::RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2])?,
        )
        .map_err(|_| anyhow!("Identity token signature failed"))?;
    let claims: IdClaims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    validate_claims(&claims, client_id, nonce)?;
    Ok(claims)
}

/// Resolves only the explicitly selected account. Rotation is serialized across processes.
pub(crate) async fn access_token(account_id: Option<&str>) -> Result<String> {
    let id =
        account_id.ok_or_else(|| anyhow!("Select a connected ChatGPT account before inference"))?;
    cache::access_token(CredentialStore::native()?, id).await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisconnectResult {
    pub locally_disconnected: bool,
    pub remote_revocation_confirmed: bool,
}
pub async fn disconnect_chatgpt(account_id: &str) -> Result<DisconnectResult> {
    let account_id = account_id.to_string();
    tokio::spawn(async move { disconnect_chatgpt_transaction(&account_id).await })
        .await
        .map_err(|_| anyhow!("Account disconnect transaction could not complete"))?
}

async fn disconnect_chatgpt_transaction(account_id: &str) -> Result<DisconnectResult> {
    let mut stored = LockedVault::load().await?;
    let r = stored
        .vault
        .accounts
        .get_mut(account_id)
        .ok_or_else(|| anyhow!("Unknown account registration"))?;
    let mut confirmed = r.credentials.is_none();
    if let Some(c) = r.credentials.take() {
        if let Ok(meta) = discovery().await {
            if let Ok(endpoint) = trusted_auth_url(&meta["revocation_endpoint"]) {
                if let Ok(response) = http_client()?
                    .post(endpoint)
                    .form(&[
                        ("token", c.refresh_token.as_str()),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", r.client_id.as_str()),
                    ])
                    .send()
                    .await
                {
                    confirmed = response.status() == reqwest::StatusCode::OK;
                }
            }
        }
    }
    stored.save().await?;
    Ok(DisconnectResult {
        locally_disconnected: true,
        remote_revocation_confirmed: confirmed,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountModel {
    pub id: String,
    pub display_name: String,
}
const MAX_MODEL_CATALOG_BYTES: usize = 2 * 1024 * 1024;
async fn read_model_catalog(mut response: reqwest::Response) -> Result<Value> {
    if !response.status().is_success() {
        bail!(
            "Model catalog failed (HTTP {}); no fallback attempted",
            response.status().as_u16()
        );
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_MODEL_CATALOG_BYTES as u64)
    {
        bail!("Model catalog exceeds the 2 MiB response bound");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > MAX_MODEL_CATALOG_BYTES {
            bail!("Model catalog exceeds the 2 MiB response bound");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("Model catalog response is invalid")
}
fn parse_chatgpt_models(data: &Value) -> Result<Vec<AccountModel>> {
    let entries = data["models"]
        .as_array()
        .ok_or_else(|| anyhow!("Account model catalog format is invalid"))?;
    if entries.len() > 4096 {
        bail!("Account model catalog exceeds the model-count bound");
    }
    // SIWC catalog order and visibility are provider controlled. Slugs are opaque.
    entries
        .iter()
        .filter(|model| model["visibility"] == "list")
        .map(|model| {
            let id = model["slug"]
                .as_str()
                .filter(|id| !id.trim().is_empty() && id.len() <= 1024)
                .ok_or_else(|| anyhow!("Account model is missing its ID"))?;
            let display_name = model["display_name"]
                .as_str()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(id);
            if display_name.len() > 4096 {
                bail!("Account model name exceeds the size bound");
            }
            Ok(AccountModel {
                id: id.to_string(),
                display_name: display_name.to_string(),
            })
        })
        .collect()
}
pub async fn chatgpt_models(account_id: &str) -> Result<Vec<AccountModel>> {
    let token = cache::explicit_access_token(CredentialStore::native()?, account_id).await?;
    chatgpt_catalog(&token).await
}

/// Automatic Settings discovery: use only a fresh, generation-checked in-memory
/// access token. Cold, expired or invalidated state cannot trigger OS interaction.
pub async fn chatgpt_models_cached(account_id: &str) -> Result<Vec<AccountModel>> {
    let token = cache::cached_access_token(CredentialStore::native()?, account_id).await?;
    chatgpt_catalog(&token).await
}

async fn chatgpt_catalog(token: &str) -> Result<Vec<AccountModel>> {
    let response = http_client()?
        .get(format!("{RESOURCE}/models"))
        .timeout(Duration::from_secs(30))
        .bearer_auth(token)
        .send()
        .await?;
    parse_chatgpt_models(&read_model_catalog(response).await?)
}

/// Explicit user action after Vibe's official browser login. This imports only the
/// documented ordinary MISTRAL_API_KEY from Exhume's dedicated VIBE_HOME/.env.
/// It does not collect OAuth/session tokens or search the user's existing profiles.
pub async fn import_mistral_runtime_credentials(label: &str) -> Result<AccountStatus> {
    if label.trim().is_empty() {
        bail!("Give this Mistral connection a recognizable account label");
    }
    let path = crate::providers::runtimes::runtime_directory("mistral")?.join(".env");
    let meta = std::fs::symlink_metadata(&path).context("Vibe has not saved a credential in Exhume's dedicated profile; complete its native login first")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 65536 {
        bail!("Vibe credential file is not a bounded regular file");
    }
    let text = std::fs::read_to_string(&path)
        .context("Cannot read the explicitly selected Vibe credential file")?;
    let key = parse_mistral_env(&text)?;
    // Only metadata goes to the provider here. Case data is never part of login.
    mistral_catalog(&key).await?;
    let id = format!(
        "mistral-{}",
        &hex::encode(Sha256::digest(key.as_bytes()))[..24]
    );
    let mut stored = LockedVault::load().await?;
    stored.vault.mistral_accounts.insert(
        id.clone(),
        MistralRegistration {
            label: label.trim().into(),
            api_key: Some(key),
        },
    );
    stored.save().await?;
    Ok(AccountStatus {
        provider: "mistral".into(),
        account_id: id,
        email: None,
        subject: label.trim().into(),
        connected: true,
        expires_at: None,
        plan_usage_enabled: false,
        usage_source: "mistral_account_api_allowance_or_payg".into(),
    })
}

fn parse_mistral_env(text: &str) -> Result<String> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != "MISTRAL_API_KEY" {
            continue;
        }
        if found.is_some() {
            bail!("Vibe credential file contains ambiguous duplicate keys");
        }
        let value = value.trim();
        let value = if value.starts_with('"') && value.ends_with('"')
            || value.starts_with('\'') && value.ends_with('\'')
        {
            value
                .get(1..value.len() - 1)
                .ok_or_else(|| anyhow!("Invalid Vibe credential value"))?
        } else {
            value
        };
        // API keys are literal credentials. Never expand environment expressions or execute shell syntax.
        if value.is_empty()
            || value
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '$' | '`' | '\\' | '"' | '\'' | '#'))
        {
            bail!("Vibe credential must be a single literal API key");
        }
        found = Some(value.to_string());
    }
    found.ok_or_else(||anyhow!("Vibe did not store a documented MISTRAL_API_KEY; unsupported credential formats are not imported"))
}
pub(crate) async fn mistral_api_key(account_id: Option<&str>) -> Result<String> {
    let id =
        account_id.ok_or_else(|| anyhow!("Select a connected Mistral account before inference"))?;
    LockedVault::load().await?.vault.mistral_accounts.get(id).and_then(|r|r.api_key.clone()).ok_or_else(||anyhow!("Mistral connection is disconnected; complete native account sign-in and explicitly reconnect"))
}
pub fn disconnect_mistral(account_id: &str) -> Result<DisconnectResult> {
    let mut stored = CredentialStore::native()?.load_locked()?;
    let r = stored
        .vault
        .mistral_accounts
        .get_mut(account_id)
        .ok_or_else(|| anyhow!("Unknown Mistral connection"))?;
    r.api_key = None;
    stored.save_sync()?;
    Ok(DisconnectResult {
        locally_disconnected: true,
        remote_revocation_confirmed: false,
    })
}
fn parse_mistral_models(value: &Value) -> Result<Vec<AccountModel>> {
    let entries = value["data"]
        .as_array()
        .or_else(|| value.as_array())
        .ok_or_else(|| anyhow!("Mistral model catalog is invalid"))?;
    if entries.len() > 4096 {
        bail!("Mistral model catalog exceeds the model-count bound");
    }
    entries
        .iter()
        .filter(|model| {
            model["capabilities"]["completion_chat"] != false && model["archived"] != true
        })
        .map(|model| {
            let id = model["id"]
                .as_str()
                .filter(|id| !id.trim().is_empty() && id.len() <= 1024)
                .ok_or_else(|| anyhow!("Mistral model catalog contains an invalid identifier"))?;
            let display_name = model["name"]
                .as_str()
                .filter(|name| !name.trim().is_empty())
                .unwrap_or(id);
            if display_name.len() > 4096 {
                bail!("Mistral model name exceeds the size bound");
            }
            Ok(AccountModel {
                id: id.to_string(),
                display_name: display_name.to_string(),
            })
        })
        .collect()
}
async fn mistral_catalog(key: &str) -> Result<Vec<AccountModel>> {
    let response = http_client()?
        .get("https://api.mistral.ai/v1/models")
        .timeout(Duration::from_secs(30))
        .bearer_auth(key)
        .send()
        .await
        .map_err(|_| anyhow!("Cannot validate the Mistral account credential"))?;
    parse_mistral_models(&read_model_catalog(response).await?)
}

pub async fn mistral_models(account_id: &str) -> Result<Vec<AccountModel>> {
    mistral_catalog(&mistral_api_key(Some(account_id)).await?).await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn assert_blocked_store_operation_is_cancellable(save: bool) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("synthetic-credentials.lock");
        let open_lock = |path: &std::path::Path| {
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(path)
                .unwrap()
        };
        let held_lock = save.then(|| {
            let file = open_lock(&path);
            file.try_lock_exclusive().unwrap();
            file
        });
        let competing_lock = open_lock(&path);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
        let mut task = tokio::spawn(credential_store_task(move || {
            let lock = match held_lock {
                Some(lock) => lock,
                None => {
                    let lock = OpenOptions::new().read(true).write(true).open(path)?;
                    lock.try_lock_exclusive()?;
                    lock
                }
            };
            let _ = started_tx.send(());
            // Synthetic OS call: only the test releases it. The emergency bound
            // also lets a failing test shut down without a stranded worker.
            let result = release_rx.recv_timeout(Duration::from_secs(5));
            drop(lock);
            let _ = finished_tx.send(());
            result.map_err(|_| anyhow!("Synthetic credential operation was not released"))
        }));
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        if !save {
            assert!(tokio::time::timeout(Duration::from_millis(30), &mut task)
                .await
                .is_err());
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            competing_lock.try_lock_exclusive().is_err(),
            "Cancelling the async caller must not release the background operation's lock"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), finished_rx)
            .await
            .unwrap()
            .unwrap();
        competing_lock.try_lock_exclusive().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_credential_read_allows_timeout_and_retains_lock_until_completion() {
        assert_blocked_store_operation_is_cancellable(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_credential_write_allows_cancellation_and_retains_owned_lock() {
        assert_blocked_store_operation_is_cancellable(true).await;
    }

    fn assert_uuid_v4_host_id(host_id: &str) {
        let uuid = host_id.strip_prefix("urn:uuid:").unwrap();
        assert_eq!(uuid.len(), 36);
        assert_eq!(
            uuid.split('-').map(str::len).collect::<Vec<_>>(),
            [8, 4, 4, 4, 12]
        );
        let bytes = hex::decode(uuid.replace('-', "")).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[6] >> 4, 4, "UUID version must be 4");
        assert_eq!(bytes[8] >> 6, 2, "UUID variant must be RFC 4122");
    }

    #[test]
    fn host_ids_are_unique_uuid_v4_urns() {
        let mut ids = std::collections::BTreeSet::new();
        for _ in 0..128 {
            let id = new_host_id().unwrap();
            assert_uuid_v4_host_id(&id);
            assert!(ids.insert(id));
        }
    }

    #[test]
    fn host_id_is_created_once_and_reused_after_vault_round_trip() {
        let mut vault = Vault::default();
        assert!(ensure_host_id(&mut vault).unwrap());
        assert_uuid_v4_host_id(&vault.host_id);
        let saved_id = vault.host_id.clone();
        let mut restored: Vault =
            serde_json::from_slice(&serde_json::to_vec(&vault).unwrap()).unwrap();
        assert!(!ensure_host_id(&mut restored).unwrap());
        assert_eq!(restored.host_id, saved_id);
    }

    #[test]
    fn legacy_host_id_migration_preserves_all_account_data() {
        let before = serde_json::json!({
            "host_id": "exhume-previously-generated-opaque-id",
            "accounts": {
                "synthetic-account": {
                    "client_id": "synthetic-issued-client",
                    "subject": "synthetic-subject",
                    "email": "synthetic@example.invalid",
                    "credentials": {
                        "access_token": "synthetic-access",
                        "refresh_token": "synthetic-refresh",
                        "id_token": "synthetic-id",
                        "expires_at": 123,
                        "scopes": ["resource.invoke", "chatgpt.tokens.use.direct"]
                    }
                },
                "disconnected-account": {
                    "client_id": "synthetic-disconnected-client",
                    "subject": "synthetic-disconnected-subject",
                    "email": null,
                    "credentials": null
                }
            },
            "mistral_accounts": {
                "synthetic-mistral": {"label": "Test account", "api_key": "synthetic-mistral-key"}
            },
            "api_keys": {"synthetic-profile": "synthetic-api-key"}
        });
        let mut vault: Vault = serde_json::from_value(before.clone()).unwrap();
        assert!(ensure_host_id(&mut vault).unwrap());
        assert_uuid_v4_host_id(&vault.host_id);
        let mut expected = before;
        expected["host_id"] = Value::String(vault.host_id.clone());
        assert_eq!(serde_json::to_value(&vault).unwrap(), expected);
        let mut restored: Vault = serde_json::from_value(expected.clone()).unwrap();
        assert!(!ensure_host_id(&mut restored).unwrap());
        assert_eq!(serde_json::to_value(restored).unwrap(), expected);
    }

    #[test]
    fn host_id_migration_preserves_existing_supported_formats() {
        for host_id in [
            "urn:uuid:5df366b5-ef5e-4f41-aacd-230b31ed4789",
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            "did:key:z6MkiTBz1yN2kAQmhnbrALFok2mBXHMFfAk7zMNY9M3WfGDN",
        ] {
            let mut vault = Vault {
                host_id: host_id.into(),
                ..Vault::default()
            };
            assert!(!ensure_host_id(&mut vault).unwrap());
            assert_eq!(vault.host_id, host_id);
        }
    }

    #[test]
    fn initial_authorization_emits_migrated_host_and_documented_parameters() {
        let mut vault = Vault {
            host_id: "exhume-legacy".into(),
            ..Vault::default()
        };
        assert!(ensure_host_id(&mut vault).unwrap());
        // RFC 7636 PKCE test vector, independent of the URL builder's hash.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let url = reqwest::Url::parse(
            &chatgpt_authorization_url(
                &vault.host_id,
                None,
                "http://127.0.0.1:43210/auth/callback",
                "synthetic-state",
                "synthetic-nonce",
                verifier,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            url.origin().ascii_serialization(),
            "https://auth.openai.com"
        );
        assert_eq!(url.path(), "/api/accounts/authorize");
        let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        let expected: BTreeMap<String, String> = [
            ("client_id", "dynamic_agent_client"),
            ("ext_agent_host_id", vault.host_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", "http://127.0.0.1:43210/auth/callback"),
            (
                "scope",
                "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            ),
            ("resource", "https://api.openai.com/v1"),
            ("state", "synthetic-state"),
            ("nonce", "synthetic-nonce"),
            ("code_challenge_method", "S256"),
            (
                "code_challenge",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ),
            ("agent_name_hint", "Exhume Agent"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect();
        assert_eq!(params, expected);
        assert_eq!(url.query_pairs().count(), expected.len());
        assert_uuid_v4_host_id(&params["ext_agent_host_id"]);
    }

    #[test]
    fn returning_authorization_reuses_host_and_issued_client_without_identity_secrets() {
        let registration = Registration {
            client_id: "synthetic-issued-client".into(),
            subject: "synthetic-subject".into(),
            email: Some("synthetic@example.invalid".into()),
            credentials: Some(Credentials {
                access_token: "synthetic-access".into(),
                refresh_token: "synthetic-refresh".into(),
                id_token: "synthetic-id".into(),
                expires_at: 123,
                scopes: vec![],
            }),
        };
        let host_id = new_host_id().unwrap();
        let url = reqwest::Url::parse(
            &chatgpt_authorization_url(
                &host_id,
                Some(&registration),
                "http://127.0.0.1:43210/auth/callback",
                "synthetic-state",
                "synthetic-nonce",
                "synthetic-verifier",
            )
            .unwrap(),
        )
        .unwrap();
        let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["ext_agent_host_id"], host_id);
        assert_eq!(params["client_id"], registration.client_id);
        assert!(!params.contains_key("agent_name_hint"));
        assert!(!params.contains_key("id_token_hint"));
        for secret in [
            "synthetic-access",
            "synthetic-refresh",
            "synthetic-id",
            "synthetic-subject",
            "synthetic@example.invalid",
        ] {
            assert!(!params.values().any(|value| value == secret));
        }
    }

    #[test]
    fn imports_only_documented_literal_mistral_key() {
        assert_eq!(
            parse_mistral_env("IGNORED=anything\nMISTRAL_API_KEY='literal-key'\n").unwrap(),
            "literal-key"
        );
        for bad in [
            "MISTRAL_API_KEY=$(command)",
            "MISTRAL_API_KEY=$OTHER",
            "MISTRAL_API_KEY=a\nMISTRAL_API_KEY=b",
            "OAUTH_TOKEN=opaque",
        ] {
            assert!(parse_mistral_env(bad).is_err());
        }
    }
    #[test]
    fn callback_rejects_wrong_state_and_registration_replacement() {
        assert!(validate_callback(
            "/auth/callback?state=wrong&code=x&client_id=c",
            "right",
            None
        )
        .is_err());
        assert!(validate_callback(
            "/auth/callback?state=s&code=x&client_id=other",
            "s",
            Some("saved")
        )
        .is_err());
        assert!(validate_callback(
            "/auth/callback?state=s&code=x&client_id=dynamic_agent_client",
            "s",
            None
        )
        .is_err());
        assert!(
            validate_callback("/auth/callback?state=s&state=s&code=x", "s", Some("saved")).is_err()
        );
        assert_eq!(
            validate_callback("/auth/callback?state=s&code=x", "s", Some("saved"))
                .unwrap()
                .client_id,
            "saved"
        );
    }
    #[test]
    fn identity_and_plan_permissions_are_distinct() {
        let claims = IdClaims {
            iss: ISSUER.into(),
            sub: "subject".into(),
            aud: Value::String("client".into()),
            exp: now() + 60,
            nonce: Some("nonce".into()),
            email: None,
        };
        assert!(validate_claims(&claims, "client", Some("nonce")).is_ok());
        assert!(validate_claims(&claims, "other", Some("nonce")).is_err());
        assert!(validate_claims(&claims, "client", Some("wrong")).is_err());
        assert!(!has_plan_scope(&["openid".into(), "email".into()]));
    }

    async fn synthetic_callback_request(address: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn callback_transport_accumulates_fragmented_http_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            receive_callback(
                &listener,
                "synthetic-state",
                Some("saved-client"),
                Duration::from_secs(2),
                Duration::from_secs(1),
            )
            .await
        });
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET /auth/cal").await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stream
            .write_all(
                b"lback?state=synthetic-state&code=synthetic-code HTTP/1.1\r\nHost: 127.0.0.1\r\n",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stream.write_all(b"\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        let result = receiver.await.unwrap().unwrap();
        assert_eq!(result.code, "synthetic-code");
        assert_eq!(result.client_id, "saved-client");
    }

    #[tokio::test]
    async fn callback_transport_ignores_idle_malformed_and_stale_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            receive_callback(
                &listener,
                "synthetic-state",
                Some("saved-client"),
                Duration::from_secs(2),
                Duration::from_millis(30),
            )
            .await
        });
        let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut ignored = String::new();
        idle.read_to_string(&mut ignored).await.unwrap();
        assert!(ignored.starts_with("HTTP/1.1 400"));
        for request in [
            "GET /auth/callback?state=stale&code=x HTTP/1.1\r\n\r\n",
            "GET /auth/callback?state=synthetic-state&state=synthetic-state&code=x HTTP/1.1\r\n\r\n",
            "GET /auth/callback?state=synthetic-state&code=x INVALID\r\n\r\n",
        ] {
            let response = synthetic_callback_request(address, request.as_bytes()).await;
            assert!(response.starts_with("HTTP/1.1 400"));
        }
        let response = synthetic_callback_request(
            address,
            b"GET /auth/callback?state=synthetic-state&code=accepted HTTP/1.1\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(receiver.await.unwrap().unwrap().code, "accepted");
    }

    #[tokio::test]
    async fn callback_transport_bounds_headers_and_keeps_absolute_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            receive_callback(
                &listener,
                "synthetic-state",
                None,
                Duration::from_millis(100),
                Duration::from_secs(1),
            )
            .await
        });
        let mut oversized = tokio::net::TcpStream::connect(address).await.unwrap();
        oversized.write_all(&vec![b'x'; 16 * 1024]).await.unwrap();
        let mut response = String::new();
        oversized.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 400"));
        // A new connection must not restart the absolute authorization deadline.
        let _idle = tokio::net::TcpStream::connect(address).await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(500), receiver)
            .await
            .unwrap()
            .unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("sign-in timed out"));
    }

    #[tokio::test]
    async fn callback_transport_authorization_denial_is_terminal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            receive_callback(
                &listener,
                "synthetic-state",
                None,
                Duration::from_secs(2),
                Duration::from_secs(1),
            )
            .await
        });
        synthetic_callback_request(
            address,
            b"GET /auth/callback?state=synthetic-state&error=access_denied HTTP/1.1\r\n\r\n",
        )
        .await;
        assert!(receiver
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("declined or failed"));
    }

    #[tokio::test]
    async fn cancelling_pending_sign_in_releases_callback_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pending = PendingSignIn {
            authorization_url: "synthetic".into(),
            listener,
            redirect_uri: "synthetic".into(),
            state: "synthetic".into(),
            nonce: "synthetic".into(),
            verifier: "synthetic".into(),
            selected: None,
        };
        let task = tokio::spawn(pending.complete());
        tokio::task::yield_now().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(TcpListener::bind(address).await.is_ok());
    }
    #[test]
    fn auth_endpoints_reject_cross_origin_and_cleartext() {
        assert!(trusted_auth_url(&Value::String("https://auth.openai.com/jwks".into())).is_ok());
        for s in [
            "http://auth.openai.com/jwks",
            "https://evil.example/jwks",
            "https://auth.openai.com:444/jwks",
        ] {
            assert!(trusted_auth_url(&Value::String(s.into())).is_err());
        }
    }
    #[test]
    fn refresh_requires_rotated_token_and_preserves_scope_only_if_omitted() {
        let old = Credentials {
            access_token: "old".into(),
            refresh_token: "refresh".into(),
            id_token: "id".into(),
            expires_at: 0,
            scopes: vec!["resource.invoke".into(), "chatgpt.tokens.use.direct".into()],
        };
        let response = TokenResponse {
            access_token: "new".into(),
            refresh_token: Some("rotated".into()),
            id_token: None,
            token_type: "Bearer".into(),
            expires_in: 3600,
            scope: None,
        };
        let new = credentials_from_response(response, Some(&old)).unwrap();
        assert!(has_plan_scope(&new.scopes));
        assert_eq!(new.refresh_token, "rotated");
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn chatgpt_uses_only_visible_slugs_in_provider_order() {
        let catalog = json!({"models":[{"slug":"second","display_name":"Second choice","visibility":"list"},{"slug":"hidden","visibility":"hidden"},{"slug":"first","visibility":"list"}]});
        let models = parse_chatgpt_models(&catalog).unwrap();
        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["second", "first"]
        );
        assert_eq!(models[0].display_name, "Second choice");
        assert_eq!(models[1].display_name, "first");
        assert!(parse_chatgpt_models(&json!({"models":[{"visibility":"list"}]})).is_err());
    }
    #[test]
    fn mistral_filters_explicit_non_chat_and_archived_models() {
        let catalog = json!({"data":[{"id":"chat","name":"Chat","capabilities":{"completion_chat":true}},{"id":"embedding","capabilities":{"completion_chat":false}},{"id":"old","archived":true},{"id":"unspecified"}]});
        let models = parse_mistral_models(&catalog).unwrap();
        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            vec!["chat", "unspecified"]
        );
        assert!(parse_mistral_models(&json!({"data":[{}]})).is_err());
    }
}
