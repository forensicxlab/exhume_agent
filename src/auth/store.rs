use super::*;
use std::{
    io::{Read, Write},
    path::{Component, Path},
    sync::Arc,
};

const INDEX_VERSION: u32 = 1;
const MAX_INDEX_BYTES: u64 = 1024 * 1024;

pub(super) trait VaultBackend: Send + Sync {
    fn load(&self) -> Result<Vault>;
    fn save(&self, vault: &Vault) -> Result<()>;
}

struct NativeBackend {
    directory: PathBuf,
    account: String,
}
impl VaultBackend for NativeBackend {
    fn load(&self) -> Result<Vault> {
        match secret_load(&self.directory, &self.account)? {
            Some(bytes) if bytes.len() <= 16 * 1024 * 1024 => serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("Account credential store is invalid; reconnect the account")),
            Some(_) => bail!("Account credential store exceeds its size limit"),
            None => Ok(Vault::default()),
        }
    }
    fn save(&self, vault: &Vault) -> Result<()> {
        secret_save(&self.directory, &self.account, &serde_json::to_vec(vault)?)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountIndex {
    version: u32,
    generation: String,
    ready: bool,
    accounts: Vec<AccountStatus>,
}

pub(super) struct CredentialStore {
    pub directory: PathBuf,
    backend: Arc<dyn VaultBackend>,
}

fn normalize_directory(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    // Resolve existing ancestors too, so aliases to a not-yet-created directory
    // still share the same native credential account, cache and lock.
    if absolute.exists() {
        return Ok(absolute.canonicalize()?);
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| anyhow!("Invalid credential directory"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| anyhow!("Invalid credential directory"))?;
    if absolute
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        let mut normalized = PathBuf::new();
        for component in absolute.components() {
            match component {
                Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        return normalize_directory(&normalized);
    }
    Ok(normalize_directory(parent)?.join(name))
}

fn native_account(directory: &Path, default_directory: Option<&Path>) -> String {
    if Some(directory) == default_directory {
        return VAULT_ACCOUNT.into();
    }
    format!(
        "{VAULT_ACCOUNT}-{}",
        hex::encode(Sha256::digest(directory.as_os_str().as_encoded_bytes()))
    )
}

impl CredentialStore {
    pub fn native() -> Result<Arc<Self>> {
        let default_directory = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|home| normalize_directory(&PathBuf::from(home).join(".config/exhume-agent")))
            .transpose()?;
        let directory = normalize_directory(&auth_directory()?)?;
        let account = native_account(&directory, default_directory.as_deref());
        Ok(Arc::new(Self {
            directory: directory.clone(),
            backend: Arc::new(NativeBackend { directory, account }),
        }))
    }

    #[cfg(test)]
    pub fn injected(directory: PathBuf, backend: Arc<dyn VaultBackend>) -> Arc<Self> {
        Arc::new(Self { directory, backend })
    }

    fn index_path(&self) -> PathBuf {
        self.directory.join("accounts-index.json")
    }

    fn read_index(&self) -> Result<Option<AccountIndex>> {
        let path = self.index_path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => bail!("Cannot read the account metadata index; explicitly refresh connections to repair it"),
        };
        if !metadata.is_file() || metadata.len() > MAX_INDEX_BYTES {
            bail!("Account metadata index is invalid; explicitly refresh connections to repair it");
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options
            .open(&path)
            .context("Cannot open account metadata index")?;
        if !file.metadata()?.is_file() {
            bail!("Account metadata index is not a regular file");
        }
        let mut bytes = Vec::new();
        file.take(MAX_INDEX_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            bail!("Account metadata index exceeds its size bound");
        }
        let index: AccountIndex = serde_json::from_slice(&bytes).map_err(|_| {
            anyhow!(
                "Account metadata index is invalid; explicitly refresh connections to repair it"
            )
        })?;
        if index.version != INDEX_VERSION
            || URL_SAFE_NO_PAD
                .decode(&index.generation)
                .map_or(true, |bytes| bytes.len() != 32)
            || index.accounts.len() > 4096
        {
            bail!("Account metadata index is unsupported or invalid; explicitly refresh connections to repair it");
        }
        Ok(Some(index))
    }

    fn write_index(&self, index: &AccountIndex) -> Result<()> {
        let bytes = serde_json::to_vec(index)?;
        if bytes.len() as u64 > MAX_INDEX_BYTES {
            bail!("Account metadata exceeds its size bound");
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(self.index_path()).map_err(|_| {
            anyhow!("Cannot publish account metadata; cached credentials remain unavailable")
        })?;
        Ok(())
    }

    pub fn account_status(&self) -> Result<Vec<AccountStatus>> {
        match self.read_index()? {
            Some(index) if index.ready => Ok(index.accounts),
            Some(_) => bail!("Account credentials are being updated or their last update failed; wait or explicitly refresh connections"),
            None => Ok(Vec::new()),
        }
    }

    /// The lock orders cache checks with disconnects and writes in other processes.
    pub fn generation(&self) -> Result<Option<String>> {
        let _lock = vault_lock_sync(&self.directory)?;
        match self.read_index()? {
            Some(index) if index.ready => Ok(Some(index.generation)),
            Some(_) => bail!("Account credentials are being updated or their last update failed; cached credentials are unavailable"),
            None => Ok(None),
        }
    }

    pub fn load_locked(self: &Arc<Self>) -> Result<LockedVault> {
        let lock = vault_lock_sync(&self.directory)?;
        let vault = self.backend.load()?;
        // A successful explicit OS read can repair a missing/interrupted index.
        let generation = match self.read_index().ok().flatten().filter(|index| index.ready) {
            Some(index) => index.generation,
            None => random_secret()?,
        };
        self.write_index(&AccountIndex {
            version: INDEX_VERSION,
            generation: generation.clone(),
            ready: true,
            accounts: vault_account_status(&vault),
        })?;
        Ok(LockedVault {
            _lock: lock,
            store: self.clone(),
            vault,
            generation,
        })
    }
}

pub(super) struct LockedVault {
    _lock: File,
    store: Arc<CredentialStore>,
    pub vault: Vault,
    pub generation: String,
}

impl LockedVault {
    pub async fn load() -> Result<Self> {
        Self::load_from(CredentialStore::native()?).await
    }
    pub async fn load_from(store: Arc<CredentialStore>) -> Result<Self> {
        credential_store_task(move || store.load_locked()).await
    }
    pub fn save_sync(self) -> Result<()> {
        self.save_with_generation().map(|_| ())
    }

    pub fn refresh_metadata(&mut self) -> Result<Vec<AccountStatus>> {
        let accounts = vault_account_status(&self.vault);
        self.generation = random_secret()?;
        self.store.write_index(&AccountIndex {
            version: INDEX_VERSION,
            generation: self.generation.clone(),
            ready: true,
            accounts: accounts.clone(),
        })?;
        Ok(accounts)
    }

    #[cfg(test)]
    pub fn publish_refreshed_metadata(mut self) -> Result<Vec<AccountStatus>> {
        self.refresh_metadata()
    }

    pub fn directory(&self) -> &std::path::Path {
        &self.store.directory
    }

    pub fn store(&self) -> Arc<CredentialStore> {
        self.store.clone()
    }

    fn save_with_generation(mut self) -> Result<String> {
        self.generation = random_secret()?;
        // Invalidate before touching the OS store, including a write that stalls
        // or fails. No other process may reuse a previously cached token then.
        self.store.write_index(&AccountIndex {
            version: INDEX_VERSION,
            generation: self.generation.clone(),
            ready: false,
            accounts: Vec::new(),
        })?;
        self.store.backend.save(&self.vault)?;
        self.store.write_index(&AccountIndex {
            version: INDEX_VERSION,
            generation: self.generation.clone(),
            ready: true,
            accounts: vault_account_status(&self.vault),
        })?;
        Ok(self.generation.clone())
    }

    pub async fn save(self) -> Result<()> {
        self.save_and_generation().await.map(|_| ())
    }
    pub async fn save_and_generation(self) -> Result<String> {
        // The closure captures the whole value; its file lock survives caller cancellation.
        credential_store_task(move || self.save_with_generation()).await
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    pub struct FakeBackend {
        pub vault: Mutex<Vault>,
        pub reads: AtomicUsize,
        pub writes: AtomicUsize,
        pub fail_read: AtomicBool,
        pub fail_write: AtomicBool,
        pub write_hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl FakeBackend {
        pub fn new(vault: Vault) -> Arc<Self> {
            Arc::new(Self {
                vault: Mutex::new(vault),
                reads: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
                fail_read: AtomicBool::new(false),
                fail_write: AtomicBool::new(false),
                write_hook: Mutex::new(None),
            })
        }
    }
    impl VaultBackend for FakeBackend {
        fn load(&self) -> Result<Vault> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_read.load(Ordering::SeqCst) {
                bail!("Synthetic OS store read failure");
            }
            Ok(self.vault.lock().unwrap().clone())
        }
        fn save(&self, vault: &Vault) -> Result<()> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if let Some(hook) = self.write_hook.lock().unwrap().take() {
                hook();
            }
            if self.fail_write.load(Ordering::SeqCst) {
                bail!("Synthetic OS store write failure");
            }
            *self.vault.lock().unwrap() = vault.clone();
            Ok(())
        }
    }
    pub fn credentials(token: &str, expires_at: u64) -> Credentials {
        Credentials {
            access_token: token.into(),
            refresh_token: format!("SECRET-refresh-{token}"),
            id_token: format!("SECRET-id-{token}"),
            expires_at,
            scopes: REQUIRED_SCOPES
                .iter()
                .map(|value| value.to_string())
                .collect(),
        }
    }
    pub fn vault() -> Vault {
        Vault {
            host_id: "SECRET-host".into(),
            accounts: BTreeMap::from([
                (
                    "one".into(),
                    Registration {
                        client_id: "SECRET-client-one".into(),
                        subject: "subject-one".into(),
                        email: Some("one@example.invalid".into()),
                        credentials: Some(credentials("SECRET-access-one", 2000)),
                    },
                ),
                (
                    "two".into(),
                    Registration {
                        client_id: "SECRET-client-two".into(),
                        subject: "subject-two".into(),
                        email: None,
                        credentials: Some(credentials("SECRET-access-two", 2000)),
                    },
                ),
            ]),
            mistral_accounts: BTreeMap::from([(
                "mistral-one".into(),
                MistralRegistration {
                    label: "Mistral account".into(),
                    api_key: Some("SECRET-mistral".into()),
                },
            )]),
            api_keys: BTreeMap::from([("profile".into(), "SECRET-api-key".into())]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use test_support::*;

    #[test]
    fn account_index_is_metadata_only_and_normal_status_never_opens_store() {
        let directory = tempfile::tempdir().unwrap();
        let backend = FakeBackend::new(vault());
        let store = CredentialStore::injected(directory.path().into(), backend.clone());
        assert!(store.account_status().unwrap().is_empty());
        assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
        store
            .load_locked()
            .unwrap()
            .publish_refreshed_metadata()
            .unwrap();
        assert_eq!(store.account_status().unwrap().len(), 3);
        assert_eq!(store.account_status().unwrap()[0].account_id, "one");
        assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
        let json = std::fs::read_to_string(store.index_path()).unwrap();
        assert!(
            !json.contains("SECRET"),
            "Tokens, API keys, client IDs and host IDs must stay out of metadata"
        );
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["ready"], true);
        assert_eq!(value["accounts"][0]["provider"], "openai");
    }

    #[test]
    fn explicit_refresh_rotates_generation_but_regular_reads_preserve_it() {
        let directory = tempfile::tempdir().unwrap();
        let store = CredentialStore::injected(directory.path().into(), FakeBackend::new(vault()));
        drop(store.load_locked().unwrap());
        let original = store.generation().unwrap();
        drop(store.load_locked().unwrap());
        assert_eq!(store.generation().unwrap(), original);
        store
            .load_locked()
            .unwrap()
            .publish_refreshed_metadata()
            .unwrap();
        assert_ne!(store.generation().unwrap(), original);
    }

    #[test]
    fn failed_write_leaves_invalidation_marker_until_explicit_store_recovery() {
        let directory = tempfile::tempdir().unwrap();
        let backend = FakeBackend::new(vault());
        let store = CredentialStore::injected(directory.path().into(), backend.clone());
        let stored = store.load_locked().unwrap();
        backend.fail_write.store(true, Ordering::SeqCst);
        assert!(stored.save_sync().is_err());
        assert!(store.generation().is_err());
        assert!(store.account_status().is_err());
        backend.fail_write.store(false, Ordering::SeqCst);
        store
            .load_locked()
            .unwrap()
            .publish_refreshed_metadata()
            .unwrap();
        assert_eq!(store.account_status().unwrap().len(), 3);
    }

    #[test]
    fn directory_aliases_preserve_default_account_and_custom_profiles_are_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let default = directory.path().join("default");
        std::fs::create_dir(&default).unwrap();
        let normalized = normalize_directory(&default).unwrap();
        let alias = normalize_directory(&default.join("../default/.")).unwrap();
        assert_eq!(normalized, alias);
        assert_eq!(native_account(&alias, Some(&normalized)), VAULT_ACCOUNT);
        let custom = normalize_directory(&directory.path().join("custom/new")).unwrap();
        assert_ne!(native_account(&custom, Some(&normalized)), VAULT_ACCOUNT);
        assert_ne!(
            native_account(&custom, Some(&normalized)),
            native_account(&directory.path().join("other"), Some(&normalized))
        );
        assert_eq!(
            native_account(&custom, None),
            native_account(&custom, Some(&normalized))
        );
        #[cfg(unix)]
        {
            let link = directory.path().join("alias");
            std::os::unix::fs::symlink(&default, &link).unwrap();
            assert_eq!(normalize_directory(&link).unwrap(), normalized);
        }
    }
}
