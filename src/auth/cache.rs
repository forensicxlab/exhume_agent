use super::*;
use futures_util::future::BoxFuture;
use std::sync::{Arc, Mutex, OnceLock};

const FRESHNESS_MARGIN: u64 = 90;
const FAILURE_BACKOFF: Duration = Duration::from_secs(5);

pub(super) trait TokenRefresher: Send + Sync {
    fn refresh(&self, registration: Registration) -> BoxFuture<'_, Result<Credentials>>;
}
struct NativeRefresher;
impl TokenRefresher for NativeRefresher {
    fn refresh(&self, registration: Registration) -> BoxFuture<'_, Result<Credentials>> {
        Box::pin(async move {
            let old = registration
                .credentials
                .as_ref()
                .ok_or_else(|| anyhow!("ChatGPT account is disconnected"))?;
            let response = token_request(&[
                ("grant_type", "refresh_token"),
                ("client_id", &registration.client_id),
                ("refresh_token", &old.refresh_token),
                ("resource", RESOURCE),
            ])
            .await?;
            if let Some(id_token) = response.id_token.as_deref() {
                let claims = validate_id_token(id_token, &registration.client_id, None).await?;
                if claims.sub != registration.subject {
                    bail!("Refreshed account identity changed");
                }
            }
            credentials_from_response(response, Some(old))
        })
    }
}

// Only the usable access token is retained. Renewable and identity credentials
// exist only in a locked transaction and the OS vault, never in this cache/index.
struct CachedAccess {
    token: String,
    expires_at: u64,
}
#[derive(Default)]
struct CacheState {
    generation: Option<String>,
    seeded: bool,
    tokens: BTreeMap<String, CachedAccess>,
    last_failure: Option<(tokio::time::Instant, String)>,
}
struct TokenCache {
    state: tokio::sync::Mutex<CacheState>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}
impl TokenCache {
    fn new(clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            state: tokio::sync::Mutex::new(CacheState::default()),
            clock,
        }
    }

    async fn access(
        self: Arc<Self>,
        store: Arc<CredentialStore>,
        id: String,
        refresher: Arc<dyn TokenRefresher>,
    ) -> Result<String> {
        self.access_with_intent(store, id, refresher, false).await
    }

    async fn access_with_intent(
        self: Arc<Self>,
        store: Arc<CredentialStore>,
        id: String,
        refresher: Arc<dyn TokenRefresher>,
        explicit: bool,
    ) -> Result<String> {
        // This task owns credential refresh through validation and persistence.
        // Dropping the caller cannot discard an already-rotated refresh token.
        // It performs no model inference and carries no case data.
        tokio::spawn(async move {
            let mut state = self.state.lock().await;
            // A deliberate user retry may follow a failed automatic/approved
            // request immediately; it must not inherit that request's backoff.
            if explicit {
                state.last_failure = None;
            }
            let result = self.access_locked(&mut state, store, &id, refresher).await;
            if let Err(error) = &result {
                if state
                    .last_failure
                    .as_ref()
                    .is_none_or(|(when, _)| when.elapsed() >= FAILURE_BACKOFF)
                {
                    state.last_failure = Some((tokio::time::Instant::now(), error.to_string()));
                }
            }
            result
        })
        .await
        .map_err(|_| anyhow!("Credential transaction could not complete"))?
    }

    async fn cached_access(&self, store: Arc<CredentialStore>, id: &str) -> Result<String> {
        // Settings may use an already-authorized access token, but must never
        // open the OS store or start a renewal (which can itself need a prompt).
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| credential_access_required())?;
        let generation = credential_store_task(move || store.generation()).await;
        match generation {
            Ok(Some(generation)) if state.generation.as_ref() == Some(&generation) => {}
            _ => {
                state.tokens.clear();
                return Err(credential_access_required());
            }
        }
        state.tokens.retain(|_, cached| {
            cached.expires_at > (self.clock)().saturating_add(FRESHNESS_MARGIN)
        });
        state
            .tokens
            .get(id)
            .map(|cached| cached.token.clone())
            .ok_or_else(credential_access_required)
    }

    fn usable_tokens(&self, vault: &Vault) -> BTreeMap<String, CachedAccess> {
        vault
            .accounts
            .iter()
            .filter_map(|(id, registration)| {
                let credentials = registration.credentials.as_ref()?;
                (has_plan_scope(&credentials.scopes)
                    && !credentials.access_token.is_empty()
                    && credentials.expires_at > (self.clock)().saturating_add(FRESHNESS_MARGIN))
                .then(|| {
                    (
                        id.clone(),
                        CachedAccess {
                            token: credentials.access_token.clone(),
                            expires_at: credentials.expires_at,
                        },
                    )
                })
            })
            .collect()
    }

    fn seed(state: &mut CacheState, generation: String, tokens: BTreeMap<String, CachedAccess>) {
        state.generation = Some(generation);
        state.seeded = true;
        state.tokens = tokens;
        state.last_failure = None;
    }

    async fn refresh_metadata(
        self: Arc<Self>,
        store: Arc<CredentialStore>,
    ) -> Result<Vec<AccountStatus>> {
        // Keep publication and cache seeding together even if the settings
        // window closes while the explicit OS read is in progress.
        tokio::spawn(async move {
            let mut state = self.state.lock().await;
            let (accounts, stored) = credential_store_task(move || {
                let mut stored = store.load_locked()?;
                let accounts = stored.refresh_metadata()?;
                Ok((accounts, stored))
            })
            .await?;
            let tokens = self.usable_tokens(&stored.vault);
            Self::seed(&mut state, stored.generation.clone(), tokens);
            Ok(accounts)
        })
        .await
        .map_err(|_| anyhow!("Credential metadata refresh could not complete"))?
    }

    async fn save_and_seed(self: Arc<Self>, stored: LockedVault) -> Result<()> {
        tokio::spawn(async move {
            let store = stored.store();
            let tokens = self.usable_tokens(&stored.vault);
            let generation = stored.save_and_generation().await?;
            // Persistence starts with an already-owned vault lock. Release it
            // before acquiring the cache mutex: all other cache operations take
            // the mutex before consulting the vault/generation lock.
            let mut state = self.state.lock().await;
            // Do not expose even a validated token until native persistence has
            // succeeded. A concurrent writer may have changed the vault while
            // we waited for the cache; never replace its newer snapshot.
            if credential_store_task(move || store.generation())
                .await
                .ok()
                .flatten()
                == Some(generation.clone())
            {
                Self::seed(&mut state, generation, tokens);
            }
            Ok(())
        })
        .await
        .map_err(|_| anyhow!("Credential persistence could not complete"))?
    }

    async fn access_locked(
        &self,
        state: &mut CacheState,
        store: Arc<CredentialStore>,
        id: &str,
        refresher: Arc<dyn TokenRefresher>,
    ) -> Result<String> {
        let generation_store = store.clone();
        let generation = credential_store_task(move || generation_store.generation()).await?;
        if state.seeded && generation.is_none() {
            state.tokens.clear();
            bail!("Account cache invalidation metadata is missing; explicitly refresh connections before reusing credentials");
        }
        if generation != state.generation {
            state.tokens.clear();
            state.last_failure = None;
            state.generation = generation;
        }
        state.tokens.retain(|_, cached| {
            cached.expires_at > (self.clock)().saturating_add(FRESHNESS_MARGIN)
        });
        if let Some(cached) = state.tokens.get(id) {
            if cached.expires_at > (self.clock)().saturating_add(FRESHNESS_MARGIN) {
                return Ok(cached.token.clone());
            }
        }
        if let Some((when, error)) = &state.last_failure {
            if when.elapsed() < FAILURE_BACKOFF {
                bail!("Recent credential access failed; retry after a short pause: {error}");
            }
        }
        let mut stored = LockedVault::load_from(store).await?;
        let registration = stored
            .vault
            .accounts
            .get(id)
            .ok_or_else(|| anyhow!("Unknown ChatGPT account"))?;
        let credentials = registration
            .credentials
            .as_ref()
            .ok_or_else(|| anyhow!("ChatGPT account is disconnected"))?;
        if !has_plan_scope(&credentials.scopes) {
            bail!("ChatGPT plan usage permission is missing");
        }
        let (access, generation) =
            if credentials.expires_at > (self.clock)().saturating_add(FRESHNESS_MARGIN) {
                let access = CachedAccess {
                    token: credentials.access_token.clone(),
                    expires_at: credentials.expires_at,
                };
                (access, stored.generation.clone())
            } else {
                // Network refresh/identity validation are bounded. An unresponsive OS
                // write remains on its blocking worker with the lock held; callers can
                // cancel independently without interrupting token persistence.
                // Each native HTTP exchange has its own request timeout. Do not wrap
                // the entire transaction in a deadline that could drop a received
                // rotated token while its identity validation is still in progress.
                let renewed = refresher.refresh(registration.clone()).await?;
                if !has_plan_scope(&renewed.scopes)
                    || renewed.access_token.is_empty()
                    || renewed.expires_at <= (self.clock)().saturating_add(FRESHNESS_MARGIN)
                {
                    bail!("Refreshed account credentials are not usable; reconnect the account");
                }
                let access = CachedAccess {
                    token: renewed.access_token.clone(),
                    expires_at: renewed.expires_at,
                };
                stored
                    .vault
                    .accounts
                    .get_mut(id)
                    .expect("account checked under lock")
                    .credentials = Some(renewed);
                let generation = stored.save_and_generation().await?;
                (access, generation)
            };
        if state.generation.as_ref() != Some(&generation) {
            state.tokens.clear();
        }
        state.generation = Some(generation);
        state.seeded = true;
        state.last_failure = None;
        let token = access.token.clone();
        state.tokens.insert(id.into(), access);
        Ok(token)
    }
}

type Caches = BTreeMap<PathBuf, Arc<TokenCache>>;
static CACHES: OnceLock<Mutex<Caches>> = OnceLock::new();

pub(super) async fn access_token(store: Arc<CredentialStore>, account_id: &str) -> Result<String> {
    cache_for_directory(&store.directory)?
        .access(store, account_id.into(), Arc::new(NativeRefresher))
        .await
}

pub(super) async fn explicit_access_token(
    store: Arc<CredentialStore>,
    account_id: &str,
) -> Result<String> {
    cache_for_directory(&store.directory)?
        .access_with_intent(store, account_id.into(), Arc::new(NativeRefresher), true)
        .await
}

pub(super) async fn cached_access_token(
    store: Arc<CredentialStore>,
    account_id: &str,
) -> Result<String> {
    cache_for_directory(&store.directory)?
        .cached_access(store, account_id)
        .await
}

pub(super) async fn refresh_account_status(
    store: Arc<CredentialStore>,
) -> Result<Vec<AccountStatus>> {
    cache_for_directory(&store.directory)?
        .refresh_metadata(store)
        .await
}

pub(super) async fn save_and_seed(stored: LockedVault) -> Result<()> {
    cache_for_directory(stored.directory())?
        .save_and_seed(stored)
        .await
}

fn cache_for_directory(directory: &std::path::Path) -> Result<Arc<TokenCache>> {
    let mut caches = CACHES
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| anyhow!("Account cache is unavailable"))?;
    Ok(caches
        .entry(directory.to_path_buf())
        .or_insert_with(|| Arc::new(TokenCache::new(Arc::new(now))))
        .clone())
}

#[cfg(test)]
mod tests {
    use super::super::store::test_support::*;
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::{Notify, Semaphore};

    struct FakeRefresher {
        calls: AtomicUsize,
        exchange_started: Notify,
        response: Semaphore,
        validation_started: Notify,
        validation: Semaphore,
    }
    impl FakeRefresher {
        fn new(paused: bool) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                exchange_started: Notify::new(),
                response: Semaphore::new(if paused { 0 } else { 100 }),
                validation_started: Notify::new(),
                validation: Semaphore::new(if paused { 0 } else { 100 }),
            })
        }
    }
    impl TokenRefresher for FakeRefresher {
        fn refresh(&self, registration: Registration) -> BoxFuture<'_, Result<Credentials>> {
            Box::pin(async move {
                assert!(registration.credentials.is_some());
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.exchange_started.notify_one();
                self.response.acquire().await.unwrap().forget();
                // The response is already rotated before the validation phase.
                let renewed = credentials("SECRET-rotated-access", 5000);
                self.validation_started.notify_one();
                self.validation.acquire().await.unwrap().forget();
                Ok(renewed)
            })
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        store: Arc<CredentialStore>,
        backend: Arc<FakeBackend>,
        cache: Arc<TokenCache>,
        clock: Arc<AtomicU64>,
        refresher: Arc<FakeRefresher>,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let backend = FakeBackend::new(vault());
            let store = CredentialStore::injected(directory.path().into(), backend.clone());
            let clock = Arc::new(AtomicU64::new(1000));
            let clock_copy = clock.clone();
            let cache = Arc::new(TokenCache::new(Arc::new(move || {
                clock_copy.load(Ordering::SeqCst)
            })));
            Self {
                _directory: directory,
                store,
                backend,
                cache,
                clock,
                refresher: FakeRefresher::new(false),
            }
        }
        async fn token(&self, id: &str) -> Result<String> {
            self.cache
                .clone()
                .access(self.store.clone(), id.into(), self.refresher.clone())
                .await
        }
        fn reads(&self) -> usize {
            self.backend.reads.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn concurrent_access_coalesces_reads_and_expired_tokens_refresh_once() {
        let fixture = Fixture::new();
        let tokens = futures_util::future::join_all((0..12).map(|_| fixture.token("one"))).await;
        assert!(tokens
            .into_iter()
            .all(|token| token.unwrap() == "SECRET-access-one"));
        assert_eq!(fixture.reads(), 1);
        fixture.clock.store(1950, Ordering::SeqCst);
        let tokens = futures_util::future::join_all((0..12).map(|_| fixture.token("one"))).await;
        assert!(tokens
            .into_iter()
            .all(|token| token.unwrap() == "SECRET-rotated-access"));
        assert_eq!(fixture.reads(), 2);
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn accounts_and_auth_directories_do_not_share_cached_tokens() {
        let one = Fixture::new();
        let two = Fixture::new();
        assert_eq!(one.token("one").await.unwrap(), "SECRET-access-one");
        assert_eq!(one.token("two").await.unwrap(), "SECRET-access-two");
        assert_eq!(one.token("one").await.unwrap(), "SECRET-access-one");
        assert_eq!(one.reads(), 2);
        two.backend
            .vault
            .lock()
            .unwrap()
            .accounts
            .get_mut("one")
            .unwrap()
            .credentials
            .as_mut()
            .unwrap()
            .access_token = "SECRET-other-directory".into();
        assert_eq!(two.token("one").await.unwrap(), "SECRET-other-directory");
        assert_eq!(two.reads(), 1);
        assert!(Arc::ptr_eq(
            &cache_for_directory(&one.store.directory).unwrap(),
            &cache_for_directory(&one.store.directory).unwrap()
        ));
        assert!(!Arc::ptr_eq(
            &cache_for_directory(&one.store.directory).unwrap(),
            &cache_for_directory(&two.store.directory).unwrap()
        ));
    }

    #[tokio::test]
    async fn independent_cache_instances_observe_mutation_and_disconnect_generation() {
        let fixture = Fixture::new();
        let other_cache = Arc::new(TokenCache::new(Arc::new(|| 1000)));
        let other_store =
            CredentialStore::injected(fixture.store.directory.clone(), fixture.backend.clone());
        assert_eq!(fixture.token("one").await.unwrap(), "SECRET-access-one");
        other_cache
            .clone()
            .access(other_store.clone(), "one".into(), fixture.refresher.clone())
            .await
            .unwrap();
        let mut writer = other_store.load_locked().unwrap();
        writer.vault.accounts.get_mut("one").unwrap().credentials =
            Some(credentials("SECRET-updated", 3000));
        writer.save_sync().unwrap();
        assert_eq!(fixture.token("one").await.unwrap(), "SECRET-updated");
        assert_eq!(
            other_cache
                .clone()
                .access(other_store.clone(), "one".into(), fixture.refresher.clone())
                .await
                .unwrap(),
            "SECRET-updated"
        );
        let mut writer = other_store.load_locked().unwrap();
        writer.vault.accounts.get_mut("one").unwrap().credentials = None;
        writer.save_sync().unwrap();
        assert!(fixture
            .token("one")
            .await
            .unwrap_err()
            .to_string()
            .contains("disconnected"));
        assert!(other_cache
            .access(other_store, "one".into(), fixture.refresher.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("disconnected"));
    }

    #[tokio::test]
    async fn explicit_refresh_invalidates_tokens_changed_outside_the_current_process() {
        let fixture = Fixture::new();
        fixture.token("one").await.unwrap();
        fixture
            .backend
            .vault
            .lock()
            .unwrap()
            .accounts
            .get_mut("one")
            .unwrap()
            .credentials = Some(credentials("SECRET-reloaded", 3000));
        fixture
            .store
            .load_locked()
            .unwrap()
            .publish_refreshed_metadata()
            .unwrap();
        assert_eq!(fixture.token("one").await.unwrap(), "SECRET-reloaded");
        assert_eq!(fixture.reads(), 3);
    }

    #[tokio::test]
    async fn seeded_cache_fails_closed_for_missing_invalid_or_pending_invalidation_state() {
        let fixture = Fixture::new();
        fixture.token("one").await.unwrap();
        let path = fixture.store.directory.join("accounts-index.json");
        std::fs::remove_file(&path).unwrap();
        assert!(fixture.token("one").await.is_err());
        std::fs::write(&path, "{}").unwrap();
        assert!(fixture.token("one").await.is_err());
        assert_eq!(
            fixture.reads(),
            1,
            "Untrusted invalidation state must not reuse tokens or silently bootstrap the OS store"
        );
        fixture
            .store
            .load_locked()
            .unwrap()
            .publish_refreshed_metadata()
            .unwrap();
        fixture.token("one").await.unwrap();
        let writer = fixture.store.load_locked().unwrap();
        fixture.backend.fail_write.store(true, Ordering::SeqCst);
        assert!(writer.save_sync().is_err());
        let reads = fixture.reads();
        assert!(fixture.token("one").await.is_err());
        assert_eq!(fixture.reads(), reads);
    }

    #[tokio::test]
    async fn failed_initial_reads_are_coalesced_without_prompt_storms() {
        let fixture = Fixture::new();
        fixture.backend.fail_read.store(true, Ordering::SeqCst);
        let results = futures_util::future::join_all((0..12).map(|_| fixture.token("one"))).await;
        assert!(results.into_iter().all(|result| result.is_err()));
        assert_eq!(fixture.reads(), 1);
    }

    #[tokio::test]
    async fn automatic_catalog_cache_miss_and_expiry_never_read_or_refresh_credentials() {
        let fixture = Fixture::new();
        for _ in 0..12 {
            let error = fixture
                .cache
                .cached_access(fixture.store.clone(), "one")
                .await
                .unwrap_err();
            assert!(error.to_string().starts_with(CREDENTIAL_ACCESS_REQUIRED));
        }
        assert_eq!(fixture.reads(), 0);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 0);
        fixture.token("one").await.unwrap();
        assert_eq!(
            fixture
                .cache
                .cached_access(fixture.store.clone(), "one")
                .await
                .unwrap(),
            "SECRET-access-one"
        );
        fixture.clock.store(1950, Ordering::SeqCst);
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .unwrap_err()
            .to_string()
            .starts_with(CREDENTIAL_ACCESS_REQUIRED));
        assert_eq!(fixture.reads(), 1);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 0);
        // The normal approved inference path still renews and persists once.
        assert_eq!(fixture.token("one").await.unwrap(), "SECRET-rotated-access");
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn automatic_catalog_checks_mutation_disconnect_and_broken_index_without_os_reads() {
        let fixture = Fixture::new();
        fixture.token("one").await.unwrap();
        let mut writer = fixture.store.load_locked().unwrap();
        writer.vault.accounts.get_mut("one").unwrap().credentials = None;
        writer.save_sync().unwrap();
        let reads = fixture.reads();
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .unwrap_err()
            .to_string()
            .starts_with(CREDENTIAL_ACCESS_REQUIRED));
        let path = fixture.store.directory.join("accounts-index.json");
        std::fs::write(&path, "{}").unwrap();
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .is_err());
        std::fs::remove_file(path).unwrap();
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .is_err());
        assert_eq!(fixture.reads(), reads);
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn explicit_metadata_refresh_seeds_valid_tokens_without_extra_os_reads() {
        let fixture = Fixture::new();
        let accounts = fixture
            .cache
            .clone()
            .refresh_metadata(fixture.store.clone())
            .await
            .unwrap();
        assert_eq!(accounts.len(), 3);
        assert_eq!(fixture.reads(), 1);
        assert_eq!(
            fixture
                .cache
                .cached_access(fixture.store.clone(), "one")
                .await
                .unwrap(),
            "SECRET-access-one"
        );
        assert_eq!(
            fixture
                .cache
                .cached_access(fixture.store.clone(), "two")
                .await
                .unwrap(),
            "SECRET-access-two"
        );
        fixture
            .backend
            .vault
            .lock()
            .unwrap()
            .accounts
            .get_mut("one")
            .unwrap()
            .credentials = Some(credentials("SECRET-external-change", 3000));
        fixture
            .backend
            .vault
            .lock()
            .unwrap()
            .accounts
            .get_mut("two")
            .unwrap()
            .credentials
            .as_mut()
            .unwrap()
            .expires_at = 1000;
        fixture
            .cache
            .clone()
            .refresh_metadata(fixture.store.clone())
            .await
            .unwrap();
        assert_eq!(
            fixture
                .cache
                .cached_access(fixture.store.clone(), "one")
                .await
                .unwrap(),
            "SECRET-external-change"
        );
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "two")
            .await
            .is_err());
        assert_eq!(fixture.reads(), 2);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn successful_sign_in_persistence_seeds_cache_but_failed_save_does_not() {
        let fixture = Fixture::new();
        let mut stored = fixture.store.load_locked().unwrap();
        stored.vault.accounts.get_mut("one").unwrap().credentials =
            Some(credentials("SECRET-sign-in", 3000));
        fixture.cache.clone().save_and_seed(stored).await.unwrap();
        assert_eq!(
            fixture
                .cache
                .cached_access(fixture.store.clone(), "one")
                .await
                .unwrap(),
            "SECRET-sign-in"
        );
        assert_eq!(fixture.reads(), 1);
        let mut stored = fixture.store.load_locked().unwrap();
        stored.vault.accounts.get_mut("one").unwrap().credentials =
            Some(credentials("SECRET-unsaved", 3000));
        fixture.backend.fail_write.store(true, Ordering::SeqCst);
        assert!(fixture.cache.clone().save_and_seed(stored).await.is_err());
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .unwrap_err()
            .to_string()
            .starts_with(CREDENTIAL_ACCESS_REQUIRED));
        assert_eq!(fixture.reads(), 2);
    }

    #[tokio::test]
    async fn cancelled_sign_in_save_finishes_persistence_and_seeds_without_another_read() {
        let fixture = Fixture::new();
        let stored = fixture.store.load_locked().unwrap();
        let (save_started, save_start) = tokio::sync::oneshot::channel();
        let (release_save, wait_save) = std::sync::mpsc::channel();
        *fixture.backend.write_hook.lock().unwrap() = Some(Box::new(move || {
            let _ = save_started.send(());
            wait_save.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let cache = fixture.cache.clone();
        let caller = tokio::spawn(async move { cache.save_and_seed(stored).await });
        tokio::time::timeout(Duration::from_secs(2), save_start)
            .await
            .unwrap()
            .unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let competitor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.store.directory.join("accounts.lock"))
            .unwrap();
        assert!(competitor.try_lock_exclusive().is_err());
        release_save.send(()).unwrap();
        let token = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(token) = fixture
                    .cache
                    .cached_access(fixture.store.clone(), "one")
                    .await
                {
                    break token;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(token, "SECRET-access-one");
        assert_eq!(fixture.reads(), 1);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 1);
        competitor.try_lock_exclusive().unwrap();
    }

    #[tokio::test]
    async fn sign_in_save_releases_vault_before_waiting_for_cache_and_skips_newer_generation() {
        let fixture = Fixture::new();
        let stored = fixture.store.load_locked().unwrap();
        let cache_guard = fixture.cache.state.lock().await;
        let (save_started, save_start) = tokio::sync::oneshot::channel();
        *fixture.backend.write_hook.lock().unwrap() = Some(Box::new(move || {
            let _ = save_started.send(());
        }));
        let cache = fixture.cache.clone();
        let caller = tokio::spawn(async move { cache.save_and_seed(stored).await });
        // This would time out if save waited for the cache while owning the vault.
        tokio::time::timeout(Duration::from_secs(2), save_start)
            .await
            .unwrap()
            .unwrap();
        let competitor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.store.directory.join("accounts.lock"))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while competitor.try_lock_exclusive().is_err() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fs2::FileExt::unlock(&competitor).unwrap();
        let mut newer = fixture.store.load_locked().unwrap();
        newer.vault.accounts.get_mut("one").unwrap().credentials = None;
        newer.save_sync().unwrap();
        drop(cache_guard);
        caller.await.unwrap().unwrap();
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .is_err());
        assert!(
            fixture.cache.state.lock().await.tokens.is_empty(),
            "The earlier sign-in snapshot must not replace the concurrent disconnect"
        );
        assert_eq!(fixture.reads(), 2);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn explicit_model_retry_bypasses_failure_backoff_without_automatic_prompt_retry() {
        let fixture = Fixture::new();
        fixture.backend.fail_read.store(true, Ordering::SeqCst);
        assert!(fixture.token("one").await.is_err());
        fixture.backend.fail_read.store(false, Ordering::SeqCst);
        assert!(fixture.token("one").await.is_err());
        assert!(fixture
            .cache
            .cached_access(fixture.store.clone(), "one")
            .await
            .is_err());
        assert_eq!(fixture.reads(), 1);
        assert_eq!(
            fixture
                .cache
                .clone()
                .access_with_intent(
                    fixture.store.clone(),
                    "one".into(),
                    fixture.refresher.clone(),
                    true
                )
                .await
                .unwrap(),
            "SECRET-access-one"
        );
        assert_eq!(fixture.reads(), 2);
    }

    #[tokio::test]
    async fn automatic_discovery_does_not_wait_for_an_active_credential_transaction() {
        let fixture = Fixture::new();
        let _active = fixture.cache.state.lock().await;
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            fixture.cache.cached_access(fixture.store.clone(), "one"),
        )
        .await
        .unwrap();
        assert!(result
            .unwrap_err()
            .to_string()
            .starts_with(CREDENTIAL_ACCESS_REQUIRED));
        assert_eq!(fixture.reads(), 0);
    }

    async fn cancelled_refresh_still_persists(after_response: bool) {
        let mut fixture = Fixture::new();
        fixture.clock.store(1950, Ordering::SeqCst);
        fixture.refresher = FakeRefresher::new(true);
        let (save_started, save_start) = tokio::sync::oneshot::channel();
        let (release_save, wait_save) = std::sync::mpsc::channel();
        *fixture.backend.write_hook.lock().unwrap() = Some(Box::new(move || {
            let _ = save_started.send(());
            wait_save.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let cache = fixture.cache.clone();
        let store = fixture.store.clone();
        let refresher = fixture.refresher.clone();
        let caller =
            tokio::spawn(async move { cache.access(store, "one".into(), refresher).await });
        tokio::time::timeout(
            Duration::from_secs(2),
            fixture.refresher.exchange_started.notified(),
        )
        .await
        .unwrap();
        if after_response {
            fixture.refresher.response.add_permits(1);
            tokio::time::timeout(
                Duration::from_secs(2),
                fixture.refresher.validation_started.notified(),
            )
            .await
            .unwrap();
        }
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let competitor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(fixture.store.directory.join("accounts.lock"))
            .unwrap();
        assert!(competitor.try_lock_exclusive().is_err());
        if !after_response {
            fixture.refresher.response.add_permits(1);
        }
        fixture.refresher.validation.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), save_start)
            .await
            .unwrap()
            .unwrap();
        assert!(
            competitor.try_lock_exclusive().is_err(),
            "Lock must remain held while OS persistence is blocked"
        );
        assert!(
            fixture.store.account_status().is_err(),
            "Pending write must invalidate every cached token"
        );
        release_save.send(()).unwrap();
        let token = tokio::time::timeout(Duration::from_secs(2), fixture.token("one"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token, "SECRET-rotated-access");
        assert_eq!(fixture.refresher.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.reads(), 1);
        assert_eq!(fixture.backend.writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixture.backend.vault.lock().unwrap().accounts["one"]
                .credentials
                .as_ref()
                .unwrap()
                .refresh_token,
            "SECRET-refresh-SECRET-rotated-access"
        );
        competitor.try_lock_exclusive().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_during_token_exchange_finishes_rotation_and_persistence() {
        cancelled_refresh_still_persists(false).await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_after_rotated_response_during_validation_preserves_new_credentials() {
        cancelled_refresh_still_persists(true).await;
    }
}
