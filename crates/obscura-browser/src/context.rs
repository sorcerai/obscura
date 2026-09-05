use std::path::PathBuf;
use std::sync::Arc;

use obscura_net::{CookieJar, ObscuraHttpClient, RobotsCache};

pub struct BrowserContext {
    pub id: String,
    pub cookie_jar: Arc<CookieJar>,
    pub http_client: Arc<ObscuraHttpClient>,
    pub user_agent: String,
    pub platform: String,
    pub ua_platform: String,
    pub ua_platform_version: String,
    pub proxy_url: Option<String>,
    pub robots_cache: Arc<RobotsCache>,
    pub obey_robots: bool,
    pub stealth: bool,
    /// When true, CDP-driven navigation to file:// URLs is permitted.
    /// Default is false: a remote CDP client cannot point the browser
    /// at /etc/shadow even if Obscura is running as a privileged user.
    /// Flip on via `obscura serve --allow-file-access` for legitimate
    /// local-HTML testing workflows. The CLI's own `obscura fetch
    /// file://...` path is unaffected because it does not go through
    /// the CDP server.
    pub allow_file_access: bool,
    pub storage_dir: Option<PathBuf>,
    /// When true, the http client allows fetching localhost / RFC1918 /
    /// link-local addresses. Set via `--allow-private-network` (issue #33).
    /// Independent of `allow_file_access` because they cover different threat
    /// models: file:// is a local file-system read, while private-network is
    /// the broader SSRF gate from issue #4.
    pub allow_private_network: bool,
    pub pending_origins: std::sync::Mutex<Vec<obscura_net::StorageStateOrigin>>,
}

impl BrowserContext {
    pub fn new(id: String) -> Self {
        Self::_new_inner(id, None, false, None, None, false)
    }

    /// Create a BrowserContext with an optional storage directory.
    /// When `storage_dir` is set, cookies are automatically loaded from
    /// `{storage_dir}/cookies.json` on creation.
    pub fn with_storage(id: String, storage_dir: Option<PathBuf>) -> Self {
        Self::_new_inner(id, None, false, None, storage_dir, false)
    }

    /// Create a BrowserContext with full options including storage_dir.
    pub fn with_storage_full(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, storage_dir, false)
    }

    /// Variant that also accepts the `allow_private_network` opt-in. All
    /// pre-existing constructors default it to `false`; callers that want the
    /// CLI's `--allow-private-network` (issue #33) behaviour go through here.
    pub fn with_storage_and_network(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        Self::_new_inner(
            id,
            proxy_url,
            stealth,
            user_agent,
            storage_dir,
            allow_private_network,
        )
    }

    fn _new_inner(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
        storage_dir: Option<PathBuf>,
        allow_private_network: bool,
    ) -> Self {
        let cookie_jar = Arc::new(CookieJar::new());
        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            proxy_url.as_deref(),
            allow_private_network,
        );
        if stealth {
            client.block_trackers = true;
        }
        let profile = crate::profiles::select_profile();
        let resolved_ua = user_agent.unwrap_or_else(|| profile.user_agent.to_string());
        let platform = profile.platform.to_string();
        let ua_platform = profile.ua_platform.to_string();
        let ua_platform_version = profile.ua_platform_version.to_string();
        // Sync the http client's UA at construction so navigation requests pick it
        // up before any async setup runs. The lock has no other holders here, so
        // try_write always succeeds; we fall back silently if it ever fails.
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = resolved_ua.clone();
        }
        let http_client = Arc::new(client);
        let ctx = BrowserContext {
            id,
            cookie_jar,
            http_client,
            user_agent: resolved_ua,
            platform,
            ua_platform,
            ua_platform_version,
            proxy_url,
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: false,
            stealth,
            allow_file_access: false,
            storage_dir,
            allow_private_network,
            pending_origins: std::sync::Mutex::new(Vec::new()),
        };

        // Restore storage state / cookies from disk if storage_dir is configured
        if let Some(ref dir) = ctx.storage_dir {
            let state_path = dir.join("storage_state.json");
            if state_path.exists() {
                match ctx.load_storage_state_file(&state_path) {
                    Ok(n) => {
                        tracing::info!(
                            "Loaded storage state ({} cookies) from {}",
                            n,
                            state_path.display()
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load storage state from {}: {}",
                            state_path.display(),
                            e
                        );
                    }
                }
            } else {
                let cookie_path = dir.join("cookies.json");
                if cookie_path.exists() {
                    match ctx.cookie_jar.load_from_file(&cookie_path) {
                        Ok(n) if n > 0 => {
                            tracing::info!("Loaded {} cookies from {}", n, cookie_path.display());
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(
                                "Failed to load cookies from {}: {}",
                                cookie_path.display(),
                                e
                            );
                        }
                    }
                }
            }
        }

        ctx
    }

    /// Load a Playwright / Reach storage state JSON file into this context.
    /// Imports cookies into the context's cookie jar and stashes origins in `pending_origins`.
    /// Returns the number of cookies imported.
    pub fn load_storage_state_file(&self, path: &std::path::Path) -> anyhow::Result<usize> {
        if !path.exists() {
            return Ok(0);
        }
        let data = std::fs::read_to_string(path)?;
        let val: serde_json::Value = serde_json::from_str(&data)?;
        let (cookie_count, origins) = self.cookie_jar.import_storage_state(&val)?;
        if !origins.is_empty() {
            if let Ok(mut pending) = self.pending_origins.lock() {
                pending.extend(origins);
            }
        }
        Ok(cookie_count)
    }

    pub fn with_options(id: String, proxy_url: Option<String>, stealth: bool) -> Self {
        Self::with_full_options(id, proxy_url, stealth, None)
    }

    pub fn with_full_options(
        id: String,
        proxy_url: Option<String>,
        stealth: bool,
        user_agent: Option<String>,
    ) -> Self {
        Self::_new_inner(id, proxy_url, stealth, user_agent, None, false)
    }

    pub fn with_proxy(id: String, proxy_url: Option<String>) -> Self {
        Self::with_options(id, proxy_url, false)
    }

    /// Create a context with the same browser configuration but independent
    /// mutable network state. Persistent copies start with the template's
    /// current cookies; incognito copies start empty and never write to the
    /// template's storage directory.
    pub fn isolated_copy(&self, id: String, persistent: bool) -> Self {
        let cookie_jar = Arc::new(CookieJar::new());
        if persistent {
            cookie_jar.set_cookies_from_cdp(self.cookie_jar.get_all_cookies());
        }

        let mut client = ObscuraHttpClient::with_full_options(
            cookie_jar.clone(),
            self.proxy_url.as_deref(),
            self.allow_private_network,
        );
        if self.stealth {
            client.block_trackers = true;
        }
        if let Ok(mut guard) = client.user_agent.try_write() {
            *guard = self.user_agent.clone();
        }

        BrowserContext {
            id,
            cookie_jar,
            http_client: Arc::new(client),
            user_agent: self.user_agent.clone(),
            platform: self.platform.clone(),
            ua_platform: self.ua_platform.clone(),
            ua_platform_version: self.ua_platform_version.clone(),
            proxy_url: self.proxy_url.clone(),
            robots_cache: Arc::new(RobotsCache::new()),
            obey_robots: self.obey_robots,
            stealth: self.stealth,
            allow_file_access: self.allow_file_access,
            storage_dir: persistent.then(|| self.storage_dir.clone()).flatten(),
            allow_private_network: self.allow_private_network,
            pending_origins: std::sync::Mutex::new(if persistent {
                self.pending_origins
                    .lock()
                    .map(|g| g.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            }),
        }
    }

    /// Export all cookies and pending origins in Playwright storage state format.
    pub fn export_storage_state(&self) -> serde_json::Value {
        let cookies = self.cookie_jar.export_storage_state_cookies();
        let origins: Vec<serde_json::Value> = self
            .pending_origins
            .lock()
            .map(|pending| {
                pending
                    .iter()
                    .filter_map(|po| serde_json::to_value(po).ok())
                    .collect()
            })
            .unwrap_or_default();
        serde_json::json!({
            "cookies": cookies,
            "origins": origins,
        })
    }

    /// Save storage state to a JSON file atomically via tempfile then rename.
    pub fn save_storage_state_file(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;
        let state = self.export_storage_state();
        let json = serde_json::to_string_pretty(&state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(json.as_bytes())?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Persist cookies and storage state to disk if storage_dir is configured.
    /// Called during graceful shutdown.
    pub fn save_cookies(&self) {
        if let Some(ref dir) = self.storage_dir {
            let _ = std::fs::create_dir_all(dir);
            let cookie_path = dir.join("cookies.json");
            if let Err(e) = self.cookie_jar.save_to_file(&cookie_path) {
                tracing::warn!("Failed to save cookies to {}: {}", cookie_path.display(), e);
            } else {
                tracing::info!("Saved cookies to {}", cookie_path.display());
            }

            let state_path = dir.join("storage_state.json");
            if let Err(e) = self.save_storage_state_file(&state_path) {
                tracing::warn!(
                    "Failed to save storage state to {}: {}",
                    state_path.display(),
                    e
                );
            } else {
                tracing::info!("Saved storage state to {}", state_path.display());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_propagates_user_agent_to_http_client() {
        let ctx = BrowserContext::with_full_options(
            "test".to_string(),
            None,
            false,
            Some("Custom-UA/1.0".to_string()),
        );
        assert_eq!(ctx.user_agent, "Custom-UA/1.0");
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert_eq!(client_ua, "Custom-UA/1.0");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_full_options_falls_back_to_chrome_default() {
        let ctx = BrowserContext::with_full_options("test".to_string(), None, false, None);
        assert!(ctx.user_agent.contains("Chrome"));
        let client_ua = ctx.http_client.user_agent.read().await.clone();
        assert!(client_ua.contains("Chrome"));
        assert_eq!(ctx.user_agent, client_ua);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_options_keeps_default_user_agent() {
        let ctx = BrowserContext::with_options("test".to_string(), None, false);
        assert!(ctx.user_agent.contains("Chrome"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn isolated_copy_does_not_share_mutable_network_state() {
        let source = BrowserContext::with_full_options(
            "source".to_string(),
            None,
            false,
            Some("Template-UA/1.0".to_string()),
        );
        source.cookie_jar.set_cookie(
            "sid=source",
            &url::Url::parse("https://example.com").unwrap(),
        );

        let persistent = source.isolated_copy("persistent".to_string(), true);
        let incognito = source.isolated_copy("incognito".to_string(), false);

        assert_eq!(persistent.cookie_jar.get_all_cookies().len(), 1);
        assert!(incognito.cookie_jar.get_all_cookies().is_empty());
        persistent.cookie_jar.clear();
        persistent
            .http_client
            .set_user_agent("Changed-UA/2.0")
            .await;

        assert_eq!(source.cookie_jar.get_all_cookies().len(), 1);
        assert_eq!(
            source.http_client.user_agent.read().await.as_str(),
            "Template-UA/1.0"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_load_storage_state_file_and_inject_on_navigation() {
        let tmp = tempfile::tempdir().unwrap();
        let state_path = tmp.path().join("storage_state.json");
        let state_json = serde_json::json!({
            "cookies": [
                {
                    "name": "auth_token",
                    "value": "xyz123",
                    "domain": "example.com",
                    "path": "/",
                    "httpOnly": true,
                    "sameSite": "Strict"
                }
            ],
            "origins": [
                {
                    "origin": "https://example.com",
                    "localStorage": [
                        { "name": "theme", "value": "dark" }
                    ]
                }
            ]
        });
        std::fs::write(&state_path, serde_json::to_string(&state_json).unwrap()).unwrap();

        let ctx = Arc::new(BrowserContext::with_storage(
            "test".into(),
            Some(tmp.path().to_path_buf()),
        ));
        // storage_state.json was loaded automatically on context creation
        assert_eq!(ctx.cookie_jar.get_all_cookies().len(), 1);
        assert_eq!(ctx.pending_origins.lock().unwrap().len(), 1);

        let mut page = crate::page::Page::new("tab".into(), ctx.clone());
        page.navigate("data:text/html,<html><body>test</body></html>")
            .await
            .unwrap();
        // Set page url to matching origin
        page.url = Some(url::Url::parse("https://example.com/home").unwrap());
        page.inject_pending_storage();

        // Pending origin should be drained
        assert_eq!(ctx.pending_origins.lock().unwrap().len(), 0);

        // localStorage should now have the injected key
        let val = page.evaluate("localStorage.getItem('theme')");
        assert_eq!(val, serde_json::json!("dark"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_page_navigate_drains_and_injects_matching_origin() {
        let ctx = Arc::new(BrowserContext::new("test".into()));
        ctx.pending_origins
            .lock()
            .unwrap()
            .push(obscura_net::StorageStateOrigin {
                origin: "http://127.0.0.1:9000".into(),
                local_storage: vec![obscura_net::StorageItem::Named {
                    name: "session".into(),
                    value: "sess_123".into(),
                }],
                session_storage: vec![],
            });

        let mut page = crate::page::Page::new("tab".into(), ctx.clone());
        page.navigate("about:blank").await.unwrap();
        assert_eq!(ctx.pending_origins.lock().unwrap().len(), 1);

        page.url = Some(url::Url::parse("http://127.0.0.1:9000/").unwrap());
        page.inject_pending_storage();
        assert_eq!(ctx.pending_origins.lock().unwrap().len(), 0);
        let val = page.evaluate("localStorage.getItem('session')");
        assert_eq!(val, serde_json::json!("sess_123"));
    }
}
