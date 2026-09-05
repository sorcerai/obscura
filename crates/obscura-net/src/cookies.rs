use std::collections::HashMap;
use std::sync::RwLock;
use url::Url;

const DEFAULT_SAME_SITE: &str = "Lax";

/// SameSite is case-insensitive per RFC 6265bis; normalize a present value to
/// title-case so stored cookies compare equal regardless of how they were sent.
/// Unrecognized values fall back to Lax per spec.
fn normalize_same_site(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "strict" => "Strict",
        "none" => "None",
        _ => "Lax",
    }
    .to_string()
}

/// The jar key for a domain. RFC 6265 4.1.2.3 ignores a leading dot, and hosts are
/// case-insensitive, so both spellings have to collapse before they reach the map.
/// Not intended for `domain_matches`, which compares without allocating on the
/// per-request path.
pub fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_start_matches('.').to_lowercase()
}

type CookieMap = HashMap<String, HashMap<(String, String), CookieEntry>>;

pub struct CookieJar {
    /// domain -> (name, path) -> entry. RFC 6265 §5.3 identifies a cookie by
    /// (name, domain, path); the outer map scopes by domain and the inner key
    /// carries name+path so same-name cookies on different paths coexist
    /// instead of clobbering each other.
    cookies: RwLock<CookieMap>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CookieEntry {
    name: String,
    value: String,
    path: String,
    domain: String,
    /// Cookies set without a Domain attribute are host-only: sent to the exact
    /// origin host and never to subdomains. `serde(default)` keeps persisted
    /// cookie files from before this field existed loadable.
    #[serde(default)]
    host_only: bool,
    secure: bool,
    http_only: bool,
    expires: Option<u64>,
    same_site: String,
}

impl CookieJar {
    pub fn new() -> Self {
        CookieJar {
            cookies: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_cookie(&self, set_cookie_str: &str, url: &Url) {
        let parts: Vec<&str> = set_cookie_str.splitn(2, ';').collect();
        let name_value = parts[0].trim();
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => return,
        };

        let request_host = url.host_str().unwrap_or("").to_lowercase();
        let mut domain_attr: Option<String> = None;
        let mut path = default_cookie_path(url.path());
        let mut secure = false;
        let mut http_only = false;
        let mut expires: Option<u64> = None;
        let mut same_site = "Lax".to_string();

        if parts.len() > 1 {
            for attr in parts[1].split(';') {
                let attr = attr.trim();
                if let Some((key, val)) = attr.split_once('=') {
                    match key.trim().to_lowercase().as_str() {
                        "domain" => {
                            domain_attr = Some(canonical_domain(val));
                        }
                        "path" => {
                            path = val.trim().to_string();
                        }
                        "expires" => {
                            if let Ok(ts) = parse_http_date(val.trim()) {
                                expires = Some(ts);
                            }
                        }
                        "max-age" => {
                            if let Ok(secs) = val.trim().parse::<i64>() {
                                if secs <= 0 {
                                    expires = Some(0);
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    expires = Some(now + secs as u64);
                                }
                            }
                        }
                        "samesite" => {
                            same_site = normalize_same_site(val);
                        }
                        _ => {}
                    }
                } else {
                    match attr.to_lowercase().as_str() {
                        "secure" => secure = true,
                        "httponly" => http_only = true,
                        _ => {}
                    }
                }
            }
        }

        // Validate Domain against the response origin (RFC 6265): an unrelated
        // or public-suffix Domain is ignored so a response from attacker.test
        // cannot scope a cookie to victim.test (GHSA-f22c-8v6q-v6h6).
        let (domain, host_only) = match resolve_cookie_domain(&request_host, domain_attr.as_deref())
        {
            Some(d) => d,
            None => return,
        };

        if let Some(exp) = expires {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if exp <= now {
                let mut cookies = self.cookies.write().unwrap();
                if let Some(domain_cookies) = cookies.get_mut(&domain) {
                    domain_cookies.remove(&(name.clone(), path.clone()));
                }
                return;
            }
        }

        let entry = CookieEntry {
            name: name.clone(),
            value,
            path: path.clone(),
            domain: domain.clone(),
            host_only,
            secure,
            http_only,
            expires,
            same_site,
        };

        let mut cookies = self.cookies.write().unwrap();
        cookies
            .entry(domain)
            .or_default()
            .insert((name, path), entry);
    }

    pub fn get_cookie_header(&self, url: &Url) -> String {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        let is_secure = url.scheme() == "https";
        let cookies = self.cookies.read().unwrap();

        let mut matching: Vec<String> = Vec::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (domain, domain_cookies) in cookies.iter() {
            if !domain_matches(host, domain) {
                continue;
            }
            for entry in domain_cookies.values() {
                if entry.host_only && !host.eq_ignore_ascii_case(domain) {
                    continue;
                }
                if let Some(exp) = entry.expires {
                    if exp <= now {
                        continue;
                    }
                }
                if entry.secure && !is_secure {
                    continue;
                }
                if !path_matches(path, &entry.path) {
                    continue;
                }
                matching.push(format!("{}={}", entry.name, entry.value));
            }
        }

        matching.join("; ")
    }

    pub fn get_all_cookies(&self) -> Vec<CookieInfo> {
        let cookies = self.cookies.read().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut result = Vec::new();
        for domain_cookies in cookies.values() {
            for entry in domain_cookies.values() {
                if entry.expires.is_some_and(|expires| expires <= now) {
                    continue;
                }
                result.push(CookieInfo {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                    domain: entry.domain.clone(),
                    path: entry.path.clone(),
                    secure: entry.secure,
                    http_only: entry.http_only,
                    same_site: entry.same_site.clone(),
                    expires: entry.expires.map(|e| e as i64),
                });
            }
        }
        result
    }

    pub fn set_cookies_from_cdp(&self, cookies: Vec<CookieInfo>) {
        let mut jar = self.cookies.write().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        for cookie in cookies {
            // RFC 6265 4.1.2.3: the leading dot is ignored. The Set-Cookie path already strips
            // it, but this code did not, which is why one cookie became two entries.
            let domain = canonical_domain(&cookie.domain);
            if cookie
                .expires
                .is_some_and(|expires| expires == 0 || (expires > 0 && expires <= now))
            {
                if let Some(domain_cookies) = jar.get_mut(&domain) {
                    domain_cookies.retain(|_key, entry| {
                        entry.name != cookie.name || entry.path != cookie.path
                    });
                }
                continue;
            }
            let same_site = if cookie.same_site.is_empty() {
                DEFAULT_SAME_SITE.to_string()
            } else {
                normalize_same_site(&cookie.same_site)
            };
            let expires = cookie
                .expires
                .and_then(|e| if e > 0 { Some(e as u64) } else { None });
            let entry = CookieEntry {
                name: cookie.name.clone(),
                value: cookie.value,
                path: cookie.path.clone(),
                domain: domain.clone(),
                // CDP/persisted import is trusted; honor the explicit domain as
                // domain-scoped (matches the prior behavior).
                host_only: false,
                secure: cookie.secure,
                http_only: cookie.http_only,
                expires,
                same_site,
            };
            jar.entry(domain)
                .or_default()
                .insert((cookie.name, cookie.path), entry);
        }
    }

    pub fn get_js_visible_cookies(&self, url: &Url) -> String {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        let is_secure = url.scheme() == "https";
        let cookies = self.cookies.read().unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut matching: Vec<String> = Vec::new();

        for (domain, domain_cookies) in cookies.iter() {
            if !domain_matches(host, domain) {
                continue;
            }
            for entry in domain_cookies.values() {
                if entry.host_only && !host.eq_ignore_ascii_case(domain) {
                    continue;
                }
                if entry.http_only {
                    continue;
                }
                if let Some(exp) = entry.expires {
                    if exp <= now {
                        continue;
                    }
                }
                if entry.secure && !is_secure {
                    continue;
                }
                if !path_matches(path, &entry.path) {
                    continue;
                }
                matching.push(format!("{}={}", entry.name, entry.value));
            }
        }

        matching.join("; ")
    }

    pub fn set_cookie_from_js(&self, cookie_str: &str, url: &Url) {
        let parts: Vec<&str> = cookie_str.splitn(2, ';').collect();
        let name_value = parts[0].trim();
        let (name, value) = match name_value.split_once('=') {
            Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
            None => return,
        };

        let request_host = url.host_str().unwrap_or("").to_lowercase();
        let mut domain_attr: Option<String> = None;
        let mut path = default_cookie_path(url.path());
        let mut secure = false;
        let mut expires: Option<u64> = None;
        let mut same_site = "Lax".to_string();

        if parts.len() > 1 {
            for attr in parts[1].split(';') {
                let attr = attr.trim();
                if let Some((key, val)) = attr.split_once('=') {
                    match key.trim().to_lowercase().as_str() {
                        "domain" => {
                            domain_attr = Some(canonical_domain(val));
                        }
                        "path" => {
                            path = val.trim().to_string();
                        }
                        "expires" => {
                            if let Ok(ts) = parse_http_date(val.trim()) {
                                expires = Some(ts);
                            }
                        }
                        "max-age" => {
                            if let Ok(secs) = val.trim().parse::<i64>() {
                                if secs <= 0 {
                                    expires = Some(0);
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    expires = Some(now + secs as u64);
                                }
                            }
                        }
                        "samesite" => {
                            same_site = normalize_same_site(val);
                        }
                        _ => {}
                    }
                } else if attr.eq_ignore_ascii_case("secure") {
                    secure = true;
                }
            }
        }

        let (domain, host_only) = match resolve_cookie_domain(&request_host, domain_attr.as_deref())
        {
            Some(d) => d,
            None => return,
        };

        if let Some(exp) = expires {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if exp <= now {
                let mut cookies = self.cookies.write().unwrap();
                if let Some(domain_cookies) = cookies.get_mut(&domain) {
                    domain_cookies.remove(&(name.clone(), path.clone()));
                }
                return;
            }
        }

        let entry = CookieEntry {
            name: name.clone(),
            value,
            path: path.clone(),
            domain: domain.clone(),
            host_only,
            secure,
            http_only: false,
            expires,
            same_site,
        };

        let mut cookies = self.cookies.write().unwrap();
        cookies
            .entry(domain)
            .or_default()
            .insert((name, path), entry);
    }

    pub fn delete_cookie(&self, name: &str, domain: &str) {
        let mut cookies = self.cookies.write().unwrap();
        if domain.is_empty() {
            for domain_cookies in cookies.values_mut() {
                domain_cookies.retain(|_k, e| e.name != name);
            }
        } else if let Some(domain_cookies) = cookies.get_mut(canonical_domain(domain).as_str()) {
            domain_cookies.retain(|_k, e| e.name != name);
        }
    }

    pub fn delete_cookies_filtered(&self, name: &str, domain: &str, path: Option<&str>) {
        let mut cookies = self.cookies.write().unwrap();
        let matches_path = |entry_path: &str| match path {
            Some(p) => entry_path == p,
            None => true,
        };
        if domain.is_empty() {
            for domain_cookies in cookies.values_mut() {
                domain_cookies.retain(|_k, e| !(e.name == name && matches_path(&e.path)));
            }
        } else if let Some(domain_cookies) = cookies.get_mut(canonical_domain(domain).as_str()) {
            domain_cookies.retain(|_k, e| !(e.name == name && matches_path(&e.path)));
        }
    }

    pub fn clear(&self) {
        self.cookies.write().unwrap().clear();
    }

    /// Serialize all non-expired cookies to a JSON file.
    /// Writes atomically via tempfile then rename.
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        use std::io::Write;

        let cookies = self.cookies.read().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut all: Vec<CookieInfo> = Vec::new();
        for domain_cookies in cookies.values() {
            for entry in domain_cookies.values() {
                if let Some(exp) = entry.expires {
                    if exp <= now {
                        continue;
                    }
                }
                all.push(CookieInfo {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                    domain: entry.domain.clone(),
                    path: entry.path.clone(),
                    secure: entry.secure,
                    http_only: entry.http_only,
                    same_site: entry.same_site.clone(),
                    expires: entry.expires.map(|e| e as i64),
                });
            }
        }

        let json = serde_json::to_string_pretty(&all)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut tmp =
            tempfile::NamedTempFile::new_in(path.parent().unwrap_or(std::path::Path::new(".")))?;
        tmp.write_all(json.as_bytes())?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Load cookies from a JSON file into the jar.
    /// Merges with existing cookies (does not clear).
    /// Returns the number of cookies loaded.
    pub fn load_from_file(&self, path: &std::path::Path) -> Result<usize, std::io::Error> {
        if !path.exists() {
            return Ok(0);
        }
        let data = std::fs::read_to_string(path)?;
        let cookies: Vec<CookieInfo> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let count = cookies.len();
        self.set_cookies_from_cdp(cookies);
        Ok(count)
    }

    /// Import cookies and origins from a Playwright/Reach storage state JSON object.
    /// Session cookies (expires <= 0.0 or None) are preserved and not purged.
    /// Returns the number of cookies loaded and the list of origin storage items.
    pub fn import_storage_state(
        &self,
        v: &serde_json::Value,
    ) -> Result<(usize, Vec<StorageStateOrigin>), serde_json::Error> {
        let state: StorageState = if let Some(s) = v.as_str() {
            serde_json::from_str(s)?
        } else if v.is_array() {
            let cookies: Vec<StorageStateCookie> = serde_json::from_value(v.clone())?;
            StorageState {
                cookies,
                origins: Vec::new(),
                jar_version: 0,
            }
        } else {
            serde_json::from_value(v.clone())?
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut jar = self.cookies.write().unwrap();
        let mut count = 0;

        for cookie in state.cookies {
            let domain = canonical_domain(&cookie.domain);
            if domain.is_empty() {
                continue;
            }

            // Expiration: <= 0.0 is a session cookie (never expired on import).
            // Only strictly positive expiration timestamps are compared to now.
            let (is_expired, expires_u64) = match cookie.expires {
                Some(exp) if exp > 0.0 => {
                    let exp_u64 = exp as u64;
                    (exp_u64 <= now, Some(exp_u64))
                }
                _ => (false, None),
            };

            if is_expired {
                if let Some(domain_cookies) = jar.get_mut(&domain) {
                    domain_cookies.retain(|_key, entry| {
                        entry.name != cookie.name || entry.path != cookie.path
                    });
                }
                continue;
            }

            let path = if cookie.path.is_empty() {
                "/".to_string()
            } else {
                cookie.path.clone()
            };

            let same_site = if cookie.same_site.is_empty() {
                DEFAULT_SAME_SITE.to_string()
            } else {
                normalize_same_site(&cookie.same_site)
            };

            // Playwright standard: leading dot indicates domain cookie, absence indicates host-only.
            let host_only = !cookie.domain.starts_with('.');

            let entry = CookieEntry {
                name: cookie.name.clone(),
                value: cookie.value,
                path: path.clone(),
                domain: domain.clone(),
                host_only,
                secure: cookie.secure,
                http_only: cookie.http_only,
                expires: expires_u64,
                same_site,
            };

            jar.entry(domain)
                .or_default()
                .insert((cookie.name, path), entry);
            count += 1;
        }

        Ok((count, state.origins))
    }

    /// Export all non-expired cookies in Playwright standard format.
    /// Playwright uses `httpOnly`, `sameSite`, and `expires: -1.0` for session cookies.
    pub fn export_storage_state_cookies(&self) -> Vec<serde_json::Value> {
        let cookies = self.cookies.read().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut result = Vec::new();
        for domain_cookies in cookies.values() {
            for entry in domain_cookies.values() {
                if let Some(exp) = entry.expires {
                    if exp <= now {
                        continue;
                    }
                }

                let domain = if entry.host_only || entry.domain.starts_with('.') {
                    entry.domain.clone()
                } else {
                    format!(".{}", entry.domain)
                };

                let same_site = if entry.same_site.is_empty() {
                    DEFAULT_SAME_SITE.to_string()
                } else {
                    normalize_same_site(&entry.same_site)
                };

                let expires = entry.expires.map(|e| e as f64).unwrap_or(-1.0);

                result.push(serde_json::json!({
                    "name": entry.name,
                    "value": entry.value,
                    "domain": domain,
                    "path": entry.path,
                    "expires": expires,
                    "httpOnly": entry.http_only,
                    "secure": entry.secure,
                    "sameSite": same_site,
                }));
            }
        }

        result.sort_by(|a, b| {
            let d_a = a.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let d_b = b.get("domain").and_then(|v| v.as_str()).unwrap_or("");
            let p_a = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let p_b = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let n_a = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let n_b = b.get("name").and_then(|v| v.as_str()).unwrap_or("");
            (d_a, p_a, n_a).cmp(&(d_b, p_b, n_b))
        });

        result
    }

    /// Sanitize a domain string matching reach's domain sanitization.
    pub fn sanitize_domain(domain: &str) -> String {
        sanitize_domain(domain)
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}

fn root_path() -> String {
    "/".into()
}

/// Sanitize a domain string matching reach's domain sanitization
/// (strip protocol, www, trailing dots, invalid chars).
pub fn sanitize_domain(domain: &str) -> String {
    let mut s = domain.trim();

    // Strip scheme if present (e.g. "https://", "http://", "ftp://")
    if let Some(pos) = s.find("://") {
        s = &s[pos + 3..];
    } else if let Some(stripped) = s.strip_prefix("//") {
        s = stripped;
    }

    // Strip path, query, and fragment (e.g. "/login", "?foo=bar", "#fragment")
    if let Some(pos) = s.find(['/', '?', '#']) {
        s = &s[..pos];
    }

    // Strip user info if present (e.g. "user:pass@host")
    if let Some(pos) = s.rfind('@') {
        s = &s[pos + 1..];
    }

    // Strip port if present (e.g. "github.com:443" or "[::1]:8080")
    if s.starts_with('[') {
        if let Some(end_bracket) = s.find(']') {
            s = &s[..=end_bracket];
        }
    } else if let Some(pos) = s.rfind(':') {
        let port_candidate = &s[pos + 1..];
        if port_candidate.chars().all(|c| c.is_ascii_digit()) && !port_candidate.is_empty() {
            s = &s[..pos];
        }
    }

    let mut lower = s.to_ascii_lowercase();

    // Repeatedly trim dots/underscores and strip leading "www."
    loop {
        let trimmed = lower.trim_matches(|c| c == '.' || c == '_' || c == '/');
        if let Some(stripped) = trimmed.strip_prefix("www.") {
            lower = stripped.to_string();
        } else {
            lower = trimmed.to_string();
            break;
        }
    }

    // Filter invalid characters (keep ascii alphanumeric, ., -, _)
    let filtered: String = lower
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect();

    // Strip leading and trailing dots and underscores
    let trimmed = filtered.trim_matches(|c| c == '.' || c == '_');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageStateCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    #[serde(default = "root_path")]
    pub path: String,
    #[serde(default)]
    pub secure: bool,
    #[serde(default, rename = "httpOnly", alias = "http_only")]
    pub http_only: bool,
    #[serde(default, rename = "sameSite", alias = "same_site")]
    pub same_site: String,
    #[serde(default)]
    pub expires: Option<f64>,
}

impl StorageStateCookie {
    pub fn to_cookie_info(&self) -> CookieInfo {
        self.clone().into()
    }
}

impl From<StorageStateCookie> for CookieInfo {
    fn from(c: StorageStateCookie) -> Self {
        let same_site = if c.same_site.is_empty() {
            DEFAULT_SAME_SITE.to_string()
        } else {
            normalize_same_site(&c.same_site)
        };
        CookieInfo {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            http_only: c.http_only,
            same_site,
            expires: c.expires.filter(|e| *e > 0.0).map(|e| e as i64),
        }
    }
}

impl From<CookieInfo> for StorageStateCookie {
    fn from(c: CookieInfo) -> Self {
        let same_site = if c.same_site.is_empty() {
            DEFAULT_SAME_SITE.to_string()
        } else {
            normalize_same_site(&c.same_site)
        };
        StorageStateCookie {
            name: c.name,
            value: c.value,
            domain: c.domain,
            path: c.path,
            secure: c.secure,
            http_only: c.http_only,
            same_site,
            expires: c.expires.map(|e| e as f64).or(Some(-1.0)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum StorageItem {
    Named { name: String, value: String },
    Pair(String, String),
}

impl StorageItem {
    pub fn into_kv(self) -> (String, String) {
        match self {
            Self::Named { name, value } => (name, value),
            Self::Pair(k, v) => (k, v),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageStateOrigin {
    pub origin: String,
    #[serde(default, rename = "localStorage", alias = "local_storage")]
    pub local_storage: Vec<StorageItem>,
    #[serde(default, rename = "sessionStorage", alias = "session_storage")]
    pub session_storage: Vec<StorageItem>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StorageState {
    #[serde(default)]
    pub cookies: Vec<StorageStateCookie>,
    #[serde(default)]
    pub origins: Vec<StorageStateOrigin>,
    #[serde(default)]
    pub jar_version: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    #[serde(rename = "httpOnly")]
    pub http_only: bool,
    #[serde(default, rename = "sameSite")]
    pub same_site: String,
    #[serde(default)]
    pub expires: Option<i64>,
}

#[allow(clippy::manual_is_multiple_of)]
fn parse_http_date(s: &str) -> Result<u64, ()> {
    let months = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];

    let s = s.replace('-', " ");
    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 5 {
        return Err(());
    }

    let day: u64 = parts[1].parse().map_err(|_| ())?;
    let month = months
        .iter()
        .position(|m| parts[2].to_lowercase().starts_with(m))
        .ok_or(())? as u64
        + 1;
    let year: u64 = parts[3].parse().map_err(|_| ())?;

    let time_parts: Vec<&str> = parts[4].split(':').collect();
    let hour: u64 = time_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minute: u64 = time_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let second: u64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut days_total: u64 = 0;
    for y in 1970..year {
        days_total += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
    }
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    for m in 1..month {
        days_total += days_in_month[m as usize] + if m == 2 && is_leap { 1 } else { 0 };
    }
    days_total += day - 1;

    Ok(days_total * 86400 + hour * 3600 + minute * 60 + second)
}

/// Resolve the storage domain and host-only flag for a cookie being set from
/// `origin_host` (RFC 6265 §5.2/§5.3). With no Domain attribute the cookie is
/// host-only: scoped to the exact origin host. A Domain attribute is honored
/// only when it domain-matches the origin (equal to it or a parent domain) and
/// is not an obvious public suffix; otherwise the attribute is ignored and the
/// cookie is stored host-only on the origin. This is what stops a response from
/// attacker.test planting a cookie scoped to victim.test.
///
/// Returns None only when the origin host itself is absent (the cookie cannot
/// be scoped and is dropped).
///
/// Note: a full public suffix list is not bundled, so multi-label public
/// suffixes (co.uk, github.io) are not rejected; the domain-match check still
/// blocks the reported cross-domain attack, and single-label suffixes (com,
/// local) are rejected.
fn resolve_cookie_domain(origin_host: &str, domain_attr: Option<&str>) -> Option<(String, bool)> {
    let origin = canonical_domain(origin_host);
    if origin.is_empty() {
        return None;
    }
    let dom = match domain_attr {
        None => return Some((origin, true)),
        Some(raw) => canonical_domain(raw),
    };
    if dom.is_empty() || dom == origin {
        return Some((origin, true));
    }
    if dom.contains('.') && origin.ends_with(&format!(".{dom}")) {
        Some((dom, false))
    } else {
        Some((origin, true))
    }
}

// RFC 6265 5.1.4 default-path: the path a cookie is scoped to when its
// Set-Cookie carries no Path attribute. It is the request URI's directory — the
// path up to but not including the right-most '/' — NOT the full request path.
// Using the full path scopes a session cookie to the exact URL that set it: a
// cookie set on `/app/login` would then not match `/app/dashboard`, silently
// logging the user out on the next navigation. Browsers store `/app` here.
pub fn default_cookie_path(request_path: &str) -> String {
    // "If the uri-path is empty or if the first character is not '/', output /."
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        // "If the uri-path contains no more than one '/', output /."
        Some(0) | None => "/".to_string(),
        // "Output the characters up to, but not including, the right-most '/'."
        Some(idx) => request_path[..idx].to_string(),
    }
}

// RFC 6265 5.1.4 path-match. A bare `starts_with` over-matches sibling paths
// that share a string prefix (a Path=/admin cookie leaking to /administrator),
// so a prefix match also requires the boundary to fall on a '/'.
fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    if !request_path.starts_with(cookie_path) {
        return false;
    }
    // Prefix match: exact when the cookie-path already ends in '/', otherwise
    // the next char of the request-path must be the '/' boundary.
    cookie_path.ends_with('/') || request_path.as_bytes().get(cookie_path.len()) == Some(&b'/')
}

fn domain_matches(host: &str, domain: &str) -> bool {
    // Avoid allocations on the hot path. Cookie lookup runs per fetch
    // (every subresource on a page) and walks every domain in the jar.
    // Previously this allocated 2 lowercase Strings + a "." prefix
    // per (host, domain) pair.
    let domain = domain.trim_start_matches('.');
    if host.len() < domain.len() {
        return false;
    }
    // Exact match (case-insensitive)
    if host.eq_ignore_ascii_case(domain) {
        return true;
    }
    // Suffix match with a '.' boundary: host = "sub.example.com",
    // domain = "example.com". The byte before the suffix in host
    // must be '.'.
    let prefix_len = host.len() - domain.len();
    if prefix_len < 1 {
        return false;
    }
    if !host.is_char_boundary(prefix_len) {
        return false;
    }
    if host.as_bytes()[prefix_len - 1] != b'.' {
        return false;
    }
    host[prefix_len..].eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_cookie() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/path").unwrap();
        jar.set_cookie("session=abc123; Path=/; Secure; HttpOnly", &url);

        let header = jar.get_cookie_header(&url);
        assert!(header.contains("session=abc123"));
    }

    #[test]
    fn test_cookie_domain_matching() {
        let jar = CookieJar::new();
        let url = Url::parse("https://www.example.com/").unwrap();
        jar.set_cookie("token=xyz; Domain=example.com", &url);

        let header = jar.get_cookie_header(&url);
        assert!(header.contains("token=xyz"));

        let sub_url = Url::parse("https://api.example.com/").unwrap();
        let header2 = jar.get_cookie_header(&sub_url);
        assert!(header2.contains("token=xyz"));

        let other_url = Url::parse("https://other.com/").unwrap();
        let header3 = jar.get_cookie_header(&other_url);
        assert!(header3.is_empty());
    }

    #[test]
    fn test_cdp_cookie_with_leading_dot_domain_matches_requests() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "token".to_string(),
            value: "xyz".to_string(),
            domain: ".example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);

        let apex_url = Url::parse("https://example.com/").unwrap();
        let apex_header = jar.get_cookie_header(&apex_url);
        assert!(apex_header.contains("token=xyz"));

        let subdomain_url = Url::parse("https://api.example.com/").unwrap();
        let subdomain_header = jar.get_cookie_header(&subdomain_url);
        assert!(subdomain_header.contains("token=xyz"));

        let other_url = Url::parse("https://other.com/").unwrap();
        let other_header = jar.get_cookie_header(&other_url);
        assert!(other_header.is_empty());
    }

    #[test]
    fn test_secure_cookie_not_sent_over_http() {
        let jar = CookieJar::new();
        let https_url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("secure_token=secret; Secure", &https_url);

        let http_url = Url::parse("http://example.com/").unwrap();
        let header = jar.get_cookie_header(&http_url);
        assert!(header.is_empty());
    }

    #[test]
    fn test_max_age_zero_deletes_cookie() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("session=abc", &url);
        assert!(jar.get_cookie_header(&url).contains("session=abc"));

        jar.set_cookie("session=abc; Max-Age=0", &url);
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_same_name_cookies_with_different_paths_coexist() {
        // RFC 6265 §5.3: a cookie is identified by (name, domain, path). Two
        // cookies that share a name but differ in path are distinct and must
        // both be retained — storing by name alone clobbers the first.
        let jar = CookieJar::new();
        let set_url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("id=1; Path=/a", &set_url);
        jar.set_cookie("id=2; Path=/b", &set_url);

        let header_a = jar.get_cookie_header(&Url::parse("https://example.com/a/page").unwrap());
        let header_b = jar.get_cookie_header(&Url::parse("https://example.com/b/page").unwrap());
        assert!(
            header_a.contains("id=1"),
            "/a must see the Path=/a cookie, got: {header_a:?}"
        );
        assert!(
            header_b.contains("id=2"),
            "/b must see the Path=/b cookie, got: {header_b:?}"
        );
        assert!(
            !header_a.contains("id=2"),
            "Path=/b cookie leaked to /a: {header_a:?}"
        );
        assert!(
            !header_b.contains("id=1"),
            "Path=/a cookie leaked to /b: {header_b:?}"
        );
    }

    #[test]
    fn test_same_name_same_path_cookie_is_replaced() {
        // Same (name, path): the newer value replaces the older one — still
        // one entry, not two.
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/a/x").unwrap();
        jar.set_cookie("id=1; Path=/a", &url);
        jar.set_cookie("id=2; Path=/a", &url);
        let header = jar.get_cookie_header(&url);
        assert!(header.contains("id=2"), "newer value must win: {header:?}");
        assert!(
            !header.contains("id=1"),
            "old value must be replaced: {header:?}"
        );
    }

    #[test]
    fn test_max_age_zero_deletes_only_matching_path() {
        // A Max-Age=0 Set-Cookie deletes the (name, path) it targets, leaving a
        // same-name cookie on a different path intact.
        let jar = CookieJar::new();
        let set_url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("id=1; Path=/a", &set_url);
        jar.set_cookie("id=2; Path=/b", &set_url);
        jar.set_cookie("id=x; Path=/a; Max-Age=0", &set_url);

        let header_a = jar.get_cookie_header(&Url::parse("https://example.com/a/page").unwrap());
        let header_b = jar.get_cookie_header(&Url::parse("https://example.com/b/page").unwrap());
        assert!(
            header_a.is_empty(),
            "Path=/a cookie should be deleted: {header_a:?}"
        );
        assert!(
            header_b.contains("id=2"),
            "Path=/b cookie must survive: {header_b:?}"
        );
    }

    #[test]
    fn test_max_age_sets_expiry() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("token=xyz; Max-Age=3600", &url);
        assert!(jar.get_cookie_header(&url).contains("token=xyz"));
    }

    #[test]
    fn test_expired_cookie_not_sent() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("old=current", &url);
        jar.set_cookie("old=gone; Expires=Thu, 01 Jan 2020 00:00:00 GMT", &url);
        assert!(jar.get_cookie_header(&url).is_empty());
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_expired_js_cookie_deletes_existing_cookie() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie_from_js("old=current", &url);
        jar.set_cookie_from_js("old=gone; Expires=Thu, 01 Jan 2020 00:00:00 GMT", &url);
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_samesite_parsed() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("strict_cookie=val; SameSite=Strict", &url);
        assert!(jar.get_cookie_header(&url).contains("strict_cookie=val"));
    }

    #[test]
    fn test_clear_cookies() {
        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("a=1", &url);
        assert!(!jar.get_cookie_header(&url).is_empty());

        jar.clear();
        assert!(jar.get_cookie_header(&url).is_empty());
    }

    #[test]
    fn test_set_cookies_from_cdp_preserves_same_site_and_expires() {
        let jar = CookieJar::new();
        let future_expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600;
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "abc".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "Strict".to_string(),
            expires: Some(future_expiry),
        }]);

        let cookies = jar.get_all_cookies();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].same_site, "Strict");
        assert_eq!(cookies[0].expires, Some(future_expiry));
    }

    #[test]
    fn test_set_cookies_from_cdp_session_when_expires_none() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "n".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        let cookies = jar.get_all_cookies();
        assert_eq!(cookies[0].expires, None);
        assert_eq!(cookies[0].same_site, DEFAULT_SAME_SITE);
    }

    #[test]
    fn test_set_cookies_from_cdp_minus_one_is_a_session_cookie() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "n".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: Some(-1),
        }]);
        let cookies = jar.get_all_cookies();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].expires, None);
    }

    fn cdp(name: &str, value: &str, domain: &str, path: &str) -> CookieInfo {
        CookieInfo {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }
    }

    fn marker(jar: &CookieJar) -> Vec<CookieInfo> {
        jar.get_all_cookies()
            .into_iter()
            .filter(|c| c.name == "marker")
            .collect()
    }

    #[test]
    fn test_cdp_domain_leading_dot_is_not_a_separate_cookie() {
        // The two entrances disagreed: CDP retained the dot, while Set-Cookie stripped it.
        let jar = CookieJar::new();
        let url = Url::parse("https://app.example.com/").unwrap();

        jar.set_cookies_from_cdp(vec![cdp("marker", "stale", ".example.com", "/")]);
        jar.set_cookie("marker=fresh; Domain=example.com; Path=/", &url);

        assert_eq!(
            marker(&jar).len(),
            1,
            "one cookie, one entry, got: {:?}",
            marker(&jar)
        );
        let header = jar.get_cookie_header(&url);
        assert_eq!(header.matches("marker=").count(), 1, "header: {header:?}");
        assert!(
            header.contains("marker=fresh"),
            "newer value must win: {header:?}"
        );
    }

    #[test]
    fn test_cdp_stored_domain_field_carries_no_dot() {
        // The dotted spelling comes LAST. That is why an implementation which only
        // canonicalizes the map key and leaves `entry.domain` raw also fails here.
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![cdp("marker", "one", "example.com", "/")]);
        jar.set_cookies_from_cdp(vec![cdp("marker", "two", ".EXAMPLE.com", "/")]);

        let all = marker(&jar);
        assert_eq!(all.len(), 1, "both spellings collapse, got: {all:?}");
        assert_eq!(
            all[0].domain, "example.com",
            "entry.domain is canonical, got: {:?}",
            all[0].domain
        );
        assert_eq!(all[0].value, "two", "newer value must win");
    }

    #[test]
    fn test_cdp_domain_leading_dot_repairs_a_persisted_store() {
        // load_from_file() imports through here, so an old store must not resurrect the
        // duplicate.
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![
            cdp("marker", "one", ".example.com", "/"),
            cdp("marker", "two", "example.com", "/"),
        ]);
        assert_eq!(marker(&jar).len(), 1, "got: {:?}", marker(&jar));
    }

    #[test]
    fn test_cdp_zero_expiry_deletes_across_domain_spellings() {
        // The insert canonicalizes the key, so every delete path has to canonicalize its
        // lookup too. Otherwise the cookie becomes unreachable and keeps going out.
        for (stored, deleted) in [
            ("Example.COM", "Example.COM"),
            (".example.com", "example.com"),
            ("example.com", ".EXAMPLE.com"),
        ] {
            let jar = CookieJar::new();
            jar.set_cookies_from_cdp(vec![cdp("marker", "current", stored, "/")]);
            let mut gone = cdp("marker", "", deleted, "/");
            gone.expires = Some(0);
            jar.set_cookies_from_cdp(vec![gone]);
            assert!(
                marker(&jar).is_empty(),
                "stored {stored:?}, deleted {deleted:?}: {:?}",
                marker(&jar)
            );
        }
    }

    #[test]
    fn test_delete_cookie_canonicalizes_its_lookup() {
        for spelling in ["Example.COM", ".example.com", "example.com"] {
            let jar = CookieJar::new();
            jar.set_cookies_from_cdp(vec![cdp("marker", "current", "Example.COM", "/")]);
            jar.delete_cookie("marker", spelling);
            assert!(
                marker(&jar).is_empty(),
                "delete_cookie({spelling:?}): {:?}",
                marker(&jar)
            );

            let jar = CookieJar::new();
            jar.set_cookies_from_cdp(vec![cdp("marker", "current", "Example.COM", "/")]);
            jar.delete_cookies_filtered("marker", spelling, Some("/"));
            assert!(
                marker(&jar).is_empty(),
                "delete_cookies_filtered({spelling:?}): {:?}",
                marker(&jar)
            );
        }
    }

    #[test]
    fn test_set_cookies_from_cdp_zero_expiry_deletes_matching_cookie() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "current".to_string(),
            domain: ".example.com".to_string(),
            path: "/account".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: String::new(),
            domain: "example.com".to_string(),
            path: "/account".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: Some(0),
        }]);
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_delete_cookies_filtered_path_mismatch_preserves_cookie() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/admin".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        jar.delete_cookies_filtered("sid", "example.com", Some("/other"));
        assert_eq!(jar.get_all_cookies().len(), 1);

        jar.delete_cookies_filtered("sid", "example.com", Some("/admin"));
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_delete_cookies_filtered_no_path_deletes_regardless() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "sid".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/admin".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        jar.delete_cookies_filtered("sid", "example.com", None);
        assert!(jar.get_all_cookies().is_empty());
    }

    #[test]
    fn test_set_cookies_from_cdp_expired_does_not_persist() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "old".to_string(),
            value: "current".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: None,
        }]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "old".to_string(),
            value: "v".to_string(),
            domain: "example.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: false,
            same_site: String::new(),
            expires: Some(now - 1),
        }]);
        assert!(jar.get_all_cookies().is_empty());
    }
    #[test]
    fn test_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cookies.json");

        let jar = CookieJar::new();
        let url = Url::parse("https://example.com/").unwrap();
        jar.set_cookie("session=abc123; Domain=example.com; Path=/", &url);
        jar.set_cookie("token=xyz; Secure; HttpOnly", &url);

        jar.save_to_file(&path).unwrap();
        assert!(path.exists());

        let jar2 = CookieJar::new();
        let count = jar2.load_from_file(&path).unwrap();
        assert_eq!(count, 2);

        let header = jar2.get_cookie_header(&url);
        assert!(header.contains("session=abc123"));
        assert!(header.contains("token=xyz"));
    }

    #[test]
    fn test_load_nonexistent_file_returns_zero() {
        let jar = CookieJar::new();
        let count = jar
            .load_from_file(std::path::Path::new("/nonexistent/cookies.json"))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_domain_matches_subdomain_without_leading_dot() {
        let jar = CookieJar::new();
        jar.set_cookies_from_cdp(vec![CookieInfo {
            name: "session".to_string(),
            value: "abc".to_string(),
            domain: "xiaohongshu.com".to_string(),
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: String::new(),
            expires: None,
        }]);
        let url = Url::parse("https://www.xiaohongshu.com/explore").unwrap();
        let header = jar.get_cookie_header(&url);
        assert!(
            header.contains("session=abc"),
            "Cookie header was: '{}'",
            header
        );
    }

    #[test]
    fn test_cookie_from_file_load_then_send_in_request() {
        // Simulate what happens: load cookies from file → navigate → cookie should be in request
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cookies.json");

        // Write cookies like we exported from Chrome
        let cookies = serde_json::json!([
            {"name": "a1", "value": "testval", "domain": "xiaohongshu.com", "path": "/", "secure": false, "httpOnly": false},
            {"name": "web_session", "value": "sess123", "domain": "xiaohongshu.com", "path": "/", "secure": false, "httpOnly": true},
        ]);
        std::fs::write(&path, serde_json::to_string(&cookies).unwrap()).unwrap();

        let jar = CookieJar::new();
        let count = jar.load_from_file(&path).unwrap();
        assert_eq!(count, 2, "Should load 2 cookies");

        let url = Url::parse("https://www.xiaohongshu.com/explore").unwrap();
        let header = jar.get_cookie_header(&url);
        assert!(header.contains("a1=testval"), "Missing a1 in: '{}'", header);
        assert!(
            header.contains("web_session=sess123"),
            "Missing web_session in: '{}'",
            header
        );
    }

    #[test]
    fn attacker_response_cannot_set_unrelated_victim_domain_cookie() {
        // GHSA-f22c-8v6q-v6h6: a response from attacker.test must not be able to
        // plant a cookie scoped to victim.test.
        let jar = CookieJar::new();
        let attacker = Url::parse("http://attacker.test/").unwrap();
        jar.set_cookie("sid=attacker; Domain=victim.test; Path=/", &attacker);

        let victim = Url::parse("http://victim.test/account").unwrap();
        assert!(
            !jar.get_cookie_header(&victim).contains("sid=attacker"),
            "cross-domain cookie leaked to victim: {}",
            jar.get_cookie_header(&victim)
        );
        // The cookie is stored host-only on the attacker origin instead.
        assert!(jar.get_cookie_header(&attacker).contains("sid=attacker"));
    }

    #[test]
    fn document_cookie_cannot_set_unrelated_victim_domain_cookie() {
        let jar = CookieJar::new();
        let attacker = Url::parse("http://attacker.test/").unwrap();
        jar.set_cookie_from_js("js_sid=attacker; Domain=victim.test; Path=/", &attacker);

        let victim = Url::parse("http://victim.test/account").unwrap();
        assert!(
            !jar.get_cookie_header(&victim).contains("js_sid=attacker"),
            "cross-domain JS cookie leaked to victim: {}",
            jar.get_cookie_header(&victim)
        );
    }

    #[test]
    fn public_suffix_domain_attribute_is_ignored() {
        let jar = CookieJar::new();
        let url = Url::parse("http://www.example.com/").unwrap();
        jar.set_cookie("bad=1; Domain=com; Path=/", &url);
        // "com" is a public suffix; the cookie must not be scoped to it.
        let other = Url::parse("http://other.com/").unwrap();
        assert!(!jar.get_cookie_header(&other).contains("bad=1"));
    }

    #[test]
    fn host_only_cookie_not_sent_to_subdomain() {
        let jar = CookieJar::new();
        let www = Url::parse("http://www.example.com/").unwrap();
        jar.set_cookie("hostonly=1; Path=/", &www); // no Domain attribute -> host-only

        assert!(jar.get_cookie_header(&www).contains("hostonly=1"));
        let sub = Url::parse("http://sub.www.example.com/").unwrap();
        assert!(
            !jar.get_cookie_header(&sub).contains("hostonly=1"),
            "host-only cookie leaked to subdomain: {}",
            jar.get_cookie_header(&sub)
        );
    }

    #[test]
    fn valid_subdomain_can_set_parent_domain_cookie() {
        // A subdomain setting Domain=<parent> (a legitimate parent) still works.
        let jar = CookieJar::new();
        let www = Url::parse("http://www.example.com/").unwrap();
        jar.set_cookie("token=1; Domain=example.com; Path=/", &www);

        let apex = Url::parse("http://example.com/").unwrap();
        assert!(jar.get_cookie_header(&apex).contains("token=1"));
        let api = Url::parse("http://api.example.com/").unwrap();
        assert!(jar.get_cookie_header(&api).contains("token=1"));
    }

    #[test]
    fn cookie_path_requires_slash_boundary() {
        // RFC 6265 5.1.4: a Path=/admin cookie must NOT be sent to a sibling
        // path like /administrator that merely shares the string prefix. It is
        // sent to /admin, /admin/, and /admin/x.
        let jar = CookieJar::new();
        let admin = Url::parse("https://example.com/admin").unwrap();
        jar.set_cookie("sess=1; Path=/admin", &admin);

        let sibling = Url::parse("https://example.com/administrator").unwrap();
        assert!(
            !jar.get_cookie_header(&sibling).contains("sess=1"),
            "cookie leaked to sibling path /administrator: {}",
            jar.get_cookie_header(&sibling)
        );

        assert!(jar.get_cookie_header(&admin).contains("sess=1"));
        let exact_slash = Url::parse("https://example.com/admin/").unwrap();
        assert!(jar.get_cookie_header(&exact_slash).contains("sess=1"));
        let sub = Url::parse("https://example.com/admin/panel").unwrap();
        assert!(jar.get_cookie_header(&sub).contains("sess=1"));
    }

    #[test]
    fn default_cookie_path_is_request_directory() {
        // RFC 6265 5.1.4 default-path: up to (not including) the right-most '/'.
        assert_eq!(default_cookie_path("/app/login"), "/app");
        assert_eq!(default_cookie_path("/app/"), "/app");
        assert_eq!(default_cookie_path("/a/b/c"), "/a/b");
        // No more than one '/', empty, or non-absolute -> "/".
        assert_eq!(default_cookie_path("/foo"), "/");
        assert_eq!(default_cookie_path("/"), "/");
        assert_eq!(default_cookie_path(""), "/");
        assert_eq!(default_cookie_path("relative"), "/");
    }

    #[test]
    fn cookie_without_path_defaults_to_directory_not_full_path() {
        // A Set-Cookie with no Path attribute on /app/login must scope to /app
        // (RFC 6265 5.1.4), so the session survives navigation to /app/dashboard.
        // Before this fix it was scoped to the full path /app/login and vanished
        // on the next page, appearing as a silent logout.
        let jar = CookieJar::new();
        let login = Url::parse("https://example.com/app/login").unwrap();
        jar.set_cookie("sid=abc", &login);

        let dashboard = Url::parse("https://example.com/app/dashboard").unwrap();
        assert!(
            jar.get_cookie_header(&dashboard).contains("sid=abc"),
            "session cookie was not sent to a sibling path under the same directory: {}",
            jar.get_cookie_header(&dashboard)
        );
        // Still sent at the directory root and the original path.
        let app_root = Url::parse("https://example.com/app/").unwrap();
        assert!(jar.get_cookie_header(&app_root).contains("sid=abc"));
        assert!(jar.get_cookie_header(&login).contains("sid=abc"));

        // But not to an unrelated top-level path outside the directory.
        let other = Url::parse("https://example.com/other").unwrap();
        assert!(
            !jar.get_cookie_header(&other).contains("sid=abc"),
            "cookie leaked outside its default-path directory"
        );
    }

    #[test]
    fn js_cookie_without_path_also_defaults_to_directory() {
        // document.cookie set on /shop/cart with no path must reach /shop/checkout.
        let jar = CookieJar::new();
        let cart = Url::parse("https://example.com/shop/cart").unwrap();
        jar.set_cookie_from_js("cart=xyz", &cart);
        let checkout = Url::parse("https://example.com/shop/checkout").unwrap();
        assert!(
            jar.get_js_visible_cookies(&checkout).contains("cart=xyz"),
            "JS cookie not visible at sibling path: {}",
            jar.get_js_visible_cookies(&checkout)
        );
    }

    #[test]
    fn test_playwright_storage_state_roundtrip() {
        let fixture = serde_json::json!({
            "cookies": [
                {
                    "name": "session_id",
                    "value": "secret123",
                    "domain": "example.com",
                    "path": "/",
                    "expires": -1.0,
                    "httpOnly": true,
                    "secure": true,
                    "sameSite": "Strict"
                }
            ],
            "origins": [
                {
                    "origin": "https://example.com",
                    "localStorage": [
                        { "name": "token", "value": "tok_xyz" }
                    ],
                    "sessionStorage": [
                        [ "temp_key", "temp_val" ]
                    ]
                }
            ]
        });

        let jar = CookieJar::new();
        let (count, origins) = jar.import_storage_state(&fixture).expect("import succeeds");
        assert_eq!(count, 1, "One cookie should be imported");
        assert_eq!(origins.len(), 1, "One origin should be parsed");
        assert_eq!(origins[0].origin, "https://example.com");
        assert_eq!(origins[0].local_storage.len(), 1);
        assert_eq!(
            origins[0].local_storage[0].clone().into_kv(),
            ("token".into(), "tok_xyz".into())
        );
        assert_eq!(origins[0].session_storage.len(), 1);
        assert_eq!(
            origins[0].session_storage[0].clone().into_kv(),
            ("temp_key".into(), "temp_val".into())
        );

        // Check that session cookie was not purged and is sent for example.com
        let url = Url::parse("https://example.com/api").unwrap();
        let header = jar.get_cookie_header(&url);
        assert!(
            header.contains("session_id=secret123"),
            "Session cookie was preserved and sent"
        );

        // Host-only: should NOT be sent to a subdomain
        let sub_url = Url::parse("https://sub.example.com/api").unwrap();
        assert!(
            !jar.get_cookie_header(&sub_url)
                .contains("session_id=secret123"),
            "Host-only cookie not sent to subdomain"
        );

        // Export storage state cookies
        let exported = jar.export_storage_state_cookies();
        assert_eq!(exported.len(), 1);
        let c = &exported[0];
        assert_eq!(c["name"], "session_id");
        assert_eq!(c["value"], "secret123");
        assert_eq!(c["domain"], "example.com"); // Host-only preserved without dot
        assert_eq!(c["path"], "/");
        assert_eq!(c["expires"], -1.0); // Session cookie expiry preserved as -1.0
        assert_eq!(c["httpOnly"], true); // httpOnly preserved
        assert_eq!(c["secure"], true);
        assert_eq!(c["sameSite"], "Strict"); // sameSite preserved

        // Roundtrip: import the exported cookies back into a new jar
        let roundtrip_fixture = serde_json::json!({
            "cookies": exported,
            "origins": []
        });
        let jar2 = CookieJar::new();
        let (count2, _) = jar2
            .import_storage_state(&roundtrip_fixture)
            .expect("roundtrip import succeeds");
        assert_eq!(count2, 1);
        let exported2 = jar2.export_storage_state_cookies();
        assert_eq!(exported, exported2);
    }

    #[test]
    fn test_sanitize_domain_cases() {
        assert_eq!(
            CookieJar::sanitize_domain("https://www.example.com/"),
            "example.com"
        );
        assert_eq!(
            CookieJar::sanitize_domain("http://www.google.com:8080/search?q=1#top"),
            "google.com"
        );
        assert_eq!(
            CookieJar::sanitize_domain("www.facebook.com"),
            "facebook.com"
        );
        assert_eq!(
            CookieJar::sanitize_domain("http://user:pass@www.gitlab.com:8443/auth"),
            "gitlab.com"
        );
        assert_eq!(
            CookieJar::sanitize_domain("...www.github.com..."),
            "github.com"
        );
        assert_eq!(
            CookieJar::sanitize_domain(".sub.domain.co.uk"),
            "sub.domain.co.uk"
        );
        assert_eq!(
            CookieJar::sanitize_domain("invalid*chars^in!domain.com"),
            "invalidcharsindomain.com"
        );
        assert_eq!(CookieJar::sanitize_domain(""), "default");
        assert_eq!(CookieJar::sanitize_domain("...___..."), "default");
    }
}
