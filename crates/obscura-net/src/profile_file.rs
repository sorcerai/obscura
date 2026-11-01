//! One device signature, loaded from `OBSCURA_PROFILE_FILE`.
//!
//! The file names an operating system and a Chrome major version. The user
//! agent, `navigator.platform`, the client-hint platform and the TLS emulation
//! target are all derived from those two, so they cannot disagree. Every other
//! field is checked against the operating system, and any conflict stops the
//! process before it serves a request. Without the file, nothing changes.

use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::OnceLock;

pub const PROFILE_FILE_ENV: &str = "OBSCURA_PROFILE_FILE";

/// Chrome majors the vendored wreq-util can emulate on the wire.
pub const SUPPORTED_CHROME: std::ops::RangeInclusive<u32> = 143..=148;

/// Values Chrome reports for `navigator.deviceMemory` (rounded, capped at 8).
const DEVICE_MEMORY: [f64; 6] = [0.25, 0.5, 1.0, 2.0, 4.0, 8.0];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    fn ua_token(self) -> &'static str {
        match self {
            Os::Windows => "Windows NT 10.0; Win64; x64",
            Os::Macos => "Macintosh; Intel Mac OS X 10_15_7",
            Os::Linux => "X11; Linux x86_64",
        }
    }

    pub fn navigator_platform(self) -> &'static str {
        match self {
            Os::Windows => "Win32",
            Os::Macos => "MacIntel",
            Os::Linux => "Linux x86_64",
        }
    }

    /// `navigator.userAgentData.platform` and `Sec-CH-UA-Platform`.
    pub fn ua_platform(self) -> &'static str {
        match self {
            Os::Windows => "Windows",
            Os::Macos => "macOS",
            Os::Linux => "Linux",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceProfile {
    pub os: Os,
    pub chrome: u32,
    /// Client-hint `platformVersion`, e.g. "15.6.1" on macOS.
    pub platform_version: String,
    /// Screen width and height in CSS pixels.
    pub screen: [u32; 2],
    pub hardware_concurrency: u32,
    pub device_memory: f64,
    /// IANA zone; it should match the exit IP's region.
    pub timezone: String,
    pub locale: String,
    /// Fixes canvas and audio noise, so it stays the same on every page.
    pub seed: u32,
}

impl DeviceProfile {
    /// Parse and check a profile, returning every problem at once.
    pub fn parse(text: &str) -> Result<Self, Vec<String>> {
        let profile: DeviceProfile =
            serde_json::from_str(text).map_err(|e| vec![format!("not a valid profile: {e}")])?;
        let problems = profile.problems();
        if problems.is_empty() {
            Ok(profile)
        } else {
            Err(problems)
        }
    }

    /// The exact user agent the wreq emulation sends for this OS and Chrome.
    pub fn user_agent(&self) -> String {
        format!(
            "Mozilla/5.0 ({}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{}.0.0.0 Safari/537.36",
            self.os.ua_token(),
            self.chrome
        )
    }

    /// The values the page's JavaScript fingerprint layer reads.
    pub fn fingerprint_json(&self) -> Value {
        json!({
            "screen": self.screen,
            "hardwareConcurrency": self.hardware_concurrency,
            "deviceMemory": self.device_memory,
            "seed": self.seed,
        })
    }

    fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !SUPPORTED_CHROME.contains(&self.chrome) {
            out.push(format!(
                "chrome {} cannot be emulated on the wire; this build supports {}-{}",
                self.chrome,
                SUPPORTED_CHROME.start(),
                SUPPORTED_CHROME.end()
            ));
        }
        let version: Vec<&str> = self.platform_version.split('.').collect();
        let numeric = version.len() == 3
            && version
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        let major: u32 = version.first().and_then(|m| m.parse().ok()).unwrap_or(0);
        let major_ok = match self.os {
            // 10.0.0 is Windows 10; Windows 11 reports 13 and up.
            Os::Windows => major == 10 || major >= 13,
            Os::Macos => (10..=26).contains(&major),
            Os::Linux => true,
        };
        if !numeric || !major_ok {
            out.push(format!(
                "platform_version {:?} is not a {} version",
                self.platform_version,
                self.os.ua_platform()
            ));
        }
        let [w, h] = self.screen;
        if !(320..=7680).contains(&w) || !(320..=4320).contains(&h) {
            out.push(format!("screen {w}x{h} is outside 320x320 to 7680x4320"));
        }
        if !(1..=128).contains(&self.hardware_concurrency) {
            out.push(format!(
                "hardware_concurrency {} is outside 1-128",
                self.hardware_concurrency
            ));
        }
        if !DEVICE_MEMORY.contains(&self.device_memory) {
            out.push(format!(
                "device_memory {} is not a value Chrome reports (0.25, 0.5, 1, 2, 4, 8)",
                self.device_memory
            ));
        }
        let tz_ok = self.timezone.contains('/')
            && self
                .timezone
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_+-".contains(&b));
        if !tz_ok {
            out.push(format!("timezone {:?} is not an IANA zone", self.timezone));
        }
        let mut parts = self.locale.split('-');
        let lang = parts.next().unwrap_or("");
        let region = parts.next();
        let locale_ok = (2..=3).contains(&lang.len())
            && lang.bytes().all(|b| b.is_ascii_lowercase())
            && region.is_none_or(|r| r.len() == 2 && r.bytes().all(|b| b.is_ascii_uppercase()))
            && parts.next().is_none();
        if !locale_ok {
            out.push(format!("locale {:?} is not like \"en-US\"", self.locale));
        }
        out
    }
}

/// Read `OBSCURA_PROFILE_FILE`. `Ok(None)` when it is unset.
pub fn load_from_env() -> Result<Option<DeviceProfile>, Vec<String>> {
    let Some(path) = std::env::var_os(PROFILE_FILE_ENV).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| vec![format!("cannot read {}: {e}", path.to_string_lossy())])?;
    DeviceProfile::parse(&text).map(Some)
}

static ACTIVE: OnceLock<Option<DeviceProfile>> = OnceLock::new();

/// The process's device profile, if any. The CLI checks the file at startup
/// and exits on a bad one, so the panic here only guards other embedders.
pub fn active() -> Option<&'static DeviceProfile> {
    ACTIVE
        .get_or_init(|| {
            load_from_env().unwrap_or_else(|problems| {
                panic!("{PROFILE_FILE_ENV} rejected: {}", problems.join("; "))
            })
        })
        .as_ref()
}

/// Refuses a user agent other than the profile's. The profile also fixes the
/// client hints and the TLS emulation, which an override cannot follow.
pub fn check_user_agent(ua: &str) -> Result<(), String> {
    check_user_agent_against(active(), ua)
}

fn check_user_agent_against(profile: Option<&DeviceProfile>, ua: &str) -> Result<(), String> {
    match profile {
        Some(p) if ua != p.user_agent() => Err(format!(
            "{PROFILE_FILE_ENV} fixes the user agent to {:?}; a different one would split the identity",
            p.user_agent()
        )),
        _ => Ok(()),
    }
}

/// The `Chrome/<major>` product and user agent the CDP version endpoints
/// report, so a client that copies them sends the profile's own values.
pub fn cdp_version() -> (String, String) {
    match active() {
        Some(p) => (format!("Chrome/{}.0.0.0", p.chrome), p.user_agent()),
        None => (
            "Chrome/145.0.0.0".to_string(),
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> Value {
        json!({
            "os": "macos", "chrome": 146, "platform_version": "15.6.1",
            "screen": [1512, 982], "hardware_concurrency": 10, "device_memory": 8,
            "timezone": "America/Chicago", "locale": "en-US", "seed": 424242
        })
    }

    fn parse(v: Value) -> Result<DeviceProfile, Vec<String>> {
        DeviceProfile::parse(&v.to_string())
    }

    #[test]
    fn a_consistent_mac_profile_derives_one_identity() {
        let p = parse(mac()).unwrap();
        assert_eq!(
            p.user_agent(),
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
        );
        assert_eq!(p.os.navigator_platform(), "MacIntel");
        assert_eq!(p.os.ua_platform(), "macOS");
        assert_eq!(p.fingerprint_json()["seed"], 424242);
    }

    #[test]
    fn one_os_field_drives_every_platform_surface() {
        let mut v = mac();
        v["os"] = json!("windows");
        v["platform_version"] = json!("15.0.0");
        let p = parse(v).unwrap();
        assert!(p.user_agent().contains("Windows NT 10.0; Win64; x64"));
        assert!(!p.user_agent().contains("Macintosh"));
        assert_eq!(p.os.navigator_platform(), "Win32");
        assert_eq!(p.os.ua_platform(), "Windows");
    }

    #[test]
    fn a_platform_version_from_another_os_is_rejected() {
        let mut v = mac();
        v["platform_version"] = json!("6.8.0");
        assert!(parse(v)
            .unwrap_err()
            .iter()
            .any(|p| p.contains("platform_version")));
    }

    #[test]
    fn unsupported_or_implausible_values_are_rejected_together() {
        let mut v = mac();
        v["chrome"] = json!(156);
        v["device_memory"] = json!(16);
        v["timezone"] = json!("CST");
        v["locale"] = json!("english");
        let problems = parse(v).unwrap_err();
        assert_eq!(problems.len(), 4, "{problems:?}");
    }

    #[test]
    fn unknown_fields_are_an_error() {
        let mut v = mac();
        v["user_agent"] = json!("anything");
        assert!(parse(v).is_err());
    }

    #[test]
    fn only_the_profiles_own_user_agent_is_accepted() {
        let p = parse(mac()).unwrap();
        assert!(check_user_agent_against(Some(&p), &p.user_agent()).is_ok());
        let windows = p.user_agent().replace(
            "Macintosh; Intel Mac OS X 10_15_7",
            "Windows NT 10.0; Win64; x64",
        );
        assert!(check_user_agent_against(Some(&p), &windows).is_err());
        assert!(check_user_agent_against(None, &windows).is_ok());
    }

    #[test]
    fn a_consistent_windows_and_linux_profile_pass() {
        let win = json!({
            "os": "windows", "chrome": 145, "platform_version": "15.0.0",
            "screen": [1920, 1080], "hardware_concurrency": 12, "device_memory": 8,
            "timezone": "America/New_York", "locale": "en-US", "seed": 7
        });
        assert!(parse(win).is_ok());
        let linux = json!({
            "os": "linux", "chrome": 144, "platform_version": "6.8.0",
            "screen": [2560, 1440], "hardware_concurrency": 16, "device_memory": 8,
            "timezone": "Europe/Berlin", "locale": "de-DE", "seed": 9
        });
        assert!(parse(linux).is_ok());
    }
}
