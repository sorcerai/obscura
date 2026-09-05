//! Roadblock Escalation Protocol: Headless Obscura -> Headed Reach Handoff.

use std::time::SystemTime;

use obscura_browser::Page;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::BrowserState;

/// Roadblock types encountered during navigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Roadblock {
    CloudflareChallenge,
    Turnstile,
    Recaptcha,
    Hcaptcha,
    LoginWall,
    Unknown,
}

/// State of an active escalation to Reach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationState {
    pub escalation_id: String,
    pub screen: u32,
    pub reach_url: String,
    pub domain: String,
    pub url: String,
    pub created_at: u64,
    #[serde(default)]
    pub lease_token: Option<String>,
}

/// Extract domain / eTLD+1 from a URL or host string.
pub fn extract_domain_key(url_or_host: &str) -> String {
    let host = if let Ok(parsed) = url::Url::parse(url_or_host) {
        parsed.host_str().unwrap_or(url_or_host).to_string()
    } else {
        url_or_host
            .split('/')
            .next()
            .unwrap_or(url_or_host)
            .to_string()
    };
    let clean = host.trim().trim_start_matches('.').to_lowercase();
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() <= 2 {
        return clean;
    }
    let last = parts[parts.len() - 1];
    let second_last = parts[parts.len() - 2];
    if parts.len() >= 3
        && (second_last == "co"
            || second_last == "com"
            || second_last == "org"
            || second_last == "net"
            || second_last == "edu"
            || second_last == "gov")
        && (last.len() == 2)
    {
        return parts[parts.len() - 3..].join(".");
    }
    parts[parts.len() - 2..].join(".")
}

/// Detect anti-bot roadblocks, CAPTCHAs, challenges, or login walls.
pub fn detect_roadblock(status: u16, headers: &http::HeaderMap, page: &Page) -> Option<Roadblock> {
    // 1. Header check: cf-mitigated == "challenge"
    for (name, val) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("cf-mitigated") {
            if let Ok(v) = val.to_str() {
                if v.trim().eq_ignore_ascii_case("challenge") {
                    return Some(Roadblock::CloudflareChallenge);
                }
            }
        }
    }

    // Resolve effective title (page.title or <title> in DOM)
    let page_title = if !page.title.is_empty() {
        page.title.clone()
    } else {
        page.with_dom(|dom| {
            dom.query_selector("title")
                .ok()
                .flatten()
                .map(|t| dom.text_content(t))
        })
        .flatten()
        .unwrap_or_default()
    };

    // 2. Status check: 403 with title containing "Just a moment" -> CloudflareChallenge
    if status == 403
        && (page_title.contains("Just a moment")
            || page_title.to_lowercase().contains("just a moment"))
    {
        return Some(Roadblock::CloudflareChallenge);
    }

    // 3. Iframe src matching probe:
    // challenges.cloudflare.com -> Turnstile
    // google.com/recaptcha -> Recaptcha
    // hcaptcha.com -> Hcaptcha
    if let Some(dom) = &page.dom {
        if let Ok(nodes) = dom.query_selector_all("iframe") {
            for node_id in nodes {
                if let Some(src) = dom
                    .with_node(node_id, |n| n.get_attribute("src").map(str::to_string))
                    .flatten()
                {
                    if src.contains("challenges.cloudflare.com") {
                        return Some(Roadblock::Turnstile);
                    }
                    if src.contains("google.com/recaptcha") || src.contains("recaptcha") {
                        return Some(Roadblock::Recaptcha);
                    }
                    if src.contains("hcaptcha.com") {
                        return Some(Roadblock::Hcaptcha);
                    }
                }
            }
        }
    }

    // Also check child frame URLs if any
    for frame in &page.frames {
        let url_str = frame.url();
        if url_str.contains("challenges.cloudflare.com") {
            return Some(Roadblock::Turnstile);
        }
        if url_str.contains("google.com/recaptcha") || url_str.contains("recaptcha") {
            return Some(Roadblock::Recaptcha);
        }
        if url_str.contains("hcaptcha.com") {
            return Some(Roadblock::Hcaptcha);
        }
    }

    // 4. Status 401 -> LoginWall
    if status == 401 {
        return Some(Roadblock::LoginWall);
    }

    None
}

/// Escalate an anti-bot roadblock to a Reach headed browser instance for human/headed takeover.
pub async fn tool_escalate(args: &Value, state: &mut BrowserState) -> Result<String, String> {
    let reach_url = args
        .get("reach_url")
        .and_then(Value::as_str)
        .unwrap_or("http://127.0.0.1:8402")
        .trim_end_matches('/');

    let reason = args.get("reason").and_then(Value::as_str).map(String::from);

    let timeout_secs = args
        .get("timeout_secs")
        .and_then(Value::as_u64)
        .unwrap_or(900);

    let current_url = args
        .get("url")
        .and_then(Value::as_str)
        .map(String::from)
        .or_else(|| {
            if state.has_active_tab() {
                Some(state.page_mut().url_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let domain = extract_domain_key(&current_url);

    // Checks if an escalation is already active for this domain; if so, returns it with "coalesced": true
    if let Some(existing) = state.escalations.get(&domain) {
        let out = json!({
            "escalation_id": existing.escalation_id,
            "screen": existing.screen,
            "novnc_url": "http://127.0.0.1:6080/vnc.html?autoconnect=true",
            "state": "AwaitingHuman",
            "coalesced": true,
        });
        return serde_json::to_string_pretty(&out).map_err(|e| e.to_string());
    }

    // Exports current storage state JSON via state.context.export_storage_state()
    let storage_state = state.context.export_storage_state();
    let storage_state_str = serde_json::to_string(&storage_state).unwrap_or_default();

    let escalation_id = format!("esc-{}", uuid::Uuid::new_v4());
    let task = args
        .get("task")
        .and_then(Value::as_str)
        .unwrap_or(&escalation_id);
    let owner = format!("obscura:{task}");

    let mut lease_token = None;

    // Calls Reach API POST {reach_url}/agent/screens/0/lease with owner "obscura:<task>"
    if !reach_url.is_empty() && !reach_url.starts_with("mock") && !reach_url.starts_with("test") {
        let client = reqwest::Client::new();
        let lease_resp = client
            .post(format!("{reach_url}/agent/screens/0/lease"))
            .json(&json!({ "owner": owner }))
            .send()
            .await;

        if let Ok(resp) = lease_resp {
            if let Ok(val) = resp.json::<Value>().await {
                if let Some(tok) = val.get("token").and_then(Value::as_str) {
                    lease_token = Some(tok.to_string());
                }
            }
        }

        // Calls Reach API POST {reach_url}/tools/auth_handoff with { "url": current_url, "storage_state": ..., "reason": ... }
        let mut handoff_body = json!({
            "url": current_url,
            "storage_state": storage_state_str,
            "timeout_seconds": timeout_secs,
            "screen": 0,
        });
        if let Some(ref r) = reason {
            handoff_body["reason"] = json!(r);
        }

        let mut req_builder = client
            .post(format!("{reach_url}/tools/auth_handoff"))
            .json(&handoff_body);

        if let Some(ref tok) = lease_token {
            req_builder = req_builder.header("x-lease-token", tok.as_str());
        }

        let _ = req_builder.send().await;
    }

    let created_at = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let esc_state = EscalationState {
        escalation_id: escalation_id.clone(),
        screen: 0,
        reach_url: reach_url.to_string(),
        domain: domain.clone(),
        url: current_url,
        created_at,
        lease_token,
    };

    state.escalations.insert(domain, esc_state);

    let out = json!({
        "escalation_id": escalation_id,
        "screen": 0,
        "novnc_url": "http://127.0.0.1:6080/vnc.html?autoconnect=true",
        "state": "AwaitingHuman"
    });

    serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
}

/// Check if human intervention on Reach is complete, reload session cookies, and resume navigation.
pub async fn tool_escalate_resume(
    args: &Value,
    state: &mut BrowserState,
) -> Result<String, String> {
    let escalation_id = args
        .get("escalation_id")
        .and_then(Value::as_str)
        .ok_or("Missing escalation_id parameter")?;

    let (domain, esc) = state
        .escalations
        .iter()
        .find(|(_, e)| e.escalation_id == escalation_id)
        .map(|(d, e)| (d.clone(), e.clone()))
        .ok_or_else(|| format!("Escalation not found: {escalation_id}"))?;

    let reach_url = esc.reach_url.trim_end_matches('/');
    let screen = esc.screen;

    let mock_phase = args.get("mock_phase").and_then(Value::as_str);

    let mut phase = String::new();
    if let Some(mp) = mock_phase {
        phase = mp.to_string();
    } else if !reach_url.is_empty()
        && !reach_url.starts_with("mock")
        && !reach_url.starts_with("test")
    {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{reach_url}/agent/screens/{screen}"))
            .send()
            .await
            .map_err(|e| format!("Failed to poll Reach screen: {e}"))?;

        let val: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse Reach screen info: {e}"))?;

        if let Some(p) = val.get("phase").and_then(Value::as_str) {
            phase = p.to_string();
        }
    }

    if phase == "HumanDone" {
        // Reloads storage state / jars for this domain into Obscura's cookie_jar
        if !reach_url.is_empty() && !reach_url.starts_with("mock") && !reach_url.starts_with("test")
        {
            let client = reqwest::Client::new();
            let exec_resp = client
                .post(format!("{reach_url}/tools/exec"))
                .json(&json!({ "command": "cat /workspace/.reach/state.json" }))
                .send()
                .await;
            if let Ok(res) = exec_resp {
                if let Ok(exec_val) = res.json::<Value>().await {
                    let text = exec_val
                        .get("stdout")
                        .or_else(|| exec_val.get("text"))
                        .and_then(Value::as_str);
                    if let Some(s) = text {
                        if let Ok(json_state) = serde_json::from_str::<Value>(s) {
                            let _ = state.context.cookie_jar.import_storage_state(&json_state);
                        }
                    }
                }
            }
        }

        // Check local storage_state path if accessible
        let local_state = std::path::Path::new("/workspace/.reach/state.json");
        if local_state.exists() {
            let _ = state.context.load_storage_state_file(local_state);
        }

        // Navigates back to saved URL
        if !esc.url.is_empty() && state.has_active_tab() {
            let _ = state
                .page_mut()
                .navigate_with_wait(&esc.url, obscura_browser::lifecycle::WaitUntil::Load)
                .await;
        }

        // Releases Reach lease: DELETE {reach_url}/agent/screens/{screen}/lease
        if !reach_url.is_empty() && !reach_url.starts_with("mock") && !reach_url.starts_with("test")
        {
            let client = reqwest::Client::new();
            let mut req = client.delete(format!("{reach_url}/agent/screens/{screen}/lease"));
            if let Some(ref tok) = esc.lease_token {
                req = req.header("x-lease-token", tok.as_str());
            }
            let _ = req.send().await;
        }

        state.escalations.remove(&domain);

        let out = json!({
            "state": "Resumed",
            "roadblock": null
        });
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
    } else {
        let out = json!({
            "state": "AwaitingHuman"
        });
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_key() {
        assert_eq!(
            extract_domain_key("https://sub.github.com/login"),
            "github.com"
        );
        assert_eq!(
            extract_domain_key("https://news.bbc.co.uk/world"),
            "bbc.co.uk"
        );
        assert_eq!(extract_domain_key("example.com"), "example.com");
    }

    #[test]
    fn test_detect_roadblock_cf_mitigated() {
        let mut headers = http::HeaderMap::new();
        headers.insert("cf-mitigated", "challenge".parse().unwrap());
        let page = Page::new(
            "test".to_string(),
            std::sync::Arc::new(obscura_browser::BrowserContext::new("ctx-1".to_string())),
        );
        assert_eq!(
            detect_roadblock(200, &headers, &page),
            Some(Roadblock::CloudflareChallenge)
        );
    }
}
