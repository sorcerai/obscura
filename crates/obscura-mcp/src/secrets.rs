use crate::BrowserState;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Ensure current page URL matches the target domain (preventing typing secrets into phishing or hijacked pages).
pub fn assert_origin(state: &BrowserState, bound_domain: &str) -> Result<(), String> {
    let page = state.page().ok_or_else(|| "No active page".to_string())?;
    let url = page.url_string();
    reach_secrets::agent_card::validate_origin(&url, bound_domain)
        .map_err(|e| format!("Origin mismatch: {e}"))
}

/// Evaluates JavaScript to fill a secret value into a form field, marks it with `data-obscura-secret="1"`,
/// dispatches trusted input/change events, and advances `state.secret_filled_gen`.
pub fn fill_secret(state: &mut BrowserState, selector: &str, secret: &str) -> Result<(), String> {
    let effective_selector =
        if selector.starts_with('e') && selector[1..].chars().all(|c| c.is_ascii_digit()) {
            state
                .ref_to_selector(selector)
                .unwrap_or_else(|_| format!("[data-obscura-ref=\"{selector}\"]"))
        } else {
            selector.to_string()
        };

    let js = format!(
        r#"(function(){{
            var el = document.querySelector({sel});
            if (!el) return "error:element not found";
            if (typeof globalThis.__obscura_setFieldValue === "function") {{
                globalThis.__obscura_setFieldValue(el, "value", {val});
            }} else {{
                el.value = {val};
            }}
            el.setAttribute("data-obscura-secret", "1");
            var inEvt = new Event("input", {{ bubbles: true }});
            var chEvt = new Event("change", {{ bubbles: true }});
            if (typeof globalThis.__obscura_markTrusted === "function") {{
                inEvt = globalThis.__obscura_markTrusted(inEvt);
                chEvt = globalThis.__obscura_markTrusted(chEvt);
            }}
            el.dispatchEvent(inEvt);
            el.dispatchEvent(chEvt);
            return "ok";
        }})()"#,
        sel = serde_json::to_string(&effective_selector).map_err(|e| e.to_string())?,
        val = serde_json::to_string(secret).map_err(|e| e.to_string())?,
    );

    let result = state.page_mut().evaluate(&js);
    if result.as_str() == Some("error:element not found") {
        return Err(format!("Element not found: {selector}"));
    }
    state.secret_filled_gen += 1;
    Ok(())
}

/// MCP tool handler to fill credentials from vault into the active page.
pub async fn tool_fill_vault(args: &Value, state: &mut BrowserState) -> Result<String, String> {
    let domain_raw = args
        .get("domain")
        .and_then(Value::as_str)
        .ok_or("Missing domain parameter")?;
    let username_sel = args.get("username").and_then(Value::as_str);
    let password_sel = args.get("password").and_then(Value::as_str);
    let totp_sel = args.get("totp").and_then(Value::as_str);
    let submit = args.get("submit").and_then(Value::as_bool).unwrap_or(false);

    let domain = reach_secrets::vault::normalize_domain(domain_raw);
    assert_origin(state, &domain)?;

    let cred = reach_secrets::vault::get(&domain)
        .ok_or_else(|| format!("No credential found in vault for domain: {domain}"))?;

    let mut filled = Vec::new();
    if let Some(sel) = username_sel {
        fill_secret(state, sel, &cred.username)?;
        filled.push("username".to_string());
    }
    if let Some(sel) = password_sel {
        fill_secret(state, sel, &cred.password)?;
        filled.push("password".to_string());
    }

    let mut totp_valid_for_secs = None;
    if let Some(sel) = totp_sel {
        let totp_code = reach_secrets::vault::generate_totp(&domain)
            .map_err(|e| format!("Failed to generate TOTP: {e}"))?;
        fill_secret(state, sel, &totp_code)?;
        filled.push("totp".to_string());

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        totp_valid_for_secs = Some(30 - (now_secs % 30));
    }

    if submit {
        let submit_js = r#"(function() {
            var el = document.activeElement;
            if (el && el.form) {
                if (typeof el.form.requestSubmit === "function") {
                    el.form.requestSubmit();
                } else {
                    el.form.submit();
                }
                return true;
            }
            var form = document.querySelector('form');
            if (form) {
                if (typeof form.requestSubmit === "function") {
                    form.requestSubmit();
                } else {
                    form.submit();
                }
                return true;
            }
            var btn = document.querySelector('button[type=submit], input[type=submit]');
            if (btn) {
                btn.click();
                return true;
            }
            return false;
        })()"#;
        state.page_mut().evaluate(submit_js);
        state.settle_synthetic_navigation().await?;
    }

    let mut res_obj = serde_json::json!({
        "filled": filled,
    });
    if let Some(secs) = totp_valid_for_secs {
        res_obj["totp_valid_for_secs"] = serde_json::json!(secs);
    }

    serde_json::to_string_pretty(&res_obj).map_err(|e| e.to_string())
}

/// MCP tool handler to fill virtual card details into payment forms on the active page.
pub async fn tool_fill_card(args: &Value, state: &mut BrowserState) -> Result<String, String> {
    let card_id = args
        .get("card_id")
        .and_then(Value::as_str)
        .ok_or("Missing card_id parameter")?;
    let number_sel = args.get("number").and_then(Value::as_str);
    let exp_month_sel = args.get("exp_month").and_then(Value::as_str);
    let exp_year_sel = args.get("exp_year").and_then(Value::as_str);
    let cvv_sel = args.get("cvv").and_then(Value::as_str);
    let expiry_combined_sel = args.get("expiry_combined").and_then(Value::as_str);

    let mut store = reach_secrets::agent_card::CardStore::load_from_default()
        .map_err(|e| format!("Failed to load card store: {e}"))?;

    let card = store
        .get_card(card_id)
        .map_err(|e| format!("Card lookup error: {e}"))?;

    if card.status != reach_secrets::agent_card::CardStatus::Active {
        return Err(format!(
            "Card '{}' is not active (status: {})",
            card_id, card.status
        ));
    }

    assert_origin(state, &card.merchant)?;

    let mut filled = Vec::new();
    if let Some(sel) = number_sel {
        fill_secret(state, sel, &card.card_number)?;
        filled.push("number".to_string());
    }

    if let Some(sel) = expiry_combined_sel {
        let combined = format!("{}/{}", card.exp_month, card.exp_year);
        fill_secret(state, sel, &combined)?;
        filled.push("expiry_combined".to_string());
    } else {
        if let Some(sel) = exp_month_sel {
            fill_secret(state, sel, &card.exp_month)?;
            filled.push("exp_month".to_string());
        }
        if let Some(sel) = exp_year_sel {
            fill_secret(state, sel, &card.exp_year)?;
            filled.push("exp_year".to_string());
        }
    }

    if let Some(sel) = cvv_sel {
        fill_secret(state, sel, &card.cvv)?;
        filled.push("cvv".to_string());
    }

    let current_url = state.page().map(|p| p.url_string());
    store
        .inject_card(
            0,
            card_id,
            "form",
            false,
            false,
            current_url.as_deref(),
            Some(true),
            None,
        )
        .map_err(|e| format!("Failed to record card injection: {e}"))?;

    let res = serde_json::json!({
        "filled": filled,
        "masked": card.masked_card_number(),
    });

    serde_json::to_string_pretty(&res).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_origin_validation_matches_etld_plus_one() {
        assert!(reach_secrets::agent_card::validate_origin(
            "https://github.com/login",
            "github.com"
        )
        .is_ok());
        assert!(reach_secrets::agent_card::validate_origin(
            "https://sub.github.com/path",
            "github.com"
        )
        .is_ok());
        assert!(reach_secrets::agent_card::validate_origin(
            "https://evil.github.com.attacker.io",
            "github.com"
        )
        .is_err());
        assert!(reach_secrets::agent_card::validate_origin(
            "http://github.com/login",
            "github.com"
        )
        .is_err());
    }
}
