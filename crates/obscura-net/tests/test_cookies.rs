use obscura_net::{CookieJar, StorageStateCookie};
use url::Url;

#[test]
fn test_playwright_storage_state_roundtrip_integration() {
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
fn test_sanitize_domain() {
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

#[test]
fn test_storage_state_cookie_camel_and_snake_case() {
    let json_camel = serde_json::json!({
        "name": "a",
        "value": "b",
        "domain": "example.com",
        "httpOnly": true,
        "sameSite": "Strict"
    });
    let c1: StorageStateCookie = serde_json::from_value(json_camel).unwrap();
    assert!(c1.http_only);
    assert_eq!(c1.same_site, "Strict");
    assert_eq!(c1.path, "/");

    let json_snake = serde_json::json!({
        "name": "a",
        "value": "b",
        "domain": "example.com",
        "http_only": true,
        "same_site": "Lax"
    });
    let c2: StorageStateCookie = serde_json::from_value(json_snake).unwrap();
    assert!(c2.http_only);
    assert_eq!(c2.same_site, "Lax");
}
