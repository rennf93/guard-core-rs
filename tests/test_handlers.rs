use std::sync::Arc;

use guard_core_rs::handlers::{IPBanManager, SecurityHeadersManager};

#[tokio::test]
async fn ipban_bans_and_checks() {
    let manager = Arc::new(IPBanManager::new());
    manager
        .ban_ip("10.0.0.1", 60, "test")
        .await
        .expect("ban");
    assert!(manager.is_ip_banned("10.0.0.1").await.expect("check"));
    assert!(!manager.is_ip_banned("10.0.0.2").await.expect("check"));
}

#[tokio::test]
async fn ipban_unban_removes_entry() {
    let manager = Arc::new(IPBanManager::new());
    manager.ban_ip("10.0.0.3", 60, "test").await.expect("ban");
    manager.unban_ip("10.0.0.3").await.expect("unban");
    assert!(!manager.is_ip_banned("10.0.0.3").await.expect("check"));
}

#[tokio::test]
async fn ipban_reset_clears_all() {
    let manager = Arc::new(IPBanManager::new());
    manager.ban_ip("10.0.0.4", 60, "test").await.expect("ban");
    manager.ban_ip("10.0.0.5", 60, "test").await.expect("ban");
    manager.reset().await.expect("reset");
    assert!(!manager.is_ip_banned("10.0.0.4").await.expect("check"));
    assert!(!manager.is_ip_banned("10.0.0.5").await.expect("check"));
}

#[tokio::test]
async fn security_headers_returns_defaults() {
    let manager = SecurityHeadersManager::new();
    let headers = manager.get_headers(None).await;
    assert!(headers.contains_key("X-Frame-Options"));
    assert!(headers.contains_key("X-Content-Type-Options"));
    assert!(headers.contains_key("Referrer-Policy"));
}

#[tokio::test]
async fn security_headers_path_cache_consistency() {
    let manager = SecurityHeadersManager::new();
    let first = manager.get_headers(Some("/api/users")).await;
    let second = manager.get_headers(Some("/api/users")).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn security_headers_reset_clears_custom() {
    let manager = SecurityHeadersManager::new();
    manager.reset().await;
    let headers = manager.get_headers(None).await;
    assert!(headers.contains_key("X-Frame-Options"));
}
