use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;

use guard_core_rs::protocols::response::{
    DynGuardResponse, GuardResponse, GuardResponseFactory,
};

#[derive(Clone)]
pub(crate) struct MockResponse {
    status: u16,
    headers: Arc<DashMap<String, String>>,
    body: Option<Bytes>,
}

impl std::fmt::Debug for MockResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockResponse")
            .field("status", &self.status)
            .field("body", &self.body.as_ref().map(|b| b.len()))
            .finish()
    }
}

impl MockResponse {
    pub(crate) fn new(status: u16, body: &str) -> Arc<Self> {
        Arc::new(Self {
            status,
            headers: Arc::new(DashMap::new()),
            body: Some(Bytes::copy_from_slice(body.as_bytes())),
        })
    }
}

impl GuardResponse for MockResponse {
    fn status_code(&self) -> u16 {
        self.status
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }
    fn set_header(&self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }
    fn remove_header(&self, name: &str) {
        self.headers.remove(name);
    }
    fn body(&self) -> Option<Bytes> {
        self.body.clone()
    }
}

#[derive(Clone, Default)]
pub(crate) struct MockResponseFactory {
    pub(crate) created: Arc<RwLock<Vec<(u16, String)>>>,
}

impl std::fmt::Debug for MockResponseFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockResponseFactory")
            .field("created", &self.created.read().len())
            .finish()
    }
}

impl GuardResponseFactory for MockResponseFactory {
    fn create_response(&self, content: &str, status_code: u16) -> DynGuardResponse {
        self.created.write().push((status_code, content.to_string()));
        MockResponse::new(status_code, content)
    }

    fn create_redirect_response(&self, url: &str, status_code: u16) -> DynGuardResponse {
        let response = MockResponse::new(status_code, "");
        response.set_header("Location", url);
        response
    }
}

#[test]
fn __touch_all_mock_response_helpers() {
    let factory = MockResponseFactory::default();
    let _ = format!("{factory:?}");
    let response = factory.create_response("content", 200);
    let _ = format!("{response:?}");
    let _ = response.status_code();
    let _ = response.headers();
    response.set_header("X-Test", "1");
    response.remove_header("X-Test");
    let _ = response.body();
    let redirect = factory.create_redirect_response("/url", 302);
    let _ = redirect.status_code();
    let direct = MockResponse::new(201, "body");
    let _ = direct.body();
    let _ = direct.status_code();
    let _ = format!("{direct:?}");
    let _ = factory.created.read().len();
}
