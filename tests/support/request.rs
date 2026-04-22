use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use guard_core_rs::error::Result;
use guard_core_rs::protocols::request::{GuardRequest, RequestState};

#[derive(Clone)]
pub(crate) struct MockRequest {
    path: String,
    scheme: String,
    method: String,
    client_host: Option<String>,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: Bytes,
    state: Arc<RequestState>,
}

impl Default for MockRequest {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl MockRequest {
    pub(crate) fn builder() -> MockRequestBuilder {
        MockRequestBuilder::default()
    }

    pub(crate) fn arc(self) -> Arc<dyn GuardRequest> {
        Arc::new(self)
    }
}

#[async_trait]
impl GuardRequest for MockRequest {
    fn url_path(&self) -> String {
        self.path.clone()
    }
    fn url_scheme(&self) -> String {
        self.scheme.clone()
    }
    fn url_full(&self) -> String {
        format!("{}://host{}", self.scheme, self.path)
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{}://host{}", scheme, self.path)
    }
    fn method(&self) -> String {
        self.method.clone()
    }
    fn client_host(&self) -> Option<String> {
        self.client_host.clone()
    }
    fn headers(&self) -> HashMap<String, String> {
        self.headers.clone()
    }
    fn query_params(&self) -> HashMap<String, String> {
        self.query.clone()
    }
    async fn body(&self) -> Result<Bytes> {
        Ok(self.body.clone())
    }
    fn state(&self) -> Arc<RequestState> {
        Arc::clone(&self.state)
    }
    fn scope(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }
}

#[derive(Default)]
pub(crate) struct MockRequestBuilder {
    path: Option<String>,
    scheme: Option<String>,
    method: Option<String>,
    client_host: Option<String>,
    headers: HashMap<String, String>,
    query: HashMap<String, String>,
    body: Option<Bytes>,
}

impl MockRequestBuilder {
    pub(crate) fn path(mut self, v: impl Into<String>) -> Self {
        self.path = Some(v.into());
        self
    }
    pub(crate) fn scheme(mut self, v: impl Into<String>) -> Self {
        self.scheme = Some(v.into());
        self
    }
    pub(crate) fn method(mut self, v: impl Into<String>) -> Self {
        self.method = Some(v.into());
        self
    }
    pub(crate) fn client_host(mut self, v: impl Into<String>) -> Self {
        self.client_host = Some(v.into());
        self
    }
    pub(crate) fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
    pub(crate) fn query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query.insert(name.into(), value.into());
        self
    }
    pub(crate) fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub(crate) fn build(self) -> MockRequest {
        MockRequest {
            path: self.path.unwrap_or_else(|| "/".into()),
            scheme: self.scheme.unwrap_or_else(|| "http".into()),
            method: self.method.unwrap_or_else(|| "GET".into()),
            client_host: self.client_host,
            headers: self.headers,
            query: self.query,
            body: self.body.unwrap_or_default(),
            state: Arc::new(RequestState::new()),
        }
    }
}

#[test]
fn __touch_all_mock_request_builder_methods() {
    let req = MockRequestBuilder::default()
        .path("/")
        .scheme("http")
        .method("GET")
        .client_host("1.1.1.1")
        .header("x", "y")
        .query("a", "b")
        .body(Bytes::from_static(b""))
        .build();
    let _: Arc<dyn GuardRequest> = req.arc();
    let _ = MockRequest::default();
}
