use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use guard_core_rs::decorators::base::{ROUTE_ID_STATE_KEY, get_route_decorator_config};
use guard_core_rs::decorators::{RouteConfig, SecurityDecorator};
use guard_core_rs::error::Result;
use guard_core_rs::models::SecurityConfig;
use guard_core_rs::protocols::request::{DynGuardRequest, GuardRequest, RequestState};

struct DemoRequest {
    path: String,
    state: Arc<RequestState>,
}

#[async_trait]
impl GuardRequest for DemoRequest {
    fn url_path(&self) -> String {
        self.path.clone()
    }
    fn url_scheme(&self) -> String {
        "https".into()
    }
    fn url_full(&self) -> String {
        format!("https://demo.example{}", self.path)
    }
    fn url_replace_scheme(&self, scheme: &str) -> String {
        format!("{scheme}://demo.example{}", self.path)
    }
    fn method(&self) -> String {
        "GET".into()
    }
    fn client_host(&self) -> Option<String> {
        Some("10.0.0.1".into())
    }
    fn headers(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    fn query_params(&self) -> HashMap<String, String> {
        HashMap::new()
    }
    async fn body(&self) -> Result<Bytes> {
        Ok(Bytes::new())
    }
    fn state(&self) -> Arc<RequestState> {
        Arc::clone(&self.state)
    }
    fn scope(&self) -> HashMap<String, serde_json::Value> {
        HashMap::new()
    }
}

fn make_request(path: &str, route_id: &str) -> DynGuardRequest {
    let req: DynGuardRequest = Arc::new(DemoRequest {
        path: path.into(),
        state: Arc::new(RequestState::new()),
    });
    req.state().set_str(ROUTE_ID_STATE_KEY, route_id);
    req
}

fn describe(rc: &RouteConfig) {
    println!("  rate_limit        : {:?}", rc.rate_limit);
    println!("  rate_limit_window : {:?}", rc.rate_limit_window);
    println!("  allowed_ips       : {:?}", rc.allowed_ips);
    println!("  require_https     : {}", rc.require_https);
    println!("  auth_required     : {:?}", rc.auth_required);
    println!("  bypassed_checks   : {:?}", rc.bypassed_checks);
    println!(
        "  required_headers  : {:?}",
        rc.required_headers.keys().collect::<Vec<_>>()
    );
}

#[tokio::main]
async fn main() {
    println!("guard-core-rs: with_decorator example");
    println!("-------------------------------------");

    let config = Arc::new(SecurityConfig::builder().build().expect("valid config"));
    let decorator = SecurityDecorator::new(Arc::clone(&config));

    let admin_route = RouteConfig::new()
        .require_https()
        .require_auth("Bearer")
        .rate_limit(10, 60)
        .require_ip(Some(vec!["10.0.0.0/24".into()]), None);
    decorator.register("admin_api", admin_route);

    let public_route = RouteConfig::new()
        .rate_limit(1000, 60)
        .bypass(vec!["penetration".into()])
        .block_user_agents(vec!["evilbot".into()]);
    decorator.register("public_api", public_route);

    let mut required = HashMap::new();
    required.insert("X-Api-Version".into(), "v2".into());
    let versioned_route = RouteConfig::new()
        .require_headers(required)
        .api_key_auth("X-Api-Key");
    decorator.register("versioned_api", versioned_route);

    println!(
        "Decorator registered {} route(s).",
        [
            decorator.get_route_config("admin_api").is_some(),
            decorator.get_route_config("public_api").is_some(),
            decorator.get_route_config("versioned_api").is_some(),
        ]
        .iter()
        .filter(|v| **v)
        .count()
    );
    println!();

    for (label, route_id, path) in [
        ("admin", "admin_api", "/admin/users"),
        ("public", "public_api", "/public/catalog"),
        ("versioned", "versioned_api", "/v2/widgets"),
        ("unknown", "missing_route", "/ghost"),
    ] {
        let request = make_request(path, route_id);
        println!("Lookup via get_route_decorator_config for {label} ({route_id}):");
        match get_route_decorator_config(&request, &decorator) {
            Some(rc) => describe(&rc),
            None => println!("  <no route config resolved>"),
        }
        println!();
    }

    decorator.unregister("public_api");
    println!(
        "After unregister('public_api'), public_api resolved: {}",
        decorator.get_route_config("public_api").is_some()
    );
}
