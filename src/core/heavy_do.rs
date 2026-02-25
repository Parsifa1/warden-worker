
use tower_http::cors::{Any, CorsLayer};
use tower_service::Service;
use worker::{durable_object, DurableObject, Env, HttpRequest, Request, Response, Result, State};

/// HeavyDo — Durable Object that handles CPU-heavy endpoints.
///
/// Durable Objects have a much higher CPU budget than regular Workers
/// (13,000 GB-s duration/day on free plan vs Worker's 10ms CPU limit).
///
/// Routes offloaded here:
///   GET  /api/config
///   GET  /api/sync
///   GET/POST/PUT/DELETE  /api/two-factor*
///   GET/POST/PUT/DELETE  /api/webauthn*
///
/// The DO simply reuses the existing axum router — no duplication needed.
#[durable_object]
pub struct HeavyDo {
    #[allow(dead_code)]
    state: State,
    env: Env,
}


impl DurableObject for HeavyDo {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        console_error_panic_hook::set_once();
        let _ = console_log::init_with_level(log::Level::Debug);

        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any);

        let http_req = HttpRequest::try_from(req)?;
        let mut app = crate::router::api_router(self.env.clone()).layer(cors);
        let http_resp = app
            .call(http_req)
            .await
            .map_err(|e| worker::Error::RustError(e.to_string()))?;

        Response::try_from(http_resp)
    }
}
