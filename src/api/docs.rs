use axum::{http::header, response::IntoResponse};
use std::sync::LazyLock;

/// The `OpenAPI` specification, stamped with this build's version once rather than per request.
static OPENAPI_YAML: LazyLock<String> = LazyLock::new(|| {
    include_str!("../../openapi.yaml").replace("version: 0.0.0", &format!("version: {}", env!("CARGO_PKG_VERSION")))
});

/// Returns the `OpenAPI` specification in YAML format.
pub(crate) async fn openapi_yaml() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/yaml")], OPENAPI_YAML.as_str())
}
