#![allow(
    clippy::panic,
    clippy::todo,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    missing_debug_implementations,
    clippy::cast_precision_loss,
    clippy::clone_on_ref_ptr,
    clippy::match_same_arms,
    clippy::items_after_statements,
    unreachable_pub,
    clippy::print_stdout,
    clippy::similar_names
)]
mod common;

use axum::http::StatusCode;
use common::TestApp;

#[tokio::test]
async fn test_openapi_yaml_endpoint() {
    let app = TestApp::spawn().await;

    let url = format!("{}/openapi.yaml", app.server_url);
    let response = app.client.get(url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/yaml");

    let body = response.text().await.unwrap();
    assert!(body.contains("openapi: 3.0.3"));
    assert!(body.contains("title: Obscura Server API"));

    // Check that the version matches Cargo.toml
    let cargo_version = env!("CARGO_PKG_VERSION");
    assert!(body.contains(&format!("version: {cargo_version}")));
}
