use crate::common::TestApp;
use obscura_server::adapters::redis::cache::RedisCache;
use std::sync::Arc;
use uuid::Uuid;

mod common;

#[tokio::test]
async fn test_redis_cache_basic_operations() {
    let app = TestApp::spawn().await;

    // Create a new cache instance pointing to the same redis pool
    // Note: We need to access the pubsub client from the app
    let redis_client = Arc::clone(&app.resources.pubsub);
    let cache = RedisCache::new(redis_client, "test:cache:".to_string(), 60);

    let key = Uuid::new_v4().to_string();
    let value = b"hello world".to_vec();

    // 1. Get non-existent key should return None
    let result = cache.get(&key).await.expect("Failed to get");
    assert_eq!(result, None, "Expected None for non-existent key");

    // 2. Set value with TTL
    cache.set(&key, &value).await.expect("Failed to set");

    // 3. Get existing key should return value
    let result = cache.get(&key).await.expect("Failed to get").expect("Expected value but got None");
    assert_eq!(result, value, "Value mismatch");

    // 4. Take returns the value and removes the key
    let result = cache.take(&key).await.expect("Failed to take");
    assert_eq!(result, Some(value), "Value mismatch");

    // 5. Taken key is gone
    assert_eq!(cache.get(&key).await.expect("Failed to get"), None, "Expected None for taken key");
    assert_eq!(cache.take(&key).await.expect("Failed to take"), None, "Expected None for taken key");
}

#[tokio::test]
async fn test_redis_cache_expiration() {
    let app = TestApp::spawn().await;
    let redis_client = Arc::clone(&app.resources.pubsub);
    let cache = RedisCache::new(redis_client, "test:cache:expire:".to_string(), 1);

    let key = Uuid::new_v4().to_string();
    let value = b"temporary".to_vec();

    // Set with 1 second TTL
    cache.set(&key, &value).await.expect("Failed to set");

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Key should be gone
    let result = cache.get(&key).await.expect("Failed to get");
    assert_eq!(result, None, "Key should have expired");
}
