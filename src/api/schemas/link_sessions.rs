use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSessionResponse {
    pub id: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LinkSessionWaitParams {
    #[serde(default)]
    pub wait: u64,
}
