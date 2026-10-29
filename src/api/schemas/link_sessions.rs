use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkSessionResponse {
    pub id: String,
    pub expires_at: i64,
}
