use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningCodeResponse {
    pub code: String,
    pub expires_at: i64,
}
