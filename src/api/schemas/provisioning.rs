use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningCodeResponse {
    pub code: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisioningRelayResponse {
    pub address: String,
    pub expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct ProvisioningWaitParams {
    #[serde(default)]
    pub wait: u64,
}
