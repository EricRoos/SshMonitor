use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
struct Payload {
    endpoint_event: EndpointEvent,
}

#[derive(Serialize)]
#[serde(tag = "event_type")]
enum EndpointEvent {
    #[serde(rename = "SshRejectionEvent")]
    SshRejection {
        endpoint_id: String,
        timestamp: i64,
        message_id: String,
        raw_metadata: SshRejectionMetadata,
    },
}

#[derive(Serialize)]
struct SshRejectionMetadata {
    ip: String,
    port: u16,
    user: String,
}

pub fn send_ssh_rejection_event(
    base_url: &str,
    public_token: &str,
    secret_token: &str,
    endpoint_id: &str,
    timestamp: i64,
    ip: &str,
    port: u16,
    user: &str,
    source_digest: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let event = EndpointEvent::SshRejection {
        endpoint_id: endpoint_id.to_string(),
        timestamp,
        message_id: source_digest.to_string(),
        raw_metadata: SshRejectionMetadata {
            ip: ip.to_string(),
            port,
            user: user.to_string(),
        },
    };

    let payload = Payload {
        endpoint_event: event,
    };
    let timestamp = Utc::now().timestamp_millis().to_string();
    let json_body = serde_json::to_string(&payload)?;
    let data_to_sign = format!("{}{}", json_body, &timestamp);

    let mut mac = HmacSha256::new_from_slice(secret_token.as_bytes())?;
    mac.update(data_to_sign.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let auth_header = format!(
        "Token token={}, public_token={}, signature={}, timestamp={}",
        secret_token, public_token, signature, timestamp
    );

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_header)?);
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    let url = format!("{}/endpoint_events", base_url);
    let client = Client::new();

    let response = client.post(url).headers(headers).body(json_body).send()?;

    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "Failed with status {}: {}",
            response.status(),
            response.text().unwrap_or_default()
        )
        .into())
    }
}
