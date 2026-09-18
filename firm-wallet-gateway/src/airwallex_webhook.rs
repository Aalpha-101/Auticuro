/**
 * Copyright 2022 Airwallex (Hong Kong) Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 *
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
use hmac::{Hmac, Mac};
use hyper::body::{self, Bytes};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use serde::Deserialize;
use std::collections::{HashSet, VecDeque};
use std::convert::Infallible;
use std::env;
use std::net::{AddrParseError, SocketAddr};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::{error, info, warn};

const AIRWALLEX_SIGNATURE_HEADER: &str = "x-signature";
const AIRWALLEX_TIMESTAMP_HEADER: &str = "x-timestamp";
const DEFAULT_WEBHOOK_BIND_ADDR: &str = "127.0.0.1";
const DEFAULT_WEBHOOK_PORT: &str = "18081";
const DEFAULT_MAX_RECORDED_EVENTS: usize = 1024;
const AIRWALLEX_WEBHOOK_PATH: &str = "/webhooks/airwallex";

type HmacSha256 = Hmac<sha2::Sha256>;

#[derive(Clone)]
pub struct AirwallexWebhookServer {
    config: AirwallexWebhookConfig,
    recorder: Arc<BoundedWebhookRecorder>,
}

impl AirwallexWebhookServer {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self::new(
            AirwallexWebhookConfig::from_env()?,
            DEFAULT_MAX_RECORDED_EVENTS,
        ))
    }

    pub fn new(config: AirwallexWebhookConfig, max_recorded_events: usize) -> Self {
        Self {
            config,
            recorder: Arc::new(BoundedWebhookRecorder::new(max_recorded_events)),
        }
    }

    pub async fn serve(self) -> Result<(), hyper::Error> {
        let bind_address = self.config.bind_address;
        let server = Arc::new(self);
        info!(
            bind_address = %bind_address,
            "Airwallex webhook receiver listening on HTTP; expose it through a public HTTPS reverse proxy in production"
        );

        Server::bind(&bind_address)
            .serve(make_service_fn(move |_| {
                let server = Arc::clone(&server);
                async move {
                    Ok::<_, Infallible>(service_fn(move |request| {
                        let server = Arc::clone(&server);
                        async move { Ok::<_, Infallible>(server.handle_request(request).await) }
                    }))
                }
            }))
            .await
    }

    async fn handle_request(&self, request: Request<Body>) -> Response<Body> {
        if request.method() != Method::POST {
            return response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        }
        if request.uri().path() != AIRWALLEX_WEBHOOK_PATH {
            return response(StatusCode::NOT_FOUND, "not found");
        }

        let timestamp = match read_header(request.headers(), AIRWALLEX_TIMESTAMP_HEADER) {
            Some(timestamp) => timestamp,
            None => {
                warn!(
                    outcome = "missing_timestamp",
                    "Rejected Airwallex webhook request"
                );
                return response(StatusCode::UNAUTHORIZED, "missing signature headers");
            }
        };
        let signature = match read_header(request.headers(), AIRWALLEX_SIGNATURE_HEADER) {
            Some(signature) => signature,
            None => {
                warn!(
                    outcome = "missing_signature",
                    "Rejected Airwallex webhook request"
                );
                return response(StatusCode::UNAUTHORIZED, "missing signature headers");
            }
        };

        let raw_body = match body::to_bytes(request.into_body()).await {
            Ok(raw_body) => raw_body,
            Err(error) => {
                error!(error = %error, outcome = "body_read_failed", "Failed to read Airwallex webhook body");
                return response(StatusCode::BAD_REQUEST, "failed to read request body");
            }
        };

        match self
            .handle_signed_payload(&timestamp, &signature, raw_body)
            .await
        {
            Ok(processed_response) => processed_response,
            Err(handler_error) => handler_error.into_response(),
        }
    }

    async fn handle_signed_payload(
        &self,
        timestamp: &str,
        signature: &str,
        raw_body: Bytes,
    ) -> Result<Response<Body>, WebhookError> {
        verify_signature(&self.config.webhook_secret, timestamp, &raw_body, signature)?;

        let event: AirwallexEventEnvelope = serde_json::from_slice(&raw_body)
            .map_err(|error| WebhookError::MalformedPayload(error.to_string()))?;

        let outcome = self.recorder.record(event.clone())?;
        let outcome_str = outcome.as_str();

        info!(
            event_id = %event.id,
            event_type = %event.event_type,
            request_id = event.request_id.as_deref().unwrap_or(""),
            outcome = outcome_str,
            "Authenticated Airwallex webhook recorded"
        );

        Ok(response(StatusCode::OK, outcome_str))
    }

    #[cfg(test)]
    fn recorded_events(&self) -> Vec<RecordedWebhookEvent> {
        self.recorder.recorded_events()
    }
}

#[derive(Clone)]
pub struct AirwallexWebhookConfig {
    pub bind_address: SocketAddr,
    webhook_secret: String,
}

impl AirwallexWebhookConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let host = env::var("AIRWALLEX_WEBHOOK_BIND_ADDR")
            .unwrap_or_else(|_| DEFAULT_WEBHOOK_BIND_ADDR.to_string());
        let port =
            env::var("AIRWALLEX_WEBHOOK_PORT").unwrap_or_else(|_| DEFAULT_WEBHOOK_PORT.to_string());
        let bind_address = format!("{}:{}", host, port)
            .parse::<SocketAddr>()
            .map_err(ConfigError::InvalidBindAddress)?;

        let webhook_secret =
            env::var("AIRWALLEX_WEBHOOK_SECRET").map_err(|_| ConfigError::MissingWebhookSecret)?;

        if webhook_secret.trim().is_empty() {
            return Err(ConfigError::MissingWebhookSecret);
        }

        Ok(Self {
            bind_address,
            webhook_secret,
        })
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("AIRWALLEX_WEBHOOK_SECRET must be configured")]
    MissingWebhookSecret,
    #[error("Invalid Airwallex webhook bind address: {0}")]
    InvalidBindAddress(AddrParseError),
}

#[derive(Clone, Debug, Deserialize)]
struct AirwallexEventEnvelope {
    id: String,
    #[serde(alias = "name", alias = "type")]
    event_type: String,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    created_at: Option<String>,
    #[serde(default, alias = "requestId", alias = "source_request_id")]
    request_id: Option<String>,
}

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(value.and_then(|value| match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(value) => Some(value),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedWebhookEvent {
    pub event_id: String,
    pub event_type: String,
    pub created_at: Option<String>,
    pub request_id: Option<String>,
}

struct BoundedWebhookRecorder {
    // TODO: Replace this bounded in-memory recorder with durable shared storage for multi-replica
    // production deployments so deduplication survives process restarts.
    inner: Mutex<BoundedWebhookRecorderState>,
}

impl BoundedWebhookRecorder {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(BoundedWebhookRecorderState::new(capacity.max(1))),
        }
    }

    fn record(&self, event: AirwallexEventEnvelope) -> Result<RecordOutcome, WebhookError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| WebhookError::Persistence("webhook recorder lock poisoned".to_string()))?;

        if state.seen_event_ids.contains(&event.id) {
            return Ok(RecordOutcome::Duplicate);
        }

        state.seen_event_ids.insert(event.id.clone());
        state.recorded_events.push_back(RecordedWebhookEvent {
            event_id: event.id.clone(),
            event_type: event.event_type.clone(),
            created_at: event.created_at,
            request_id: event.request_id,
        });
        state.event_id_order.push_back(event.id);

        while state.event_id_order.len() > state.capacity {
            if let Some(expired_event_id) = state.event_id_order.pop_front() {
                state.seen_event_ids.remove(&expired_event_id);
            }
            state.recorded_events.pop_front();
        }

        Ok(RecordOutcome::Recorded)
    }

    #[cfg(test)]
    fn recorded_events(&self) -> Vec<RecordedWebhookEvent> {
        self.inner
            .lock()
            .expect("webhook recorder lock poisoned")
            .recorded_events
            .iter()
            .cloned()
            .collect()
    }
}

struct BoundedWebhookRecorderState {
    capacity: usize,
    seen_event_ids: HashSet<String>,
    event_id_order: VecDeque<String>,
    recorded_events: VecDeque<RecordedWebhookEvent>,
}

impl BoundedWebhookRecorderState {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen_event_ids: HashSet::new(),
            event_id_order: VecDeque::new(),
            recorded_events: VecDeque::new(),
        }
    }
}

#[derive(Clone, Copy)]
enum RecordOutcome {
    Recorded,
    Duplicate,
}

impl RecordOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::Duplicate => "duplicate",
        }
    }
}

#[derive(Debug, Error)]
enum WebhookError {
    #[error("missing or invalid webhook signature")]
    InvalidSignature,
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
    #[error("failed to record webhook: {0}")]
    Persistence(String),
}

impl WebhookError {
    fn into_response(self) -> Response<Body> {
        match self {
            Self::InvalidSignature => {
                warn!(
                    outcome = "invalid_signature",
                    "Rejected Airwallex webhook request"
                );
                response(StatusCode::UNAUTHORIZED, "invalid signature")
            }
            Self::MalformedPayload(error) => {
                warn!(error = %error, outcome = "malformed_payload", "Rejected Airwallex webhook request");
                response(StatusCode::BAD_REQUEST, "malformed payload")
            }
            Self::Persistence(error) => {
                error!(error = %error, outcome = "persistence_failed", "Failed to record Airwallex webhook");
                response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to record webhook",
                )
            }
        }
    }
}

fn verify_signature(
    secret: &str,
    timestamp: &str,
    raw_body: &[u8],
    provided_signature: &str,
) -> Result<(), WebhookError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| WebhookError::InvalidSignature)?;
    mac.update(timestamp.as_bytes());
    mac.update(raw_body);

    let provided_signature = provided_signature.trim().to_ascii_lowercase();
    let expected_signature = to_lower_hex(&mac.finalize().into_bytes());

    if expected_signature.len() != provided_signature.len()
        || expected_signature
            .as_bytes()
            .ct_eq(provided_signature.as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(WebhookError::InvalidSignature);
    }

    Ok(())
}

fn to_lower_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

fn read_header(headers: &hyper::HeaderMap<HeaderValue>, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

fn response(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .expect("response builder should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::to_bytes;

    const TEST_SECRET: &str = "test-airwallex-secret";
    const TEST_TIMESTAMP: &str = "1712345678000";

    fn test_server() -> AirwallexWebhookServer {
        AirwallexWebhookServer::new(
            AirwallexWebhookConfig {
                bind_address: "127.0.0.1:18081".parse().unwrap(),
                webhook_secret: TEST_SECRET.to_string(),
            },
            8,
        )
    }

    fn sign_body(secret: &str, timestamp: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.as_bytes());
        mac.update(body);
        to_lower_hex(&mac.finalize().into_bytes())
    }

    fn signed_request(body: &'static str) -> Request<Body> {
        let signature = sign_body(TEST_SECRET, TEST_TIMESTAMP, body.as_bytes());
        Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .header(AIRWALLEX_SIGNATURE_HEADER, signature)
            .body(Body::from(body))
            .unwrap()
    }

    async fn response_body(response: Response<Body>) -> String {
        String::from_utf8(to_bytes(response.into_body()).await.unwrap().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn accepts_valid_signature() {
        let server = test_server();
        let request = signed_request(
            r#"{"id":"evt_1","name":"payment.transfer.updated","created_at":"2026-09-18T23:00:00Z","request_id":"req_1"}"#,
        );

        let response = server.handle_request(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, "recorded");
        assert_eq!(
            server.recorded_events(),
            vec![RecordedWebhookEvent {
                event_id: "evt_1".to_string(),
                event_type: "payment.transfer.updated".to_string(),
                created_at: Some("2026-09-18T23:00:00Z".to_string()),
                request_id: Some("req_1".to_string()),
            }]
        );
    }

    #[tokio::test]
    async fn rejects_invalid_signature() {
        let server = test_server();
        let request = Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .header(AIRWALLEX_SIGNATURE_HEADER, "invalid-signature")
            .body(Body::from(
                r#"{"id":"evt_1","name":"payment.transfer.updated"}"#,
            ))
            .unwrap();

        let response = server.handle_request(request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_missing_signature() {
        let server = test_server();
        let request = Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .body(Body::from(
                r#"{"id":"evt_1","name":"payment.transfer.updated"}"#,
            ))
            .unwrap();

        let response = server.handle_request(request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn handles_duplicate_event_ids_idempotently() {
        let server = test_server();
        let request_body =
            r#"{"id":"evt_duplicate","name":"payment.transfer.updated","request_id":"req_1"}"#;

        let first_response = server.handle_request(signed_request(request_body)).await;
        let second_response = server.handle_request(signed_request(request_body)).await;

        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(response_body(second_response).await, "duplicate");
        assert_eq!(server.recorded_events().len(), 1);
    }

    #[tokio::test]
    async fn rejects_malformed_json() {
        let server = test_server();
        let malformed_body = r#"{"id":"evt_bad","name":"payment.transfer.updated""#;
        let signature = sign_body(TEST_SECRET, TEST_TIMESTAMP, malformed_body.as_bytes());
        let request = Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .header(AIRWALLEX_SIGNATURE_HEADER, signature)
            .body(Body::from(malformed_body))
            .unwrap();

        let response = server.handle_request(request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn accepts_unknown_event_types() {
        let server = test_server();
        let request = signed_request(
            r#"{"id":"evt_unknown","name":"something.completely_new","created_at":1720000000}"#,
        );

        let response = server.handle_request(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            server.recorded_events()[0].event_type,
            "something.completely_new"
        );
    }

    #[tokio::test]
    async fn verifies_signature_against_raw_body() {
        let server = test_server();
        let raw_body = "{\n  \"id\": \"evt_raw\",\n  \"name\": \"payment.transfer.updated\"\n}";
        let signature = sign_body(TEST_SECRET, TEST_TIMESTAMP, raw_body.as_bytes());

        let valid_request = Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .header(AIRWALLEX_SIGNATURE_HEADER, signature.clone())
            .body(Body::from(raw_body))
            .unwrap();
        let tampered_request = Request::builder()
            .method(Method::POST)
            .uri(AIRWALLEX_WEBHOOK_PATH)
            .header(AIRWALLEX_TIMESTAMP_HEADER, TEST_TIMESTAMP)
            .header(AIRWALLEX_SIGNATURE_HEADER, signature)
            .body(Body::from(
                r#"{"id":"evt_raw","name":"payment.transfer.updated"}"#,
            ))
            .unwrap();

        let valid_response = server.handle_request(valid_request).await;
        let tampered_response = server.handle_request(tampered_request).await;

        assert_eq!(valid_response.status(), StatusCode::OK);
        assert_eq!(tampered_response.status(), StatusCode::UNAUTHORIZED);
    }
}
