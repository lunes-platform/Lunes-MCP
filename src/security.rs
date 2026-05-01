//! HTTP transport security for public deployments.

use jsonrpsee::server::{HttpBody, HttpRequest, HttpResponse};
use parking_lot::Mutex;
use serde_json::json;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tower::{Layer, Service};

pub const API_KEY_ENV_VAR: &str = "LUNES_MCP_API_KEY";
pub const API_KEY_HEADER: &str = "x-lunes-mcp-api-key";
pub const AUTH_ERROR_CODE: i64 = -32090;
pub const RATE_LIMIT_ERROR_CODE: i64 = -32099;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitSettings {
    pub per_second: u64,
    pub burst: u32,
}

impl RateLimitSettings {
    pub fn enabled(self) -> bool {
        self.per_second > 0 && self.burst > 0
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublicExposureError {
    #[error("public bind requires {API_KEY_ENV_VAR}")]
    MissingApiKey,
    #[error("public bind requires an enabled rate limit")]
    RateLimitDisabled,
}

pub fn is_public_bind(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => !ip.is_loopback(),
        IpAddr::V6(ip) => !ip.is_loopback(),
    }
}

pub fn validate_public_exposure(
    addr: &SocketAddr,
    api_key_configured: bool,
    rate_limit: RateLimitSettings,
) -> Result<(), PublicExposureError> {
    if !is_public_bind(addr) {
        return Ok(());
    }

    if !api_key_configured {
        return Err(PublicExposureError::MissingApiKey);
    }

    if !rate_limit.enabled() {
        return Err(PublicExposureError::RateLimitDisabled);
    }

    Ok(())
}

#[derive(Clone)]
pub struct TransportSecurityLayer {
    state: Arc<TransportSecurityState>,
}

impl TransportSecurityLayer {
    pub fn new(state: Arc<TransportSecurityState>) -> Self {
        Self { state }
    }
}

impl<S> Layer<S> for TransportSecurityLayer {
    type Service = TransportSecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TransportSecurityService {
            inner,
            state: self.state.clone(),
        }
    }
}

#[derive(Clone)]
pub struct TransportSecurityService<S> {
    inner: S,
    state: Arc<TransportSecurityState>,
}

impl<S, ReqBody> Service<HttpRequest<ReqBody>> for TransportSecurityService<S>
where
    S: Service<HttpRequest<ReqBody>, Response = HttpResponse> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = HttpResponse;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: HttpRequest<ReqBody>) -> Self::Future {
        if let Err(rejection) = self.state.check_request(request.headers()) {
            return Box::pin(async move { Ok(rejection.into_response()) });
        }

        let future = self.inner.call(request);
        Box::pin(future)
    }
}

pub struct TransportSecurityState {
    api_key: Option<String>,
    rate_limiter: Option<TokenBucket>,
}

impl TransportSecurityState {
    pub fn new(api_key: Option<String>, rate_limit: RateLimitSettings) -> Self {
        let api_key = api_key.and_then(|key| {
            let trimmed = key.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
        let rate_limiter = rate_limit
            .enabled()
            .then(|| TokenBucket::new(rate_limit.per_second, rate_limit.burst));

        Self {
            api_key,
            rate_limiter,
        }
    }

    pub fn api_key_configured(&self) -> bool {
        self.api_key.is_some()
    }

    fn check_request(&self, headers: &http::HeaderMap) -> Result<(), SecurityRejection> {
        if let Some(expected) = &self.api_key {
            if !has_valid_api_key(headers, expected) {
                return Err(SecurityRejection::Unauthorized);
            }
        }

        if let Some(rate_limiter) = &self.rate_limiter {
            rate_limiter
                .check()
                .map_err(SecurityRejection::RateLimited)?;
        }

        Ok(())
    }
}

enum SecurityRejection {
    Unauthorized,
    RateLimited(Duration),
}

impl SecurityRejection {
    fn into_response(self) -> HttpResponse {
        match self {
            Self::Unauthorized => json_response(
                http::StatusCode::UNAUTHORIZED,
                AUTH_ERROR_CODE,
                "missing or invalid API key",
                &[("www-authenticate", "Bearer")],
            ),
            Self::RateLimited(retry_after) => {
                let retry_after = retry_after.as_secs().max(1).to_string();
                json_response(
                    http::StatusCode::TOO_MANY_REQUESTS,
                    RATE_LIMIT_ERROR_CODE,
                    "rate limit active",
                    &[("retry-after", retry_after.as_str())],
                )
            }
        }
    }
}

fn json_response(
    status: http::StatusCode,
    code: i64,
    message: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut builder = HttpResponse::builder()
        .status(status)
        .header("content-type", "application/json");

    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }

    let body = json!({
        "jsonrpc": "2.0",
        "error": {
            "code": code,
            "message": message,
        },
        "id": null,
    })
    .to_string();

    builder
        .body(HttpBody::from(body))
        .expect("static HTTP response is valid")
}

fn has_valid_api_key(headers: &http::HeaderMap, expected: &str) -> bool {
    let bearer = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let api_key_header = headers
        .get(API_KEY_HEADER)
        .and_then(|value| value.to_str().ok());

    bearer
        .into_iter()
        .chain(api_key_header)
        .any(|candidate| constant_time_eq(candidate.as_bytes(), expected.as_bytes()))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for idx in 0..max_len {
        let l = *left.get(idx).unwrap_or(&0);
        let r = *right.get(idx).unwrap_or(&0);
        diff |= (l ^ r) as usize;
    }

    diff == 0
}

struct TokenBucket {
    per_second: u64,
    burst: u32,
    state: Mutex<TokenBucketState>,
}

struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(per_second: u64, burst: u32) -> Self {
        Self {
            per_second,
            burst,
            state: Mutex::new(TokenBucketState {
                tokens: burst as f64,
                last_refill: Instant::now(),
            }),
        }
    }

    fn check(&self) -> Result<(), Duration> {
        self.check_at(Instant::now())
    }

    fn check_at(&self, now: Instant) -> Result<(), Duration> {
        let mut state = self.state.lock();
        let elapsed = now.saturating_duration_since(state.last_refill);
        let refill = elapsed.as_secs_f64() * self.per_second as f64;

        if refill > 0.0 {
            state.tokens = (state.tokens + refill).min(self.burst as f64);
            state.last_refill = now;
        }

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            return Ok(());
        }

        let missing = 1.0 - state.tokens;
        let wait_seconds = missing / self.per_second as f64;
        Err(Duration::from_secs_f64(wait_seconds.max(0.001)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_bind_does_not_require_api_key() {
        let addr: SocketAddr = "127.0.0.1:9950".parse().unwrap();
        let rate_limit = RateLimitSettings {
            per_second: 0,
            burst: 0,
        };

        assert_eq!(validate_public_exposure(&addr, false, rate_limit), Ok(()));
    }

    #[test]
    fn public_bind_requires_api_key() {
        let addr: SocketAddr = "0.0.0.0:9950".parse().unwrap();
        let rate_limit = RateLimitSettings {
            per_second: 10,
            burst: 20,
        };

        assert_eq!(
            validate_public_exposure(&addr, false, rate_limit),
            Err(PublicExposureError::MissingApiKey)
        );
    }

    #[test]
    fn public_bind_requires_rate_limit() {
        let addr: SocketAddr = "0.0.0.0:9950".parse().unwrap();
        let rate_limit = RateLimitSettings {
            per_second: 0,
            burst: 20,
        };

        assert_eq!(
            validate_public_exposure(&addr, true, rate_limit),
            Err(PublicExposureError::RateLimitDisabled)
        );
    }

    #[test]
    fn api_key_accepts_bearer_and_custom_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer secret-token"),
        );
        assert!(has_valid_api_key(&headers, "secret-token"));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            API_KEY_HEADER,
            http::HeaderValue::from_static("secret-token"),
        );
        assert!(has_valid_api_key(&headers, "secret-token"));
    }

    #[test]
    fn api_key_rejects_missing_or_wrong_token() {
        let mut headers = http::HeaderMap::new();
        assert!(!has_valid_api_key(&headers, "secret-token"));

        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_static("Bearer wrong"),
        );
        assert!(!has_valid_api_key(&headers, "secret-token"));
    }

    #[test]
    fn auth_rejection_does_not_consume_authenticated_rate_limit() {
        let state = TransportSecurityState::new(
            Some("secret-token".into()),
            RateLimitSettings {
                per_second: 1,
                burst: 1,
            },
        );
        let headers = http::HeaderMap::new();

        assert!(matches!(
            state.check_request(&headers),
            Err(SecurityRejection::Unauthorized)
        ));
        assert!(matches!(
            state.check_request(&headers),
            Err(SecurityRejection::Unauthorized)
        ));

        let mut headers = http::HeaderMap::new();
        headers.insert(
            API_KEY_HEADER,
            http::HeaderValue::from_static("secret-token"),
        );
        assert!(state.check_request(&headers).is_ok());
        assert!(matches!(
            state.check_request(&headers),
            Err(SecurityRejection::RateLimited(_))
        ));
    }

    #[test]
    fn token_bucket_allows_burst_then_blocks() {
        let limiter = TokenBucket::new(1, 2);
        let now = Instant::now();

        assert!(limiter.check_at(now).is_ok());
        assert!(limiter.check_at(now).is_ok());
        assert!(limiter.check_at(now).is_err());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = TokenBucket::new(1, 1);
        let now = Instant::now();

        assert!(limiter.check_at(now).is_ok());
        assert!(limiter.check_at(now).is_err());
        assert!(limiter.check_at(now + Duration::from_secs(1)).is_ok());
    }
}
