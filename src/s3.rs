//! S3 REST API: routing, addressing-style resolution, and all request
//! handlers. Every response carries an `x-amz-request-id`; every failure is
//! converted into the standard S3 XML error document.

use crate::auth::{self, AuthResult, ChunkDecoder, PayloadShaMode, Verified};
use crate::error::{S3Error, XMLNS_S3, error_xml};
use crate::storage::{ObjectMeta, Storage};
use crate::xml::{Xml, parse as xml_parse};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub creds: auth::CredentialStore,
}

impl AppState {
    pub fn new(storage: Storage, creds: auth::CredentialStore) -> Self {
        Self { storage, creds }
    }
}

/// Identity of the authenticated requester, injected by the auth middleware.
#[derive(Clone)]
pub struct AuthContext {
    pub access_key: String,
}

pub fn router(state: AppState) -> axum::Router {
    axum::Router::new()
        .fallback(entry)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_and_request_id,
        ))
        .with_state(state)
}

// ---------------------------------------------------------------- middleware

async fn auth_and_request_id(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let method = req.method().to_string();
    let raw_path = req.uri().path().to_string();
    let query = parse_query(req.uri().query().unwrap_or(""));
    let headers = req.headers().clone();

    let verified = match auth::verify_request(&state.creds, &method, &raw_path, &query, &headers) {
        Ok(v) => v,
        Err(e) => return error_response(e, &raw_path, &request_id),
    };
    let verified = match verified {
        AuthResult::Header(v) | AuthResult::Presigned(v) => v,
    };
    req.extensions_mut().insert(AuthContext {
        access_key: verified.access_key.clone(),
    });

    // Wrap the body: hash-observation always; chunk decoding when streaming-signed.
    let body_state = Arc::new(Mutex::new(BodyStateInner::new(&verified)));
    let decoder = match verified.payload_sha_mode {
        PayloadShaMode::StreamingSigned => Some(ChunkDecoder::new(
            verified.signing_key.clone(),
            verified.scope.clone(),
            verified.amz_date.clone(),
            verified.signature.clone(),
        )),
        _ => None,
    };
    let inner_stream = std::mem::replace(req.body_mut(), Body::empty()).into_data_stream();
    let observe = ObservingBody {
        inner: inner_stream,
        state: body_state.clone(),
        decoder,
    };
    let new_body = Body::from_stream(observe);
    req = req.map(|_| new_body);
    req.extensions_mut().insert(BodyStateHandle(body_state));

    let start = std::time::Instant::now();
    let mut res = next.run(req).await;
    let dur = start.elapsed();
    tracing::info!(%method, path = %raw_path, status = res.status().as_u16(), ?dur, request_id = %request_id, "request");
    res.headers_mut().insert(
        "x-amz-request-id",
        HeaderValue::from_str(&request_id).unwrap(),
    );
    res
}

#[derive(Clone)]
pub struct BodyStateHandle(pub Arc<Mutex<BodyStateInner>>);

pub struct BodyStateInner {
    pub sha: sha2::Sha256,
    pub md5: md5::Md5,
    pub expected_sha: Option<String>,
    pub content_md5_hex: Option<String>,
    pub error: Option<S3Error>,
}

impl BodyStateInner {
    fn new(verified: &Verified) -> Self {
        let expected_sha = match &verified.payload_sha_mode {
            PayloadShaMode::SignedFull(h) => Some(h.clone()),
            _ => None,
        };
        Self {
            sha: sha2::Sha256::new(),
            md5: md5::Md5::new(),
            expected_sha,
            content_md5_hex: None,
            error: None,
        }
    }
}

/// Body wrapper: observes hashes and optionally decodes aws-chunked framing.
struct ObservingBody {
    inner: axum::body::BodyDataStream,
    state: Arc<Mutex<BodyStateInner>>,
    decoder: Option<auth::ChunkDecoder>,
}

impl Stream for ObservingBody {
    type Item = Result<Bytes, S3Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match self.inner.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    {
                        let mut st = self.state.lock().unwrap();
                        st.sha.update(&chunk);
                        st.md5.update(&chunk);
                    }
                    match &mut self.decoder {
                        Some(dec) => {
                            let mut out = Vec::new();
                            match dec.push(&chunk, &mut out) {
                                Ok(()) => {
                                    if out.is_empty() {
                                        if dec.is_finished() {
                                            continue; // poll for end of stream
                                        }
                                        continue;
                                    }
                                    return Poll::Ready(Some(Ok(bytes::Bytes::from(out.concat()))));
                                }
                                Err(e) => {
                                    self.state.lock().unwrap().error = Some(e);
                                    return Poll::Ready(Some(Err(S3Error::invalid_argument(
                                        "chunked payload error",
                                    ))));
                                }
                            }
                        }
                        None => return Poll::Ready(Some(Ok(chunk))),
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(S3Error::internal(format!(
                        "body read error: {e}"
                    )))));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ---------------------------------------------------------------- helpers

pub fn parse_query(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let k = auth::percent_decode(k).unwrap_or_else(|| k.to_string());
        let v = auth::percent_decode(v).unwrap_or_else(|| v.to_string());
        out.push((k, v));
    }
    out
}

pub fn xml_response(status: u16, body: String, extra: HeaderMap) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(status).unwrap())
        .header("content-type", "application/xml");
    for (k, v) in &extra {
        builder = builder.header(k, v);
    }
    builder.body(Body::from(body)).unwrap()
}

pub fn error_response(err: S3Error, resource: &str, request_id: &str) -> Response {
    let body = error_xml(err.code, &err.message, resource, request_id);
    let mut res = xml_response(err.status, body, HeaderMap::new());
    res.headers_mut().insert(
        "x-amz-request-id",
        HeaderValue::from_str(request_id).unwrap_or(HeaderValue::from_static("unknown")),
    );
    res
}

fn http_date(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc2822()
        .replace("+0000", "GMT")
}

fn xml_date(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

fn header_opt(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn user_metadata(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut md = BTreeMap::new();
    for (name, value) in headers {
        let name = name.as_str().to_lowercase();
        if let Some(rest) = name.strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                md.insert(rest.to_string(), v.to_string());
            }
        }
    }
    md
}

fn content_md5_hex(headers: &HeaderMap) -> Option<String> {
    header_opt(headers, "content-md5").and_then(|b64| {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()
            .map(hex::encode)
    })
}

/// Addressing-style resolution: virtual-hosted bucket from the Host header.
pub fn bucket_from_host(host: &str) -> Option<String> {
    let host = host.split(':').next()?;
    for suffix in [
        ".localhost",
        ".s3.local",
        ".localdomain",
        ".s3.amazonaws.com",
    ] {
        if let Some(bucket) = host.strip_suffix(suffix) {
            if !bucket.is_empty() && !bucket.contains('/') {
                return Some(bucket.to_string());
            }
        }
    }
    None
}

fn object_headers(meta: &ObjectMeta) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "etag",
        HeaderValue::from_str(&format!("\"{}\"", meta.etag)).unwrap(),
    );
    h.insert(
        "last-modified",
        HeaderValue::from_str(&http_date(meta.last_modified)).unwrap(),
    );
    h.insert("accept-ranges", HeaderValue::from_static("bytes"));
    if let Ok(v) = HeaderValue::from_str(&meta.content_type) {
        h.insert("content-type", v);
    }
    for (k, v) in &meta.metadata {
        if let (Ok(name), Ok(val)) = (
            axum::http::HeaderName::from_bytes(format!("x-amz-meta-{k}").as_bytes()),
            HeaderValue::from_str(v),
        ) {
            h.insert(name, val);
        }
    }
    h
}

fn resource_path(bucket: &str, key: &str) -> String {
    if key.is_empty() {
        format!("/{bucket}")
    } else {
        format!("/{bucket}/{key}")
    }
}

// ---------------------------------------------------------------- entry / dispatch

async fn entry(State(state): State<AppState>, req: Request) -> Response {
    let request_id = req
        .headers()
        .get("x-amz-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    match dispatch(state, req).await {
        Ok(res) => res,
        Err(e) => {
            let resource = resource_from_error(&e);
            error_response(e, &resource, &request_id)
        }
    }
}

fn resource_from_error(e: &S3Error) -> String {
    // best effort: error messages carry the resource already in most cases
    let _ = e;
    String::new()
}

fn decode_path(path: &str) -> Result<Vec<String>, S3Error> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|seg| {
            auth::percent_decode(seg)
                .ok_or_else(|| S3Error::invalid_argument("Invalid URL encoding in path"))
        })
        .collect()
}

async fn dispatch(state: AppState, req: Request) -> Result<Response, S3Error> {
    let method = req.method().clone();
    let query = parse_query(req.uri().query().unwrap_or(""));
    let headers = req.headers().clone();

    // virtual-hosted-style: bucket from Host header
    let vhost_bucket = header_opt(&headers, "host").and_then(|h| bucket_from_host(&h));
    let raw_path = req.uri().path();
    let segments = decode_path(if vhost_bucket.is_some() {
        raw_path
    } else {
        raw_path
    })?;
    let (bucket, key): (String, String) = match (&vhost_bucket, segments.is_empty()) {
        (Some(b), false) => (b.clone(), segments.join("/")),
        (Some(b), true) => (b.clone(), String::new()),
        (None, true) => (String::new(), String::new()),
        (None, false) => (segments[0].clone(), segments[1..].join("/")),
    };

    if bucket.is_empty() {
        return match method {
            Method::GET => list_buckets(&state).await,
            _ => Err(S3Error::method_not_allowed()),
        };
    }

    if key.is_empty() {
        // bucket-level operations
        return match method {
            Method::PUT => create_bucket(&state, &bucket, req).await,
            Method::DELETE => delete_bucket(&state, &bucket).await,
            Method::HEAD => head_bucket(&state, &bucket).await,
            Method::GET => bucket_get(&state, &bucket, &query, &headers).await,
            Method::POST if query.iter().any(|(k, _)| k == "delete") => {
                delete_objects(&state, &bucket, req).await
            }
            _ => Err(S3Error::method_not_allowed()),
        };
    }

    // object-level operations
    let has = |name: &str| query.iter().any(|(k, _)| k == name);
    let get_q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    match method {
        Method::PUT => {
            if let (Some(upload_id), Some(part_number)) = (get_q("uploadId"), get_q("partNumber")) {
                let part: u32 = part_number
                    .parse()
                    .map_err(|_| S3Error::invalid_argument("Invalid partNumber"))?;
                if headers.contains_key("x-amz-copy-source") {
                    return upload_part_copy(&state, &bucket, &key, &upload_id, part, &headers)
                        .await;
                }
                return upload_part(&state, &bucket, &key, &upload_id, part, req).await;
            }
            if headers.contains_key("x-amz-copy-source") {
                return copy_object(&state, &bucket, &key, &headers).await;
            }
            put_object(&state, &bucket, &key, req).await
        }
        Method::GET => {
            if get_q("uploadId").is_some() {
                return list_parts(&state, &bucket, &key, &query).await;
            }
            get_object(&state, &bucket, &key, &query, &headers, false).await
        }
        Method::HEAD => get_object(&state, &bucket, &key, &query, &headers, true).await,
        Method::DELETE => {
            if let Some(upload_id) = get_q("uploadId") {
                return abort_multipart(&state, &bucket, &key, &upload_id).await;
            }
            delete_object(&state, &bucket, &key).await
        }
        Method::POST => {
            if has("uploads") {
                return create_multipart(&state, &bucket, &key, &headers).await;
            }
            if let Some(upload_id) = get_q("uploadId") {
                return complete_multipart(&state, &bucket, &key, &upload_id, req).await;
            }
            Err(S3Error::method_not_allowed())
        }
        _ => Err(S3Error::method_not_allowed()),
    }
}

/// Verify streamed-body invariants recorded by the observing body wrapper.
fn check_body_state(
    state: &BodyStateHandle,
    put_result: Option<&crate::storage::PutResult>,
) -> Result<(), S3Error> {
    let st = state.0.lock().unwrap();
    if let Some(e) = &st.error {
        return Err(e.clone());
    }
    if let Some(expected) = &st.expected_sha {
        let actual = hex::encode(st.sha.clone().finalize());
        if &actual != expected {
            return Err(S3Error::sha_mismatch());
        }
    }
    if let (Some(expected), Some(put)) = (&st.content_md5_hex, put_result) {
        if expected != &put.content_md5_hex {
            return Err(S3Error::bad_digest());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- bucket handlers

async fn list_buckets(state: &AppState) -> Result<Response, S3Error> {
    let buckets = state.storage.list_buckets().await?;
    let mut doc = Xml::new().open("ListAllMyBucketsResult", &[("xmlns", XMLNS_S3)]);
    doc = doc
        .open("Owner", &[])
        .el("ID", "los-cara-owner")
        .el("DisplayName", "los-cara")
        .close("Owner");
    doc = doc.open("Buckets", &[]);
    for (name, created) in buckets {
        doc = doc
            .open("Bucket", &[])
            .el("Name", &name)
            .el("CreationDate", &xml_date(created))
            .close("Bucket");
    }
    doc = doc.close("Buckets").close("ListAllMyBucketsResult");
    Ok(xml_response(200, doc.finish(), HeaderMap::new()))
}

async fn create_bucket(state: &AppState, bucket: &str, req: Request) -> Result<Response, S3Error> {
    let body = axum::body::to_bytes(req.into_body(), 1 << 20)
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
    // LocationConstraint is accepted but not enforced
    if !body.is_empty() {
        xml_parse(&body).map_err(|_| S3Error::malformed_xml())?;
    }
    match state.storage.create_bucket(bucket).await? {
        true => {
            let mut h = HeaderMap::new();
            h.insert(
                "location",
                HeaderValue::from_str(&format!("/{bucket}")).unwrap(),
            );
            Ok(xml_response(200, String::new(), h))
        }
        // single-account server: the bucket is owned by the requester
        false => Ok(xml_response(200, String::new(), {
            let mut h = HeaderMap::new();
            h.insert(
                "location",
                HeaderValue::from_str(&format!("/{bucket}")).unwrap(),
            );
            h
        })),
    }
}

async fn delete_bucket(state: &AppState, bucket: &str) -> Result<Response, S3Error> {
    state.storage.delete_bucket(bucket).await?;
    Ok(xml_response(204, String::new(), HeaderMap::new()))
}

async fn head_bucket(state: &AppState, bucket: &str) -> Result<Response, S3Error> {
    state.storage.bucket_created(bucket).await?;
    let mut h = HeaderMap::new();
    h.insert("x-amz-bucket-region", HeaderValue::from_static("us-east-1"));
    Ok(xml_response(200, String::new(), h))
}

async fn bucket_get(
    state: &AppState,
    bucket: &str,
    query: &[(String, String)],
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let has = |name: &str| query.iter().any(|(k, _)| k == name);
    let get_q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    // neutral subresource probes
    for neutral in [
        "versioning",
        "acl",
        "cors",
        "lifecycle",
        "tagging",
        "website",
        "encryption",
        "policy",
        "object-lock",
        "notification",
        "replication",
        "logging",
        "requestPayment",
        "accelerate",
    ] {
        if has(neutral) {
            return Ok(neutral_bucket_response(neutral, state, bucket).await);
        }
    }
    if has("location") {
        return Ok(xml_response(
            200,
            Xml::new()
                .open("LocationConstraint", &[("xmlns", XMLNS_S3)])
                .close("LocationConstraint")
                .finish(),
            HeaderMap::new(),
        ));
    }
    if has("uploads") {
        return list_multipart_uploads(state, bucket).await;
    }
    let list_type = get_q("list-type");
    match list_type.as_deref() {
        Some("2") => list_objects_v2(state, bucket, query).await,
        _ => list_objects_v1(state, bucket, query).await,
    }
    .map(|res| {
        let _ = headers;
        res
    })
}

async fn neutral_bucket_response(sub: &str, state: &AppState, bucket: &str) -> Response {
    let _ = (state, bucket);
    let body = match sub {
        "versioning" => Xml::new()
            .open("VersioningConfiguration", &[("xmlns", XMLNS_S3)])
            .close("VersioningConfiguration")
            .finish(),
        "location" => Xml::new()
            .open("LocationConstraint", &[("xmlns", XMLNS_S3)])
            .close("LocationConstraint")
            .finish(),
        "acl" => Xml::new()
            .open("AccessControlPolicy", &[("xmlns", XMLNS_S3)])
            .open("Owner", &[])
            .el("ID", "los-cara-owner")
            .el("DisplayName", "los-cara")
            .close("Owner")
            .open("AccessControlList", &[])
            .open("Grant", &[])
            .open(
                "Grantee",
                &[
                    ("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"),
                    ("xsi:type", "CanonicalUser"),
                ],
            )
            .el("ID", "los-cara-owner")
            .el("DisplayName", "los-cara")
            .close("Grantee")
            .el("Permission", "FULL_CONTROL")
            .close("Grant")
            .close("AccessControlList")
            .close("AccessControlPolicy")
            .finish(),
        _ => String::new(),
    };
    xml_response(200, body, HeaderMap::new())
}

// ---------------------------------------------------------------- object handlers

async fn put_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    req: Request,
) -> Result<Response, S3Error> {
    let (parts, body_stream) = req.into_parts();
    let content_type =
        header_opt(&parts.headers, "content-type").unwrap_or_else(|| "binary/octet-stream".into());
    let metadata = user_metadata(&parts.headers);
    let body_state = parts
        .extensions
        .get::<BodyStateHandle>()
        .cloned()
        .ok_or_else(|| S3Error::internal("missing body state"))?;
    if let Some(md5hex) = content_md5_hex(&parts.headers) {
        body_state.0.lock().unwrap().content_md5_hex = Some(md5hex);
    }

    // The request body is the middleware's observing stream (decoded + hashed).
    let result = state
        .storage
        .put_object(
            bucket,
            key,
            BoxBodyStream {
                body: body_stream.into_data_stream(),
            },
            content_type,
            metadata,
        )
        .await;
    match result {
        Ok(put) => {
            if let Err(e) = check_body_state(&body_state, Some(&put)) {
                let _ = state.storage.delete_object(bucket, key).await;
                return Err(e);
            }
            let _ = &put.meta;
            let mut h = HeaderMap::new();
            h.insert(
                "etag",
                HeaderValue::from_str(&format!("\"{}\"", put.meta.etag)).unwrap(),
            );
            Ok(xml_response(200, String::new(), h))
        }
        Err(e) => {
            // surface auth-body errors with their proper S3 code
            let st_err = body_state.0.lock().unwrap().error.clone();
            Err(st_err.unwrap_or(e))
        }
    }
}

/// Adapter: the axum body stream (already decoded/hashed by middleware) yields
/// Result<Bytes, axum::Error>; convert to Result<Bytes, S3Error>.
struct BoxBodyStream {
    body: axum::body::BodyDataStream,
}

impl Stream for BoxBodyStream {
    type Item = Result<Bytes, S3Error>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.body.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(b))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(S3Error::invalid_argument(
                format!("body error: {e}"),
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn get_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    _query: &[(String, String)],
    headers: &HeaderMap,
    head_only: bool,
) -> Result<Response, S3Error> {
    let meta = match state.storage.head_object(bucket, key).await {
        Ok(m) => m,
        Err(e) if e.code == "NoSuchBucket" || e.code == "NoSuchKey" => {
            if head_only {
                // HEAD has no body; status only
                return Ok(xml_response(e.status, String::new(), HeaderMap::new()));
            }
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    // conditional requests
    if let Some(resp) = evaluate_conditions(headers, &meta)? {
        return Ok(resp);
    }

    // range
    let mut range_headers = HeaderMap::new();
    let mut range: Option<(u64, Option<u64>)> = None;
    if let Some(range_header) = header_opt(headers, "range") {
        match parse_range(&range_header, meta.size) {
            RangeParse::Valid(start, len) => {
                range = Some((start, Some(len)));
                range_headers.insert(
                    "content-range",
                    HeaderValue::from_str(&format!(
                        "bytes {start}-{}-{}",
                        start + len - 1,
                        meta.size
                    ))
                    .unwrap(),
                );
            }
            RangeParse::Invalid => return Err(S3Error::invalid_range()),
            RangeParse::Ignored => {}
        }
    }

    let (meta, reader) = if let Some((start, len)) = range {
        let (m, r) = state
            .storage
            .get_object_range(bucket, key, start, len)
            .await?;
        (m, r)
    } else {
        state.storage.get_object(bucket, key).await?
    };

    let mut h = object_headers(&meta);
    h.insert(
        "content-length",
        HeaderValue::from_str(&meta.size.to_string()).unwrap(),
    );
    for (k, v) in range_headers {
        if let (Some(k), v) = (k, v) {
            h.insert(k, v);
        }
    }
    let status = if range.is_some() { 206 } else { 200 };

    if head_only {
        // headers only; hyper suppresses the body for HEAD
        let _ = reader;
        let mut h = h;
        h.remove("content-length"); // hyper sets it from body; for HEAD we set explicit
        let mut builder = Response::builder().status(StatusCode::from_u16(status).unwrap());
        for (k, v) in h {
            if let (Some(k), v) = (k, v) {
                builder = builder.header(k, v);
            }
        }
        // preserve declared content length for HEAD
        let mut builder = builder;
        return Ok(builder.body(Body::empty()).unwrap());
    }

    let stream = crate::storage::tokio_util_wrap::reader_stream(reader);
    let mut builder = Response::builder().status(StatusCode::from_u16(status).unwrap());
    for (k, v) in h {
        if let (Some(k), v) = (k, v) {
            builder = builder.header(k, v);
        }
    }
    Ok(builder.body(Body::from_stream(stream)).unwrap())
}

fn evaluate_conditions(
    headers: &HeaderMap,
    meta: &ObjectMeta,
) -> Result<Option<Response>, S3Error> {
    let etag = format!("\"{}\"", meta.etag);
    let last_modified = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(meta.last_modified)
        .unwrap_or_default();

    let if_match = header_opt(headers, "if-match");
    let if_none_match = header_opt(headers, "if-none-match");
    let if_modified_since = header_opt(headers, "if-modified-since")
        .and_then(|s| chrono::DateTime::parse_from_rfc2822(&s).ok());
    let if_unmodified_since = header_opt(headers, "if-unmodified-since")
        .and_then(|s| chrono::DateTime::parse_from_rfc2822(&s).ok());

    let match_list = |v: &str| {
        v.split(',')
            .map(|s| s.trim().trim_matches('"'))
            .any(|t| t == "*" || t == meta.etag)
    };

    if let Some(im) = &if_match {
        if !match_list(im) {
            return Err(S3Error::precondition_failed());
        }
    } else if let Some(ius) = if_unmodified_since {
        if last_modified > ius {
            return Err(S3Error::precondition_failed());
        }
    }

    if let Some(inm) = &if_none_match {
        if match_list(inm) {
            return Ok(Some(xml_response(304, String::new(), HeaderMap::new())));
        }
    } else if let Some(ims) = if_modified_since {
        if last_modified <= ims {
            return Ok(Some(xml_response(304, String::new(), HeaderMap::new())));
        }
    }
    let _ = etag;
    Ok(None)
}

enum RangeParse {
    Valid(u64, u64),
    Invalid,
    Ignored,
}

fn parse_range(header: &str, size: u64) -> RangeParse {
    let spec = match header.strip_prefix("bytes=") {
        Some(s) => s,
        None => return RangeParse::Ignored,
    };
    if spec.contains(',') {
        return RangeParse::Ignored; // multipart ranges unsupported: ignore
    }
    let (start_s, end_s) = match spec.split_once('-') {
        Some(p) => p,
        None => return RangeParse::Ignored,
    };
    if start_s.is_empty() {
        // suffix range: last N bytes
        let n: u64 = match end_s.parse::<u64>() {
            Ok(n) => n,
            Err(_) => return RangeParse::Ignored,
        };
        if n == 0 || size == 0 {
            return RangeParse::Invalid;
        }
        let start = size.saturating_sub(n);
        return RangeParse::Valid(start, size - start);
    }
    let start: u64 = match start_s.parse() {
        Ok(n) => n,
        Err(_) => return RangeParse::Ignored,
    };
    if start >= size {
        return RangeParse::Invalid;
    }
    let end: u64 = if end_s.is_empty() {
        size - 1
    } else {
        match end_s.parse::<u64>() {
            Ok(n) => n.min(size - 1),
            Err(_) => return RangeParse::Ignored,
        }
    };
    if end < start {
        return RangeParse::Ignored;
    }
    RangeParse::Valid(start, end - start + 1)
}

async fn delete_object(state: &AppState, bucket: &str, key: &str) -> Result<Response, S3Error> {
    state.storage.delete_object(bucket, key).await?;
    Ok(xml_response(204, String::new(), HeaderMap::new()))
}

async fn delete_objects(state: &AppState, bucket: &str, req: Request) -> Result<Response, S3Error> {
    let body = axum::body::to_bytes(req.into_body(), 4 << 20)
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
    let root = xml_parse(&body).map_err(|_| S3Error::malformed_xml())?;
    if root.tag != "Delete" {
        return Err(S3Error::malformed_xml());
    }
    let keys: Vec<String> = root
        .find_all("Object")
        .iter()
        .filter_map(|o| o.text_of("Key"))
        .collect();
    if keys.len() > 1000 {
        return Err(S3Error::invalid_argument(
            "Delete list must not exceed 1000 keys",
        ));
    }
    let quiet = root.text_of("Quiet").map(|q| q == "true").unwrap_or(false);
    let mut doc = Xml::new().open("DeleteResult", &[("xmlns", XMLNS_S3)]);
    for key in &keys {
        match state.storage.delete_object(bucket, key).await {
            Ok(()) => {
                if !quiet {
                    doc = doc.open("Deleted", &[]).el("Key", key).close("Deleted");
                }
            }
            Err(_) => {
                doc = doc.open("Error", &[]).el("Key", key).close("Error");
            }
        }
    }
    let body = doc.close("DeleteResult").finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn copy_object(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let copy_source = header_opt(headers, "x-amz-copy-source")
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source"))?;
    let copy_source = copy_source.split('?').next().unwrap_or(&copy_source);
    let decoded = auth::percent_decode(copy_source).unwrap_or_else(|| copy_source.to_string());
    let (src_bucket, src_key) = decoded
        .strip_prefix('/')
        .unwrap_or(&decoded)
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))?;
    let directive = header_opt(headers, "x-amz-metadata-directive").unwrap_or_default();
    let replace = if directive.eq_ignore_ascii_case("REPLACE") {
        let ct =
            header_opt(headers, "content-type").unwrap_or_else(|| "binary/octet-stream".into());
        Some((ct, user_metadata(headers)))
    } else {
        None
    };
    let meta = state
        .storage
        .copy_object(src_bucket, src_key, bucket, key, replace)
        .await?;
    let body = Xml::new()
        .open("CopyObjectResult", &[("xmlns", XMLNS_S3)])
        .el("ETag", &format!("\"{}\"", meta.etag))
        .el("LastModified", &xml_date(meta.last_modified))
        .close("CopyObjectResult")
        .finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

// ---------------------------------------------------------------- listing

async fn list_objects_v2(
    state: &AppState,
    bucket: &str,
    query: &[(String, String)],
) -> Result<Response, S3Error> {
    let get_q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let prefix = get_q("prefix").unwrap_or_default();
    let delimiter = get_q("delimiter").unwrap_or_default();
    let max_keys = get_q("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(1000);
    let continuation = get_q("continuation-token");
    let start_after = get_q("start-after").unwrap_or_default();
    let start_pos = continuation.clone().unwrap_or(start_after);

    let page = state
        .storage
        .list_objects(bucket, &prefix, &delimiter, &start_pos, max_keys)
        .await?;

    let key_count = page.contents.len() + page.common_prefixes.len();
    let mut doc = Xml::new().open("ListBucketResult", &[("xmlns", XMLNS_S3)]);
    doc = doc.el("Name", bucket).el("Prefix", &prefix);
    if !delimiter.is_empty() {
        doc = doc.el("Delimiter", &delimiter);
    }
    if let Some(tok) = &continuation {
        doc = doc.el("ContinuationToken", tok);
    }
    if let Some(sa) = get_q("start-after") {
        doc = doc.el("StartAfter", &sa);
    }
    doc = doc.el("KeyCount", &key_count.to_string());
    doc = doc.el("MaxKeys", &max_keys.to_string());
    doc = doc.el("IsTruncated", if page.truncated { "true" } else { "false" });
    for obj in &page.contents {
        doc = doc
            .open("Contents", &[])
            .el("Key", &obj.key)
            .el("LastModified", &xml_date(obj.last_modified))
            .el("ETag", &format!("\"{}\"", obj.etag))
            .el("Size", &obj.size.to_string())
            .el("StorageClass", "STANDARD")
            .close("Contents");
    }
    for cp in &page.common_prefixes {
        doc = doc
            .open("CommonPrefixes", &[])
            .el("Prefix", cp)
            .close("CommonPrefixes");
    }
    if page.truncated {
        // continuation token: the position to resume after
        let next = page
            .next_prefix_token
            .clone()
            .or(page.next_token.clone())
            .unwrap_or_default();
        doc = doc.el("NextContinuationToken", &next);
    }
    let body = doc.close("ListBucketResult").finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn list_objects_v1(
    state: &AppState,
    bucket: &str,
    query: &[(String, String)],
) -> Result<Response, S3Error> {
    let get_q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let prefix = get_q("prefix").unwrap_or_default();
    let delimiter = get_q("delimiter").unwrap_or_default();
    let max_keys = get_q("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000)
        .min(1000);
    let marker = get_q("marker").unwrap_or_default();

    let page = state
        .storage
        .list_objects(bucket, &prefix, &delimiter, &marker, max_keys)
        .await?;

    let mut doc = Xml::new().open("ListBucketResult", &[("xmlns", XMLNS_S3)]);
    doc = doc
        .el("Name", bucket)
        .el("Prefix", &prefix)
        .el("Marker", &marker);
    if !delimiter.is_empty() {
        doc = doc.el("Delimiter", &delimiter);
    }
    doc = doc.el("MaxKeys", &max_keys.to_string());
    doc = doc.el("IsTruncated", if page.truncated { "true" } else { "false" });
    for obj in &page.contents {
        doc = doc
            .open("Contents", &[])
            .el("Key", &obj.key)
            .el("LastModified", &xml_date(obj.last_modified))
            .el("ETag", &format!("\"{}\"", obj.etag))
            .el("Size", &obj.size.to_string())
            .el("StorageClass", "STANDARD")
            .close("Contents");
    }
    for cp in &page.common_prefixes {
        doc = doc
            .open("CommonPrefixes", &[])
            .el("Prefix", cp)
            .close("CommonPrefixes");
    }
    if page.truncated {
        // V1 NextMarker: only emitted when delimiter is used; clients otherwise
        // use the last returned key as the next marker.
        if let Some(nt) = page.next_prefix_token.clone().or(page.next_token.clone()) {
            doc = doc.el("NextMarker", &nt);
        }
    }
    let body = doc.close("ListBucketResult").finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

// ---------------------------------------------------------------- multipart

async fn create_multipart(
    state: &AppState,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let content_type =
        header_opt(headers, "content-type").unwrap_or_else(|| "binary/octet-stream".into());
    let metadata = user_metadata(headers);
    let m = state
        .storage
        .create_multipart(bucket, key, content_type, metadata)
        .await?;
    let body = Xml::new()
        .open("InitiateMultipartUploadResult", &[("xmlns", XMLNS_S3)])
        .el("Bucket", bucket)
        .el("Key", key)
        .el("UploadId", &m.upload_id)
        .close("InitiateMultipartUploadResult")
        .finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn upload_part(
    state: &AppState,
    _bucket: &str,
    _key: &str,
    upload_id: &str,
    part_number: u32,
    req: Request,
) -> Result<Response, S3Error> {
    let (parts, body) = req.into_parts();
    let body_state = parts
        .extensions
        .get::<BodyStateHandle>()
        .cloned()
        .ok_or_else(|| S3Error::internal("missing body state"))?;
    match state
        .storage
        .upload_part(
            upload_id,
            part_number,
            BoxBodyStream {
                body: body.into_data_stream(),
            },
        )
        .await
    {
        Ok((etag, _size)) => {
            check_body_state(&body_state, None)?;
            let mut h = HeaderMap::new();
            h.insert(
                "etag",
                HeaderValue::from_str(&format!("\"{etag}\"")).unwrap(),
            );
            Ok(xml_response(200, String::new(), h))
        }
        Err(e) => {
            let st_err = body_state.0.lock().unwrap().error.clone();
            Err(st_err.unwrap_or(e))
        }
    }
}

async fn upload_part_copy(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    part_number: u32,
    headers: &HeaderMap,
) -> Result<Response, S3Error> {
    let _ = (bucket, key);
    let copy_source = header_opt(headers, "x-amz-copy-source")
        .ok_or_else(|| S3Error::invalid_argument("missing x-amz-copy-source"))?;
    let copy_source = copy_source
        .split('?')
        .next()
        .unwrap_or(&copy_source)
        .to_string();
    let decoded = auth::percent_decode(&copy_source).unwrap_or(copy_source);
    let (src_bucket, src_key) = decoded
        .strip_prefix('/')
        .unwrap_or(&decoded)
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("x-amz-copy-source must be bucket/key"))?;
    let (etag, _size) = state
        .storage
        .upload_part_copy(upload_id, part_number, src_bucket, src_key)
        .await?;
    let body = Xml::new()
        .open("CopyPartResult", &[("xmlns", XMLNS_S3)])
        .el("ETag", &format!("\"{etag}\""))
        .el(
            "LastModified",
            &xml_date(chrono::Utc::now().timestamp_millis()),
        )
        .close("CopyPartResult")
        .finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn list_parts(
    state: &AppState,
    bucket: &str,
    key: &str,
    query: &[(String, String)],
) -> Result<Response, S3Error> {
    let _ = (bucket, key);
    let get_q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let upload_id =
        get_q("uploadId").ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let max_parts = get_q("max-parts")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1000);
    let marker: u32 = get_q("part-number-marker")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let m = state.storage.list_parts(&upload_id).await?;
    let all: Vec<(&u32, &(String, u64))> = m.parts.iter().filter(|(n, _)| **n > marker).collect();
    let truncated = all.len() > max_parts;
    let shown = &all[..all.len().min(max_parts)];
    let next_marker = shown.last().map(|(n, _)| **n);

    let mut doc = Xml::new().open("ListPartsResult", &[("xmlns", XMLNS_S3)]);
    doc = doc
        .el("Bucket", &m.bucket)
        .el("Key", &m.key)
        .el("UploadId", &m.upload_id)
        .open("Initiator", &[])
        .el("ID", "los-cara-owner")
        .el("DisplayName", "los-cara")
        .close("Initiator")
        .open("Owner", &[])
        .el("ID", "los-cara-owner")
        .el("DisplayName", "los-cara")
        .close("Owner")
        .el("StorageClass", "STANDARD")
        .el("PartNumberMarker", &marker.to_string());
    if let Some(nm) = next_marker {
        doc = doc.el("NextPartNumberMarker", &nm.to_string());
    }
    doc = doc.el("MaxParts", &max_parts.to_string());
    doc = doc.el("IsTruncated", if truncated { "true" } else { "false" });
    for (n, (etag, size)) in shown {
        doc = doc
            .open("Part", &[])
            .el("PartNumber", &n.to_string())
            .el("LastModified", &xml_date(m.initiated))
            .el("ETag", &format!("\"{etag}\""))
            .el("Size", &size.to_string())
            .close("Part");
    }
    let body = doc.close("ListPartsResult").finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn complete_multipart(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
    req: Request,
) -> Result<Response, S3Error> {
    let _ = (bucket, key);
    let body = axum::body::to_bytes(req.into_body(), 4 << 20)
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
    let root = xml_parse(&body).map_err(|_| S3Error::malformed_xml())?;
    let parts: Vec<(u32, String)> = root
        .find_all("Part")
        .iter()
        .map(|p| {
            (
                p.text_of("PartNumber")
                    .unwrap_or_default()
                    .parse::<u32>()
                    .unwrap_or(0),
                p.text_of("ETag")
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
            )
        })
        .collect();

    let meta = state.storage.complete_multipart(upload_id, &parts).await?;
    let body = Xml::new()
        .open("CompleteMultipartUploadResult", &[("xmlns", XMLNS_S3)])
        .el(
            "Location",
            &format!("http://localhost/{bucket}/{}", meta.key),
        )
        .el("Bucket", bucket)
        .el("Key", &meta.key)
        .el("ETag", &format!("\"{}\"", meta.etag))
        .close("CompleteMultipartUploadResult")
        .finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}

async fn abort_multipart(
    state: &AppState,
    bucket: &str,
    key: &str,
    upload_id: &str,
) -> Result<Response, S3Error> {
    let _ = (bucket, key);
    state.storage.abort_multipart(upload_id).await?;
    Ok(xml_response(204, String::new(), HeaderMap::new()))
}

async fn list_multipart_uploads(state: &AppState, bucket: &str) -> Result<Response, S3Error> {
    let uploads = state.storage.list_multipart_uploads(bucket).await?;
    let mut doc = Xml::new().open("ListMultipartUploadsResult", &[("xmlns", XMLNS_S3)]);
    doc = doc
        .el("Bucket", bucket)
        .el("KeyMarker", "")
        .el("UploadIdMarker", "");
    doc = doc.el("MaxUploads", "1000").el("IsTruncated", "false");
    for m in &uploads {
        doc = doc
            .open("Upload", &[])
            .el("Key", &m.key)
            .el("UploadId", &m.upload_id)
            .open("Initiator", &[])
            .el("ID", "los-cara-owner")
            .el("DisplayName", "los-cara")
            .close("Initiator")
            .open("Owner", &[])
            .el("ID", "los-cara-owner")
            .el("DisplayName", "los-cara")
            .close("Owner")
            .el("StorageClass", "STANDARD")
            .el("Initiated", &xml_date(m.initiated))
            .close("Upload");
    }
    let body = doc.close("ListMultipartUploadsResult").finish();
    Ok(xml_response(200, body, HeaderMap::new()))
}
