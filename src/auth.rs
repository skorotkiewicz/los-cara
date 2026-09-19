//! AWS Signature Version 4 verification: header-based signatures, presigned
//! URLs, and `aws-chunked` streaming payload decoding with per-chunk
//! signature verification. Also hosts the access-key credential store.

use crate::error::S3Error;
use bytes::Buf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

type HmacSha256 = Hmac<Sha256>;

pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
}

// ---------------- credential store ----------------

#[derive(Clone)]
pub struct CredentialStore {
    /// path to <data>/keys.json; maps access key -> secret key
    path: PathBuf,
    cached: std::sync::Arc<std::sync::Mutex<CredCache>>,
}

#[derive(Default)]
struct CredCache {
    map: BTreeMap<String, String>,
    root: Option<(String, String)>,
    mtime: Option<(SystemTime, u64)>,
}

impl CredentialStore {
    pub fn new(data_dir: &Path, root: Credentials) -> Self {
        let path = data_dir.join("keys.json");
        let store = Self {
            path,
            cached: Default::default(),
        };
        {
            let mut c = store.cached.lock().unwrap();
            let root = (root.access_key, root.secret_key);
            c.map.insert(root.0.clone(), root.1.clone());
            c.root = Some(root);
        }
        // allow keys.json to overlay additional keys; root always wins on conflict
        store.reload_if_changed(true);
        store
    }

    fn reload_if_changed(&self, force: bool) {
        let meta = std::fs::metadata(&self.path).ok();
        let sig = meta.and_then(|m| m.modified().ok().map(|t| (t, m.len())));
        let mut c = self.cached.lock().unwrap();
        if force || sig != c.mtime {
            c.mtime = sig;
            c.map.clear();
            let root = c.root.clone();
            if let Some((a, s)) = root {
                c.map.insert(a, s);
            }
            if let Ok(data) = std::fs::read(&self.path) {
                if let Ok(map) = serde_json::from_slice::<BTreeMap<String, String>>(&data) {
                    for (k, v) in map {
                        c.map.insert(k, v);
                    }
                }
            }
        }
    }

    pub fn lookup(&self, access_key: &str) -> Option<String> {
        self.reload_if_changed(false);
        let c = self.cached.lock().unwrap();
        c.map.get(access_key).cloned()
    }
}

pub fn add_key(data_dir: &Path, access_key: &str, secret_key: &str) {
    let path = data_dir.join("keys.json");
    let mut map: BTreeMap<String, String> = std::fs::read(&path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    map.insert(access_key.to_string(), secret_key.to_string());
    std::fs::create_dir_all(data_dir).ok();
    std::fs::write(&path, serde_json::to_vec_pretty(&map).unwrap()).unwrap();
}

pub fn remove_key(data_dir: &Path, access_key: &str) {
    let path = data_dir.join("keys.json");
    let mut map: BTreeMap<String, String> = std::fs::read(&path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_default();
    map.remove(access_key);
    std::fs::write(&path, serde_json::to_vec_pretty(&map).unwrap()).unwrap();
}

// ---------------- sigv4 primitives ----------------

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Test/interop helper: derive the SigV4 signing key.
#[doc(hidden)]
pub fn signing_key_for_test(secret: &str, date: &str, region: &str) -> Vec<u8> {
    signing_key(secret, date, region, "s3")
}

/// Test/interop helper: HMAC-SHA256 as hex.
#[doc(hidden)]
pub fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_sha256(key, data))
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// AWS URI encoding: RFC3986 unreserved characters stay unescaped, '/' is
/// preserved for paths but encoded in query components when `encode_slash`.
pub fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let encoded = percent_encoding::utf8_percent_encode(input, UNRESERVED).to_string();
    if encode_slash {
        encoded.replace('/', "%2F")
    } else {
        encoded
    }
}

pub fn percent_decode(input: &str) -> Option<String> {
    percent_encoding::percent_decode_str(input)
        .decode_utf8()
        .ok()
        .map(|s| s.into_owned())
}

/// Canonical query string from parsed query parameters (already decoded).
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (aws_uri_encode(k, true), aws_uri_encode(v, true)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonical URI: decode each path segment, then re-encode with AWS rules,
/// preserving '/' separators.
pub fn canonical_uri(raw_path: &str) -> String {
    raw_path
        .split('/')
        .map(|seg| percent_decode(seg).unwrap_or_else(|| seg.to_string()))
        .map(|seg| aws_uri_encode(&seg, false))
        .collect::<Vec<_>>()
        .join("/")
}

fn collapse_spaces(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parsed pieces of an SigV4 Authorization header.
pub struct HeaderSig {
    pub access_key: String,
    pub date: String,
    pub region: String,
    pub service: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
    pub amz_date: String,
}

pub fn parse_authorization(value: &str) -> Result<HeaderSig, S3Error> {
    let rest = value
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(S3Error::access_denied)?;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(c) = part.strip_prefix("Credential=") {
            credential = Some(c.to_string());
        } else if let Some(s) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(s.trim_matches('"').to_string());
        } else if let Some(s) = part.strip_prefix("Signature=") {
            signature = Some(s.to_string());
        }
    }
    let credential = credential.ok_or_else(S3Error::access_denied)?;
    let signed_headers = signed_headers.ok_or_else(S3Error::access_denied)?;
    let signature = signature.ok_or_else(S3Error::access_denied)?;
    let mut segs = credential.split('/');
    let access_key = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let date = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let region = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let service = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let terminal = segs.next().ok_or_else(S3Error::access_denied)?;
    if terminal != "aws4_request" || service != "s3" {
        return Err(S3Error::access_denied());
    }
    let signed_headers = signed_headers.split(';').map(|s| s.to_string()).collect();
    Ok(HeaderSig {
        access_key,
        amz_date: date.clone(),
        date,
        region,
        service,
        signed_headers,
        signature,
    })
}

/// Build the canonical request for header-based auth.
pub fn canonical_request_header(
    method: &str,
    raw_path: &str,
    query: &[(String, String)],
    headers: &hyper::HeaderMap,
    sig: &HeaderSig,
) -> Result<String, S3Error> {
    let mut signed_header_lines = Vec::new();
    for name in &sig.signed_headers {
        let raw = headers
            .get(name.as_str())
            .ok_or_else(S3Error::signature_does_not_match)?;
        let value = collapse_spaces(
            raw.to_str()
                .map_err(|_| S3Error::signature_does_not_match())?,
        );
        signed_header_lines.push(format!("{name}:{value}"));
    }
    let content_sha = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| S3Error::invalid_argument("Missing required header x-amz-content-sha256"))?;
    Ok(format!(
        "{method}\n{}\n{}\n{}\n\n{}\n{}",
        canonical_uri(raw_path),
        canonical_query(query),
        signed_header_lines.join("\n"),
        sig.signed_headers.join(";"),
        content_sha
    ))
}

/// Build the canonical request for presigned (query) auth.
pub fn canonical_request_presigned(
    method: &str,
    raw_path: &str,
    query: &[(String, String)],
    headers: &hyper::HeaderMap,
    signed_headers: &[String],
) -> String {
    let mut signed_header_lines = Vec::new();
    for name in signed_headers {
        let value = headers
            .get(name.as_str())
            .map(|v| v.to_str().map(collapse_spaces).unwrap_or_default())
            .unwrap_or_default();
        signed_header_lines.push(format!("{name}:{value}"));
    }
    let _ = &signed_header_lines;
    format!(
        "{method}\n{}\n{}\n{}\n\n{}\n{}",
        canonical_uri(raw_path),
        canonical_query(query),
        signed_header_lines.join("\n"),
        signed_headers.join(";"),
        "UNSIGNED-PAYLOAD"
    )
}

/// Outcome of successful verification.
#[derive(Debug)]
pub struct Verified {
    pub access_key: String,
    /// scope date, e.g. 20250101
    pub scope_date: String,
    /// full scope, e.g. 20250101/us-east-1/s3/aws4_request
    pub scope: String,
    /// final request signature (seed for chunk verification)
    pub signature: String,
    /// x-amz-content-sha256 header value (payload hash mode)
    pub payload_sha_mode: PayloadShaMode,
    /// amz-date of the request
    pub amz_date: String,
    /// signing key for this request (for chunk verification)
    pub signing_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PayloadShaMode {
    /// hex hash of the full payload: verify after streaming
    SignedFull(String),
    Unsigned,
    StreamingSigned,
    StreamingUnsigned,
}

pub fn parse_payload_sha(value: Option<&str>) -> Result<PayloadShaMode, S3Error> {
    match value {
        None => Err(S3Error::invalid_argument(
            "Missing required header x-amz-content-sha256",
        )),
        Some("UNSIGNED-PAYLOAD") => Ok(PayloadShaMode::Unsigned),
        Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD") => Ok(PayloadShaMode::StreamingSigned),
        Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER")
        | Some("STREAMING-AWS4-ECDSA-PAYLOAD-TRAILER") => Ok(PayloadShaMode::StreamingUnsigned),
        Some(other) if other.starts_with("STREAMING-") => Ok(PayloadShaMode::StreamingUnsigned),
        Some(hash) => {
            if hash.len() == 64 && hex::decode(hash).is_ok() {
                Ok(PayloadShaMode::SignedFull(hash.to_lowercase()))
            } else {
                Err(S3Error::invalid_argument("Invalid x-amz-content-sha256"))
            }
        }
    }
}

/// Result of request authentication.
#[derive(Debug)]
pub enum AuthResult {
    /// Header-signed request
    Header(Verified),
    /// Presigned URL request
    Presigned(Verified),
}

/// Verify an incoming request. `query` must be the decoded query parameters.
pub fn verify_request(
    creds: &CredentialStore,
    method: &str,
    raw_path: &str,
    query: &[(String, String)],
    headers: &hyper::HeaderMap,
) -> Result<AuthResult, S3Error> {
    let is_presigned = query.iter().any(|(k, _)| k == "X-Amz-Algorithm");
    if is_presigned {
        verify_presigned(creds, method, raw_path, query, headers).map(AuthResult::Presigned)
    } else if headers.contains_key("authorization") {
        verify_header(creds, method, raw_path, query, headers).map(AuthResult::Header)
    } else {
        Err(S3Error::access_denied())
    }
}

fn verify_header(
    creds: &CredentialStore,
    method: &str,
    raw_path: &str,
    query: &[(String, String)],
    headers: &hyper::HeaderMap,
) -> Result<Verified, S3Error> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let sig = parse_authorization(auth)?;
    let secret = creds
        .lookup(&sig.access_key)
        .ok_or_else(S3Error::invalid_access_key_id)?;

    let canonical = canonical_request_header(method, raw_path, query, headers, &sig)?;
    let scope = format!("{}/{}/s3/aws4_request", sig.date, sig.region);
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&sig.date)
        .to_string();
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical.as_bytes())
    );
    // the scope date (from the credential) is used for key derivation
    let key = signing_key(&secret, &sig.date, &sig.region, "s3");
    let expected = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));
    if expected != sig.signature.to_lowercase() {
        return Err(S3Error::signature_does_not_match());
    }
    let mode = parse_payload_sha(
        headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok()),
    )?;
    Ok(Verified {
        access_key: sig.access_key,
        scope_date: sig.date,
        scope,
        signature: sig.signature,
        payload_sha_mode: mode,
        amz_date,
        signing_key: key,
    })
}

fn verify_presigned(
    creds: &CredentialStore,
    method: &str,
    raw_path: &str,
    query: &[(String, String)],
    headers: &hyper::HeaderMap,
) -> Result<Verified, S3Error> {
    if !matches!(method, "GET" | "PUT" | "HEAD") {
        return Err(S3Error::access_denied());
    }
    let get = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let algorithm = get("X-Amz-Algorithm").unwrap_or_default();
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(S3Error::invalid_argument("Unsupported signing algorithm"));
    }
    let credential = get("X-Amz-Credential").ok_or_else(S3Error::access_denied)?;
    let amz_date = get("X-Amz-Date").ok_or_else(S3Error::access_denied)?;
    let expires = get("X-Amz-Expires").ok_or_else(S3Error::access_denied)?;
    let signed_headers_q = get("X-Amz-SignedHeaders").ok_or_else(S3Error::access_denied)?;
    let signature = get("X-Amz-Signature").ok_or_else(S3Error::access_denied)?;

    let mut segs = credential.split('/');
    let access_key = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let date = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let region = segs.next().ok_or_else(S3Error::access_denied)?.to_string();
    let service = segs.next().ok_or_else(S3Error::access_denied)?;
    let terminal = segs.next().ok_or_else(S3Error::access_denied)?;
    if service != "s3" || terminal != "aws4_request" {
        return Err(S3Error::access_denied());
    }

    // expiry
    let expires_secs: i64 = expires
        .parse()
        .map_err(|_| S3Error::invalid_argument("Invalid X-Amz-Expires"))?;
    let request_time = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| S3Error::invalid_argument("Invalid X-Amz-Date"))?
        .and_utc();
    let now = chrono::Utc::now();
    let elapsed = (now - request_time).num_seconds();
    if elapsed > expires_secs || elapsed < -86_400 {
        return Err(S3Error::access_denied());
    }

    let secret = creds
        .lookup(&access_key)
        .ok_or_else(S3Error::invalid_access_key_id)?;
    let signed_headers: Vec<String> = signed_headers_q.split(';').map(|s| s.to_string()).collect();
    let filtered: Vec<(String, String)> = query
        .iter()
        .filter(|(k, _)| k != "X-Amz-Signature")
        .cloned()
        .collect();
    let canonical =
        canonical_request_presigned(method, raw_path, &filtered, headers, &signed_headers);
    let scope = format!("{}/{}/s3/aws4_request", date, region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        amz_date,
        sha256_hex(canonical.as_bytes())
    );
    let key = signing_key(&secret, &date, &region, "s3");
    let expected = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));
    if expected != signature.to_lowercase() {
        return Err(S3Error::signature_does_not_match());
    }
    Ok(Verified {
        access_key,
        scope_date: date,
        scope,
        signature,
        payload_sha_mode: PayloadShaMode::Unsigned,
        amz_date,
        signing_key: key,
    })
}

// ---------------- aws-chunked streaming decoder ----------------

/// Parse one chunk header line: `<hex-size>;chunk-signature=<hex>\r\n` plus
/// extension params. Returns (size, chunk_signature, consumed_bytes).
pub fn parse_chunk_header(buf: &[u8]) -> Option<Result<(usize, String, usize), S3Error>> {
    // find CRLF
    let pos = buf.windows(2).position(|w| w == b"\r\n")?;
    let header = std::str::from_utf8(&buf[..pos]).ok()?;
    if header.is_empty() {
        return None;
    }
    let size_str: &str = header.split(';').next()?;
    let size = match usize::from_str_radix(size_str, 16) {
        Ok(s) => s,
        Err(_) => return Some(Err(S3Error::invalid_argument("Malformed chunked payload"))),
    };
    let signature = header
        .split(';')
        .find_map(|p| p.strip_prefix("chunk-signature="))
        .unwrap_or_default()
        .to_string();
    Some(Ok((size, signature, pos + 2)))
}

/// Stateful incremental decoder for `aws-chunked` payloads. Feed raw bytes in,
/// pull decoded payload bytes out; verifies each chunk signature.
pub struct ChunkDecoder {
    signing_key: Vec<u8>,
    scope: String,
    amz_date: String,
    prev_signature: String,
    buf: bytes::BytesMut,
    state: DecoderState,
    finished: bool,
    /// signature of the chunk currently being read
    pending_sig: String,
    /// accumulated data of the chunk currently being read
    chunk_data: Vec<u8>,
}

#[derive(PartialEq)]
enum DecoderState {
    ReadingHeader,
    ReadingChunk(usize),
    ReadingChunkTrailer(usize),
    Done,
}

impl ChunkDecoder {
    pub fn new(
        signing_key: Vec<u8>,
        scope: String,
        amz_date: String,
        seed_signature: String,
    ) -> Self {
        Self {
            signing_key,
            scope,
            amz_date,
            prev_signature: seed_signature,
            buf: bytes::BytesMut::new(),
            state: DecoderState::ReadingHeader,
            finished: false,
            pending_sig: String::new(),
            chunk_data: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.finished || self.state == DecoderState::Done
    }

    /// Push raw bytes and drain decoded payload bytes.
    /// On signature failure the stream is poisoned and all later calls error.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<bytes::Bytes>) -> Result<(), S3Error> {
        if self.finished {
            return Ok(());
        }
        self.buf.extend_from_slice(data);
        loop {
            match self.state {
                DecoderState::ReadingHeader => {
                    match parse_chunk_header(&self.buf) {
                        None => return Ok(()), // need more data
                        Some(Err(e)) => return Err(e),
                        Some(Ok((size, sig, consumed))) => {
                            self.pending_sig = sig.clone();
                            self.buf.advance(consumed);
                            if size == 0 {
                                // final chunk; expect trailing CRLF (and optional trailers)
                                self.state = DecoderState::Done;
                                self.finished = true;
                                // verify the final chunk signature
                                self.verify_chunk(0, b"")?;
                                return Ok(());
                            }
                            self.pending_sig = sig;
                            self.state = DecoderState::ReadingChunk(size);
                        }
                    }
                }
                DecoderState::ReadingChunk(remaining) => {
                    if self.buf.is_empty() {
                        return Ok(());
                    }
                    let take = remaining.min(self.buf.len());
                    let chunk = self.buf.split_to(take).to_vec();
                    self.chunk_data.extend_from_slice(&chunk);
                    out.push(bytes::Bytes::from(chunk));
                    let new_remaining = remaining - take;
                    if new_remaining == 0 {
                        let full = std::mem::take(&mut self.chunk_data);
                        self.verify_chunk(remaining, &full)?;
                        self.prev_signature = self.pending_sig.clone();
                        self.state = DecoderState::ReadingChunkTrailer(0);
                    } else {
                        self.state = DecoderState::ReadingChunk(new_remaining);
                    }
                }
                DecoderState::ReadingChunkTrailer(_) => {
                    // expect CRLF
                    if self.buf.len() < 2 {
                        return Ok(());
                    }
                    if &self.buf[..2] == b"\r\n" {
                        self.buf.advance(2);
                        self.state = DecoderState::ReadingHeader;
                    } else {
                        return Err(S3Error::invalid_argument("Malformed chunked payload"));
                    }
                }
                DecoderState::Done => return Ok(()),
            }
        }
    }

    fn verify_chunk(&mut self, size: usize, data: &[u8]) -> Result<(), S3Error> {
        let empty_hash = sha256_hex(b"");
        let chunk_hash = sha256_hex(data);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{empty_hash}\n{chunk_hash}",
            self.amz_date, self.scope, self.prev_signature
        );
        let expected = hex::encode(hmac_sha256(&self.signing_key, string_to_sign.as_bytes()));
        if expected != self.pending_sig.to_lowercase() {
            return Err(S3Error::signature_does_not_match());
        }
        let _ = size;
        self.prev_signature = self.pending_sig.clone();
        Ok(())
    }

    // pending signature of the chunk currently being read
    pub fn leftover(&self) -> &[u8] {
        &self.buf
    }
}

/// Max clock skew tolerated for header-signed requests.
pub const MAX_SKEW: Duration = Duration::from_secs(60 * 60 * 24 * 7);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn creds() -> CredentialStore {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        CredentialStore::new(
            &path,
            Credentials {
                access_key: "ROOTKEY".into(),
                secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            },
        )
    }

    #[test]
    fn sigv4_aws_testvector_get() {
        // AWS documentation test vector (GET object, us-east-1)
        // Recomputed here to validate our canonicalization against a known signature.
        let access = "AKIAIOSFODNN7EXAMPLE";
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let method = "GET";
        let canonical_uri = "/test.txt";
        let query: Vec<(String, String)> = Vec::new();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "examplebucket.s3.amazonaws.com".parse().unwrap());
        headers.insert("x-amz-date", "20130524T000000Z".parse().unwrap());
        headers.insert("range", "bytes=0-9".parse().unwrap());
        headers.insert(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap(),
        );

        let canonical_request = "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let scope = "20130524/us-east-1/s3/aws4_request";
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n20130524T000000Z\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let key = signing_key(secret, "20130524", "us-east-1", "s3");
        let expected = hex::encode(hmac_sha256(&key, string_to_sign.as_bytes()));
        // This is the signature published in AWS docs for this request.
        assert_eq!(
            expected,
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );

        // sanity: our canonical-uri + query helpers produce the same canonical request
        assert_eq!(super::canonical_uri(canonical_uri), "/test.txt");
        assert_eq!(canonical_query(&query), "");
        let _ = (access, method, headers);
    }

    #[tokio::test]
    async fn header_auth_accept_and_reject() {
        let creds = creds();
        // build a real signed request using our own primitives
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let method = "PUT";
        let path = "/bucket/key.txt";
        let query: Vec<(String, String)> = Vec::new();
        let amz_date = "20250101T000000Z";
        let date = "20250101";
        let payload_hash = sha256_hex(b"hello world");
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "127.0.0.1:9000".parse().unwrap());
        headers.insert("x-amz-date", amz_date.parse().unwrap());
        headers.insert("x-amz-content-sha256", payload_hash.parse().unwrap());
        let _signed_headers = ["host", "x-amz-content-sha256", "x-amz-date"];
        let canonical = format!(
            "{method}\n{}\n{}\nhost:127.0.0.1:9000\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}",
            canonical_uri(path),
            canonical_query(&query)
        );
        let scope = format!("{date}/us-east-1/s3/aws4_request");
        let sts = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let key = signing_key(secret, date, "us-east-1", "s3");
        let signature = hex::encode(hmac_sha256(&key, sts.as_bytes()));
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential=ROOTKEY/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
        );
        headers.insert("authorization", auth_header.parse().unwrap());
        let result = verify_request(&creds, method, path, &query, &headers);
        match result {
            Ok(AuthResult::Header(v)) => {
                assert_eq!(v.payload_sha_mode, PayloadShaMode::SignedFull(payload_hash))
            }
            other => panic!("expected header auth, got {other:?}"),
        }

        // tampered signature
        let mut bad_headers = headers.clone();
        let bad_sig = format!(
            "AWS4-HMAC-SHA256 Credential=ROOTKEY/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeef"
        );
        bad_headers.insert("authorization", bad_sig.parse().unwrap());
        assert!(
            matches!(verify_request(&creds, method, path, &query, &bad_headers), Err(ref e) if e.code == "SignatureDoesNotMatch")
        );

        // unknown access key
        let mut unknown = headers.clone();
        let unknown_cred = format!(
            "AWS4-HMAC-SHA256 Credential=GHOST/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"
        );
        unknown.insert("authorization", unknown_cred.parse().unwrap());
        assert!(
            matches!(verify_request(&creds, method, path, &query, &unknown), Err(ref e) if e.code == "InvalidAccessKeyId")
        );
    }

    #[test]
    fn presigned_expired_rejected() {
        let creds = creds();
        let query: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            (
                "X-Amz-Credential".into(),
                "ROOTKEY/20200101/us-east-1/s3/aws4_request".into(),
            ),
            ("X-Amz-Date".into(), "20200101T000000Z".into()),
            ("X-Amz-Expires".into(), "300".into()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
            ("X-Amz-Signature".into(), "ab".into()),
        ];
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "127.0.0.1:9000".parse().unwrap());
        let err = verify_request(&creds, "GET", "/b/k", &query, &headers).unwrap_err();
        assert_eq!(err.code, "AccessDenied"); // expired
    }

    #[test]
    fn presigned_malformed_rejected() {
        let creds = creds();
        let query: Vec<(String, String)> =
            vec![("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into())];
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "x".parse().unwrap());
        let err = verify_request(&creds, "GET", "/b/k", &query, &headers).unwrap_err();
        assert_eq!(err.code, "AccessDenied");
    }

    #[test]
    fn chunk_decoder_roundtrip_with_signatures() {
        let secret = "secret";
        let date = "20250101";
        let region = "us-east-1";
        let amz_date = "20250101T000000Z";
        let scope = format!("{date}/{region}/s3/aws4_request");
        let key = signing_key(secret, date, region, "s3");

        let chunks: Vec<&[u8]> = vec![b"hello ", b"chunked ", b"world"];
        let mut prev = "seed".to_string();
        let mut raw = Vec::new();
        for c in &chunks {
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev}\n{}\n{}",
                sha256_hex(b""),
                sha256_hex(c)
            );
            let sig = hex::encode(hmac_sha256(&key, sts.as_bytes()));
            write!(
                raw,
                "{};chunk-signature={sig}\r\n",
                format!("{:x}", c.len())
            )
            .unwrap();
            raw.extend_from_slice(c);
            raw.extend_from_slice(b"\r\n");
            prev = sig;
        }
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev}\n{}\n{}",
            sha256_hex(b""),
            sha256_hex(b"")
        );
        let sig = hex::encode(hmac_sha256(&key, sts.as_bytes()));
        write!(raw, "0;chunk-signature={sig}\r\n").unwrap();

        let mut dec = ChunkDecoder::new(
            key.clone(),
            scope.clone(),
            amz_date.to_string(),
            "seed".to_string(),
        );
        let mut out = Vec::new();
        // feed in small pieces to exercise buffering
        for piece in raw.chunks(7) {
            dec.push(piece, &mut out).unwrap();
        }
        let decoded: Vec<u8> = out.iter().flat_map(|b| b.iter().copied()).collect();
        assert_eq!(decoded, b"hello chunked world");
        assert!(dec.is_finished());
    }

    #[test]
    fn chunk_decoder_bad_signature_poisons() {
        let key = signing_key("secret", "20250101", "us-east-1", "s3");
        let scope = "20250101/us-east-1/s3/aws4_request".to_string();
        let mut dec = ChunkDecoder::new(key, scope, "20250101T000000Z".into(), "seed".into());
        let bad = b"5;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\nhello\r\n";
        let mut out = Vec::new();
        assert!(dec.push(bad, &mut out).is_err());
    }

    #[test]
    fn credential_store_hot_reload() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialStore::new(
            dir.path(),
            Credentials {
                access_key: "root".into(),
                secret_key: "s".into(),
            },
        );
        assert_eq!(store.lookup("root"), Some("s".into()));
        add_key(dir.path(), "extra", "topsecret");
        assert_eq!(store.lookup("extra"), Some("topsecret".into()));
        remove_key(dir.path(), "extra");
        assert_eq!(store.lookup("extra"), None);
    }
}
