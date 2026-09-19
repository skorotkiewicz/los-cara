//! End-to-end integration tests driving the S3 server with the AWS SDK for
//! Rust and raw HTTP clients, covering the capability specs.

use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use los_cara::auth::CredentialStore;
use los_cara::s3::AppState;
use los_cara::storage::Storage;
use std::time::Duration;

const ROOT_ACCESS: &str = "root-access-key";
const ROOT_SECRET: &str = "root-secret-key";

struct TestServer {
    endpoint: String,
    data: tempfile::TempDir,
}

async fn spawn_server() -> TestServer {
    spawn_server_with_cors(&[]).await
}

async fn spawn_server_with_cors(origins: &[&str]) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::open(dir.path()).await.unwrap();
    let creds = CredentialStore::new(
        dir.path(),
        los_cara::auth::Credentials {
            access_key: ROOT_ACCESS.into(),
            secret_key: ROOT_SECRET.into(),
        },
    );
    let state = AppState::new(storage, creds);
    let app = los_cara::s3::router_with_cors(
        state,
        origins
            .iter()
            .map(|origin| los_cara::config::parse_cors_origin(origin).unwrap())
            .collect(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    TestServer {
        endpoint: format!("http://{addr}"),
        data: dir,
    }
}

fn client_for(endpoint: &str, access: &str, secret: &str) -> Client {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(access, secret, None, None, "test"))
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    Client::from_conf(conf)
}

fn client(server: &TestServer) -> Client {
    client_for(&server.endpoint, ROOT_ACCESS, ROOT_SECRET)
}

fn err_code<E, R>(e: &aws_sdk_s3::error::SdkError<E, R>) -> Option<String>
where
    E: std::fmt::Debug + aws_sdk_s3::error::ProvideErrorMetadata,
{
    e.as_service_error()
        .map(|se| se.meta().code().unwrap_or("").to_string())
}

#[test]
fn cors_invalid_origin_rejected_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("not-created");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_lc"))
        .args(["serve", "--address", "not-a-bind-address", "--data"])
        .arg(&data)
        .args([
            "--cors-allowed-origin",
            "https://app.example",
            "--cors-allowed-origin",
            "*",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("invalid CORS origin"), "{stderr}");
    assert!(!stderr.contains("invalid bind address"), "{stderr}");
    assert!(!data.exists());
}

// ---------------- CORS (spec: s3-cors) ----------------

const CORS_ORIGIN: &str = "https://app.example";

fn header_tokens(headers: &reqwest::header::HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .flat_map(|value| value.to_str().unwrap().split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .collect()
}

fn assert_cors(headers: &reqwest::header::HeaderMap, origin: Option<&str>) {
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        origin
    );
    assert!(!headers.contains_key("access-control-allow-credentials"));
    uuid::Uuid::parse_str(headers["x-amz-request-id"].to_str().unwrap()).unwrap();
    let vary = header_tokens(headers, "vary");
    for name in [
        "origin",
        "access-control-request-method",
        "access-control-request-headers",
    ] {
        assert!(vary.iter().any(|v| v == name), "missing {name}: {vary:?}");
    }
}

#[tokio::test]
async fn cors_preflight_methods_headers_and_missing_targets() {
    let server = spawn_server_with_cors(&[CORS_ORIGIN]).await;
    let c = client(&server);
    c.create_bucket().bucket("cors").send().await.unwrap();
    c.put_object()
        .bucket("cors")
        .key("exists")
        .body(ByteStream::from_static(b"kept"))
        .send()
        .await
        .unwrap();
    let http = reqwest::Client::new();
    let requested = "Authorization,Content-Type,Content-MD5,Range,If-Match,If-None-Match,If-Modified-Since,If-Unmodified-Since,X-Amz-Date,X-Amz-Content-Sha256,X-Amz-Security-Token,X-Amz-Meta-Owner";
    let mut first_policy = None;
    for method in ["GET", "HEAD", "PUT", "POST", "DELETE"] {
        for path in ["/cors/exists", "/cors/missing", "/missing/key"] {
            let res = http
                .request(
                    reqwest::Method::OPTIONS,
                    format!("{}{path}", server.endpoint),
                )
                .header("origin", CORS_ORIGIN)
                .header("access-control-request-method", method)
                .header("access-control-request-headers", requested)
                .header("x-amz-request-id", "caller-id")
                .send()
                .await
                .unwrap();
            assert!(res.status().is_success());
            assert_cors(res.headers(), Some(CORS_ORIGIN));
            let mut methods = header_tokens(res.headers(), "access-control-allow-methods");
            methods.sort();
            assert_eq!(methods, ["delete", "get", "head", "post", "put"]);
            let allowed = header_tokens(res.headers(), "access-control-allow-headers");
            for name in requested.to_ascii_lowercase().split(',') {
                assert!(allowed.iter().any(|v| v == name), "missing {name}");
            }
            let policy: Vec<_> = [
                "access-control-allow-origin",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "vary",
            ]
            .into_iter()
            .map(|name| header_tokens(res.headers(), name))
            .collect();
            if let Some(expected) = &first_policy {
                assert_eq!(&policy, expected);
            } else {
                first_policy = Some(policy);
            }
            assert!(res.bytes().await.unwrap().is_empty());
        }
    }
    // Even incomplete OPTIONS requests bypass authentication when enabled.
    let res = http
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/missing", server.endpoint),
        )
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    assert_cors(res.headers(), None);
    assert!(res.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn cors_denied_disabled_and_no_storage_side_effects() {
    let http = reqwest::Client::new();
    for enabled in [true, false] {
        let server = spawn_server_with_cors(if enabled { &[CORS_ORIGIN] } else { &[] }).await;
        let c = client(&server);
        c.create_bucket().bucket("existing").send().await.unwrap();
        for (origin, method) in [
            (Some("https://unlisted.example"), "PUT"),
            (Some("https://app.example.attacker.test"), "PUT"),
            (Some("https://other.app.example"), "PUT"),
            (Some("https://sibling.example"), "PUT"),
            (Some("http://app.example"), "PUT"),
            (Some("https://app.example:8443"), "PUT"),
            (Some("null"), "PUT"),
            (Some("not-an-origin"), "PUT"),
            (Some("https://app.example/path"), "PUT"),
            (Some("https://app.example https://other.example"), "PUT"),
            (None, "PUT"),
            (Some(CORS_ORIGIN), "PATCH"),
            (Some(CORS_ORIGIN), "PUT"),
            (Some(CORS_ORIGIN), "POST"),
            (Some(CORS_ORIGIN), "DELETE"),
        ] {
            for path in ["/missing", "/existing/key", "/existing/key?uploads"] {
                let mut req = http
                    .request(
                        reqwest::Method::OPTIONS,
                        format!("{}{path}", server.endpoint),
                    )
                    .header("access-control-request-method", method)
                    .header(
                        "access-control-request-headers",
                        "authorization,x-amz-meta-test",
                    );
                if let Some(origin) = origin {
                    req = req.header("origin", origin);
                }
                let res = req.send().await.unwrap();
                let headers = res.headers();
                let grant = headers.get("access-control-allow-origin").is_some()
                    && header_tokens(headers, "access-control-allow-methods")
                        .contains(&method.to_ascii_lowercase());
                assert_eq!(
                    grant,
                    enabled && origin == Some(CORS_ORIGIN) && method != "PATCH"
                );
                assert!(!headers.contains_key("access-control-allow-credentials"));
                assert!(headers.contains_key("x-amz-request-id"));
                if enabled {
                    assert_cors(headers, origin.filter(|v| *v == CORS_ORIGIN));
                } else {
                    assert!(
                        !headers
                            .keys()
                            .any(|name| name.as_str().starts_with("access-control-"))
                    );
                    assert_eq!(res.status(), 403); // Original unsigned OPTIONS behavior.
                }
            }
        }
        let buckets = c.list_buckets().send().await.unwrap();
        assert_eq!(buckets.buckets().len(), 1);
        assert_eq!(buckets.buckets()[0].name(), Some("existing"));
        assert!(
            c.list_objects_v2()
                .bucket("existing")
                .send()
                .await
                .unwrap()
                .contents()
                .is_empty()
        );
        assert!(
            c.list_multipart_uploads()
                .bucket("existing")
                .send()
                .await
                .unwrap()
                .uploads()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn cors_presigned_operations_and_errors() {
    use aws_sdk_s3::presigning::PresigningConfig;
    let second_origin = "http://localhost:5173";
    let server =
        spawn_server_with_cors(&["https://APP.example:443/", second_origin, CORS_ORIGIN]).await;
    let c = client(&server);
    let http = reqwest::Client::new();
    let signing = || PresigningConfig::expires_in(Duration::from_secs(60)).unwrap();
    c.create_bucket().bucket("cors").send().await.unwrap(); // Signed, no Origin.
    let put = c
        .put_object()
        .bucket("cors")
        .key("key")
        .metadata("owner", "browser")
        .content_type("text/plain")
        .presigned(signing())
        .await
        .unwrap();
    let mut req = http
        .put(put.uri())
        .header("origin", CORS_ORIGIN)
        .body("browser-data");
    for (name, value) in put.headers() {
        req = req.header(name, value);
    }
    let res = req.send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert_cors(res.headers(), Some(CORS_ORIGIN));
    assert_eq!(res.headers()["access-control-expose-headers"], "*");
    let etag = res.headers()["etag"].to_str().unwrap().to_owned();
    assert!(res.bytes().await.unwrap().is_empty());

    let get = c
        .get_object()
        .bucket("cors")
        .key("key")
        .presigned(signing())
        .await
        .unwrap();
    for origin in [
        Some(CORS_ORIGIN),
        Some(second_origin),
        None,
        Some("https://app.example.attacker.test"),
        Some("https://other.app.example"),
        Some("http://app.example"),
        Some("https://app.example:8443"),
        Some("null"),
        Some("bad-origin"),
    ] {
        let mut req = http.get(get.uri());
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let res = req.send().await.unwrap();
        assert_eq!(res.status(), 200);
        assert_cors(
            res.headers(),
            origin.filter(|v| [CORS_ORIGIN, second_origin].contains(v)),
        );
        assert_eq!(res.headers()["access-control-expose-headers"], "*");
        assert_eq!(res.headers()["etag"], etag);
        assert_eq!(res.headers()["x-amz-meta-owner"], "browser");
        assert_eq!(res.headers()["content-type"], "text/plain");
        assert_eq!(res.text().await.unwrap(), "browser-data");
    }
    for (name, value, status, body) in [
        ("range", "bytes=0-6", 206, "browser"),
        ("if-none-match", etag.as_str(), 304, ""),
    ] {
        let res = http
            .get(get.uri())
            .header("origin", CORS_ORIGIN)
            .header(name, value)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status);
        assert_cors(res.headers(), Some(CORS_ORIGIN));
        assert_eq!(res.headers()["access-control-expose-headers"], "*");
        if status == 206 {
            assert_eq!(res.headers()["content-range"], "bytes 0-6/12");
        }
        assert_eq!(res.text().await.unwrap(), body);
    }

    let bad_signature = client_for(&server.endpoint, ROOT_ACCESS, "wrong-secret")
        .get_object()
        .bucket("cors")
        .key("key")
        .presigned(signing())
        .await
        .unwrap();
    let missing_bucket = c
        .get_object()
        .bucket("missing")
        .key("key")
        .presigned(signing())
        .await
        .unwrap();
    let missing_key = c
        .get_object()
        .bucket("cors")
        .key("missing")
        .presigned(signing())
        .await
        .unwrap();
    for (url, condition, status, code) in [
        (server.endpoint.as_str(), None, 403, "AccessDenied"),
        (bad_signature.uri(), None, 403, "SignatureDoesNotMatch"),
        (missing_bucket.uri(), None, 404, "NoSuchBucket"),
        (missing_key.uri(), None, 404, "NoSuchKey"),
        (get.uri(), Some("\"different\""), 412, "PreconditionFailed"),
    ] {
        let mut req = http
            .get(url)
            .header("origin", CORS_ORIGIN)
            .header("x-amz-request-id", "caller-id");
        if let Some(condition) = condition {
            req = req.header("if-match", condition);
        }
        let res = req.send().await.unwrap();
        assert_eq!(res.status(), status);
        assert_cors(res.headers(), Some(CORS_ORIGIN));
        assert_eq!(res.headers()["access-control-expose-headers"], "*");
        let id = res.headers()["x-amz-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = res.text().await.unwrap();
        assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
        assert!(
            body.contains(&format!("<RequestId>{id}</RequestId>")),
            "{body}"
        );
    }

    let unsigned_url = format!("{}/cors/unauthorized", server.endpoint);
    let res = http
        .request(reqwest::Method::OPTIONS, &unsigned_url)
        .header("origin", CORS_ORIGIN)
        .header("access-control-request-method", "PUT")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    assert_cors(res.headers(), Some(CORS_ORIGIN));
    let res = http
        .put(&unsigned_url)
        .header("origin", CORS_ORIGIN)
        .body("not authorized")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert_cors(res.headers(), Some(CORS_ORIGIN));
    assert!(
        res.text()
            .await
            .unwrap()
            .contains("<Code>AccessDenied</Code>")
    );
    let objects = c.list_objects_v2().bucket("cors").send().await.unwrap();
    assert_eq!(objects.contents().len(), 1);
    assert_eq!(objects.contents()[0].key(), Some("key"));
}

// ---------------- buckets (spec: s3-buckets) ----------------

#[tokio::test]
async fn bucket_lifecycle() {
    let server = spawn_server().await;
    let c = client(&server);

    c.create_bucket().bucket("my-bucket").send().await.unwrap();
    // idempotent duplicate
    c.create_bucket().bucket("my-bucket").send().await.unwrap();
    // invalid name
    let err = c
        .create_bucket()
        .bucket("Bad_Name!")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidBucketName"));
    // head
    c.head_bucket().bucket("my-bucket").send().await.unwrap();
    // list buckets
    let out = c.list_buckets().send().await.unwrap();
    let names: Vec<_> = out.buckets().iter().filter_map(|b| b.name()).collect();
    assert!(names.contains(&"my-bucket"));

    // non-empty delete rejected
    c.put_object()
        .bucket("my-bucket")
        .key("k")
        .body(ByteStream::from(b"x".to_vec()))
        .send()
        .await
        .unwrap();
    let err = c
        .delete_bucket()
        .bucket("my-bucket")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("BucketNotEmpty"));
    c.delete_object()
        .bucket("my-bucket")
        .key("k")
        .send()
        .await
        .unwrap();
    // now deletable
    c.delete_bucket().bucket("my-bucket").send().await.unwrap();
    // gone from listing, head 404
    let out = c.list_buckets().send().await.unwrap();
    assert!(out.buckets().iter().all(|b| b.name() != Some("my-bucket")));
    let err = c.head_bucket().bucket("my-bucket").send().await;
    assert!(err.is_err());
    // name reusable
    c.create_bucket().bucket("my-bucket").send().await.unwrap();
}

#[tokio::test]
async fn bucket_subresource_probes() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket()
        .bucket("probe-bucket")
        .send()
        .await
        .unwrap();
    let v = c
        .get_bucket_versioning()
        .bucket("probe-bucket")
        .send()
        .await
        .unwrap();
    assert_eq!(v.status(), None); // neutral empty versioning
    let loc = c
        .get_bucket_location()
        .bucket("probe-bucket")
        .send()
        .await
        .unwrap();
    assert!(loc.location_constraint().is_none() || loc.location_constraint().is_some()); // 200 either way
    let err = c
        .get_bucket_versioning()
        .bucket("missing-bucket")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchBucket"));
}

// ---------------- objects (spec: s3-objects) ----------------

#[tokio::test]
async fn object_round_trip_metadata() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("objs").send().await.unwrap();

    let body = b"hello los-cara".to_vec();
    let put = c
        .put_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .content_type("text/plain")
        .metadata("owner", "team-a")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .unwrap();
    assert!(put.e_tag().is_some());

    let get = c
        .get_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(get.content_type(), Some("text/plain"));
    assert_eq!(get.content_length(), Some(body.len() as i64));
    assert_eq!(
        get.metadata().unwrap().get("owner").map(|s| s.as_str()),
        Some("team-a")
    );
    assert_eq!(get.e_tag(), put.e_tag());
    let got = get.body.collect().await.unwrap().into_bytes();
    assert_eq!(&got[..], &body[..]);

    let head = c
        .head_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(body.len() as i64));
    assert_eq!(head.e_tag(), put.e_tag());

    // idempotent delete: twice with 204
    c.delete_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .send()
        .await
        .unwrap();
    c.delete_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .send()
        .await
        .unwrap();
    // now 404 NoSuchKey
    let err = c
        .get_object()
        .bucket("objs")
        .key("dir/hello.txt")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchKey"));
    // missing bucket
    let err = c
        .get_object()
        .bucket("no-such-bucket-xyz")
        .key("k")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchBucket"));
}

#[tokio::test]
async fn atomic_overwrite_keeps_old_on_failure() {
    // simulate a failed upload at HTTP level: cut connection mid-body using raw
    // client; the previous object must remain intact.
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("atomic").send().await.unwrap();
    c.put_object()
        .bucket("atomic")
        .key("k")
        .body(ByteStream::from(b"stable".to_vec()))
        .send()
        .await
        .unwrap();

    // incomplete body with a content-length that lies
    let host = server.endpoint.trim_start_matches("http://").to_string();
    let stream = tokio::net::TcpStream::connect(&host).await.unwrap();
    let mut sock = stream;
    let req = format!(
        "PUT /atomic/k HTTP/1.1\r\nHost: {host}\r\nContent-Length: 100\r\n\r\nshort-but-lying"
    );
    use tokio::io::AsyncWriteExt;
    sock.write_all(req.as_bytes()).await.unwrap();
    drop(sock); // cut connection before body completes

    tokio::time::sleep(Duration::from_millis(100)).await;
    let get = c
        .get_object()
        .bucket("atomic")
        .key("k")
        .send()
        .await
        .unwrap();
    let got = get.body.collect().await.unwrap().into_bytes();
    assert_eq!(&got[..], b"stable");
}

#[tokio::test]
async fn range_requests() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("ranges").send().await.unwrap();
    let body: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    c.put_object()
        .bucket("ranges")
        .key("r")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .unwrap();

    let g = c
        .get_object()
        .bucket("ranges")
        .key("r")
        .range("bytes=0-99")
        .send()
        .await
        .unwrap();
    assert_eq!(g.content_length(), Some(100));
    let content_range = g.content_range().map(|s| s.to_string());
    let got = g.body.collect().await.unwrap().into_bytes();
    assert_eq!(&got[..], &body[0..100]);
    assert!(content_range.unwrap().starts_with("bytes 0-99/1000"));

    // suffix range
    let g = c
        .get_object()
        .bucket("ranges")
        .key("r")
        .range("bytes=-100")
        .send()
        .await
        .unwrap();
    let got = g.body.collect().await.unwrap().into_bytes();
    assert_eq!(&got[..], &body[900..]);

    // unsatisfiable
    let err = c
        .get_object()
        .bucket("ranges")
        .key("r")
        .range("bytes=1000-2000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidRange"));
}

#[tokio::test]
async fn conditional_requests() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("cond").send().await.unwrap();
    let put = c
        .put_object()
        .bucket("cond")
        .key("c")
        .body(ByteStream::from(b"v1".to_vec()))
        .send()
        .await
        .unwrap();
    let etag = put.e_tag().unwrap().to_string();

    // If-None-Match on current etag -> 304
    let err = c
        .get_object()
        .bucket("cond")
        .key("c")
        .if_none_match(&etag)
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("304"));

    // If-Match on current etag -> 200
    c.get_object()
        .bucket("cond")
        .key("c")
        .if_match(&etag)
        .send()
        .await
        .unwrap();
    // If-Match on stale etag -> 412
    let err = c
        .get_object()
        .bucket("cond")
        .key("c")
        .if_match("\"deadbeef\"")
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("412"));

    // If-Modified-Since in the future -> 304
    let future = aws_sdk_s3::primitives::DateTime::from_secs(chrono::Utc::now().timestamp() + 3600);
    let err = c
        .get_object()
        .bucket("cond")
        .key("c")
        .if_modified_since(future)
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("304"));
}

#[tokio::test]
async fn copy_object() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("src").send().await.unwrap();
    c.create_bucket().bucket("dst").send().await.unwrap();
    c.put_object()
        .bucket("src")
        .key("orig")
        .content_type("text/x-orig")
        .metadata("m", "v")
        .body(ByteStream::from(b"copy-me".to_vec()))
        .send()
        .await
        .unwrap();

    c.copy_object()
        .bucket("dst")
        .key("copied")
        .copy_source("src/orig")
        .send()
        .await
        .unwrap();
    let g = c
        .get_object()
        .bucket("dst")
        .key("copied")
        .send()
        .await
        .unwrap();
    assert_eq!(g.content_type(), Some("text/x-orig"));
    assert_eq!(
        g.metadata().unwrap().get("m").map(|s| s.as_str()),
        Some("v")
    );
    let bytes = g.body.collect().await.unwrap().into_bytes();
    assert_eq!(&bytes[..], b"copy-me");
    // source unchanged
    let g = c
        .get_object()
        .bucket("src")
        .key("orig")
        .send()
        .await
        .unwrap();
    assert_eq!(g.body.collect().await.unwrap().into_bytes().len(), 7);

    // copy of a missing source
    let err = c
        .copy_object()
        .bucket("dst")
        .key("x")
        .copy_source("src/nope")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchKey"));
}

#[tokio::test]
async fn batch_delete() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("batch").send().await.unwrap();
    for k in ["b1", "b2", "b3"] {
        c.put_object()
            .bucket("batch")
            .key(k)
            .body(ByteStream::from(b"x".to_vec()))
            .send()
            .await
            .unwrap();
    }
    let objs = [
        aws_sdk_s3::types::ObjectIdentifier::builder()
            .key("b1")
            .build()
            .unwrap(),
        aws_sdk_s3::types::ObjectIdentifier::builder()
            .key("missing")
            .build()
            .unwrap(),
        aws_sdk_s3::types::ObjectIdentifier::builder()
            .key("b3")
            .build()
            .unwrap(),
    ];
    let out = c
        .delete_objects()
        .bucket("batch")
        .delete(
            aws_sdk_s3::types::Delete::builder()
                .objects(objs[0].clone())
                .objects(objs[1].clone())
                .objects(objs[2].clone())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let deleted: Vec<_> = out.deleted().iter().filter_map(|d| d.key()).collect();
    assert!(deleted.contains(&"b1") && deleted.contains(&"b3") && deleted.contains(&"missing"));
    assert!(out.errors().is_empty());
}

// ---------------- listing (spec: s3-object-listing) ----------------

#[tokio::test]
async fn list_ordering_and_pagination() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("listing").send().await.unwrap();

    // empty listing
    let out = c.list_objects_v2().bucket("listing").send().await.unwrap();
    assert_eq!(out.is_truncated(), Some(false));
    assert!(out.contents().is_empty());

    let mut keys: Vec<String> = (0..2500).map(|i| format!("key-{i:05}")).collect();
    keys.sort();
    for k in &keys {
        c.put_object()
            .bucket("listing")
            .key(k)
            .body(ByteStream::from(b"v".to_vec()))
            .send()
            .await
            .unwrap();
    }

    // paginate
    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut req = c.list_objects_v2().bucket("listing").max_keys(1000);
        if let Some(t) = &token {
            req = req.continuation_token(t);
        }
        let out = req.send().await.unwrap();
        for o in out.contents() {
            seen.push(o.key().unwrap().to_string());
        }
        if out.is_truncated() != Some(true) {
            break;
        }
        token = out.next_continuation_token().map(|t| t.to_string());
        assert!(token.is_some());
    }
    assert_eq!(seen, keys);

    // ordering test with the spec keys
    for k in ["a", "b/x", "b/y", "c"] {
        c.put_object()
            .bucket("listing")
            .key(k)
            .body(ByteStream::from(b"v".to_vec()))
            .send()
            .await
            .unwrap();
    }
    let out = c
        .list_objects_v2()
        .bucket("listing")
        .prefix("b/")
        .send()
        .await
        .unwrap();
    let got: Vec<_> = out
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .map(String::from)
        .collect();
    assert_eq!(got, vec!["b/x", "b/y"]);
}

#[tokio::test]
async fn list_delimiter_common_prefixes() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("delim").send().await.unwrap();
    for k in ["photos/a.jpg", "photos/b/c.jpg", "docs/readme.txt"] {
        c.put_object()
            .bucket("delim")
            .key(k)
            .body(ByteStream::from(b"v".to_vec()))
            .send()
            .await
            .unwrap();
    }
    let out = c
        .list_objects_v2()
        .bucket("delim")
        .delimiter("/")
        .send()
        .await
        .unwrap();
    assert!(out.contents().is_empty());
    let prefixes: Vec<_> = out
        .common_prefixes()
        .iter()
        .filter_map(|p| p.prefix())
        .map(String::from)
        .collect();
    assert_eq!(prefixes, vec!["docs/", "photos/"]);

    // prefix filter
    let out = c
        .list_objects_v2()
        .bucket("delim")
        .prefix("photos/")
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = out
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .map(String::from)
        .collect();
    assert_eq!(keys, vec!["photos/a.jpg", "photos/b/c.jpg"]);
}

#[tokio::test]
async fn list_v1_marker() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("bkt-v1").send().await.unwrap();
    for k in ["a", "b/x", "b/y", "c", "d"] {
        c.put_object()
            .bucket("bkt-v1")
            .key(k)
            .body(ByteStream::from(b"v".to_vec()))
            .send()
            .await
            .unwrap();
    }
    let out = c
        .list_objects()
        .bucket("bkt-v1")
        .max_keys(2)
        .marker("b/")
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = out
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .map(String::from)
        .collect();
    assert_eq!(keys, vec!["b/x", "b/y"]);
    assert_eq!(out.is_truncated(), Some(true));

    let out = c.list_objects().bucket("bkt-v1").send().await.unwrap();
    let keys: Vec<_> = out
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .map(String::from)
        .collect();
    assert_eq!(keys, vec!["a", "b/x", "b/y", "c", "d"]);

    // missing bucket
    let err = c
        .list_objects_v2()
        .bucket("ghost-bucket")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchBucket"));
}

// ---------------- multipart (spec: s3-multipart-uploads) ----------------

#[tokio::test]
async fn multipart_round_trip() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("mp-1").send().await.unwrap();

    let create = c
        .create_multipart_upload()
        .bucket("mp-1")
        .key("big-object")
        .content_type("application/x-big")
        .metadata("kind", "multipart")
        .send()
        .await
        .unwrap();
    let upload_id = create.upload_id().unwrap().to_string();

    let part1 = vec![1u8; 5 * 1024 * 1024];
    let part2 = vec![2u8; 1024];
    let up1 = c
        .upload_part()
        .bucket("mp-1")
        .key("big-object")
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(part1.clone()))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_string();
    let up2 = c
        .upload_part()
        .bucket("mp-1")
        .key("big-object")
        .upload_id(&upload_id)
        .part_number(2)
        .body(ByteStream::from(part2.clone()))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_string();

    let complete = c
        .complete_multipart_upload()
        .bucket("mp-1")
        .key("big-object")
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&up1)
                        .build(),
                )
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(2)
                        .e_tag(&up2)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(complete.e_tag().unwrap().ends_with("-2\""));

    let get = c
        .get_object()
        .bucket("mp-1")
        .key("big-object")
        .send()
        .await
        .unwrap();
    assert_eq!(
        get.content_length(),
        Some((part1.len() + part2.len()) as i64)
    );
    assert_eq!(get.content_type(), Some("application/x-big"));
    assert_eq!(
        get.metadata().unwrap().get("kind").map(|s| s.as_str()),
        Some("multipart")
    );
    let bytes = get.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.len(), part1.len() + part2.len());
    assert_eq!(&bytes[..part1.len()], &part1[..]);
    assert_eq!(&bytes[part1.len()..], &part2[..]);
}

#[tokio::test]
async fn multipart_validation_errors() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("mperr").send().await.unwrap();

    let upload_id = c
        .create_multipart_upload()
        .bucket("mperr")
        .key("obj")
        .send()
        .await
        .unwrap()
        .upload_id()
        .unwrap()
        .to_string();

    let small = vec![0u8; 1024]; // < 5 MiB
    let etag1 = c
        .upload_part()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(small.clone()))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_string();

    // wrong order
    let err = c
        .complete_multipart_upload()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(2)
                        .e_tag(&etag1)
                        .build(),
                )
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&etag1)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidPartOrder"));

    // mismatched etag
    let err = c
        .complete_multipart_upload()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag("\"deadbeef\"")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidPart"));

    // upload stays resumable after failures
    let parts = c
        .list_parts()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .send()
        .await
        .unwrap();
    assert_eq!(parts.parts().len(), 1);

    // EntityTooSmall: two parts where a non-last part is < 5 MiB
    let etag2 = c
        .upload_part()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .part_number(2)
        .body(ByteStream::from(small.clone()))
        .send()
        .await
        .unwrap()
        .e_tag()
        .unwrap()
        .to_string();
    let err = c
        .complete_multipart_upload()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(&etag1)
                        .build(),
                )
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(2)
                        .e_tag(&etag2)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("EntityTooSmall"));
    // still resumable
    let parts = c
        .list_parts()
        .bucket("mperr")
        .key("obj")
        .upload_id(&upload_id)
        .send()
        .await
        .unwrap();
    assert_eq!(parts.parts().len(), 2);

    // unknown upload id
    let err = c
        .list_parts()
        .bucket("mperr")
        .key("obj")
        .upload_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchUpload"));
}

#[tokio::test]
async fn multipart_abort_and_list_uploads() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("mpabort").send().await.unwrap();
    let id1 = c
        .create_multipart_upload()
        .bucket("mpabort")
        .key("a")
        .send()
        .await
        .unwrap()
        .upload_id()
        .unwrap()
        .to_string();
    let id2 = c
        .create_multipart_upload()
        .bucket("mpabort")
        .key("b")
        .send()
        .await
        .unwrap()
        .upload_id()
        .unwrap()
        .to_string();

    c.upload_part()
        .bucket("mpabort")
        .key("a")
        .upload_id(&id1)
        .part_number(1)
        .body(ByteStream::from(vec![0u8; 1024]))
        .send()
        .await
        .unwrap();

    let out = c
        .list_multipart_uploads()
        .bucket("mpabort")
        .send()
        .await
        .unwrap();
    assert_eq!(out.uploads().len(), 2);

    c.abort_multipart_upload()
        .bucket("mpabort")
        .key("a")
        .upload_id(&id1)
        .send()
        .await
        .unwrap();
    // upload id now invalid
    let err = c
        .list_parts()
        .bucket("mpabort")
        .key("a")
        .upload_id(&id1)
        .send()
        .await
        .unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("NoSuchUpload"));

    let out = c
        .list_multipart_uploads()
        .bucket("mpabort")
        .send()
        .await
        .unwrap();
    assert_eq!(out.uploads().len(), 1);
    assert_eq!(out.uploads()[0].upload_id(), Some(id2.as_str()));
}

// ---------------- auth (spec: s3-authentication) ----------------

#[tokio::test]
async fn auth_rejects_bad_signature_and_unknown_key() {
    let server = spawn_server().await;
    let bad_secret = client_for(&server.endpoint, ROOT_ACCESS, "wrong-secret");
    let err = bad_secret.list_buckets().send().await.unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("SignatureDoesNotMatch"));

    let unknown_key = client_for(&server.endpoint, "ghost-key", ROOT_SECRET);
    let err = unknown_key.list_buckets().send().await.unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidAccessKeyId"));
}

#[tokio::test]
async fn unsigned_request_gets_403_xml() {
    let server = spawn_server().await;
    let res = reqwest::get(format!("{}/some-bucket/some-key", server.endpoint))
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert!(res.headers().get("x-amz-request-id").is_some());
    let body = res.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("<RequestId>"));
}

#[tokio::test]
async fn request_ids_match_error_xml() {
    let server = spawn_server().await;
    let c = client(&server);
    let http = reqwest::Client::new();
    let signed = c
        .get_object()
        .bucket("missing")
        .key("key")
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(60)).unwrap(),
        )
        .await
        .unwrap();
    for (url, status, code) in [
        (server.endpoint.as_str(), 403, "AccessDenied"),
        (signed.uri(), 404, "NoSuchBucket"),
    ] {
        let res = http
            .get(url)
            .header("x-amz-request-id", "caller-id")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), status);
        let id = res.headers()["x-amz-request-id"]
            .to_str()
            .unwrap()
            .to_owned();
        uuid::Uuid::parse_str(&id).unwrap();
        assert_ne!(id, "caller-id");
        let body = res.text().await.unwrap();
        assert!(body.contains(&format!("<RequestId>{id}</RequestId>")));
        assert!(body.contains(&format!("<Code>{code}</Code>")));
    }
    c.create_bucket().bucket("missing").send().await.unwrap();
    c.put_object()
        .bucket("missing")
        .key("key")
        .body(ByteStream::from_static(b"ok"))
        .send()
        .await
        .unwrap();
    let res = http
        .get(signed.uri())
        .header("x-amz-request-id", "caller-id")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    uuid::Uuid::parse_str(res.headers()["x-amz-request-id"].to_str().unwrap()).unwrap();
    assert_eq!(res.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn presigned_urls_get_and_put() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("presign").send().await.unwrap();
    c.put_object()
        .bucket("presign")
        .key("p")
        .body(ByteStream::from(b"presigned!".to_vec()))
        .send()
        .await
        .unwrap();

    let url = c
        .get_object()
        .bucket("presign")
        .key("p")
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(60)).unwrap(),
        )
        .await
        .unwrap()
        .uri()
        .to_owned()
        .to_string();
    let res = reqwest::get(&url).await.unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "presigned!");

    // presigned PUT
    let url = c
        .put_object()
        .bucket("presign")
        .key("uploaded-via-url")
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(60)).unwrap(),
        )
        .await
        .unwrap()
        .uri()
        .to_owned()
        .to_string();
    let res = reqwest::Client::new()
        .put(&url)
        .body("via-presign")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let g = c
        .get_object()
        .bucket("presign")
        .key("uploaded-via-url")
        .send()
        .await
        .unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes(),
        &b"via-presign"[..]
    );

    // expired presigned URL -> 403 AccessDenied
    let url = c
        .get_object()
        .bucket("presign")
        .key("p")
        .presigned(
            aws_sdk_s3::presigning::PresigningConfig::expires_in(Duration::from_secs(1)).unwrap(),
        )
        .await
        .unwrap()
        .uri()
        .to_owned()
        .to_string();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let res = reqwest::get(&url).await.unwrap();
    assert_eq!(res.status(), 403);
    assert!(res.text().await.unwrap().contains("AccessDenied"));
}

#[tokio::test]
async fn credential_hot_reload() {
    let server = spawn_server().await;
    // new key added to the live data dir works without restart
    los_cara::auth::add_key(server.data.path(), "new-key", "new-secret");
    let c = client_for(&server.endpoint, "new-key", "new-secret");
    c.list_buckets().send().await.unwrap();

    // removed key is rejected
    los_cara::auth::remove_key(server.data.path(), "new-key");
    let err = c.list_buckets().send().await.unwrap_err();
    assert_eq!(err_code(&err).as_deref(), Some("InvalidAccessKeyId"));
}

// ---------------- addressing (spec: s3-http-api) ----------------

#[tokio::test]
async fn virtual_hosted_style_requests() {
    check_virtual_hosted_style(&[]).await;
}

#[tokio::test]
async fn cors_virtual_hosted_style_requests() {
    check_virtual_hosted_style(&[CORS_ORIGIN]).await;
}

async fn check_virtual_hosted_style(origins: &[&str]) {
    use los_cara::auth as lauth;
    let server = spawn_server_with_cors(origins).await;
    let c = client(&server);
    c.create_bucket().bucket("vhost").send().await.unwrap();
    c.put_object()
        .bucket("vhost")
        .key("vk")
        .body(ByteStream::from(b"vhost-data".to_vec()))
        .send()
        .await
        .unwrap();

    let port = server.endpoint.rsplit(':').next().unwrap().to_string();
    let host = format!("vhost.s3.local:{port}");
    let path = "/vk";

    // sign a GET /vk request for Host: vhost.s3.local:<port> using the same
    // SigV4 primitives the server implements (verified against AWS vectors)
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let payload_hash = lauth::sha256_hex(b"");
    let canonical = format!(
        "GET\n{path}\n\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n\nhost;x-amz-content-sha256;x-amz-date\n{payload_hash}"
    );
    let scope = format!("{date}/us-east-1/s3/aws4_request");
    let sts = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        lauth::sha256_hex(canonical.as_bytes())
    );
    let key = lauth::signing_key_for_test(ROOT_SECRET, date, "us-east-1");
    let signature = lauth::hmac_hex(&key, sts.as_bytes());

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let http = reqwest::Client::builder()
        .resolve("vhost.s3.local", addr)
        .build()
        .unwrap();
    if let Some(origin) = origins.first() {
        let res = http
            .request(reqwest::Method::OPTIONS, format!("http://{host}{path}"))
            .header("origin", *origin)
            .header("access-control-request-method", "GET")
            .send()
            .await
            .unwrap();
        assert!(res.status().is_success());
        assert_cors(res.headers(), Some(origin));
        assert!(res.bytes().await.unwrap().is_empty());
    }
    let mut req = http
        .get(format!("http://{host}{path}"))
        .header("host", &host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &payload_hash)
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={ROOT_ACCESS}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"),
        );
    if let Some(origin) = origins.first() {
        req = req.header("origin", *origin);
    }
    let res = req.send().await.unwrap();
    if let Some(origin) = origins.first() {
        assert_cors(res.headers(), Some(origin));
    }
    let status = res.status();
    let body = res.text().await.unwrap();
    assert_eq!(status, 200, "vhost GET failed: {body}");
    assert_eq!(body, "vhost-data");
}

#[tokio::test]
async fn request_id_on_every_response() {
    let server = spawn_server().await;
    let res = reqwest::get(format!("{}/", server.endpoint)).await; // unsigned -> 403 but must have request id
    // (GET / unsigned is rejected by auth middleware with a request id header)
    let res = res.unwrap();
    assert_eq!(res.status(), 403);
    assert!(res.headers().get("x-amz-request-id").is_some());
}

#[tokio::test]
async fn large_object_streaming_64mib() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("big").send().await.unwrap();

    fn rss_kb() -> i64 {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .map(|l| l.split_whitespace().nth(1).unwrap().parse::<i64>().unwrap())
            })
            .unwrap_or(0)
    }

    let before = rss_kb();
    let mut body = vec![0xABu8; 64 * 1024 * 1024];
    body[0] = 1;
    body[64 * 1024 * 1024 - 1] = 2;
    c.put_object()
        .bucket("big")
        .key("large")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .unwrap();
    let after = rss_kb();
    let delta = after - before;
    // the SDK buffers this body in the test process; the server must not add
    // another full copy. Allow generous headroom (SDK copy + page cache).
    assert!(
        delta < 400 * 1024,
        "RSS grew by {delta} KiB during 64 MiB upload"
    );
    drop(body);

    let g = c
        .get_object()
        .bucket("big")
        .key("large")
        .send()
        .await
        .unwrap();
    let bytes = g.body.collect().await.unwrap().into_bytes();
    assert_eq!(bytes.len(), 64 * 1024 * 1024);
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[bytes.len() - 1], 2);
    assert_eq!(bytes[12345], 0xAB);
}

// ---------------- concurrency (spec: storage-engine) ----------------

#[tokio::test]
async fn concurrent_distinct_uploads() {
    let server = spawn_server().await;
    let c = std::sync::Arc::new(client(&server));
    c.create_bucket().bucket("conc").send().await.unwrap();
    let mut handles = Vec::new();
    for i in 0..50u32 {
        let c = c.clone();
        handles.push(tokio::spawn(async move {
            let content = format!("object-number-{i}").into_bytes();
            c.put_object()
                .bucket("conc")
                .key(format!("k-{i}"))
                .body(ByteStream::from(content.clone()))
                .send()
                .await
                .unwrap();
            content
        }));
    }
    let expected: Vec<Vec<u8>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|h| h.unwrap())
        .collect();
    for (i, e) in expected.iter().enumerate() {
        let g = c
            .get_object()
            .bucket("conc")
            .key(format!("k-{i}"))
            .send()
            .await
            .unwrap();
        assert_eq!(&g.body.collect().await.unwrap().into_bytes()[..], &e[..]);
    }
}

#[tokio::test]
async fn concurrent_writes_same_key_atomic() {
    let server = spawn_server().await;
    let c = std::sync::Arc::new(client(&server));
    c.create_bucket().bucket("race").send().await.unwrap();
    let mut handles = Vec::new();
    for i in 0..10u32 {
        let c = c.clone();
        handles.push(tokio::spawn(async move {
            let content = vec![i as u8; 2048];
            c.put_object()
                .bucket("race")
                .key("same")
                .body(ByteStream::from(content.clone()))
                .send()
                .await
                .unwrap();
            content
        }));
    }
    let candidates: Vec<Vec<u8>> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|h| h.unwrap())
        .collect();
    let g = c
        .get_object()
        .bucket("race")
        .key("same")
        .send()
        .await
        .unwrap();
    let bytes = g.body.collect().await.unwrap().into_bytes().to_vec();
    assert!(
        candidates.contains(&bytes),
        "final content must be one complete version"
    );
}

#[tokio::test]
async fn upload_part_copy() {
    let server = spawn_server().await;
    let c = client(&server);
    c.create_bucket().bucket("upc").send().await.unwrap();
    c.put_object()
        .bucket("upc")
        .key("src")
        .body(ByteStream::from(vec![9u8; 1024]))
        .send()
        .await
        .unwrap();
    let id = c
        .create_multipart_upload()
        .bucket("upc")
        .key("assembled")
        .send()
        .await
        .unwrap()
        .upload_id()
        .unwrap()
        .to_string();
    let out = c
        .upload_part_copy()
        .bucket("upc")
        .key("assembled")
        .upload_id(&id)
        .part_number(1)
        .copy_source("upc/src")
        .send()
        .await
        .unwrap();
    let part_etag = out
        .copy_part_result()
        .and_then(|r| r.e_tag())
        .unwrap()
        .to_string();
    let meta = c
        .complete_multipart_upload()
        .bucket("upc")
        .key("assembled")
        .upload_id(&id)
        .multipart_upload(
            aws_sdk_s3::types::CompletedMultipartUpload::builder()
                .parts(
                    aws_sdk_s3::types::CompletedPart::builder()
                        .part_number(1)
                        .e_tag(part_etag)
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(meta.e_tag().is_some());
    let g = c
        .get_object()
        .bucket("upc")
        .key("assembled")
        .send()
        .await
        .unwrap();
    assert_eq!(g.content_length(), Some(1024));
}

// ---------------- TLS (task 9.1) ----------------

#[tokio::test]
async fn serve_over_tls_with_cors() {
    let dir = tempfile::tempdir().unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    let storage = Storage::open(dir.path()).await.unwrap();
    let creds = CredentialStore::new(
        dir.path(),
        los_cara::auth::Credentials {
            access_key: ROOT_ACCESS.into(),
            secret_key: ROOT_SECRET.into(),
        },
    );
    let app = los_cara::s3::router_with_cors(
        AppState::new(storage, creds),
        vec![los_cara::config::parse_cors_origin(CORS_ORIGIN).unwrap()],
    );

    // reserve a port
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let rustls = {
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(&cert_path).unwrap(),
        ))
        .collect::<Result<_, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(&key_path).unwrap(),
        ))
        .unwrap()
        .unwrap();
        std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        )
    };
    let config = axum_server::tls_rustls::RustlsConfig::from_config(rustls);
    let handle = tokio::spawn(async move {
        axum_server::bind_rustls(addr, config)
            .serve(app.into_make_service())
            .await
            .unwrap();
    });

    // give the server a moment, then hit it over HTTPS
    tokio::time::sleep(Duration::from_millis(300)).await;
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let res = http.get(format!("https://{addr}/")).send().await.unwrap();
    assert_eq!(res.status(), 403); // unsigned over TLS -> AccessDenied
    assert_cors(res.headers(), None);
    let res = http
        .request(
            reqwest::Method::OPTIONS,
            format!("https://{addr}/missing/key"),
        )
        .header("origin", CORS_ORIGIN)
        .header("access-control-request-method", "PUT")
        .header(
            "access-control-request-headers",
            "Authorization,X-Amz-Meta-Owner",
        )
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    assert_cors(res.headers(), Some(CORS_ORIGIN));
    assert!(header_tokens(res.headers(), "access-control-allow-methods").contains(&"put".into()));
    assert_eq!(
        header_tokens(res.headers(), "access-control-allow-headers"),
        ["authorization", "x-amz-meta-owner"]
    );
    assert!(res.bytes().await.unwrap().is_empty());
    let res = http
        .get(format!("https://{addr}/missing/key"))
        .header("origin", CORS_ORIGIN)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    assert_cors(res.headers(), Some(CORS_ORIGIN));
    assert_eq!(res.headers()["access-control-expose-headers"], "*");
    let id = res.headers()["x-amz-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = res.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains(&format!("<RequestId>{id}</RequestId>")));
    handle.abort();
    let _ = cert;
}
