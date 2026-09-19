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
    let app = los_cara::s3::router(state);
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
    let future =
        aws_sdk_s3::primitives::DateTime::from_secs((chrono::Utc::now().timestamp() + 3600) as i64);
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
    let objs = vec![
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
    use los_cara::auth as lauth;
    let server = spawn_server().await;
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
    let res = http
        .get(format!("http://{host}{path}"))
        .header("host", &host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &payload_hash)
        .header(
            "authorization",
            format!("AWS4-HMAC-SHA256 Credential={ROOT_ACCESS}/{scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}"),
        )
        .send()
        .await
        .unwrap();
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
        candidates.iter().any(|cand| *cand == bytes),
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
async fn serve_over_tls() {
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
    let app = los_cara::s3::router(AppState::new(storage, creds));

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
    handle.abort();
    let _ = cert;
}
