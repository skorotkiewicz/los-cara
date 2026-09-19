# los-cara

An S3-compatible object storage server written in Rust. Point any standard S3
client (AWS SDKs, AWS CLI, rclone, s5cmd, MinIO clients) at it and store data.

## Quickstart

```bash
# build
cargo build --release

# start the server (root credentials via flags or env)
./target/release/lc serve \
    --address 127.0.0.1:9000 \
    --data ./data \
    --access-key my-access-key \
    --secret-key my-secret-key

# or with TLS
./target/release/lc serve --address 0.0.0.0:9000 --data ./data \
    --access-key AK --secret-key SK \
    --tls-cert cert.pem --tls-key key.pem
```

### Use with the AWS CLI

```bash
export AWS_ACCESS_KEY_ID=my-access-key
export AWS_SECRET_ACCESS_KEY=my-secret-key
export AWS_DEFAULT_REGION=us-east-1

aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://my-bucket
aws --endpoint-url http://127.0.0.1:9000 s3 cp file.bin s3://my-bucket/file.bin
aws --endpoint-url http://127.0.0.1:9000 s3 ls s3://my-bucket
aws --endpoint-url http://127.0.0.1:9000 s3 cp s3://my-bucket/file.bin out.bin
aws --endpoint-url http://127.0.0.1:9000 s3 presign s3://my-bucket/file.bin
aws --endpoint-url http://127.0.0.1:9000 s3 rb s3://my-bucket --force
```

### Use with rclone

```bash
rclone config create loscara s3 \
    provider=Other endpoint=http://127.0.0.1:9000 \
    access_key_id=my-access-key secret_key=my-secret-key
rclone ls loscara:my-bucket
```

### Managing extra access keys

```bash
lc add-key --data ./data --access-key app-key --secret-key app-secret
lc remove-key --data ./data --access-key app-key
```

Key changes are picked up by a running server without restart.

## Supported operations

- **Buckets:** CreateBucket, DeleteBucket, HeadBucket, ListBuckets
- **Objects:** PutObject, GetObject (Range, conditional requests), HeadObject,
  DeleteObject, DeleteObjects (batch), CopyObject
- **Listing:** ListObjects (V1) and ListObjectsV2 with prefix, delimiter,
  common prefixes, and pagination
- **Multipart:** CreateMultipartUpload, UploadPart, UploadPartCopy, ListParts,
  CompleteMultipartUpload, AbortMultipartUpload, ListMultipartUploads
- **Auth:** AWS Signature Version 4 (headers and presigned URLs), including
  `aws-chunked` streaming payload verification
- **Transport:** HTTP and HTTPS (rustls)

## Architecture

Single static binary; all state lives in the `--data` directory (plain files,
no external database). Objects are stored content-intact with atomic
temp-file-then-rename writes; object metadata files are the source of truth.
See `openspec/` for the full behavioral specs.

## Limitations

Not implemented (yet): bucket versioning, lifecycle policies, CORS,
bucket policies/IAM/ACLs, encryption at rest, replication, website hosting,
and event notifications. Unimplemented subresource probes return neutral
responses so common S3 clients work. Max object size is 5 GiB per S3 limits.
Atomicity guarantees rely on `rename(2)`; best-effort on non-POSIX filesystems.
