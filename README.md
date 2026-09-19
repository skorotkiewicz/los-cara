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

### systemd deployment (Linux)

The `packaging/systemd/` directory contains a hardened service unit, an
environment template, and an installer script:

```bash
sudo ./packaging/systemd/install.sh [path-to-lc-binary]
# then: edit /etc/default/lc (credentials/TLS) and
sudo systemctl enable --now lc
journalctl -u lc -f
```

Files: `lc.service` (runs as the `lc` user with systemd sandboxing,
data in `/var/lib/lc`), `lc.env.example` (environment template installed to
`/etc/default/lc`), `install.sh` (one-shot installer). Linux release
tarballs from CI include the systemd files.

### Browser access with CORS

CORS is disabled by default. Repeat `--cors-allowed-origin` to allow browser
origins across all buckets on HTTP or HTTPS:

```bash
lc serve --address 127.0.0.1:9000 --data ./data \
    --access-key AK --secret-key SK \
    --cors-allowed-origin https://app.example \
    --cors-allowed-origin http://localhost:5173
```

Each value must be an HTTP or HTTPS origin with a host and optional port.
IPv6 addresses must use brackets, for example `http://[::1]:5173`.
Host case and default ports are normalized. A root slash is accepted and removed.
Duplicate origins are harmless. Wildcards, `null`, user information, non-root
paths, queries, fragments, malformed values, and control characters cause startup to fail.
Matching is exact, not by domain suffix. Other schemes, subdomains, and
non-default ports need separate entries. Restart the server to change the list.
Remove all origin flags and restart to disable CORS.

Allowed origins can preflight GET, HEAD, PUT, POST, and DELETE without a signature.
Responses expose all headers, including ETag, request IDs, and user metadata.
Browser credential mode is not supported. Use a presigned URL from a trusted
backend with `credentials: "omit"`:

```javascript
// presignedUrl is a GET URL supplied by your backend.
const response = await fetch(presignedUrl, { credentials: "omit" });
if (!response.ok) throw new Error(await response.text());
const etag = response.headers.get("etag");
const object = await response.blob();
```

Never put root secrets in browser code. CORS is not authorization.
Every actual S3 operation still requires a valid SigV4 signature or presigned URL.
A successful preflight does not authorize the next request.
Unlisted origins receive no browser grant, but valid signed requests still run.
CORS does not block non-browser clients. This server-wide policy does not implement
bucket CORS configuration APIs. Existing bucket subresource probes remain neutral.

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

Not implemented (yet): bucket versioning, lifecycle policies, bucket CORS APIs,
bucket policies/IAM/ACLs, encryption at rest, replication, website hosting,
and event notifications. Unimplemented subresource probes return neutral
responses so common S3 clients work. Max object size is 5 GiB per S3 limits.
Atomicity guarantees rely on `rename(2)`; best-effort on non-POSIX filesystems.
