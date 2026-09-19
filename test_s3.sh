#!/usr/bin/env bash
# End-to-end smoke test for lc (S3-compatible storage):
# start server on a temp data dir -> add a new access key -> create bucket ->
# upload file -> download -> verify -> presign -> cleanup.
set -euo pipefail

PORT="${PORT:-19099}"
ENDPOINT="http://127.0.0.1:${PORT}"
ROOT_KEY="root-key"
ROOT_SECRET="root-secret"
NEW_KEY="test-user"
NEW_SECRET="test-user-secret"
BUCKET="smoke-test-bucket"
WORKDIR="$(mktemp -d)"
DATA_DIR="${WORKDIR}/data"
FILE="${WORKDIR}/testfile.bin"

log() { echo "[test_s3] $*"; }
cleanup() {
    [[ -n "${SERVER_PID:-}" ]] && kill "${SERVER_PID}" 2>/dev/null || true
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

# ---- build ----
log "building (debug)"
cargo build -q

# ---- test file: >5 MiB so aws cli uses multipart upload ----
dd if=/dev/urandom of="${FILE}" bs=1M count=6 status=none
log "test file: $(du -h "${FILE}" | cut -f1) at ${FILE}"

# ---- start server ----
log "starting server on ${ENDPOINT} (data: ${DATA_DIR})"
RUST_LOG=error ./target/debug/lc serve \
    --address "127.0.0.1:${PORT}" \
    --data "${DATA_DIR}" \
    --access-key "${ROOT_KEY}" \
    --secret-key "${ROOT_SECRET}" &
SERVER_PID=$!
for _ in $(seq 1 50); do
    curl -s -o /dev/null "${ENDPOINT}/" && break
    sleep 0.1
done
log "server is up (pid ${SERVER_PID})"

# ---- create a new access key ----
log "creating new access key '${NEW_KEY}'"
./target/debug/lc add-key --data "${DATA_DIR}" \
    --access-key "${NEW_KEY}" --secret-key "${NEW_SECRET}" >/dev/null

# ---- configure aws cli with the NEW key ----
export AWS_ACCESS_KEY_ID="${NEW_KEY}"
export AWS_SECRET_ACCESS_KEY="${NEW_SECRET}"
export AWS_DEFAULT_REGION=us-east-1
AWS="aws --endpoint-url ${ENDPOINT}"

# ---- workflow ----
log "create bucket ${BUCKET}"
${AWS} s3 mb "s3://${BUCKET}" >/dev/null

log "upload file (multipart, >5 MiB)"
${AWS} s3 cp "${FILE}" "s3://${BUCKET}/testfile.bin" --quiet

log "list bucket"
${AWS} s3 ls "s3://${BUCKET}" --human-readable --summarize | sed 's/^/    /'

log "download and verify"
${AWS} s3 cp "s3://${BUCKET}/testfile.bin" "${WORKDIR}/downloaded.bin" --quiet
cmp "${FILE}" "${WORKDIR}/downloaded.bin"
log "downloaded copy is byte-identical"

log "presigned URL"
PRESIGNED=$(${AWS} s3 presign "s3://${BUCKET}/testfile.bin" --expires-in 60)
STATUS=$(curl -s -o "${WORKDIR}/presigned.bin" -w "%{http_code}" "${PRESIGNED}")
[[ "${STATUS}" == "200" ]] && cmp "${FILE}" "${WORKDIR}/presigned.bin"
log "presigned GET returned ${STATUS}, content verified"

log "upload a second small object + head"
echo "hello from lc" | ${AWS} s3 cp - "s3://${BUCKET}/hello.txt" --quiet
${AWS} s3api head-object --bucket "${BUCKET}" --key hello.txt --query ContentLength >/dev/null

log "delete everything"
${AWS} s3 rm "s3://${BUCKET}" --recursive --quiet
${AWS} s3 rb "s3://${BUCKET}" >/dev/null

log "ALL CHECKS PASSED ✓"
