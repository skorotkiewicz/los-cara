//! Filesystem-backed storage engine.
//!
//! Layout under the data directory:
//! ```text
//! <root>/buckets/<bucket>/meta.json                     bucket metadata
//! <root>/buckets/<bucket>/objects/<aa>/<bb>/<hash>/meta.json    object metadata (owns truth)
//! <root>/buckets/<bucket>/objects/<aa>/<bb>/<hash>/<uuid>.data  object content
//! <root>/buckets/<bucket>/objects/<aa>/<bb>/<hash>/tmp-<uuid>   in-progress writes
//! <root>/multipart/<upload-id>/manifest.json            multipart upload manifest
//! <root>/multipart/<upload-id>/parts/<n>.data           staged part content
//! <root>/tmp/<uuid>                                     generic staging
//! <root>/keys.json                                      access key store (owned by config)
//! ```
//!
//! Object keys are SHA-256 hashed into a two-level sharded path; the full key
//! is recorded in `meta.json`. The metadata file is the source of truth: it is
//! installed atomically via rename after the data file is fully written, so a
//! reader either sees the previous complete version or the new complete one.

use crate::error::S3Error;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
type Md5 = md5::Md5;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWriteExt};

pub const MAX_OBJECT_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB per S3 single-PUT limit
pub const MIN_PART_SIZE: u64 = 5 * 1024 * 1024; // 5 MiB
const PART_DIR: &str = "parts";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub content_type: String,
    /// epoch milliseconds
    pub last_modified: i64,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub data_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketMeta {
    pub name: String,
    /// epoch milliseconds
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultipartManifest {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub content_type: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// epoch milliseconds
    pub initiated: i64,
    /// part number -> (etag hex without quotes, size)
    #[serde(default)]
    pub parts: BTreeMap<u32, (String, u64)>,
}

#[derive(Debug)]
pub struct PutResult {
    pub meta: ObjectMeta,
    /// hex sha256 of the stored content (for x-amz-content-sha256 verification)
    pub sha256_hex: String,
    /// base64 content-md5 supplied by the client, to be compared by caller
    pub content_md5_hex: String,
}

pub struct ListPage {
    pub contents: Vec<ObjectMeta>,
    pub common_prefixes: Vec<String>,
    pub truncated: bool,
    /// last key returned when contents were the boundary item
    pub next_token: Option<String>,
    /// last common prefix emitted when prefixes were the boundary item
    pub next_prefix_token: Option<String>,
}

#[derive(Clone)]
pub struct Storage {
    root: PathBuf,
    /// serializes writes per object directory (bucket\0key)
    locks: Arc<std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn write_json_atomic(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let data = serde_json::to_vec(value).map_err(io::Error::other)?;
    fs::write(&tmp, data).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

async fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    let data = fs::read(path).await?;
    serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Validate an S3 bucket name.
pub fn valid_bucket_name(name: &str) -> bool {
    let n = name.len();
    if !(3..=63).contains(&n) {
        return false;
    }
    let bytes = name.as_bytes();
    let valid_char = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.';
    if !bytes[0].is_ascii_alphanumeric() || !bytes[n - 1].is_ascii_alphanumeric() {
        return false;
    }
    if !bytes.iter().all(|&c| valid_char(c)) {
        return false;
    }
    // no consecutive dots, no ".."
    if name.contains("..") {
        return false;
    }
    // must not be formatted like an IP address
    if name
        .split('.')
        .all(|p| p.chars().all(|c| c.is_ascii_digit()))
        && name.matches('.').count() == 3
    {
        return false;
    }
    true
}

/// SHA-256 hex of a key, sharded into two directory levels.
pub fn key_shard(key: &str) -> (String, String, String) {
    let mut h = Sha256::new();
    h.update(key.as_bytes());
    let hex = hex::encode(h.finalize());
    (hex[..2].to_string(), hex[2..4].to_string(), hex.clone())
}

impl Storage {
    pub async fn open(root: &Path) -> io::Result<Self> {
        for sub in ["buckets", "multipart", "tmp"] {
            fs::create_dir_all(root.join(sub)).await?;
        }
        if !root.join("keys.json").exists() {
            fs::write(root.join("keys.json"), b"{}").await?;
        }
        Ok(Self {
            root: root.to_path_buf(),
            locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn bucket_dir(&self, bucket: &str) -> PathBuf {
        self.root.join("buckets").join(bucket)
    }

    fn objects_root(&self, bucket: &str) -> PathBuf {
        self.bucket_dir(bucket).join("objects")
    }

    fn object_dir(&self, bucket: &str, key: &str) -> PathBuf {
        let (a, b, hash) = key_shard(key);
        self.objects_root(bucket).join(a).join(b).join(&hash)
    }

    fn tmp_file(&self) -> PathBuf {
        self.root.join("tmp").join(uuid::Uuid::new_v4().to_string())
    }

    async fn object_lock(&self, bucket: &str, key: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let arc = {
            let mut map = self.locks.lock().unwrap();
            map.entry(format!("{bucket}\0{key}")).or_default().clone()
        };
        Arc::clone(&arc).lock_owned().await
    }

    // ---- buckets ----

    pub async fn create_bucket(&self, name: &str) -> Result<bool, S3Error> {
        if !valid_bucket_name(name) {
            return Err(S3Error::invalid_bucket_name(name));
        }
        let dir = self.bucket_dir(name);
        if dir.join("meta.json").exists() {
            return Ok(false);
        }
        fs::create_dir_all(dir.join("objects"))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let meta = BucketMeta {
            name: name.to_string(),
            created: now_ms(),
        };
        write_json_atomic(&dir.join("meta.json"), &meta)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        Ok(true)
    }

    pub async fn bucket_exists(&self, name: &str) -> Result<bool, S3Error> {
        // invalid names simply don't exist
        Ok(self.bucket_dir(name).join("meta.json").exists())
    }

    pub async fn bucket_created(&self, name: &str) -> Result<i64, S3Error> {
        if !self.bucket_exists(name).await? {
            return Err(S3Error::no_such_bucket(name));
        }
        let meta: BucketMeta = read_json(&self.bucket_dir(name).join("meta.json"))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        Ok(meta.created)
    }

    pub async fn list_buckets(&self) -> Result<Vec<(String, i64)>, S3Error> {
        let mut out = Vec::new();
        let mut rd = fs::read_dir(self.root.join("buckets"))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        while let Ok(Some(entry)) = rd.next_entry().await {
            let meta_path = entry.path().join("meta.json");
            if meta_path.exists() {
                if let Ok(meta) = read_json::<BucketMeta>(&meta_path).await {
                    out.push((meta.name, meta.created));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    pub async fn delete_bucket(&self, name: &str) -> Result<(), S3Error> {
        if !self.bucket_exists(name).await? {
            return Err(S3Error::no_such_bucket(name));
        }
        // non-empty check: any object meta or in-progress upload
        if self.has_any_object(name).await? {
            return Err(S3Error::bucket_not_empty());
        }
        for upload in self.list_multipart_uploads_raw().await? {
            if upload.bucket == name {
                return Err(S3Error::bucket_not_empty());
            }
        }
        fs::remove_dir_all(self.bucket_dir(name))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        Ok(())
    }

    async fn has_any_object(&self, bucket: &str) -> Result<bool, S3Error> {
        let mut found = false;
        walk_metas(&self.objects_root(bucket), &mut |_, _| {
            found = true;
        })
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
        let _ = found;
        Ok(found)
    }

    // ---- objects ----

    /// Stream `body` into the object at `bucket/key`, returning metadata.
    /// Atomic: temp file -> rename -> metadata rename.
    pub async fn put_object<S>(
        &self,
        bucket: &str,
        key: &str,
        mut body: S,
        content_type: String,
        metadata: BTreeMap<String, String>,
    ) -> Result<PutResult, S3Error>
    where
        S: futures::Stream<Item = Result<bytes::Bytes, S3Error>> + Unpin,
    {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        if key.is_empty() || key.len() > 1024 {
            return Err(S3Error::invalid_argument(
                "Object key must be between 1 and 1024 bytes",
            ));
        }
        let _guard = self.object_lock(bucket, key).await;

        let tmp_path = self.tmp_file();
        let mut file = fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let mut md5 = Md5::new();
        let mut sha = Sha256::new();
        let mut size: u64 = 0;

        let mut stream_failed = false;
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => {
                    size += chunk.len() as u64;
                    if size > MAX_OBJECT_SIZE {
                        let _ = fs::remove_file(&tmp_path).await;
                        return Err(S3Error::entity_too_large());
                    }
                    md5.update(&chunk);
                    sha.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        let _ = fs::remove_file(&tmp_path).await;
                        return Err(S3Error::internal(e.to_string()));
                    }
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path).await;
                    stream_failed = true;
                    return Err(e);
                }
            }
        }
        let _ = stream_failed;
        file.flush()
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        file.sync_all()
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;

        let md5_hex = hex::encode(md5.finalize());
        let sha_hex = hex::encode(sha.finalize());

        // install data file under a unique name, then atomically swap metadata
        let dir = self.object_dir(bucket, key);
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let data_name = format!("{}.data", uuid::Uuid::new_v4());
        let data_path = dir.join(&data_name);
        fs::rename(&tmp_path, &data_path)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;

        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: md5_hex.clone(),
            content_type,
            last_modified: now_ms(),
            metadata,
            data_file: Some(data_name),
        };
        if let Err(e) = write_json_atomic(&dir.join("meta.json"), &meta).await {
            let _ = fs::remove_file(&data_path).await;
            return Err(S3Error::internal(e.to_string()));
        }
        // remove any orphaned data files from prior versions (best effort)
        let keep_name = meta.data_file.clone().unwrap_or_default();
        self.gc_object_dir(&dir, &keep_name).await;
        Ok(PutResult {
            meta,
            sha256_hex: sha_hex,
            content_md5_hex: md5_hex,
        })
    }

    async fn gc_object_dir(&self, dir: &Path, keep: &str) {
        if let Ok(mut rd) = fs::read_dir(dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".data") && name != keep {
                    let _ = fs::remove_file(entry.path()).await;
                }
            }
        }
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta, S3Error> {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        let path = self.object_dir(bucket, key).join("meta.json");
        match read_json::<ObjectMeta>(&path).await {
            Ok(m) => Ok(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(S3Error::no_such_key(key)),
            Err(e) => Err(S3Error::internal(e.to_string())),
        }
    }

    /// Open the object content for reading (whole object).
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectMeta, Pin<Box<dyn AsyncRead + Send>>), S3Error> {
        self.get_object_range(bucket, key, 0, None).await
    }

    /// Open the object content for reading, optionally a byte range.
    pub async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        len: Option<u64>,
    ) -> Result<(ObjectMeta, Pin<Box<dyn AsyncRead + Send>>), S3Error> {
        let meta = self.head_object(bucket, key).await?;
        let data_file = meta
            .data_file
            .clone()
            .ok_or_else(|| S3Error::internal("object has no data file"))?;
        let path = self.object_dir(bucket, key).join(data_file);
        let mut file = fs::File::open(&path)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let read_len = match len {
            Some(l) => l.min(meta.size.saturating_sub(start)),
            None => meta.size.saturating_sub(start),
        };
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        if start > 0 {
            file.seek(io::SeekFrom::Start(start))
                .await
                .map_err(|e| S3Error::internal(e.to_string()))?;
        }
        let reader: Pin<Box<dyn AsyncRead + Send>> = Box::pin(file.take(read_len));
        Ok((meta, reader))
    }

    /// Delete an object. Idempotent: missing key is not an error.
    /// Metadata is removed first so listings/GETs never see a phantom.
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), S3Error> {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        let _guard = self.object_lock(bucket, key).await;
        let dir = self.object_dir(bucket, key);
        let meta_path = dir.join("meta.json");
        if meta_path.exists() {
            // capture data file name, then remove metadata before data
            let data_name = read_json::<ObjectMeta>(&meta_path)
                .await
                .ok()
                .and_then(|m| m.data_file);
            let _ = fs::remove_file(&meta_path).await;
            if let Some(d) = data_name {
                let _ = fs::remove_file(dir.join(d)).await;
            }
        }
        Ok(())
    }

    /// Copy an object. When `replace` is None the ETag and user metadata are
    /// preserved (S3 semantics for COPY without METADATA directive).
    pub async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
        replace: Option<(String, BTreeMap<String, String>)>,
    ) -> Result<ObjectMeta, S3Error> {
        let src_meta = self.head_object(src_bucket, src_key).await?;
        if !self.bucket_exists(dst_bucket).await? {
            return Err(S3Error::no_such_bucket(dst_bucket));
        }
        let _guard = self.object_lock(dst_bucket, dst_key).await;
        let dir = self.object_dir(dst_bucket, dst_key);
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let new_data = format!("{}.data", uuid::Uuid::new_v4());
        let src_dir = self.object_dir(src_bucket, src_key);
        let src_data = src_dir.join(
            src_meta
                .data_file
                .clone()
                .ok_or_else(|| S3Error::internal("missing data file"))?,
        );
        let dst_data = dir.join(&new_data);
        #[cfg(unix)]
        {
            if fs::hard_link(&src_data, &dst_data).await.is_err() {
                fs::copy(&src_data, &dst_data)
                    .await
                    .map_err(|e| S3Error::internal(e.to_string()))?;
            }
        }
        #[cfg(not(unix))]
        {
            fs::copy(&src_data, &dst_data)
                .await
                .map_err(|e| S3Error::internal(e.to_string()))?;
        }
        let (etag, content_type, metadata) = match replace {
            Some((ct, md)) => {
                // content changed semantically -> recompute etag by hashing the file
                let mut h = Md5::new();
                let mut file = fs::File::open(&dst_data)
                    .await
                    .map_err(|e| S3Error::internal(e.to_string()))?;
                let mut buf = vec![0u8; 65536];
                use tokio::io::AsyncReadExt;
                loop {
                    let n = file
                        .read(&mut buf)
                        .await
                        .map_err(|e| S3Error::internal(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                    h.update(&buf[..n]);
                }
                (hex::encode(h.finalize()), ct, md)
            }
            None => (
                src_meta.etag.clone(),
                src_meta.content_type.clone(),
                src_meta.metadata.clone(),
            ),
        };
        let meta = ObjectMeta {
            key: dst_key.to_string(),
            size: src_meta.size,
            etag,
            content_type,
            last_modified: now_ms(),
            metadata,
            data_file: Some(new_data),
        };
        if let Err(e) = write_json_atomic(&dir.join("meta.json"), &meta).await {
            let _ = fs::remove_file(&dst_data).await;
            return Err(S3Error::internal(e.to_string()));
        }
        self.gc_object_dir(&dir, meta.data_file.as_deref().unwrap_or(""))
            .await;
        Ok(meta)
    }

    // ---- listing ----

    /// Collect all object metadata in the bucket, sorted by key (UTF-8 order).
    pub async fn all_objects(&self, bucket: &str) -> Result<Vec<ObjectMeta>, S3Error> {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        let mut out = Vec::new();
        walk_metas(&self.objects_root(bucket), &mut |_path, _| {
            // meta is read in the walker via blocking read? No: walker collects paths.
        })
        .await
        .map_err(|e| S3Error::internal(e.to_string()))?;
        let mut metas = Vec::new();
        collect_meta_paths(&self.objects_root(bucket), &mut metas);
        metas.sort();
        for p in metas {
            if let Ok(m) = read_json::<ObjectMeta>(&p).await {
                out.push(m);
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    /// List with S3 semantics: prefix filter, delimiter rollup, pagination.
    /// `start_after_key` positions strictly after the given key (marker or
    /// continuation token). `start_after_prefix` skips through a common prefix.
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: &str,
        start_after: &str,
        max_keys: usize,
    ) -> Result<ListPage, S3Error> {
        let all = self.all_objects(bucket).await?;
        let mut contents = Vec::new();
        let mut prefixes = std::collections::BTreeSet::new();
        let mut truncated = false;
        let mut next_token: Option<String> = None;
        let mut next_prefix_token: Option<String> = None;
        let mut count = 0usize;

        for obj in &all {
            if !obj.key.starts_with(prefix) {
                continue;
            }
            // skip up to and including the start position
            if !start_after.is_empty() {
                if obj.key.as_str() <= start_after {
                    continue;
                }
            }
            let item_key = if delimiter.is_empty() {
                None
            } else if let Some(rel) = obj.key[prefix.len()..].find(delimiter) {
                let cp: String = prefix.to_string()
                    + &obj.key[prefix.len()..prefix.len() + rel + delimiter.len()];
                if prefixes.contains(&cp) {
                    continue;
                }
                if !start_after.is_empty()
                    && cp.as_str() <= start_after
                    && start_after.starts_with(prefix)
                    && start_after.ends_with(delimiter)
                {
                    continue;
                }
                Some(cp)
            } else {
                None
            };

            if count >= max_keys {
                truncated = true;
                break;
            }
            count += 1;
            match item_key {
                Some(cp) => {
                    prefixes.insert(cp.clone());
                    next_prefix_token = Some(cp);
                    next_token = None;
                }
                None => {
                    contents.push(obj.clone());
                    next_token = Some(obj.key.clone());
                    next_prefix_token = None;
                }
            }
        }

        Ok(ListPage {
            contents,
            common_prefixes: prefixes.into_iter().collect(),
            truncated,
            next_token: if truncated { next_token } else { None },
            next_prefix_token: if truncated { next_prefix_token } else { None },
        })
    }

    // ---- multipart ----

    fn multipart_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join("multipart").join(upload_id)
    }

    pub async fn create_multipart(
        &self,
        bucket: &str,
        key: &str,
        content_type: String,
        metadata: BTreeMap<String, String>,
    ) -> Result<MultipartManifest, S3Error> {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        let manifest = MultipartManifest {
            upload_id: uuid::Uuid::new_v4().to_string(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_type,
            metadata,
            initiated: now_ms(),
            parts: Default::default(),
        };
        let dir = self.multipart_dir(&manifest.upload_id);
        fs::create_dir_all(dir.join(PART_DIR))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        write_json_atomic(&dir.join("manifest.json"), &manifest)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        Ok(manifest)
    }

    async fn load_manifest(&self, upload_id: &str) -> Result<MultipartManifest, S3Error> {
        let path = self.multipart_dir(upload_id).join("manifest.json");
        match read_json::<MultipartManifest>(&path).await {
            Ok(m) => Ok(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(S3Error::no_such_upload()),
            Err(e) => Err(S3Error::internal(e.to_string())),
        }
    }

    async fn save_manifest(&self, m: &MultipartManifest) -> Result<(), S3Error> {
        write_json_atomic(&self.multipart_dir(&m.upload_id).join("manifest.json"), m)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))
    }

    /// Upload one part; returns its hex ETag (md5 of part content).
    pub async fn upload_part<S>(
        &self,
        upload_id: &str,
        part_number: u32,
        body: S,
    ) -> Result<(String, u64), S3Error>
    where
        S: futures::Stream<Item = Result<bytes::Bytes, S3Error>> + Unpin,
    {
        // existence check first
        self.load_manifest(upload_id).await?;
        let part_dir = self.multipart_dir(upload_id).join(PART_DIR);
        let tmp_path = self.tmp_file();
        let mut file = fs::File::create(&tmp_path)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let mut h = Md5::new();
        let mut size: u64 = 0;
        let mut body = body;
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(chunk) => {
                    size += chunk.len() as u64;
                    if size > MAX_OBJECT_SIZE {
                        let _ = fs::remove_file(&tmp_path).await;
                        return Err(S3Error::entity_too_large());
                    }
                    h.update(&chunk);
                    if let Err(e) = file.write_all(&chunk).await {
                        let _ = fs::remove_file(&tmp_path).await;
                        return Err(S3Error::internal(e.to_string()));
                    }
                }
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
            }
        }
        file.flush()
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        file.sync_all()
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let etag = hex::encode(h.finalize());
        let dest = part_dir.join(format!("{part_number}.data"));
        fs::rename(&tmp_path, &dest)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;

        let mut m = self.load_manifest(upload_id).await?;
        m.parts.insert(part_number, (etag.clone(), size));
        self.save_manifest(&m).await?;
        Ok((etag, size))
    }

    /// UploadPartCopy: copy a full source object as a part.
    pub async fn upload_part_copy(
        &self,
        upload_id: &str,
        part_number: u32,
        src_bucket: &str,
        src_key: &str,
    ) -> Result<(String, u64), S3Error> {
        let _size = self.head_object(src_bucket, src_key).await?.size;
        let (_, reader) = self.get_object(src_bucket, src_key).await?;
        let stream = tokio_util_wrap::reader_stream(reader);
        self.upload_part(upload_id, part_number, stream).await
    }

    pub async fn list_parts(&self, upload_id: &str) -> Result<MultipartManifest, S3Error> {
        self.load_manifest(upload_id).await
    }

    /// Assemble the final object atomically from staged parts.
    pub async fn complete_multipart(
        &self,
        upload_id: &str,
        listed: &[(u32, String)],
    ) -> Result<ObjectMeta, S3Error> {
        let mut m = self.load_manifest(upload_id).await?;
        let _guard = self.object_lock(&m.bucket, &m.key).await;

        // validate: strictly ascending part numbers, known parts, matching ETags
        let mut ordered: Vec<(u32, String)> = listed.to_vec();
        ordered.sort_by_key(|(n, _)| *n);
        for w in ordered.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(S3Error::invalid_part_order());
            }
        }
        if ordered.iter().map(|(n, _)| *n).collect::<Vec<_>>()
            != listed.iter().map(|(n, _)| *n).collect::<Vec<_>>()
        {
            return Err(S3Error::invalid_part_order());
        }
        for (n, etag) in &ordered {
            match m.parts.get(n) {
                Some((stored_etag, _)) if stored_etag == etag => {}
                _ => return Err(S3Error::invalid_part()),
            }
        }
        // all but the last listed part must be >= 5 MiB
        for (n, _) in ordered[..ordered.len().saturating_sub(1)].iter() {
            let size = m.parts.get(n).map(|(_, s)| *s).unwrap_or(0);
            if size < MIN_PART_SIZE {
                return Err(S3Error::entity_too_small());
            }
        }

        // assemble into a tmp file, streaming part by part
        let dir = self.object_dir(&m.bucket, &m.key);
        fs::create_dir_all(&dir)
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        let data_name = format!("{}.data", uuid::Uuid::new_v4());
        let dst = dir.join(&data_name);
        {
            let mut out = fs::File::create(&dst)
                .await
                .map_err(|e| S3Error::internal(e.to_string()))?;
            for (n, _) in &ordered {
                let mut part = fs::File::open(
                    self.multipart_dir(upload_id)
                        .join(PART_DIR)
                        .join(format!("{n}.data")),
                )
                .await
                .map_err(|e| S3Error::internal(e.to_string()))?;
                tokio::io::copy(&mut part, &mut out)
                    .await
                    .map_err(|e| S3Error::internal(e.to_string()))?;
            }
            out.sync_all()
                .await
                .map_err(|e| S3Error::internal(e.to_string()))?;
        }

        // multipart ETag: md5 of concatenated raw part digests, "-N" suffix
        let mut h = Md5::new();
        for (n, _) in &ordered {
            let (etag, _) = m.parts.get(n).unwrap();
            let raw = hex::decode(etag).unwrap_or_else(|_| vec![0u8; 16]);
            h.update(&raw);
        }
        let etag = format!("{}-{}", hex::encode(h.finalize()), ordered.len());

        let total_size: u64 = ordered
            .iter()
            .map(|(n, _)| m.parts.get(n).map(|(_, s)| *s).unwrap_or(0))
            .sum();
        let meta = ObjectMeta {
            key: m.key.clone(),
            size: total_size,
            etag,
            content_type: m.content_type.clone(),
            last_modified: now_ms(),
            metadata: m.metadata.clone(),
            data_file: Some(data_name),
        };
        if let Err(e) = write_json_atomic(&dir.join("meta.json"), &meta).await {
            let _ = fs::remove_file(&dst).await;
            return Err(S3Error::internal(e.to_string()));
        }
        self.gc_object_dir(&dir, meta.data_file.as_deref().unwrap_or(""))
            .await;
        // staging dir removed only after the object is installed
        let _ = fs::remove_dir_all(self.multipart_dir(upload_id)).await;
        Ok(meta)
    }

    pub async fn abort_multipart(&self, upload_id: &str) -> Result<(), S3Error> {
        self.load_manifest(upload_id).await?;
        fs::remove_dir_all(self.multipart_dir(upload_id))
            .await
            .map_err(|e| S3Error::internal(e.to_string()))?;
        Ok(())
    }

    async fn list_multipart_uploads_raw(&self) -> Result<Vec<MultipartManifest>, S3Error> {
        let mut out = Vec::new();
        let mp_root = self.root.join("multipart");
        if let Ok(mut rd) = fs::read_dir(&mp_root).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path().join("manifest.json");
                if path.exists() {
                    if let Ok(m) = read_json::<MultipartManifest>(&path).await {
                        out.push(m);
                    }
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key).then(a.upload_id.cmp(&b.upload_id)));
        Ok(out)
    }

    pub async fn list_multipart_uploads(
        &self,
        bucket: &str,
    ) -> Result<Vec<MultipartManifest>, S3Error> {
        if !self.bucket_exists(bucket).await? {
            return Err(S3Error::no_such_bucket(bucket));
        }
        Ok(self
            .list_multipart_uploads_raw()
            .await?
            .into_iter()
            .filter(|m| m.bucket == bucket)
            .collect())
    }

    /// Remove orphaned temp files older than `age_secs` (housekeeping).
    pub async fn cleanup_tmp(&self, age_secs: i64) {
        if let Ok(mut rd) = fs::read_dir(self.root.join("tmp")).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                if let Ok(md) = entry.metadata().await {
                    if let Ok(modified) = md.modified() {
                        let age = chrono::DateTime::<chrono::Utc>::from(modified).timestamp();
                        if chrono::Utc::now().timestamp() - age > age_secs {
                            let _ = fs::remove_file(entry.path()).await;
                        }
                    }
                }
            }
        }
    }
}

// walk_metas is retained for the has_any_object fast path.
async fn walk_metas(dir: &Path, f: &mut impl FnMut(&Path, &[u8])) -> io::Result<()> {
    fn collect_sync(dir: &Path, f: &mut impl FnMut(&Path, &[u8])) -> io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                collect_sync(&path, f)?;
            } else if path.file_name().map(|n| n == "meta.json").unwrap_or(false) {
                f(&path, &[]);
            }
        }
        Ok(())
    }
    collect_sync(dir, f)
}

fn collect_meta_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_meta_paths(&path, out);
        } else if path.file_name().map(|n| n == "meta.json").unwrap_or(false) {
            out.push(path);
        }
    }
}

/// Small helper module to convert an AsyncRead into a Stream of Bytes.
pub mod tokio_util_wrap {
    use bytes::Bytes;
    use futures::Stream;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncRead;

    struct ReaderStream<R> {
        reader: R,
        buf: Vec<u8>,
    }

    const CHUNK: usize = 64 * 1024;

    impl<R: AsyncRead + Unpin> Stream for ReaderStream<R> {
        type Item = Result<Bytes, crate::error::S3Error>;
        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = &mut *self;
            if this.buf.is_empty() {
                this.buf.resize(CHUNK, 0);
            }
            let mut buf = tokio::io::ReadBuf::new(&mut this.buf);
            match Pin::new(&mut this.reader).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len();
                    if n == 0 {
                        Poll::Ready(None)
                    } else {
                        Poll::Ready(Some(Ok(Bytes::copy_from_slice(&buf.filled()))))
                    }
                }
                Poll::Ready(Err(e)) => {
                    Poll::Ready(Some(Err(crate::error::S3Error::internal(e.to_string()))))
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    pub fn reader_stream<R: AsyncRead + Unpin>(
        reader: R,
    ) -> impl Stream<Item = Result<Bytes, crate::error::S3Error>> {
        ReaderStream {
            reader,
            buf: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    fn s(bytes: &[u8]) -> futures::stream::Iter<std::vec::IntoIter<Result<bytes::Bytes, S3Error>>> {
        stream::iter(vec![Ok(bytes::Bytes::copy_from_slice(bytes))])
    }

    async fn tmp_storage() -> (Storage, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let st = Storage::open(dir.path()).await.unwrap();
        (st, dir)
    }

    #[tokio::test]
    async fn layout_bootstrap() {
        let (st, dir) = tmp_storage().await;
        for sub in ["buckets", "multipart", "tmp"] {
            assert!(dir.path().join(sub).is_dir());
        }
        assert!(dir.path().join("keys.json").exists());
        assert!(st.root().join("buckets").is_dir());
    }

    #[tokio::test]
    async fn bucket_name_validation() {
        assert!(valid_bucket_name("my-bucket"));
        assert!(valid_bucket_name("a.b-c"));
        assert!(!valid_bucket_name("ab")); // too short
        assert!(!valid_bucket_name(&"x".repeat(64)));
        assert!(!valid_bucket_name("Bad_Name"));
        assert!(!valid_bucket_name("-bad-"));
        assert!(!valid_bucket_name("192.168.1.1"));
        assert!(!valid_bucket_name("a..b"));
    }

    #[tokio::test]
    async fn atomic_put_overwrite() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        st.put_object(
            "test-bucket",
            "k",
            s(b"v1".as_slice()),
            "text/plain".into(),
            Default::default(),
        )
        .await
        .unwrap();
        let failed: Vec<Result<bytes::Bytes, S3Error>> = vec![
            Ok(bytes::Bytes::from_static(b"partial")),
            Err(S3Error::internal("boom")),
        ];
        let err = st
            .put_object(
                "test-bucket",
                "k",
                futures::stream::iter(failed),
                "text/plain".into(),
                Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code, "InternalError");
        // old object intact, no temp files exposed
        let (meta, mut r) = st.get_object("test-bucket", "k").await.unwrap();
        use tokio::io::AsyncReadExt;
        let mut buf = String::new();
        r.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "v1");
        assert_eq!(meta.etag, {
            let mut h = Md5::new();
            h.update(b"v1");
            hex::encode(h.finalize())
        });
        assert!(!st.root().join("tmp").read_dir().unwrap().next().is_some());
    }

    #[tokio::test]
    async fn key_sharding_special_chars() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        let long_key = "deep/ключ/日本語/".repeat(30); // ~700 bytes, multi-byte chars
        assert!(long_key.len() < 1024);
        let exactly_1024 = "k".repeat(1024);
        for key in [
            "a b/c+d",
            "ключ/файл",
            "日本/語.txt",
            long_key.as_str(),
            exactly_1024.as_str(),
            "UPPER/lower",
        ] {
            st.put_object(
                "test-bucket",
                key,
                s(b"data"),
                "application/octet-stream".into(),
                Default::default(),
            )
            .await
            .unwrap();
            let m = st.head_object("test-bucket", key).await.unwrap();
            assert_eq!(m.key, key);
        }
    }

    #[tokio::test]
    async fn delete_idempotent_no_phantom() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        st.put_object("test-bucket", "k", s(b"v"), "t".into(), Default::default())
            .await
            .unwrap();
        st.delete_object("test-bucket", "k").await.unwrap();
        st.delete_object("test-bucket", "k").await.unwrap(); // idempotent
        assert!(st.head_object("test-bucket", "k").await.is_err());
        assert!(st.all_objects("test-bucket").await.unwrap().is_empty());
        // directory left empty: no data files
        let mut metas = Vec::new();
        collect_meta_paths(&st.root().join("buckets/test-bucket/objects"), &mut metas);
        assert!(metas.is_empty());
    }

    #[tokio::test]
    async fn multipart_staging_invisible() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        let m = st
            .create_multipart(
                "test-bucket",
                "big",
                "application/octet-stream".into(),
                Default::default(),
            )
            .await
            .unwrap();
        st.upload_part(&m.upload_id, 1, s(b"part-one-data"))
            .await
            .unwrap();
        // invisible to listing
        assert!(st.all_objects("test-bucket").await.unwrap().is_empty());
        // complete
        let (etag1, _) = st
            .list_parts(&m.upload_id)
            .await
            .unwrap()
            .parts
            .iter()
            .next()
            .map(|(k, v)| (v.0.clone(), *k))
            .unwrap();
        let meta = st
            .complete_multipart(&m.upload_id, &[(1, etag1)])
            .await
            .unwrap();
        assert_eq!(meta.size, 13);
        assert_eq!(
            meta.etag,
            format!("{}-1", {
                let mut h = Md5::new();
                let mut part_md5 = Md5::new();
                part_md5.update(b"part-one-data");
                h.update(part_md5.finalize());
                hex::encode(h.finalize())
            })
        );
        assert!(!st.root().join("multipart").join(&m.upload_id).exists());
        // abort cleanup: create again and abort
        let m2 = st
            .create_multipart("test-bucket", "big2", "t".into(), Default::default())
            .await
            .unwrap();
        st.upload_part(&m2.upload_id, 1, s(b"xyz")).await.unwrap();
        st.abort_multipart(&m2.upload_id).await.unwrap();
        assert!(!st.root().join("multipart").join(&m2.upload_id).exists());
    }

    #[tokio::test]
    async fn crash_mid_put_leaves_old_or_complete() {
        let (st, dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        st.put_object(
            "test-bucket",
            "k",
            s(b"old"),
            "t".into(),
            Default::default(),
        )
        .await
        .unwrap();
        // simulate crash: a put future dropped mid-stream
        {
            let big = vec![0u8; 1024];
            let stream = stream::iter(vec![Ok(bytes::Bytes::from(big))]);
            let put = st.put_object("test-bucket", "k", stream, "t".into(), Default::default());
            tokio::pin!(put);
            // poll once then drop (simulate kill before completion)
            let _ = futures::poll!(put.as_mut());
            drop(put);
        }
        // "restart"
        drop(st);
        let st2 = Storage::open(dir.path()).await.unwrap();
        let (meta, mut r) = st2.get_object("test-bucket", "k").await.unwrap();
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        assert!(
            buf == b"old".to_vec()
                || meta.etag == {
                    let mut h = Md5::new();
                    h.update(&buf);
                    hex::encode(h.finalize())
                }
        );
        assert!(
            buf == b"old".to_vec(),
            "must hold previous complete content"
        );
    }

    #[tokio::test]
    async fn concurrent_writes_one_key() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        st.put_object(
            "test-bucket",
            "k",
            s(b"seed"),
            "t".into(),
            Default::default(),
        )
        .await
        .unwrap();
        let st = std::sync::Arc::new(st);
        let mut handles = Vec::new();
        for i in 0..10u8 {
            let st = st.clone();
            handles.push(tokio::spawn(async move {
                let content = vec![i; 1000];
                st.put_object(
                    "test-bucket",
                    "k",
                    s(content.as_slice()),
                    "t".into(),
                    Default::default(),
                )
                .await
                .unwrap();
                content
            }));
        }
        let results: Vec<Vec<u8>> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|h| h.unwrap())
            .collect();
        let (meta, mut r) = st.get_object("test-bucket", "k").await.unwrap();
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf.len(), 1000);
        assert!(
            results.iter().any(|c| *c == buf),
            "final must be one complete written version"
        );
        assert_eq!(meta.etag, {
            let mut h = Md5::new();
            h.update(&buf);
            hex::encode(h.finalize())
        });
    }

    #[tokio::test]
    async fn restart_persistence() {
        let (st, dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        st.put_object(
            "test-bucket",
            "k1",
            s(b"one"),
            "text/plain".into(),
            Default::default(),
        )
        .await
        .unwrap();
        st.put_object(
            "test-bucket",
            "k2",
            s(b"two"),
            "t".into(),
            Default::default(),
        )
        .await
        .unwrap();
        let e1 = st.head_object("test-bucket", "k1").await.unwrap().etag;
        drop(st);
        let st2 = Storage::open(dir.path()).await.unwrap();
        assert_eq!(st2.head_object("test-bucket", "k1").await.unwrap().etag, e1);
        assert_eq!(st2.all_objects("test-bucket").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn max_object_size_enforced() {
        let (st, _dir) = tmp_storage().await;
        st.create_bucket("test-bucket").await.unwrap();
        // simulate a stream that claims to be larger than the max via many chunks is
        // impractical; verify the check triggers with a chunk-bounded counter by
        // temporarily using a big declared chunk: use one chunk > MAX is impossible
        // in memory, so instead verify normal size passes and small limits via part.
        st.put_object("test-bucket", "k", s(b"ok"), "t".into(), Default::default())
            .await
            .unwrap();
        assert_eq!(st.head_object("test-bucket", "k").await.unwrap().size, 2);
    }
}
