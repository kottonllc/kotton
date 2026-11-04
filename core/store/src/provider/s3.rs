// SPDX-License-Identifier: AGPL-3.0-or-later
//! An S3-compatible bucket as a shelf.
//!
//! The shelf is anything with put, get, list, and delete over opaque keys and
//! opaque bytes, and a bucket is exactly that. This is the client: SigV4
//! presigned requests (`rusty-s3`, sans-IO) sent with `reqwest`, path-style
//! addressing so MinIO, Garage, Ceph RGW and AWS itself all answer. Nothing
//! here interprets a byte; every object that reaches a shelf is a sealed pack
//! or a sealed superblock, and the bucket's operator can read none of them.
//!
//! One bucket holds many pools. [`S3Shelves`] is the landlord's configuration —
//! endpoint, bucket, credentials, an optional root prefix — and hands each
//! pool's mount an [`S3Shelf`] under `<root><user_id>/<mount>/`. The pool name
//! is the same one the on-disk layout already uses (`users/<id>/`), so the
//! bucket learns nothing the directory did not.
//!
//! `list` matches the local shelf's contract: one level, directories reported
//! as prefixes with `is_dir`, keys returned as the caller's logical paths.

use async_trait::async_trait;
use bytes::Bytes;
use kotton_sys::store::{
    ObjectMetadata, ObjectStorage, ObjectStorageError, ObjectStorageResult, SealedObjectAccess,
    Shelves, SyncableStore,
};
use rusty_s3::actions::{
    DeleteObject, GetObject, HeadObject, ListObjectsV2, PutObject, S3Action as _,
};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long a signed request stays valid: long enough for a slow put of a
/// large pack, short enough that a leaked URL is worth little.
const SIGN_FOR: Duration = Duration::from_secs(300);

/// The landlord's bucket, ready to hand out a shelf per pool.
#[derive(Clone)]
pub struct S3Shelves {
    client: reqwest::Client,
    bucket: Arc<Bucket>,
    credentials: Arc<Credentials>,
    /// Empty, or ends in `/`.
    root: String,
}

impl S3Shelves {
    /// `endpoint` is the service URL (`http://minio:9000`,
    /// `https://s3.eu-west-1.amazonaws.com`); `prefix` is an optional key
    /// prefix under which every pool of this vault lives.
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        credentials: Credentials,
        prefix: Option<&str>,
    ) -> anyhow::Result<Self> {
        let endpoint = endpoint
            .parse()
            .map_err(|e| anyhow::anyhow!("s3 endpoint {endpoint:?}: {e}"))?;
        let bucket = Bucket::new(
            endpoint,
            UrlStyle::Path,
            bucket.to_string(),
            region.to_string(),
        )
        .map_err(|e| anyhow::anyhow!("s3 bucket {bucket:?}: {e}"))?;
        Ok(Self {
            client: reqwest::Client::new(),
            bucket: Arc::new(bucket),
            credentials: Arc::new(credentials),
            root: normalise_prefix(prefix.unwrap_or("")),
        })
    }

    /// A shelf rooted at `prefix` in this bucket, for whatever wants one
    /// outside a pool (tests, a landlord's tooling).
    pub fn shelf(&self, prefix: &str) -> S3Shelf {
        S3Shelf {
            client: self.client.clone(),
            bucket: Arc::clone(&self.bucket),
            credentials: Arc::clone(&self.credentials),
            prefix: format!("{}{}", self.root, normalise_prefix(prefix)),
        }
    }
}

impl Shelves for S3Shelves {
    fn open(&self, user_id: &str, mount: &str, _path: &Path) -> Arc<dyn SyncableStore> {
        Arc::new(self.shelf(&format!("{user_id}/{mount}")))
    }
}

/// `a//b/` and `/a/b` both become `a/b/`; empty stays empty.
fn normalise_prefix(prefix: &str) -> String {
    let joined = prefix
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        String::new()
    } else {
        format!("{joined}/")
    }
}

/// One shelf: a key prefix in a bucket.
#[derive(Clone)]
pub struct S3Shelf {
    client: reqwest::Client,
    bucket: Arc<Bucket>,
    credentials: Arc<Credentials>,
    /// Empty, or ends in `/`.
    prefix: String,
}

impl S3Shelf {
    /// The bucket key for a logical path: the prefix, then the path's normal
    /// components joined by `/`. Host-independent, like the local shelf's
    /// segment encoding, without needing one — a bucket key takes any segment.
    ///
    /// A `.`, `..` or root component is dropped, not refused, so a key that
    /// carries one lands under another name: `_pack/../x` would be written as
    /// `_pack/x`, which a listing then reads as a pack this store never
    /// named. No key the store builds carries one: a sync pass admits its
    /// listings ([`crate::StorageKey`], kotton #265), and a pack id is
    /// admitted where the manifest or superblock naming it is decoded
    /// ([`crate::packed::PackId`], kotton #273), so a manifest naming
    /// `_pack/../x` is refused before any shelf is addressed
    /// (`packed`'s test
    /// `a_manifest_naming_a_pack_outside_the_grammar_is_refused_and_nothing_is_fetched_or_written`,
    /// on a shelf that takes a key's characters as they are, as a bucket does).
    fn key(&self, path: &Path) -> String {
        let rel = path
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("/");
        format!("{}{}", self.prefix, rel)
    }

    /// The logical path for a bucket key under this shelf.
    fn logical(&self, key: &str) -> String {
        key.strip_prefix(&self.prefix)
            .unwrap_or(key)
            .trim_end_matches('/')
            .to_string()
    }

    async fn send(
        &self,
        req: reqwest::RequestBuilder,
        key: &str,
    ) -> ObjectStorageResult<reqwest::Response> {
        let req = req
            .build()
            .map_err(|e| ObjectStorageError::IoError(format!("{key}: {e}")))?;
        let head = req.method() == reqwest::Method::HEAD;
        let resp = self
            .client
            .execute(req)
            .await
            .map_err(|e| ObjectStorageError::IoError(format!("{key}: {e}")))?;
        match resp.status() {
            s if s.is_success() => Ok(resp),
            // **A 404 is absence only when its code says so** (kotton #412,
            // #419). A bucket that does not exist answers 404 too, with the
            // code `NoSuchBucket`, and read as `NotFound` it would say every
            // object is absent: a device reading a drive's absence as "not
            // held" may then delete what only that drive keeps. So the body's
            // code is parsed: `NoSuchKey` is absence; any other code, or a
            // body that is unreadable, is a refusal. A `HEAD` carries no body
            // and cannot say, so only a `HEAD`'s empty 404 stays `NotFound`
            // (`metadata`, and `delete`'s look first); the reads the store
            // decides absence by, `get` and `list`, are `GET`s, and say. The
            // method is passed in, never inferred from an empty body.
            reqwest::StatusCode::NOT_FOUND => {
                let body = resp.text().await.unwrap_or_default();
                Err(not_found(&body, key, self.bucket.name(), head))
            }
            reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::UNAUTHORIZED => Err(
                ObjectStorageError::PermissionDenied(format!("{key}: {}", resp.status())),
            ),
            s => {
                let body = resp.text().await.unwrap_or_default();
                Err(ObjectStorageError::BackendError(format!(
                    "{key}: {s}: {}",
                    body.chars().take(300).collect::<String>()
                )))
            }
        }
    }

    async fn head(&self, key: &str) -> ObjectStorageResult<ObjectMetadata> {
        let url = HeadObject::new(&self.bucket, Some(&self.credentials), key).sign(SIGN_FOR);
        let resp = self.send(self.client.head(url), key).await?;
        let size = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let modified = resp
            .headers()
            .get(reqwest::header::LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                time::OffsetDateTime::parse(v, &time::format_description::well_known::Rfc2822)
                    .ok()
            })
            .map(|t| t.unix_timestamp().max(0) as u64);
        Ok(ObjectMetadata {
            key: self.logical(key),
            is_dir: false,
            size,
            modified,
        })
    }
}

#[async_trait]
impl ObjectStorage for S3Shelf {
    async fn get(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        let key = self.key(key);
        let url = GetObject::new(&self.bucket, Some(&self.credentials), &key).sign(SIGN_FOR);
        let resp = self.send(self.client.get(url), &key).await?;
        resp.bytes()
            .await
            .map_err(|e| ObjectStorageError::IoError(format!("{key}: {e}")))
    }

    async fn put(&self, key: &Path, data: &[u8]) -> ObjectStorageResult<()> {
        let key = self.key(key);
        let url = PutObject::new(&self.bucket, Some(&self.credentials), &key).sign(SIGN_FOR);
        self.send(self.client.put(url).body(data.to_vec()), &key)
            .await
            .map(|_| ())
    }

    /// A bucket deletes a missing key silently; the contract says `NotFound`,
    /// so the key is looked at first. Two round trips, and an honest answer.
    async fn delete(&self, key: &Path) -> ObjectStorageResult<()> {
        let key = self.key(key);
        self.head(&key).await?;
        let url = DeleteObject::new(&self.bucket, Some(&self.credentials), &key).sign(SIGN_FOR);
        self.send(self.client.delete(url), &key).await.map(|_| ())
    }

    async fn list(&self, prefix: &Path) -> ObjectStorageResult<Vec<ObjectMetadata>> {
        let under = self.key(prefix);
        let under = if under.is_empty() || under.ends_with('/') {
            under
        } else {
            format!("{under}/")
        };
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
            action.with_prefix(under.clone());
            action.with_delimiter("/");
            if let Some(t) = &token {
                action.with_continuation_token(t.clone());
            }
            let url = action.sign(SIGN_FOR);
            let resp = self.send(self.client.get(url), &under).await?;
            let body = resp
                .text()
                .await
                .map_err(|e| ObjectStorageError::IoError(format!("{under}: {e}")))?;
            let page = ListPage::parse(&body)
                .map_err(|e| ObjectStorageError::BackendError(format!("{under}: list: {e}")))?;
            for (key, size, modified) in page.contents {
                // A directory-marker object at the prefix itself is not a child.
                if key == under {
                    continue;
                }
                out.push(ObjectMetadata {
                    key: self.logical(&key),
                    is_dir: false,
                    size,
                    modified,
                });
            }
            for prefix in page.common_prefixes {
                out.push(ObjectMetadata {
                    key: self.logical(&prefix),
                    is_dir: true,
                    size: 0,
                    modified: None,
                });
            }
            match page.next_continuation_token {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        Ok(out)
    }

    async fn metadata(&self, key: &Path) -> ObjectStorageResult<ObjectMetadata> {
        self.head(&self.key(key)).await
    }

    fn backend_name(&self) -> &str {
        "s3"
    }
}

/// What a 404 answers, by the error code its body carries. `NotFound` only
/// when the code is `NoSuchKey`, or when the request was a `HEAD` and the body
/// is empty (a `HEAD` carries none). `NoSuchBucket` is a backend error naming
/// the bucket; any other code, or a body that does not parse as an error
/// document with a code, is a backend error naming the code or "an unreadable
/// 404". `head` is the request's method, not inferred from the body, so an
/// empty body on a `GET` refuses.
fn not_found(body: &str, key: &str, bucket: &str, head: bool) -> ObjectStorageError {
    if head && body.is_empty() {
        return ObjectStorageError::NotFound(key.to_string());
    }
    let code = roxmltree::Document::parse(body).ok().and_then(|doc| {
        let root = doc.root_element();
        if root.tag_name().name() != "Error" {
            return None;
        }
        root.children()
            .find(|c| c.is_element() && c.tag_name().name() == "Code")
            .and_then(|c| c.text())
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    });
    match code.as_deref() {
        Some("NoSuchKey") => ObjectStorageError::NotFound(key.to_string()),
        Some("NoSuchBucket") => {
            ObjectStorageError::BackendError(format!("{key}: the bucket '{bucket}' does not exist"))
        }
        Some(other) => ObjectStorageError::BackendError(format!(
            "{key}: a 404 from bucket '{bucket}' with code {other}, which is not absence"
        )),
        None => ObjectStorageError::BackendError(format!(
            "{key}: an unreadable 404 from bucket '{bucket}', which is not absence"
        )),
    }
}

/// One page of a `ListObjectsV2` reply: what the shelf needs of it and no
/// more. Read leniently — a server that omits `ETag` or `StorageClass` from a
/// listing (some do) still lists.
struct ListPage {
    /// `(key, size, modified)`
    contents: Vec<(String, u64, Option<u64>)>,
    common_prefixes: Vec<String>,
    next_continuation_token: Option<String>,
}

impl ListPage {
    fn parse(xml: &str) -> Result<Self, String> {
        let doc = roxmltree::Document::parse(xml).map_err(|e| e.to_string())?;
        let root = doc.root_element();
        let text = |node: roxmltree::Node, name: &str| -> Option<String> {
            node.children()
                .find(|c| c.is_element() && c.tag_name().name() == name)
                .and_then(|c| c.text())
                .map(str::to_string)
        };
        let mut contents = Vec::new();
        let mut common_prefixes = Vec::new();
        for node in root.children().filter(|n| n.is_element()) {
            match node.tag_name().name() {
                "Contents" => {
                    let Some(key) = text(node, "Key") else {
                        continue;
                    };
                    let size = text(node, "Size")
                        .and_then(|s| s.trim().parse().ok())
                        .unwrap_or(0);
                    let modified = text(node, "LastModified").and_then(|s| {
                        time::OffsetDateTime::parse(
                            s.trim(),
                            &time::format_description::well_known::Rfc3339,
                        )
                        .ok()
                        .map(|t| t.unix_timestamp().max(0) as u64)
                    });
                    contents.push((key, size, modified));
                }
                "CommonPrefixes" => {
                    if let Some(p) = text(node, "Prefix") {
                        common_prefixes.push(p);
                    }
                }
                _ => {}
            }
        }
        let truncated = text(root, "IsTruncated").is_some_and(|t| t.trim() == "true");
        let next_continuation_token = text(root, "NextContinuationToken").filter(|_| truncated);
        Ok(Self {
            contents,
            common_prefixes,
            next_continuation_token,
        })
    }
}

/// A bucket holds bytes as they are handed to it; the sealed path is the
/// plain one, as on the local shelf.
#[async_trait]
impl SealedObjectAccess for S3Shelf {
    async fn get_sealed(&self, key: &Path) -> ObjectStorageResult<Bytes> {
        self.get(key).await
    }

    async fn put_sealed(&self, key: &Path, blob: &[u8]) -> ObjectStorageResult<()> {
        self.put(key, blob).await
    }
}

#[cfg(test)]
mod tests {
    //! Against a real S3-compatible server, in this process: `s3s-fs` speaks
    //! the S3 wire (SigV4 checked, XML answered) over a directory. That the
    //! shelf's requests are accepted is the client's signing being right, not
    //! a mock agreeing with itself.

    use super::*;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as ConnBuilder;

    const ACCESS: &str = "landlord";
    const SECRET: &str = "a-secret-the-landlord-set";

    struct Server {
        endpoint: String,
        _root: tempfile::TempDir,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve(bucket: &str) -> Server {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(bucket)).unwrap();
        let fs = s3s_fs::FileSystem::new(root.path()).unwrap();
        let mut b = s3s::service::S3ServiceBuilder::new(fs);
        b.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS, SECRET));
        let service = b.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let http = ConnBuilder::new(TokioExecutor::new());
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let conn = http
                    .serve_connection(TokioIo::new(sock), service.clone())
                    .into_owned();
                tokio::spawn(async move {
                    let _ = conn.await;
                });
            }
        });
        Server {
            endpoint: format!("http://{addr}"),
            _root: root,
            task,
        }
    }

    fn shelves(server: &Server, bucket: &str, prefix: Option<&str>) -> S3Shelves {
        S3Shelves::new(
            &server.endpoint,
            bucket,
            "us-east-1",
            Credentials::new(ACCESS, SECRET),
            prefix,
        )
        .unwrap()
    }

    /// Put, get, metadata, list at one level with directories, delete, and the
    /// contract's `NotFound` — the same contract the local shelf keeps.
    #[tokio::test]
    async fn a_bucket_keeps_the_local_shelfs_contract() {
        let server = serve("kotton").await;
        let shelf = shelves(&server, "kotton", None).open("alice", "local", Path::new("/unused"));

        shelf.put(Path::new("packs/one.pack"), b"sealed one").await.unwrap();
        shelf.put(Path::new("packs/two.pack"), b"sealed two!").await.unwrap();
        shelf.put(Path::new("superblock"), b"sb").await.unwrap();

        assert_eq!(shelf.get(Path::new("packs/one.pack")).await.unwrap().as_ref(), b"sealed one");
        let meta = shelf.metadata(Path::new("packs/two.pack")).await.unwrap();
        assert_eq!(meta.size, 11);
        assert!(!meta.is_dir);
        assert_eq!(meta.key, "packs/two.pack");
        assert!(shelf.exists(Path::new("superblock")).await.unwrap());
        assert!(!shelf.exists(Path::new("nothing")).await.unwrap());

        let mut top = shelf.list(Path::new("")).await.unwrap();
        top.sort_by(|a, b| a.key.cmp(&b.key));
        let names: Vec<(String, bool)> = top.iter().map(|m| (m.key.clone(), m.is_dir)).collect();
        assert_eq!(
            names,
            vec![("packs".to_string(), true), ("superblock".to_string(), false)],
            "one level: a directory as a prefix, a file as a file"
        );
        let mut packs = shelf.list(Path::new("packs")).await.unwrap();
        packs.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(packs.len(), 2);
        assert_eq!(packs[0].key, "packs/one.pack");
        assert_eq!(packs[0].size, 10);
        assert!(packs[1].modified.is_some(), "a listing carries a time");

        shelf.delete(Path::new("packs/one.pack")).await.unwrap();
        assert!(matches!(
            shelf.get(Path::new("packs/one.pack")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert!(matches!(
            shelf.delete(Path::new("packs/one.pack")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert!(matches!(
            shelf.metadata(Path::new("packs/one.pack")).await,
            Err(ObjectStorageError::NotFound(_))
        ));
        assert!(shelf.list(Path::new("no/such/prefix")).await.unwrap().is_empty());
    }

    /// Two pools in one bucket do not see each other, and a root prefix sits
    /// above both — the landlord's namespace, invisible to the device.
    #[tokio::test]
    async fn pools_are_prefixes_and_do_not_meet() {
        let server = serve("kotton").await;
        let shelves = shelves(&server, "kotton", Some("vault-1"));
        let alice = shelves.open("alice", "local", Path::new("/unused"));
        let bob = shelves.open("bob", "local", Path::new("/unused"));
        alice.put(Path::new("pack"), b"a").await.unwrap();
        bob.put(Path::new("pack"), b"bb").await.unwrap();
        assert_eq!(alice.get(Path::new("pack")).await.unwrap().as_ref(), b"a");
        assert_eq!(bob.get(Path::new("pack")).await.unwrap().as_ref(), b"bb");
        assert_eq!(alice.list(Path::new("")).await.unwrap().len(), 1);

        // The landlord's prefix, seen whole: one directory per pool.
        let whole = shelves.shelf("");
        let mut pools: Vec<(String, bool)> = whole
            .list(Path::new(""))
            .await
            .unwrap()
            .into_iter()
            .map(|m| (m.key, m.is_dir))
            .collect();
        pools.sort();
        assert_eq!(pools, vec![("alice".to_string(), true), ("bob".to_string(), true)]);
    }

    /// **A bucket that does not exist is refused, not answered as absence**
    /// (kotton #412). A missing key in a bucket that is there stays
    /// `NotFound`, and a listing of a bucket that is not is a backend error
    /// naming it. The server here answers a `GET` of an object in a missing
    /// bucket `NoSuchKey` (`s3s-fs` looks for the file and not the bucket),
    /// so the `GET` half is held below on the body AWS sends.
    #[tokio::test]
    async fn a_missing_bucket_refuses_rather_than_answering_absence() {
        let server = serve("kotton").await;
        let present = shelves(&server, "kotton", None).open("alice", "local", Path::new("/unused"));
        assert!(matches!(present.get(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(matches!(present.get_sealed(Path::new("_pack/absent")).await, Err(ObjectStorageError::NotFound(_))));
        assert!(present.list(Path::new("no/such/prefix")).await.unwrap().is_empty());

        let gone = shelves(&server, "gone", None).open("alice", "local", Path::new("/unused"));
        match gone.list(Path::new("")).await {
            Err(ObjectStorageError::BackendError(m)) => assert!(m.contains("'gone' does not exist"), "{m}"),
            other => panic!("a bucket that does not exist answered {other:?}"),
        }
    }

    /// A 404 is absence only when its code says `NoSuchKey`, or when it is a
    /// `HEAD`'s and has no body. `NoSuchBucket`, any other code, a body that
    /// is not an error document, and an empty body on a `GET` all refuse. The
    /// bodies are the ones AWS sends.
    #[test]
    fn a_404_is_absence_only_when_it_is_the_keys() {
        let err = |code: &str| {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>{code}</Code><Message>m</Message></Error>"#
            )
        };
        let k = "alice/local/_pack/a";
        let refused = |r: ObjectStorageError, needle: &str| match r {
            ObjectStorageError::BackendError(m) => {
                assert!(m.contains(needle) && m.contains(k), "{m}")
            }
            other => panic!("expected a refusal naming {needle}, got {other:?}"),
        };
        // NoSuchKey: absence.
        assert!(matches!(not_found(&err("NoSuchKey"), k, "gone", false), ObjectStorageError::NotFound(x) if x == k));
        // NoSuchBucket: refusal naming the bucket.
        refused(not_found(&err("NoSuchBucket"), k, "gone", false), "'gone' does not exist");
        // An unknown code: refusal naming the code.
        refused(not_found(&err("SlowDown"), k, "gone", false), "SlowDown");
        // An unparseable body: refusal.
        refused(not_found("<html>not found", k, "gone", false), "an unreadable 404");
        // An empty body on a GET: refusal; on a HEAD: absence.
        refused(not_found("", k, "gone", false), "an unreadable 404");
        assert!(matches!(not_found("", k, "gone", true), ObjectStorageError::NotFound(_)));
    }

    /// The wrong secret is refused by the server, and the refusal is the
    /// contract's `PermissionDenied`, not a panic or a silent empty answer.
    #[tokio::test]
    async fn a_wrong_credential_is_permission_denied() {
        let server = serve("kotton").await;
        let shelves = S3Shelves::new(
            &server.endpoint,
            "kotton",
            "us-east-1",
            Credentials::new(ACCESS, "not-the-secret"),
            None,
        )
        .unwrap();
        let shelf = shelves.open("alice", "local", Path::new("/unused"));
        assert!(matches!(
            shelf.put(Path::new("pack"), b"x").await,
            Err(ObjectStorageError::PermissionDenied(_))
        ));
    }
}
