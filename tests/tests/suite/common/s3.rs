// SPDX-License-Identifier: AGPL-3.0-or-later
//! An S3-compatible server in this process, for a vault to shelve on.
//!
//! `s3s-fs` speaks the S3 wire — SigV4 checked, XML answered — over a
//! directory, so a vault configured for a bucket is exercised against the
//! protocol a landlord's MinIO, Garage or AWS speaks, not against a mock. The
//! directory is inspectable: what the bucket holds is what the landlord holds.

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use std::path::PathBuf;

pub const ACCESS: &str = "landlord";
pub const SECRET: &str = "a-secret-the-landlord-set";

pub struct S3Server {
    pub endpoint: String,
    pub bucket: String,
    root: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for S3Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl S3Server {
    /// The directory the bucket is, on the landlord's disk.
    pub fn bucket_dir(&self) -> PathBuf {
        self.root.path().join(&self.bucket)
    }

    /// Every object key in the bucket, by walking the landlord's disk.
    pub fn keys(&self) -> Vec<String> {
        fn walk(dir: &std::path::Path, rel: &str, out: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                // s3s-fs keeps its own bookkeeping in dot-prefixed entries.
                if name.starts_with('.') {
                    continue;
                }
                let key = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
                if e.path().is_dir() {
                    walk(&e.path(), &key, out);
                } else {
                    out.push(key);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.bucket_dir(), "", &mut out);
        out.sort();
        out
    }

    /// The vault's `KVAULTD_S3_*` shelves, pointed at this server.
    pub fn shelves(&self, prefix: Option<&str>) -> std::sync::Arc<dyn kotton_sys::store::Shelves> {
        std::sync::Arc::new(
            kotton_store::S3Shelves::new(
                &self.endpoint,
                &self.bucket,
                "us-east-1",
                rusty_s3::Credentials::new(ACCESS, SECRET),
                prefix,
            )
            .expect("s3 shelves"),
        )
    }
}

pub async fn serve(bucket: &str) -> S3Server {
    let root = tempfile::tempdir().expect("bucket root");
    std::fs::create_dir_all(root.path().join(bucket)).unwrap();
    let fs = s3s_fs::FileSystem::new(root.path()).expect("s3s-fs");
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
    S3Server {
        endpoint: format!("http://{addr}"),
        bucket: bucket.to_string(),
        root,
        task,
    }
}
