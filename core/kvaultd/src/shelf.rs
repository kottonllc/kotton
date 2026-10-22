// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which shelves this vault's pools rest on — the landlord's configuration
//! (RFC-0084 V5), read from the environment once at start.
//!
//! ```text
//! KVAULTD_SHELF=local                     the disk under KOTTON_BASE_DIR (default)
//! KVAULTD_SHELF=s3                        an S3-compatible bucket:
//!   KVAULTD_S3_ENDPOINT=http://minio:9000     the service URL
//!   KVAULTD_S3_BUCKET=kotton                  the bucket, which must exist
//!   KVAULTD_S3_REGION=us-east-1               (default us-east-1)
//!   KVAULTD_S3_PREFIX=                        optional key prefix for every pool
//!   KVAULTD_S3_ACCESS_KEY / KVAULTD_S3_SECRET_KEY
//!     or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
//! ```
//!
//! The person never sees any of this. Their device is told a number, and the
//! number is the same meter whichever shelf is beneath it.

use kotton_sys::store::Shelves;
use std::io;
use std::sync::Arc;

/// The disk: a directory per mount, through the host filesystem.
pub fn local() -> Arc<dyn Shelves> {
    Arc::new(kotton_store::LocalShelves(kotton_fs::OsFilesystem))
}

/// A bucket, from the `KVAULTD_S3_*` variables.
pub fn s3_from_env() -> io::Result<Arc<dyn Shelves>> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let need = |k: &str| var(k).ok_or_else(|| io::Error::other(format!("KVAULTD_SHELF=s3 needs {k}")));
    let endpoint = need("KVAULTD_S3_ENDPOINT")?;
    let bucket = need("KVAULTD_S3_BUCKET")?;
    let region = var("KVAULTD_S3_REGION").unwrap_or_else(|| "us-east-1".to_string());
    let prefix = var("KVAULTD_S3_PREFIX");
    let access = var("KVAULTD_S3_ACCESS_KEY").or_else(|| var("AWS_ACCESS_KEY_ID"));
    let secret = var("KVAULTD_S3_SECRET_KEY").or_else(|| var("AWS_SECRET_ACCESS_KEY"));
    let (access, secret) = match (access, secret) {
        (Some(a), Some(s)) => (a, s),
        _ => {
            return Err(io::Error::other(
                "KVAULTD_SHELF=s3 needs KVAULTD_S3_ACCESS_KEY and KVAULTD_S3_SECRET_KEY \
                 (or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)",
            ))
        }
    };
    let shelves = kotton_store::S3Shelves::new(
        &endpoint,
        &bucket,
        &region,
        rusty_s3::Credentials::new(access, secret),
        prefix.as_deref(),
    )
    .map_err(|e| io::Error::other(e.to_string()))?;
    tracing::info!(endpoint = %endpoint, bucket = %bucket, region = %region, "shelf: an S3-compatible bucket");
    Ok(Arc::new(shelves))
}

/// What `KVAULTD_SHELF` names; the disk when it names nothing.
pub fn from_env() -> io::Result<Arc<dyn Shelves>> {
    match std::env::var("KVAULTD_SHELF").as_deref().map(str::trim) {
        Ok("") | Ok("local") | Err(_) => Ok(local()),
        Ok("s3") => s3_from_env(),
        Ok(other) => Err(io::Error::other(format!(
            "KVAULTD_SHELF={other:?}: a shelf is `local` or `s3`"
        ))),
    }
}
