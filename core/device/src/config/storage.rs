// SPDX-License-Identifier: AGPL-3.0-or-later
//! Storage backend configuration

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageConfig {
    /// Local filesystem storage
    Local {
        /// Path to data directory
        path: PathBuf,
    },

    /// AWS S3 storage
    S3 {
        /// S3 bucket name
        bucket: String,

        /// AWS region
        region: String,

        /// Optional credentials (None = use environment/IAM)
        #[serde(skip_serializing_if = "Option::is_none")]
        credentials: Option<AwsCredentials>,
    },

    /// Azure Blob Storage
    Azure {
        /// Storage account name
        account: String,

        /// Container name
        container: String,

        /// Account key
        key: String,
    },
}

/// AWS credentials for S3 access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

impl StorageConfig {
    /// Validate storage configuration
    pub fn validate(&self) -> Result<(), String> {
        match self {
            StorageConfig::S3 {
                bucket,
                region,
                credentials: _,
            } => {
                if bucket.is_empty() {
                    return Err("S3 bucket name cannot be empty".to_string());
                }
                if region.is_empty() {
                    return Err("S3 region cannot be empty".to_string());
                }
            }
            StorageConfig::Azure {
                account,
                container,
                key,
            } => {
                if account.is_empty() {
                    return Err("Azure account name cannot be empty".to_string());
                }
                if container.is_empty() {
                    return Err("Azure container name cannot be empty".to_string());
                }
                if key.is_empty() {
                    return Err("Azure storage key cannot be empty".to_string());
                }
            }
            StorageConfig::Local { path: _ } => {
                // Path validation could be added here if needed
            }
        }

        Ok(())
    }
}
