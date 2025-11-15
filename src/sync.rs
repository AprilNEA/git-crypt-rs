use std::path::Path;

#[cfg(not(feature = "sync-s3"))]
use crate::error::Result;

#[cfg(feature = "sync-s3")]
mod s3sync {
    use super::*;
    use crate::error::{GitCryptError, Result};
    use config::{Config, File, FileFormat};
    use s3::{bucket::Bucket, creds::Credentials, region::Region};
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;

    const CONFIG_FILE: &str = ".git-crypt.toml";
    const ENV_PREFIX: &str = "GIT_CRYPT_SYNC_S3_";

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct SyncFile {
        #[serde(default)]
        sync_s3: Option<SyncS3Config>,
    }

    #[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
    pub(crate) struct SyncS3Config {
        #[serde(default = "default_enabled")]
        pub(crate) enabled: bool,
        #[serde(default)]
        pub(crate) bucket: String,
        #[serde(default)]
        pub(crate) scope: String,
        pub(crate) repo: Option<String>,
        pub(crate) region: Option<String>,
        pub(crate) endpoint: Option<String>,
        pub(crate) access_key: Option<String>,
        pub(crate) secret_key: Option<String>,
        #[serde(default)]
        pub(crate) path_style: bool,
    }

    fn default_enabled() -> bool {
        true
    }

    pub fn maybe_sync_age_key(git_dir: &Path, age_file: &Path, alias: &str) -> Result<()> {
        let repo_root = repo_root_from_git_dir(git_dir);
        let Some(cfg) = load_config(&repo_root)? else {
            return Ok(());
        };
        if !cfg.enabled {
            return Ok(());
        }

        let repo_name = cfg.resolve_repo_name(&repo_root)?;
        let key_bytes = fs::read(age_file)?;
        cfg.upload(&repo_name, alias, &key_bytes)?;
        Ok(())
    }

    pub(crate) fn load_config(repo_root: &Path) -> Result<Option<SyncS3Config>> {
        use std::env;

        let config_path = repo_root.join(CONFIG_FILE);

        // Load from file using config crate
        let mut cfg = if config_path.exists() {
            let file_cfg = Config::builder()
                .add_source(File::new(
                    config_path.to_str().ok_or_else(|| {
                        GitCryptError::Other("Invalid config path".into())
                    })?,
                    FileFormat::Toml,
                ))
                .build()
                .map_err(|err| {
                    GitCryptError::Other(format!("Failed to load config file: {err}"))
                })?;

            file_cfg
                .get::<SyncS3Config>("sync_s3")
                .ok()
        } else {
            None
        };

        // Apply environment variable overrides manually
        let env_enabled = env::var(format!("{ENV_PREFIX}ENABLED"))
            .ok()
            .and_then(|v| v.parse().ok());
        let env_bucket = env::var(format!("{ENV_PREFIX}BUCKET")).ok();
        let env_scope = env::var(format!("{ENV_PREFIX}SCOPE")).ok();
        let env_repo = env::var(format!("{ENV_PREFIX}REPO")).ok();
        let env_region = env::var(format!("{ENV_PREFIX}REGION")).ok();
        let env_endpoint = env::var(format!("{ENV_PREFIX}ENDPOINT")).ok();
        let env_access_key = env::var(format!("{ENV_PREFIX}ACCESS_KEY")).ok();
        let env_secret_key = env::var(format!("{ENV_PREFIX}SECRET_KEY")).ok();
        let env_path_style = env::var(format!("{ENV_PREFIX}PATH_STYLE"))
            .ok()
            .and_then(|v| v.parse().ok());

        // If we have a file config, apply env overrides
        if let Some(ref mut c) = cfg {
            if let Some(enabled) = env_enabled {
                c.enabled = enabled;
            }
            if let Some(bucket) = env_bucket {
                c.bucket = bucket;
            }
            if let Some(scope) = env_scope {
                c.scope = scope;
            }
            if let Some(repo) = env_repo {
                c.repo = Some(repo);
            }
            if let Some(region) = env_region {
                c.region = Some(region);
            }
            if let Some(endpoint) = env_endpoint {
                c.endpoint = Some(endpoint);
            }
            if let Some(access_key) = env_access_key {
                c.access_key = Some(access_key);
            }
            if let Some(secret_key) = env_secret_key {
                c.secret_key = Some(secret_key);
            }
            if let Some(path_style) = env_path_style {
                c.path_style = path_style;
            }
        } else if env_bucket.is_some() && env_scope.is_some() {
            // Create config from environment variables only
            cfg = Some(SyncS3Config {
                enabled: env_enabled.unwrap_or(true),
                bucket: env_bucket.unwrap(),
                scope: env_scope.unwrap(),
                repo: env_repo,
                region: env_region,
                endpoint: env_endpoint,
                access_key: env_access_key,
                secret_key: env_secret_key,
                path_style: env_path_style.unwrap_or(false),
            });
        }

        Ok(cfg)
    }

    fn repo_root_from_git_dir(git_dir: &Path) -> PathBuf {
        if git_dir.ends_with(".git") {
            git_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| git_dir.to_path_buf())
        } else {
            git_dir.to_path_buf()
        }
    }

    impl SyncS3Config {
        pub(crate) fn resolve_repo_name(&self, repo_root: &Path) -> Result<String> {
            if let Some(name) = &self.repo {
                return Ok(name.clone());
            }
            repo_root
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .ok_or_else(|| GitCryptError::Other("Could not determine repository name".into()))
        }

        fn region(&self) -> Result<Region> {
            match (&self.endpoint, self.region.as_deref()) {
                (Some(endpoint), Some(region_name)) => Ok(Region::Custom {
                    region: region_name.to_string(),
                    endpoint: endpoint.to_string(),
                }),
                (Some(endpoint), None) => Ok(Region::Custom {
                    region: "custom".into(),
                    endpoint: endpoint.to_string(),
                }),
                (None, Some(region)) => region
                    .parse()
                    .map_err(|_| GitCryptError::Other(format!("Invalid region: {region}"))),
                (None, None) => Ok(Region::UsEast1),
            }
        }

        fn credentials(&self) -> Result<Credentials> {
            Credentials::new(
                self.access_key.as_deref(),
                self.secret_key.as_deref(),
                None,
                None,
                None,
            )
            .map_err(|err| GitCryptError::Other(format!("S3 credentials error: {err}")))
        }

        fn bucket(&self) -> Result<Bucket> {
            let region = self.region()?;
            let credentials = self.credentials()?;
            let bucket = Bucket::new(self.bucket.as_str(), region, credentials)
                .map_err(|err| GitCryptError::Other(format!("S3 bucket error: {err}")))?;
            if self.path_style {
                Ok(*bucket.with_path_style())
            } else {
                Ok(*bucket)
            }
        }

        fn remote_path(&self, repo: &str, alias: &str) -> String {
            format!("{}/{}/keys/age/{}.age", self.scope, repo, alias)
        }

        fn upload(&self, repo: &str, alias: &str, bytes: &[u8]) -> Result<()> {
            let remote_path = self.remote_path(repo, alias);
            let bucket = self.bucket()?;
            bucket
                .put_object_blocking(remote_path.as_str(), bytes)
                .map_err(|err| GitCryptError::Other(format!("Failed to upload to S3: {err}")))?;
            println!("Uploaded age key to s3://{}/{remote_path}", self.bucket);
            Ok(())
        }

    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile::TempDir;

        #[test]
        #[serial_test::serial]
        fn load_config_none_when_missing() {
            use std::env;
            // Clear any env vars that might interfere
            let vars_to_clear = [
                format!("{ENV_PREFIX}BUCKET"),
                format!("{ENV_PREFIX}SCOPE"),
            ];
            for var in &vars_to_clear {
                env::remove_var(var);
            }

            let temp = TempDir::new().unwrap();
            assert!(load_config(temp.path()).unwrap().is_none());
        }

        #[test]
        fn load_config_parses_all_fields() {
            let temp = TempDir::new().unwrap();
            std::fs::write(
                temp.path().join(".git-crypt.toml"),
                r#"
                    [sync_s3]
                    enabled = true
                    bucket = "git-crypt"
                    scope = "team"
                    repo = "demo"
                    region = "us-west-2"
                    endpoint = "http://localhost:9000"
                    access_key = "minio"
                    secret_key = "secret"
                    path_style = true
                "#,
            )
            .unwrap();

            let cfg = load_config(temp.path()).unwrap().unwrap();
            assert!(cfg.enabled);
            assert_eq!(cfg.bucket, "git-crypt");
            assert_eq!(cfg.scope, "team");
            assert_eq!(cfg.repo.as_deref(), Some("demo"));
            assert_eq!(cfg.region.as_deref(), Some("us-west-2"));
            assert_eq!(cfg.endpoint.as_deref(), Some("http://localhost:9000"));
            assert_eq!(cfg.access_key.as_deref(), Some("minio"));
            assert_eq!(cfg.secret_key.as_deref(), Some("secret"));
            assert!(cfg.path_style);
            assert_eq!(
                cfg.remote_path("demo", "alice"),
                "team/demo/keys/age/alice.age"
            );
        }

        #[test]
        #[serial_test::serial]
        fn repo_name_defaults_to_dir_name() {
            use std::env;
            // Clear any env vars that might interfere
            env::remove_var(&format!("{ENV_PREFIX}REPO"));

            let temp = TempDir::new().unwrap();
            std::fs::write(
                temp.path().join(".git-crypt.toml"),
                r#"
                    [sync_s3]
                    bucket = "git-crypt"
                    scope = "team"
                "#,
            )
            .unwrap();
            let cfg = load_config(temp.path()).unwrap().unwrap();
            assert!(cfg.repo.is_none());
            let repo_name = cfg.resolve_repo_name(temp.path()).unwrap();
            // The repo name should be the directory name
            let expected_name = temp.path().file_name().unwrap().to_string_lossy();
            assert_eq!(repo_name, expected_name);
        }

        #[test]
        #[serial_test::serial]
        fn env_only_config_is_loaded() {
            use std::env;

            // Set up test environment variables
            // Note: config crate with separator "_" will convert GIT_CRYPT_SYNC_S3_BUCKET
            // to nested structure sync_s3.bucket
            let test_vars = [
                ("GIT_CRYPT_SYNC_S3_BUCKET", "git-crypt"),
                ("GIT_CRYPT_SYNC_S3_SCOPE", "team"),
                ("GIT_CRYPT_SYNC_S3_REPO", "demo"),
                ("GIT_CRYPT_SYNC_S3_ENABLED", "true"),
                ("GIT_CRYPT_SYNC_S3_PATH_STYLE", "true"),
            ];

            // Set environment variables
            for (key, value) in &test_vars {
                env::set_var(key, value);
            }

            let temp = TempDir::new().unwrap();
            let cfg = load_config(temp.path()).unwrap().unwrap();

            assert_eq!(cfg.bucket, "git-crypt");
            assert_eq!(cfg.scope, "team");
            assert_eq!(cfg.repo.as_deref(), Some("demo"));
            assert!(cfg.enabled);
            assert!(cfg.path_style);

            // Clean up environment variables
            for (key, _) in &test_vars {
                env::remove_var(key);
            }
        }
    }
}

#[cfg(not(feature = "sync-s3"))]
pub fn maybe_sync_age_key(_git_dir: &Path, _age_file: &Path, _alias: &str) -> Result<()> {
    Ok(())
}

#[cfg(feature = "sync-s3")]
pub use s3sync::maybe_sync_age_key;
