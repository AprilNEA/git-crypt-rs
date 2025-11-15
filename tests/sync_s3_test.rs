#![cfg(feature = "sync-s3")]

use git_crypt::sync::maybe_sync_age_key;
use s3::{
    bucket::Bucket, bucket_ops::BucketConfiguration, creds::Credentials, error::S3Error,
    region::Region,
};
use std::{fs, net::TcpStream, path::Path, process::Command, thread, time::Duration};
use tempfile::TempDir;

const DOCKER_COMPOSE: &str = "docker";
const SERVICE_NAME: &str = "minio";
const ENDPOINT: &str = "http://localhost:9000";
const ACCESS_KEY: &str = "minioadmin";
const SECRET_KEY: &str = "minioadmin";

#[test]
fn syncs_age_key_to_minio() {
    if std::env::var("SYNC_S3_TEST").is_err() {
        eprintln!("SYNC_S3_TEST not set; skipping sync_s3 integration test");
        return;
    }

    run_docker_compose(["compose", "up", "-d", SERVICE_NAME]);
    wait_for_port(9000, Duration::from_secs(30)).expect("MinIO did not become ready in time");

    let temp_repo = TempDir::new().unwrap();
    fs::create_dir(temp_repo.path().join(".git")).unwrap();
    let age_dir = temp_repo
        .path()
        .join(".git")
        .join("git-crypt")
        .join("keys")
        .join("age");
    fs::create_dir_all(&age_dir).unwrap();
    let age_file = age_dir.join("alice.age");
    let contents = b"test-age-data";
    fs::write(&age_file, contents).unwrap();

    let bucket_name = format!("git-crypt-test-{}", nanoid::nanoid!(8));
    ensure_bucket(&bucket_name);

    write_config(
        temp_repo.path(),
        r#"
            [sync_s3]
            enabled = true
            bucket = "{bucket}"
            scope = "team-alpha"
            repo = "demo-repo"
            endpoint = "{endpoint}"
            access_key = "{access}"
            secret_key = "{secret}"
            path_style = true
        "#,
        &[
            ("{bucket}", bucket_name.as_str()),
            ("{endpoint}", ENDPOINT),
            ("{access}", ACCESS_KEY),
            ("{secret}", SECRET_KEY),
        ],
    );

    maybe_sync_age_key(temp_repo.path().join(".git").as_path(), &age_file, "alice")
        .expect("sync should succeed");

    let bucket = build_bucket(&bucket_name).unwrap();
    let remote_path = "team-alpha/demo-repo/keys/age/alice.age";
    let response = bucket
        .get_object_blocking(remote_path)
        .expect("object should exist");
    assert_eq!(response.bytes().as_ref(), contents);

    cleanup_bucket(&bucket, remote_path);
    run_docker_compose(["compose", "down", "-v"]);
}

fn run_docker_compose<I, S>(args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let status = Command::new(DOCKER_COMPOSE).args(args).status();
    match status {
        Ok(status) if status.success() => {}
        Ok(_) | Err(_) => {
            panic!("Failed to run docker compose; ensure Docker is installed and accessible");
        }
    }
}

fn wait_for_port(port: u16, timeout: Duration) -> std::io::Result<()> {
    let start = std::time::Instant::now();
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(_) => return Ok(()),
            Err(_err) if start.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

fn ensure_bucket(name: &str) {
    let region = Region::Custom {
        region: "us-east-1".into(),
        endpoint: ENDPOINT.into(),
    };
    let credentials =
        Credentials::new(Some(ACCESS_KEY), Some(SECRET_KEY), None, None, None).unwrap();

    let _ = Bucket::create_with_path_style_blocking(
        name,
        region.clone(),
        credentials.clone(),
        BucketConfiguration::default(),
    )
    .expect("Failed to create bucket");
}

fn build_bucket(name: &str) -> Result<Bucket, S3Error> {
    let region = Region::Custom {
        region: "us-east-1".into(),
        endpoint: ENDPOINT.into(),
    };
    let credentials =
        Credentials::new(Some(ACCESS_KEY), Some(SECRET_KEY), None, None, None).unwrap();

    Bucket::new(name, region, credentials).map(|b| *b.with_path_style())
}

fn cleanup_bucket(bucket: &Bucket, remote_path: &str) {
    let _ = bucket.delete_object_blocking(remote_path);
    // Note: delete_bucket_blocking is not available in rust-s3 0.36
    // The bucket will be cleaned up by docker compose down -v
}

fn write_config(repo: &Path, template: &str, replacements: &[(&str, &str)]) {
    let mut content = template.to_string();
    for (needle, value) in replacements {
        content = content.replace(needle, value);
    }
    fs::write(repo.join(".git-crypt.toml"), content).unwrap();
}
