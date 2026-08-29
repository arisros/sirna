//! Where the bytes actually live.
//!
//! Two implementations behind one trait. `FsStore` exists so the entire test
//! suite runs with no infrastructure at all; `S3Store` is what runs in
//! production, against the Garage cluster that already exists in the homelab.
//!
//! Neither knows what an envelope is. To a store, a blob is an opaque byte
//! string with a random name.

use std::future::Future;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// The `+ Send` bounds are load-bearing: axum requires handler futures to be
/// `Send`, and a bare `async fn` in a trait makes no such promise, so the
/// handlers would silently fail to satisfy `Handler` with an error that points
/// at the route rather than at the cause.
pub trait BlobStore: Send + Sync + 'static {
    fn put(&self, id: &str, bytes: Vec<u8>) -> impl Future<Output = Result<()>> + Send;
    fn get(&self, id: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn delete(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
    /// Cheap liveness probe for `/readyz`. A store that cannot be reached is a
    /// server that will fail every request, and that should surface as not
    /// ready rather than as a stream of 500s.
    fn health(&self) -> impl Future<Output = Result<()>> + Send;
}

/// Filesystem-backed store. Used by the tests and by `--store fs` for local
/// development, so neither needs S3 credentials or a running Garage.
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating blob directory {}", root.display()))?;
        Ok(Self { root })
    }

    fn path(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }
}

impl BlobStore for FsStore {
    async fn put(&self, id: &str, bytes: Vec<u8>) -> Result<()> {
        let path = self.path(id);
        tokio::fs::write(&path, bytes)
            .await
            .with_context(|| format!("writing {}", path.display()))
    }

    async fn get(&self, id: &str) -> Result<Vec<u8>> {
        let path = self.path(id);
        tokio::fs::read(&path)
            .await
            .with_context(|| format!("reading {}", path.display()))
    }

    async fn delete(&self, id: &str) -> Result<()> {
        match tokio::fs::remove_file(self.path(id)).await {
            Ok(()) => Ok(()),
            // Already gone is the desired end state, not a failure. The reaper
            // runs repeatedly and must be safe to re-run.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn health(&self) -> Result<()> {
        tokio::fs::metadata(&self.root)
            .await
            .map(|_| ())
            .context("blob directory is not reachable")
    }
}

/// Garage, or any S3-compatible endpoint.
pub struct S3Store {
    bucket: Box<s3::Bucket>,
}

impl S3Store {
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let creds =
            s3::creds::Credentials::new(Some(access_key), Some(secret_key), None, None, None)
                .context("building S3 credentials")?;

        let region = s3::Region::Custom {
            region: region.to_string(),
            endpoint: endpoint.to_string(),
        };

        // Path-style is mandatory here. Garage's configured `root_domain` is
        // `.s3.garage.local`, which has no DNS behind it, so the SDK default of
        // virtual-host addressing would fail to resolve.
        let bucket = s3::Bucket::new(bucket, region, creds)
            .context("opening S3 bucket")?
            .with_path_style();

        Ok(Self { bucket })
    }
}

impl BlobStore for S3Store {
    async fn put(&self, id: &str, bytes: Vec<u8>) -> Result<()> {
        let resp = self
            .bucket
            .put_object(format!("/{id}"), &bytes)
            .await
            .context("S3 put failed")?;
        anyhow::ensure!(
            resp.status_code() < 300,
            "S3 put returned {}",
            resp.status_code()
        );
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Vec<u8>> {
        let resp = self
            .bucket
            .get_object(format!("/{id}"))
            .await
            .context("S3 get failed")?;
        anyhow::ensure!(
            resp.status_code() < 300,
            "S3 get returned {}",
            resp.status_code()
        );
        Ok(resp.to_vec())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let resp = self
            .bucket
            .delete_object(format!("/{id}"))
            .await
            .context("S3 delete failed")?;
        // 404 means the object is already gone, which is what we wanted.
        anyhow::ensure!(
            resp.status_code() < 300 || resp.status_code() == 404,
            "S3 delete returned {}",
            resp.status_code()
        );
        Ok(())
    }

    async fn health(&self) -> Result<()> {
        // A HEAD on a key that does not exist still proves the endpoint,
        // credentials and bucket are all working: 404 is a successful
        // conversation, a connection error is not.
        match self.bucket.head_object("/__healthz").await {
            Ok(_) => Ok(()),
            Err(s3::error::S3Error::HttpFailWithBody(404, _)) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("S3 endpoint is not reachable: {e}")),
        }
    }
}
