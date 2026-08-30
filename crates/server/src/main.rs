//! Entry point: configuration, the reaper, and graceful shutdown.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info, warn};

use sirna_server::api::{router, AppState};
use sirna_server::db::Db;
use sirna_server::limit::RateLimiter;
use sirna_server::store::{BlobStore, FsStore, S3Store};

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Settings {
    max_blob_bytes: usize,
    default_ttl: u64,
    max_ttl: u64,
    grace: u64,
    rate_burst: u32,
    rate_per_sec: f64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let addr: SocketAddr = format!("0.0.0.0:{}", env_or("PORT", "8080"))
        .parse()
        .context("invalid PORT")?;
    let db_path = env_or("DB_PATH", "/data/sirna.db");

    let settings = Settings {
        max_blob_bytes: env_num("MAX_BLOB_BYTES", 32 * 1024 * 1024),
        default_ttl: env_num("DEFAULT_TTL_SECS", 86_400),
        max_ttl: env_num("MAX_TTL_SECS", 604_800),
        grace: env_num("DOWNLOAD_GRACE_SECS", 300),
        rate_burst: env_num("RATE_BURST", 20),
        rate_per_sec: env_num("RATE_PER_SEC", 2.0),
    };

    let db = Db::open(&db_path)?;
    info!(%db_path, "metadata store ready");

    // `fs` keeps the whole service runnable — and testable — with no S3 at all.
    match env_or("STORE", "s3").as_str() {
        "fs" => {
            let root = env_or("BLOB_DIR", "/data/blobs");
            let store = FsStore::new(&root)?;
            info!(%root, "using filesystem blob store");
            serve(addr, db, store, settings).await
        }
        _ => {
            let store = S3Store::new(
                &env_or("S3_ENDPOINT", "http://garage.apps.svc.cluster.local:3900"),
                &env_or("S3_REGION", "garage"),
                &env_or("S3_BUCKET", "sirna-blobs"),
                &std::env::var("S3_ACCESS_KEY_ID").context("S3_ACCESS_KEY_ID is required")?,
                &std::env::var("S3_SECRET_ACCESS_KEY")
                    .context("S3_SECRET_ACCESS_KEY is required")?,
            )?;
            info!("using S3 blob store");
            serve(addr, db, store, settings).await
        }
    }
}

async fn serve<S: BlobStore>(addr: SocketAddr, db: Db, store: S, settings: Settings) -> Result<()> {
    let grace = settings.grace;
    let max_blob_bytes = settings.max_blob_bytes;
    let state = Arc::new(AppState {
        db: tokio::sync::Mutex::new(db),
        store,
        limiter: RateLimiter::new(settings.rate_burst, settings.rate_per_sec),
        relay: sirna_server::rendezvous::Relay::new(),
        max_blob_bytes: settings.max_blob_bytes,
        default_ttl: settings.default_ttl,
        max_ttl: settings.max_ttl,
    });

    // The reaper deletes objects, not the download handler. Removing an object
    // inline would mean a reader whose connection dropped mid-transfer loses
    // the message with no recourse; a short grace window costs nothing and
    // avoids that entirely.
    let reaper = Arc::clone(&state);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let ids = {
                let db = reaper.db.lock().await;
                db.reapable(now, grace).unwrap_or_default()
            };

            for id in ids {
                if let Err(e) = reaper.store.delete(&id).await {
                    warn!(%id, error = %e, "reaper could not delete object");
                    continue;
                }
                let db = reaper.db.lock().await;
                if let Err(e) = db.forget(&id) {
                    error!(%id, error = %e, "reaper could not clear metadata");
                }
            }

            reaper.limiter.sweep(Duration::from_secs(600));
        }
    });

    let app = router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, max_blob_bytes, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;

    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutting down");
}
