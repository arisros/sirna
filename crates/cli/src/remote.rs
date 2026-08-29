//! Talking to a Sirna server.
//!
//! The server is a dumb blob store: it takes an envelope and gives it back
//! once. No key ever appears in these requests, which is why `push` can be
//! pointed at someone else's server without thinking hard about it.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Created {
    pub id: String,
    pub delete_token: String,
    pub expires_at: u64,
}

pub fn push(server: &str, envelope: &[u8], ttl: Option<u64>) -> Result<Created> {
    let base = server.trim_end_matches('/');
    let mut url = format!("{base}/api/v1/blobs");
    if let Some(ttl) = ttl {
        url.push_str(&format!("?ttl={ttl}"));
    }

    let resp = ureq::post(&url)
        .set("content-type", "application/octet-stream")
        .send_bytes(envelope);

    match resp {
        Ok(r) => r.into_json::<Created>().context("decoding server response"),
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            bail!("server refused the upload ({code}): {body}")
        }
        Err(e) => Err(e).context("could not reach the server"),
    }
}

pub fn pull(server: &str, id: &str) -> Result<Vec<u8>> {
    let base = server.trim_end_matches('/');
    let resp = ureq::get(&format!("{base}/api/v1/blobs/{id}")).call();

    match resp {
        Ok(r) => {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut r.into_reader(), &mut buf)
                .context("reading the envelope")?;
            Ok(buf)
        }
        // 410 is the normal, expected answer for anything already read,
        // expired, or never present — the server deliberately does not say
        // which.
        Err(ureq::Error::Status(410, _)) => {
            bail!("not available — already read, expired, or never existed")
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            bail!("server refused ({code}): {body}")
        }
        Err(e) => Err(e).context("could not reach the server"),
    }
}
