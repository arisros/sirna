//! Blob metadata, and the one-time-read state machine.
//!
//! SQLite rather than the object store, because one-time semantics need an
//! atomic compare-and-set and S3 cannot provide one. The pragmas mirror what
//! OTM learned the hard way: without WAL and a busy timeout, two concurrent
//! writers meet `database is locked` instead of queueing.

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {path}"))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS blobs (
                id                TEXT PRIMARY KEY,
                state             TEXT NOT NULL,
                size              INTEGER NOT NULL,
                created_at        INTEGER NOT NULL,
                expires_at        INTEGER NOT NULL,
                consumed_at       INTEGER,
                delete_token_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS blobs_expiry ON blobs (expires_at);
            CREATE INDEX IF NOT EXISTS blobs_state  ON blobs (state, consumed_at);
            "#,
        )?;

        Ok(Self { conn })
    }

    pub fn insert(
        &self,
        id: &str,
        size: u64,
        created_at: u64,
        expires_at: u64,
        delete_token_hash: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO blobs (id, state, size, created_at, expires_at, delete_token_hash)
             VALUES (?1, 'live', ?2, ?3, ?4, ?5)",
            rusqlite::params![
                id,
                size as i64,
                created_at as i64,
                expires_at as i64,
                delete_token_hash
            ],
        )?;
        Ok(())
    }

    /// Claim a blob for reading. **The claim is the read.**
    ///
    /// This single statement is the whole of the one-time guarantee. Only the
    /// transaction that changes exactly one row wins; every concurrent reader
    /// updates zero rows and is turned away. Doing the check and the update
    /// separately would leave a window where two readers both see `live`.
    ///
    /// There is deliberately no intermediate state and no way back to `live`.
    /// An earlier version handed the claim back when a download failed, so a
    /// reader whose connection dropped was not left with nothing. That is a
    /// kinder failure mode and it is the wrong trade: it means a blob can be
    /// served more than once, and "once" is the whole promise. A dropped
    /// transfer now loses the message permanently. That cost is accepted.
    pub fn try_claim(&self, id: &str, now: u64) -> Result<Claim> {
        let changed = self.conn.execute(
            "UPDATE blobs SET state = 'consumed', consumed_at = ?2
             WHERE id = ?1 AND state = 'live' AND (expires_at = 0 OR expires_at > ?2)",
            rusqlite::params![id, now as i64],
        )?;

        if changed == 1 {
            return Ok(Claim::Won);
        }

        // Distinguish "never existed" from "already taken" for logging only.
        // Both are reported to the caller as the same thing, so the API does
        // not confirm whether a given id ever existed.
        let state: Option<String> = self
            .conn
            .query_row("SELECT state FROM blobs WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;

        Ok(match state {
            None => Claim::Unknown,
            Some(_) => Claim::Taken,
        })
    }

    pub fn delete_token_hash(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT delete_token_hash FROM blobs WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }

    pub fn forget(&self, id: &str) -> Result<()> {
        self.conn.execute("DELETE FROM blobs WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Blobs whose objects can now be removed from the store: expired, or read.
    ///
    /// `grace_secs` is only about reaper scheduling — a consumed blob is
    /// already unreachable the instant it was claimed, so this delay grants
    /// nobody a second attempt. It exists so the object is not deleted out from
    /// under a response that is still being written.
    pub fn reapable(&self, now: u64, grace_secs: u64) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM blobs
             WHERE (expires_at != 0 AND expires_at <= ?1)
                OR (state = 'consumed' AND consumed_at IS NOT NULL AND consumed_at <= ?2)
             LIMIT 500",
        )?;

        let rows = stmt.query_map(
            rusqlite::params![now as i64, now.saturating_sub(grace_secs) as i64],
            |r| r.get::<_, String>(0),
        )?;

        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn counts(&self) -> Result<(i64, i64, i64)> {
        let live: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM blobs WHERE state = 'live'", [], |r| {
                    r.get(0)
                })?;
        let consumed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM blobs WHERE state = 'consumed'",
            [],
            |r| r.get(0),
        )?;
        let bytes: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE state != 'consumed'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok((live, consumed, bytes))
    }

    pub fn ping(&self) -> Result<()> {
        self.conn.query_row("SELECT 1", [], |_| Ok(()))?;
        Ok(())
    }
}

/// States live in the database as plain strings ('live', 'consumed') so that a
/// human can read the table during an incident without a decoder ring. There
/// are only two, and the transition between them is one-way.
#[derive(Debug, PartialEq, Eq)]
pub enum Claim {
    Won,
    /// Already read, or expired.
    Taken,
    Unknown,
}
