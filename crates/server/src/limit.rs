//! Per-IP rate limiting.
//!
//! Deliberately modelled on what OTM got wrong. Its limiter kept two maps with
//! no mutex, so two simultaneous visitors could trigger a concurrent map write
//! — an unrecoverable fatal error in Go. It also slept for the whole cooldown
//! before replying 429, which turned the limiter into a self-inflicted denial
//! of service. Neither mistake is repeated here.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Bucket>>,
    capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: capacity as f64,
            refill_per_sec,
        }
    }

    /// Returns false when the caller is over budget. Never blocks: a limiter
    /// that holds the request open is worse than the traffic it is limiting.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        let bucket = buckets.entry(key.to_string()).or_insert(Bucket {
            tokens: self.capacity,
            last: now,
        });

        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop idle entries so the map cannot grow without bound. OTM's never
    /// shrank, which is a slow memory leak driven entirely by strangers.
    pub fn sweep(&self, idle: Duration) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, b| now.duration_since(b.last) < idle);
    }

    /// Test-only: the tests live in this module, so this need not be public.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refuse() {
        let l = RateLimiter::new(3, 1.0);
        assert!(l.allow("a"));
        assert!(l.allow("a"));
        assert!(l.allow("a"));
        assert!(
            !l.allow("a"),
            "fourth request in a burst of 3 must be refused"
        );
    }

    #[test]
    fn buckets_are_per_key() {
        let l = RateLimiter::new(1, 1.0);
        assert!(l.allow("a"));
        assert!(!l.allow("a"));
        assert!(
            l.allow("b"),
            "one visitor must not exhaust another's budget"
        );
    }

    #[test]
    fn sweep_drops_idle_entries() {
        let l = RateLimiter::new(1, 1.0);
        l.allow("a");
        assert_eq!(l.len(), 1);
        l.sweep(Duration::from_secs(0));
        assert_eq!(l.len(), 0);
    }
}
