//! Bytes per remote, process, service and country over time.
//!
//! A flow's own counters cover its whole life, so a window's total can't be
//! read from them: a connection open for nine hours would count all nine in
//! "last 1h". Each tick adds what flows moved since the previous one. The last
//! hour stays here by minute; every closed minute also goes to the store, which
//! keeps it by hour (`Store::add_window_bytes`).

use std::collections::{HashMap, VecDeque};

use crate::store::FlowRow;

pub const REMOTE: u8 = 0;
pub const PROCESS: u8 = 1;
pub const SERVICE: u8 = 2;
pub const COUNTRY: u8 = 3;
/// Everything, under the key "".
pub const TOTAL: u8 = 4;

/// Keys kept per dimension, per minute here and per hour in the store; the
/// rest is added up under the key "" so totals still add up.
pub const KEEP: usize = 500;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bytes {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub label: Option<String>,
    pub country: Option<String>,
    pub as_org: Option<String>,
}

impl Bytes {
    fn add(&mut self, o: &Bytes) {
        self.bytes_in += o.bytes_in;
        self.bytes_out += o.bytes_out;
        if self.label.is_none() {
            self.label.clone_from(&o.label);
        }
        if self.country.is_none() {
            self.country.clone_from(&o.country);
        }
        if self.as_org.is_none() {
            self.as_org.clone_from(&o.as_org);
        }
    }
}

pub type Bucket = HashMap<(u8, String), Bytes>;

/// Adds `b` into `into`, key by key.
pub fn merge(into: &mut Bucket, b: &Bucket) {
    for (k, v) in b {
        into.entry(k.clone()).or_default().add(v);
    }
}

/// The groups a flow counts in, as the Connections summary ranks them:
/// (dimension, key, label).
pub fn group_keys(f: &FlowRow) -> [(u8, String, Option<String>); 4] {
    [
        (REMOTE, f.remote.clone(), f.remote_name.clone()),
        (
            PROCESS,
            crate::store::owner_key(
                f.container.as_deref(),
                f.unit.as_deref(),
                f.process.as_deref(),
            ),
            f.exe.clone(),
        ),
        (
            SERVICE,
            format!("{}/{} {}", f.service_port, f.proto, f.dir),
            f.service.clone(),
        ),
        (
            COUNTRY,
            f.country.clone().unwrap_or_else(|| "--".into()),
            None,
        ),
    ]
}

/// Keeps the `KEEP` biggest keys of each dimension and adds the rest up under "".
fn cap(b: Bucket) -> Bucket {
    let mut per_dim: HashMap<u8, Vec<(String, Bytes)>> = HashMap::new();
    let mut out = Bucket::new();
    for ((dim, key), v) in b {
        if dim == TOTAL || key.is_empty() {
            out.entry((dim, key)).or_default().add(&v);
        } else {
            per_dim.entry(dim).or_default().push((key, v));
        }
    }
    for (dim, mut rows) in per_dim {
        rows.sort_by_key(|(k, v)| (std::cmp::Reverse(v.bytes_in + v.bytes_out), k.clone()));
        for (i, (key, v)) in rows.into_iter().enumerate() {
            if i < KEEP {
                out.entry((dim, key)).or_default().add(&v);
            } else {
                let rest = out.entry((dim, String::new())).or_default();
                rest.bytes_in += v.bytes_in;
                rest.bytes_out += v.bytes_out;
            }
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct ByteWindows {
    /// Closed minutes of the last hour, oldest first.
    minutes: VecDeque<(i64, Bucket)>,
    current: Option<(i64, Bucket)>,
    /// Closed minutes the store hasn't got yet.
    unsaved: Vec<(i64, Bucket)>,
}

impl ByteWindows {
    /// Counts `bytes_in`/`bytes_out` that flow `f` moved by `now`.
    pub fn add(&mut self, now: i64, f: &FlowRow, bytes_in: u64, bytes_out: u64) {
        self.roll(now);
        let (_, b) = self.current.as_mut().expect("rolled");
        let moved = |label: Option<String>| Bytes {
            bytes_in,
            bytes_out,
            label,
            country: None,
            as_org: None,
        };
        for (dim, key, label) in group_keys(f) {
            let mut v = moved(label);
            if dim == REMOTE {
                v.country.clone_from(&f.country);
                v.as_org.clone_from(&f.as_org);
            }
            b.entry((dim, key)).or_default().add(&v);
        }
        b.entry((TOTAL, String::new()))
            .or_default()
            .add(&moved(None));
    }

    /// Closes the current minute once `now` is in a later one.
    pub fn roll(&mut self, now: i64) {
        let ts = now - now.rem_euclid(60);
        if self.current.as_ref().is_some_and(|(t, _)| *t != ts) {
            self.close();
        }
        if self.current.is_none() {
            self.current = Some((ts, Bucket::new()));
        }
        while self.minutes.front().is_some_and(|(t, _)| *t < ts - 3600) {
            self.minutes.pop_front();
        }
    }

    /// Closes the current minute now (shutdown).
    pub fn close(&mut self) {
        if let Some((t, b)) = self.current.take() {
            let b = cap(b);
            self.unsaved.push((t, b.clone()));
            self.minutes.push_back((t, b));
        }
    }

    /// Closed minutes for the store.
    pub fn take_unsaved(&mut self) -> Vec<(i64, Bucket)> {
        std::mem::take(&mut self.unsaved)
    }

    /// Minutes starting at or after `since`, the open one included.
    pub fn since(&self, since: i64) -> Bucket {
        let mut out = Bucket::new();
        for (t, b) in self.minutes.iter().chain(self.current.as_ref()) {
            if *t >= since {
                merge(&mut out, b);
            }
        }
        out
    }

    /// What the store doesn't have yet: unsaved minutes and the open one.
    pub fn unstored(&self) -> Bucket {
        let mut out = Bucket::new();
        for (_, b) in self.unsaved.iter().chain(self.current.as_ref()) {
            merge(&mut out, b);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(remote: &str, process: &str) -> FlowRow {
        FlowRow {
            proto: "tcp".into(),
            remote: remote.into(),
            dir: "out".into(),
            process: Some(process.into()),
            country: Some("US".into()),
            service_port: 443,
            ..Default::default()
        }
    }

    fn total(b: &Bucket) -> (u64, u64) {
        let t = &b[&(TOTAL, String::new())];
        (t.bytes_in, t.bytes_out)
    }

    #[test]
    fn counts_bytes_by_minute_and_group() {
        let mut w = ByteWindows::default();
        let (a, b) = (row("192.0.2.1", "curl"), row("192.0.2.2", "peer"));
        w.add(1_000_020, &a, 100, 10);
        w.add(1_000_030, &b, 50, 5);
        w.add(1_000_090, &a, 7, 1); // the next minute
        assert_eq!(total(&w.since(0)), (157, 16));
        assert_eq!(total(&w.since(1_000_080)), (7, 1));
        let all = w.since(0);
        assert_eq!(all[&(REMOTE, "192.0.2.1".into())].bytes_in, 107);
        assert_eq!(all[&(PROCESS, "peer".into())].bytes_in, 50);
        assert_eq!(all[&(SERVICE, "443/tcp out".into())].bytes_in, 157);
        assert_eq!(
            all[&(REMOTE, "192.0.2.1".into())].country.as_deref(),
            Some("US")
        );

        // The first minute closed when the second began; the open one isn't saved yet.
        let saved = w.take_unsaved();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].0, 1_000_020);
        assert_eq!(total(&saved[0].1), (150, 15));
        assert_eq!(total(&w.unstored()), (7, 1));
        assert!(w.take_unsaved().is_empty());
        w.close();
        assert_eq!(total(&w.take_unsaved()[0].1), (7, 1));
    }

    #[test]
    fn keeps_an_hour() {
        let mut w = ByteWindows::default();
        let a = row("192.0.2.1", "curl");
        w.add(0, &a, 1, 0);
        w.add(3_600, &a, 2, 0);
        assert_eq!(total(&w.since(i64::MIN)), (3, 0));
        w.roll(3_660);
        assert_eq!(total(&w.since(i64::MIN)), (2, 0));
    }

    #[test]
    fn caps_each_dimension_and_keeps_the_totals() {
        let mut w = ByteWindows::default();
        for i in 0..KEEP + 2 {
            let r = row(&format!("10.0.{}.{}", i / 256, i % 256), "p");
            w.add(0, &r, 1000 + i as u64, 0);
        }
        w.close();
        let b = &w.take_unsaved()[0].1;
        let remotes = b.keys().filter(|(d, _)| *d == REMOTE).count();
        assert_eq!(remotes, KEEP + 1);
        // The two smallest went to "".
        assert_eq!(b[&(REMOTE, String::new())].bytes_in, 1000 + 1001);
        let sum: u64 = b
            .iter()
            .filter(|((d, _), _)| *d == REMOTE)
            .map(|(_, v)| v.bytes_in)
            .sum();
        assert_eq!(sum, total(b).0);
    }
}
