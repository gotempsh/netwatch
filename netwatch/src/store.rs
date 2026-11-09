//! SQLite persistence: alerts, bans, offence history, allow rules, hourly
//! per-source traffic, finished flows, DNS queries and connection events, so
//! activity can be reviewed after the fact.

use std::path::Path;

use anyhow::Context as _;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub ip: String,
    pub kind: String,
    pub score: u32,
    pub summary: String,
    pub location: String,
    pub first_ts: i64,
    pub last_ts: i64,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BanRow {
    pub target: String,
    pub created: i64,
    pub expires: Option<i64>,
    pub reason: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryRow {
    pub ip: String,
    pub location: String,
    pub in_packets: i64,
    pub in_bytes: i64,
    pub syn: i64,
    pub blocked: i64,
    pub max_score: i64,
    pub hours: i64,
    pub last_hour: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CountryRow {
    pub country: String,
    pub sources: i64,
    pub syn: i64,
    pub in_packets: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HourRow {
    pub hour: i64,
    pub in_packets: i64,
    pub in_bytes: i64,
    pub syn: i64,
    pub blocked: i64,
    pub max_score: i64,
}

pub struct NewProposal<'a> {
    pub target: &'a str,
    pub action: &'a str,
    pub ttl_secs: Option<i64>,
    pub reason: &'a str,
    pub source: &'a str,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProposalRow {
    pub id: i64,
    pub created: i64,
    pub target: String,
    pub action: String,
    pub ttl_secs: Option<i64>,
    pub reason: String,
    pub source: String,
    pub confidence: f64,
    pub status: String,
    pub decided_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshEventRow {
    pub ts: i64,
    pub kind: String,
    pub user: Option<String>,
    pub ip: String,
    pub method: Option<String>,
    pub location: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LlmRunRow {
    pub ts: i64,
    pub kind: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub summary: String,
    pub proposals: i64,
}

#[derive(Debug, Clone)]
pub struct PolicyRow {
    pub text: String,
    /// JSON array of `policy::Rule`.
    pub rules: String,
    pub compiled_at: i64,
    pub compiled_by: String,
}

/// One conversation, finished (from the store) or still active (from memory).
#[derive(Debug, Clone, Serialize)]
pub struct FlowRow {
    pub iface: String,
    pub proto: String,
    pub local: String,
    pub lport: u16,
    pub remote: String,
    pub rport: u16,
    /// in, out or unknown: who opened it.
    pub dir: String,
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub state: String,
    pub connect_ms: Option<f64>,
    pub retrans: u64,
    pub rst_sent: u64,
    pub rst_recv: u64,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub exe: Option<String>,
    pub container: Option<String>,
    /// systemd service of the process when it isn't in a container.
    pub unit: Option<String>,
    /// The process on the remote end when it is on this host (another
    /// container, or a host process such as docker-proxy), found while the
    /// flow was active.
    pub remote_pid: Option<u32>,
    pub remote_process: Option<String>,
    pub remote_container: Option<String>,
    pub remote_unit: Option<String>,
    /// Name the remote address was resolved from (DNS seen by netwatch).
    pub remote_name: Option<String>,
    /// Parsed first-payload metadata (`dissect::AppMeta`).
    pub app: serde_json::Value,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    /// The port that identifies the service: local for inbound, remote for outbound.
    pub service_port: u16,
    pub service: Option<String>,
    pub active: bool,
    /// Bytes per second over the last tick (0 for finished flows).
    pub rate_in: f64,
    pub rate_out: f64,
}

/// Everything this host (or a local container) connected out to at one remote address.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DestinationRow {
    pub remote: String,
    /// DNS name or TLS SNI seen for it; None if it was reached without either.
    pub name: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub flows: u64,
    /// Flows still open (0 from the store).
    pub active: u64,
    pub failed: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    /// "tcp/443", sorted.
    pub ports: Vec<String>,
    /// Who connected: "container/process", "unit/process" or "process", sorted.
    pub processes: Vec<String>,
}

/// Owner label of a flow, as the flow summary groups processes.
pub fn owner_key(container: Option<&str>, unit: Option<&str>, process: Option<&str>) -> String {
    match (container.or(unit), process) {
        (Some(c), p) => format!("{c}/{}", p.unwrap_or("?")),
        (None, Some(p)) => p.to_string(),
        (None, None) => "unknown".into(),
    }
}

/// Filters for flow history; every field is optional.
#[derive(Debug, Default, Clone)]
pub struct FlowFilter {
    pub since: i64,
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub process: Option<String>,
    pub dir: Option<String>,
    pub iface: Option<String>,
    pub proto: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRow {
    pub ts: i64,
    pub iface: String,
    pub client: String,
    pub server: String,
    pub dir: String,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub answers: Vec<String>,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnEventRow {
    pub ts: i64,
    pub kind: String,
    pub proto: String,
    pub local: String,
    pub lport: u16,
    pub remote: Option<String>,
    pub rport: Option<u16>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub container: Option<String>,
    pub unit: Option<String>,
    pub detail: String,
}

/// Inbound counters for one source over part of an hour.
pub struct HourDelta<'a> {
    pub ip: &'a str,
    pub country: &'a str,
    pub location: &'a str,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub syn: u64,
    pub blocked: u64,
    pub score: u32,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY, ip TEXT NOT NULL, kind TEXT NOT NULL, score INTEGER NOT NULL,
                summary TEXT NOT NULL, location TEXT NOT NULL, first_ts INTEGER NOT NULL,
                last_ts INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1);
             CREATE INDEX IF NOT EXISTS alerts_last ON alerts(last_ts);
             CREATE INDEX IF NOT EXISTS alerts_ip ON alerts(ip, kind, last_ts);
             CREATE TABLE IF NOT EXISTS bans (
                target TEXT PRIMARY KEY, created INTEGER NOT NULL, expires INTEGER,
                reason TEXT NOT NULL, source TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS offences (
                ip TEXT PRIMARY KEY, count INTEGER NOT NULL, last_ts INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS allow_rules (
                target TEXT PRIMARY KEY, created INTEGER NOT NULL, note TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS traffic_hourly (
                hour INTEGER NOT NULL, ip TEXT NOT NULL, country TEXT NOT NULL, location TEXT NOT NULL,
                in_packets INTEGER NOT NULL, in_bytes INTEGER NOT NULL, syn INTEGER NOT NULL,
                blocked INTEGER NOT NULL, max_score INTEGER NOT NULL, PRIMARY KEY (hour, ip));
             CREATE TABLE IF NOT EXISTS proposals (
                id INTEGER PRIMARY KEY, created INTEGER NOT NULL, target TEXT NOT NULL, action TEXT NOT NULL,
                ttl_secs INTEGER, reason TEXT NOT NULL, source TEXT NOT NULL, confidence REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending', decided_at INTEGER);
             CREATE INDEX IF NOT EXISTS proposals_status ON proposals(status, created);
             CREATE TABLE IF NOT EXISTS ssh_events (
                ts INTEGER NOT NULL, kind TEXT NOT NULL, user TEXT, ip TEXT NOT NULL, method TEXT,
                location TEXT NOT NULL, UNIQUE (ts, kind, ip, user, method));
             CREATE INDEX IF NOT EXISTS ssh_events_ts ON ssh_events(ts);
             CREATE INDEX IF NOT EXISTS ssh_events_ip ON ssh_events(ip, ts);
             CREATE TABLE IF NOT EXISTS llm_runs (
                ts INTEGER NOT NULL, kind TEXT NOT NULL, model TEXT NOT NULL, prompt_tokens INTEGER NOT NULL,
                completion_tokens INTEGER NOT NULL, summary TEXT NOT NULL, proposals INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS policy (
                id INTEGER PRIMARY KEY CHECK (id = 1), text TEXT NOT NULL, rules TEXT NOT NULL,
                compiled_at INTEGER NOT NULL, compiled_by TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY, iface TEXT NOT NULL, proto TEXT NOT NULL, local TEXT NOT NULL,
                lport INTEGER NOT NULL, remote TEXT NOT NULL, rport INTEGER NOT NULL, dir TEXT NOT NULL,
                first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, bytes_in INTEGER NOT NULL,
                bytes_out INTEGER NOT NULL, pkts_in INTEGER NOT NULL, pkts_out INTEGER NOT NULL,
                state TEXT NOT NULL, connect_ms REAL, retrans INTEGER NOT NULL, rst_sent INTEGER NOT NULL,
                rst_recv INTEGER NOT NULL, pid INTEGER, process TEXT, exe TEXT, container TEXT,
                remote_name TEXT, app TEXT, country TEXT, asn INTEGER, as_org TEXT, service_port INTEGER NOT NULL,
                unit TEXT);
             CREATE INDEX IF NOT EXISTS flows_last ON flows(last_seen);
             CREATE INDEX IF NOT EXISTS flows_remote ON flows(remote, last_seen);
             CREATE INDEX IF NOT EXISTS flows_process ON flows(process, last_seen);
             CREATE TABLE IF NOT EXISTS dns_queries (
                ts INTEGER NOT NULL, iface TEXT NOT NULL, client TEXT NOT NULL, server TEXT NOT NULL,
                dir TEXT NOT NULL, qname TEXT NOT NULL, qtype TEXT NOT NULL, rcode TEXT NOT NULL,
                answers TEXT NOT NULL, latency_ms REAL);
             CREATE INDEX IF NOT EXISTS dns_ts ON dns_queries(ts);
             CREATE INDEX IF NOT EXISTS dns_qname ON dns_queries(qname, ts);
             CREATE TABLE IF NOT EXISTS conn_events (
                ts INTEGER NOT NULL, kind TEXT NOT NULL, proto TEXT NOT NULL, local TEXT NOT NULL,
                lport INTEGER NOT NULL, remote TEXT, rport INTEGER, pid INTEGER, process TEXT,
                container TEXT, detail TEXT NOT NULL, unit TEXT);
             CREATE INDEX IF NOT EXISTS conn_events_ts ON conn_events(ts);",
        )?;
        // Columns added after the first release of a table.
        for (table, col, decl) in [
            ("flows", "unit", "TEXT"),
            ("conn_events", "unit", "TEXT"),
            ("flows", "remote_pid", "INTEGER"),
            ("flows", "remote_process", "TEXT"),
            ("flows", "remote_container", "TEXT"),
            ("flows", "remote_unit", "TEXT"),
        ] {
            let has = conn
                .prepare(&format!(
                    "SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"
                ))?
                .exists([col])?;
            if !has {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {decl}"))?;
            }
        }
        Ok(Self { conn })
    }

    /// Repeated detections of the same kind for an IP within 30 minutes extend one alert.
    pub fn upsert_alert(
        &self,
        ip: &str,
        kind: &str,
        score: u32,
        summary: &str,
        location: &str,
        now: i64,
    ) -> anyhow::Result<()> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT id FROM alerts WHERE ip=?1 AND kind=?2 AND last_ts>=?3 ORDER BY last_ts DESC LIMIT 1",
                params![ip, kind, now - 1800],
                |r| r.get(0),
            )
            .optional()?;
        match existing {
            Some(id) => self.conn.execute(
                "UPDATE alerts SET last_ts=?1, count=count+1, score=MAX(score, ?2), summary=?3 WHERE id=?4",
                params![now, score, summary, id],
            )?,
            None => self.conn.execute(
                "INSERT INTO alerts (ip, kind, score, summary, location, first_ts, last_ts) VALUES (?1,?2,?3,?4,?5,?6,?6)",
                params![ip, kind, score, summary, location, now],
            )?,
        };
        Ok(())
    }

    pub fn alerts(
        &self,
        since: i64,
        ip: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<AlertRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ip, kind, score, summary, location, first_ts, last_ts, count FROM alerts
             WHERE last_ts>=?1 AND (?2 IS NULL OR ip=?2) ORDER BY last_ts DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![since, ip, limit], |r| {
            Ok(AlertRow {
                id: r.get(0)?,
                ip: r.get(1)?,
                kind: r.get(2)?,
                score: r.get(3)?,
                summary: r.get(4)?,
                location: r.get(5)?,
                first_ts: r.get(6)?,
                last_ts: r.get(7)?,
                count: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn put_ban(&self, ban: &BanRow) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO bans (target, created, expires, reason, source) VALUES (?1,?2,?3,?4,?5)
             ON CONFLICT(target) DO UPDATE SET created=?2, expires=?3, reason=?4, source=?5",
            params![ban.target, ban.created, ban.expires, ban.reason, ban.source],
        )?;
        Ok(())
    }

    pub fn delete_ban(&self, target: &str) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM bans WHERE target=?1", params![target])?
            > 0)
    }

    pub fn bans(&self) -> anyhow::Result<Vec<BanRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT target, created, expires, reason, source FROM bans ORDER BY created DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(BanRow {
                target: r.get(0)?,
                created: r.get(1)?,
                expires: r.get(2)?,
                reason: r.get(3)?,
                source: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn offences(&self, ip: &str) -> anyhow::Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT count FROM offences WHERE ip=?1", params![ip], |r| {
                r.get(0)
            })
            .optional()?
            .unwrap_or(0))
    }

    pub fn add_offence(&self, ip: &str, now: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO offences (ip, count, last_ts) VALUES (?1, 1, ?2)
             ON CONFLICT(ip) DO UPDATE SET count=count+1, last_ts=?2",
            params![ip, now],
        )?;
        Ok(())
    }

    pub fn allow_rules(&self) -> anyhow::Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare("SELECT target, note FROM allow_rules")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn put_allow(&self, target: &str, note: &str, now: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO allow_rules (target, created, note) VALUES (?1,?2,?3)",
            params![target, now, note],
        )?;
        Ok(())
    }

    pub fn delete_allow(&self, target: &str) -> anyhow::Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM allow_rules WHERE target=?1", params![target])?
            > 0)
    }

    pub fn record_hourly(&mut self, hour: i64, rows: &[HourDelta<'_>]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO traffic_hourly (hour, ip, country, location, in_packets, in_bytes, syn, blocked, max_score)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(hour, ip) DO UPDATE SET in_packets=in_packets+?5, in_bytes=in_bytes+?6,
                   syn=syn+?7, blocked=blocked+?8, max_score=MAX(max_score, ?9)",
            )?;
            for r in rows {
                stmt.execute(params![
                    hour,
                    r.ip,
                    r.country,
                    r.location,
                    r.in_packets as i64,
                    r.in_bytes as i64,
                    r.syn as i64,
                    r.blocked as i64,
                    r.score
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Top sources since `since`, ordered by `order` (syn, in_bytes, in_packets, blocked, max_score).
    pub fn history(&self, since: i64, order: &str, limit: u32) -> anyhow::Result<Vec<HistoryRow>> {
        let order = match order {
            "in_bytes" | "in_packets" | "blocked" | "max_score" => order,
            _ => "syn",
        };
        let sql = format!(
            "SELECT ip, MAX(location), SUM(in_packets), SUM(in_bytes), SUM(syn), SUM(blocked), MAX(max_score),
                    COUNT(*), MAX(hour)
             FROM traffic_hourly WHERE hour>=?1 GROUP BY ip ORDER BY {} DESC LIMIT ?2",
            if order == "max_score" { "MAX(max_score)".to_string() } else { format!("SUM({order})") }
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![since, limit], |r| {
            Ok(HistoryRow {
                ip: r.get(0)?,
                location: r.get(1)?,
                in_packets: r.get(2)?,
                in_bytes: r.get(3)?,
                syn: r.get(4)?,
                blocked: r.get(5)?,
                max_score: r.get(6)?,
                hours: r.get(7)?,
                last_hour: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn history_countries(&self, since: i64, limit: u32) -> anyhow::Result<Vec<CountryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT country, COUNT(DISTINCT ip), SUM(syn), SUM(in_packets) FROM traffic_hourly
             WHERE hour>=?1 GROUP BY country ORDER BY COUNT(DISTINCT ip) DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit], |r| {
            Ok(CountryRow {
                country: r.get(0)?,
                sources: r.get(1)?,
                syn: r.get(2)?,
                in_packets: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_flows(&mut self, rows: &[FlowRow]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO flows (iface, proto, local, lport, remote, rport, dir, first_seen, last_seen, bytes_in,
                   bytes_out, pkts_in, pkts_out, state, connect_ms, retrans, rst_sent, rst_recv, pid, process, exe,
                   container, remote_name, app, country, asn, as_org, service_port, unit, remote_pid, remote_process,
                   remote_container, remote_unit)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,
                   ?30,?31,?32,?33)",
            )?;
            for r in rows {
                let app = if r.app.is_null() {
                    None
                } else {
                    Some(r.app.to_string())
                };
                stmt.execute(params![
                    r.iface,
                    r.proto,
                    r.local,
                    r.lport,
                    r.remote,
                    r.rport,
                    r.dir,
                    r.first_seen,
                    r.last_seen,
                    r.bytes_in as i64,
                    r.bytes_out as i64,
                    r.pkts_in as i64,
                    r.pkts_out as i64,
                    r.state,
                    r.connect_ms,
                    r.retrans as i64,
                    r.rst_sent as i64,
                    r.rst_recv as i64,
                    r.pid,
                    r.process,
                    r.exe,
                    r.container,
                    r.remote_name,
                    app,
                    r.country,
                    r.asn,
                    r.as_org,
                    r.service_port,
                    r.unit,
                    r.remote_pid,
                    r.remote_process,
                    r.remote_container,
                    r.remote_unit
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Finished flows matching `f`, newest first.
    pub fn flows(&self, f: &FlowFilter, limit: u32) -> anyhow::Result<Vec<FlowRow>> {
        let mut sql = String::from(
            "SELECT iface, proto, local, lport, remote, rport, dir, first_seen, last_seen, bytes_in, bytes_out,
                    pkts_in, pkts_out, state, connect_ms, retrans, rst_sent, rst_recv, pid, process, exe, container,
                    remote_name, app, country, asn, as_org, service_port, unit, remote_pid, remote_process,
                    remote_container, remote_unit
             FROM flows WHERE last_seen >= ?",
        );
        let mut args: Vec<rusqlite::types::Value> = vec![f.since.into()];
        if let Some(ip) = &f.ip {
            sql.push_str(" AND (remote = ? OR local = ?)");
            args.push(ip.clone().into());
            args.push(ip.clone().into());
        }
        if let Some(p) = f.port {
            sql.push_str(" AND (lport = ? OR rport = ?)");
            args.push((p as i64).into());
            args.push((p as i64).into());
        }
        for (col, v) in [
            ("process", &f.process),
            ("dir", &f.dir),
            ("iface", &f.iface),
            ("proto", &f.proto),
        ] {
            if let Some(v) = v {
                sql.push_str(&format!(" AND {col} = ?"));
                args.push(v.clone().into());
            }
        }
        if let Some(q) = &f.q {
            sql.push_str(
                " AND (remote LIKE ? OR remote_name LIKE ? OR process LIKE ? OR container LIKE ? OR unit LIKE ?
                   OR remote_process LIKE ? OR remote_container LIKE ? OR app LIKE ? OR as_org LIKE ? OR country = ?)",
            );
            let like = format!("%{q}%");
            for _ in 0..9 {
                args.push(like.clone().into());
            }
            args.push(q.to_ascii_uppercase().into());
        }
        sql.push_str(" ORDER BY last_seen DESC LIMIT ?");
        args.push((limit as i64).into());
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
            let app: Option<String> = r.get(23)?;
            let service_port: u16 = r.get(27)?;
            Ok(FlowRow {
                iface: r.get(0)?,
                proto: r.get(1)?,
                local: r.get(2)?,
                lport: r.get(3)?,
                remote: r.get(4)?,
                rport: r.get(5)?,
                dir: r.get(6)?,
                first_seen: r.get(7)?,
                last_seen: r.get(8)?,
                bytes_in: r.get::<_, i64>(9)? as u64,
                bytes_out: r.get::<_, i64>(10)? as u64,
                pkts_in: r.get::<_, i64>(11)? as u64,
                pkts_out: r.get::<_, i64>(12)? as u64,
                state: r.get(13)?,
                connect_ms: r.get(14)?,
                retrans: r.get::<_, i64>(15)? as u64,
                rst_sent: r.get::<_, i64>(16)? as u64,
                rst_recv: r.get::<_, i64>(17)? as u64,
                pid: r.get(18)?,
                process: r.get(19)?,
                exe: r.get(20)?,
                container: r.get(21)?,
                unit: r.get(28)?,
                remote_pid: r.get(29)?,
                remote_process: r.get(30)?,
                remote_container: r.get(31)?,
                remote_unit: r.get(32)?,
                remote_name: r.get(22)?,
                app: app
                    .and_then(|a| serde_json::from_str(&a).ok())
                    .unwrap_or(serde_json::Value::Null),
                country: r.get(24)?,
                asn: r.get(25)?,
                as_org: r.get(26)?,
                service_port,
                service: crate::util::service_name(service_port).map(str::to_string),
                active: false,
                rate_in: 0.0,
                rate_out: 0.0,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Finished outbound flows since `since`, one row per remote address.
    pub fn destinations(&self, since: i64) -> anyhow::Result<Vec<DestinationRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT remote, MAX(remote_name), MAX(country), MAX(asn), MAX(as_org), COUNT(*), SUM(state = 'failed'),
                    SUM(bytes_in), SUM(bytes_out), MIN(first_seen), MAX(last_seen),
                    GROUP_CONCAT(DISTINCT proto || '/' || rport),
                    GROUP_CONCAT(DISTINCT CASE WHEN COALESCE(container, unit) IS NOT NULL
                        THEN COALESCE(container, unit) || '/' || COALESCE(process, '?')
                        ELSE COALESCE(process, 'unknown') END)
             FROM flows WHERE dir = 'out' AND last_seen >= ?1 GROUP BY remote",
        )?;
        let list = |s: Option<String>| -> Vec<String> {
            let mut v: Vec<String> = s
                .unwrap_or_default()
                .split(',')
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect();
            v.sort();
            v
        };
        let rows = stmt.query_map([since], |r| {
            Ok(DestinationRow {
                remote: r.get(0)?,
                name: r.get(1)?,
                country: r.get(2)?,
                asn: r.get(3)?,
                as_org: r.get(4)?,
                flows: r.get::<_, i64>(5)? as u64,
                active: 0,
                failed: r.get::<_, i64>(6)? as u64,
                bytes_in: r.get::<_, i64>(7)? as u64,
                bytes_out: r.get::<_, i64>(8)? as u64,
                first_seen: r.get(9)?,
                last_seen: r.get(10)?,
                ports: list(r.get(11)?),
                processes: list(r.get(12)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_dns(&mut self, rows: &[DnsRow]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO dns_queries (ts, iface, client, server, dir, qname, qtype, rcode, answers, latency_ms)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            )?;
            for r in rows {
                stmt.execute(params![
                    r.ts,
                    r.iface,
                    r.client,
                    r.server,
                    r.dir,
                    r.qname,
                    r.qtype,
                    r.rcode,
                    r.answers.join(","),
                    r.latency_ms
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn dns(
        &self,
        since: i64,
        q: Option<&str>,
        rcode: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<DnsRow>> {
        let mut sql = String::from(
            "SELECT ts, iface, client, server, dir, qname, qtype, rcode, answers, latency_ms FROM dns_queries WHERE ts >= ?",
        );
        let mut args: Vec<rusqlite::types::Value> = vec![since.into()];
        if let Some(q) = q {
            sql.push_str(" AND (qname LIKE ? OR client = ? OR server = ? OR answers LIKE ?)");
            args.push(format!("%{q}%").into());
            args.push(q.to_string().into());
            args.push(q.to_string().into());
            args.push(format!("%{q}%").into());
        }
        if let Some(r) = rcode {
            sql.push_str(" AND rcode = ?");
            args.push(r.to_string().into());
        }
        sql.push_str(" ORDER BY ts DESC LIMIT ?");
        args.push((limit as i64).into());
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), |r| {
            let answers: String = r.get(8)?;
            Ok(DnsRow {
                ts: r.get(0)?,
                iface: r.get(1)?,
                client: r.get(2)?,
                server: r.get(3)?,
                dir: r.get(4)?,
                qname: r.get(5)?,
                qtype: r.get(6)?,
                rcode: r.get(7)?,
                answers: answers
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                latency_ms: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Most-queried names since `since`: (qname, queries, nxdomain, clients, last_ts).
    pub fn dns_top(&self, since: i64, limit: u32) -> anyhow::Result<Vec<serde_json::Value>> {
        let mut stmt = self.conn.prepare(
            "SELECT qname, COUNT(*), SUM(rcode = 'NXDOMAIN'), COUNT(DISTINCT client), MAX(ts)
             FROM dns_queries WHERE ts >= ?1 GROUP BY qname ORDER BY COUNT(*) DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit], |r| {
            Ok(serde_json::json!({
                "qname": r.get::<_, String>(0)?,
                "queries": r.get::<_, i64>(1)?,
                "nxdomain": r.get::<_, i64>(2)?,
                "clients": r.get::<_, i64>(3)?,
                "last_ts": r.get::<_, i64>(4)?,
            }))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_conn_events(&mut self, rows: &[ConnEventRow]) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO conn_events (ts, kind, proto, local, lport, remote, rport, pid, process, container, detail, unit)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            )?;
            for r in rows {
                stmt.execute(params![
                    r.ts,
                    r.kind,
                    r.proto,
                    r.local,
                    r.lport,
                    r.remote,
                    r.rport,
                    r.pid,
                    r.process,
                    r.container,
                    r.detail,
                    r.unit
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn conn_events(
        &self,
        since: i64,
        kind: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<ConnEventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, kind, proto, local, lport, remote, rport, pid, process, container, detail, unit FROM conn_events
             WHERE ts >= ?1 AND (?2 IS NULL OR kind = ?2) ORDER BY ts DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![since, kind, limit], |r| {
            Ok(ConnEventRow {
                ts: r.get(0)?,
                kind: r.get(1)?,
                proto: r.get(2)?,
                local: r.get(3)?,
                lport: r.get(4)?,
                remote: r.get(5)?,
                rport: r.get(6)?,
                pid: r.get(7)?,
                process: r.get(8)?,
                container: r.get(9)?,
                unit: r.get(11)?,
                detail: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn prune_flows(&self, retention_days: u32, now: i64) -> anyhow::Result<()> {
        let cutoff = now - retention_days as i64 * 86_400;
        self.conn
            .execute("DELETE FROM flows WHERE last_seen<?1", params![cutoff])?;
        self.conn
            .execute("DELETE FROM dns_queries WHERE ts<?1", params![cutoff])?;
        self.conn
            .execute("DELETE FROM conn_events WHERE ts<?1", params![cutoff])?;
        Ok(())
    }

    pub fn prune(&self, retention_days: u32, now: i64) -> anyhow::Result<()> {
        let cutoff = now - retention_days as i64 * 86_400;
        self.conn
            .execute("DELETE FROM alerts WHERE last_ts<?1", params![cutoff])?;
        self.conn
            .execute("DELETE FROM traffic_hourly WHERE hour<?1", params![cutoff])?;
        self.conn
            .execute("DELETE FROM ssh_events WHERE ts<?1", params![cutoff])?;
        self.conn
            .execute("DELETE FROM llm_runs WHERE ts<?1", params![cutoff])?;
        self.conn.execute(
            "DELETE FROM proposals WHERE status!='pending' AND created<?1",
            params![cutoff],
        )?;
        // Pending proposals go stale after a day: the situation they describe has moved on.
        self.conn.execute(
            "UPDATE proposals SET status='expired', decided_at=?1 WHERE status='pending' AND created<?2",
            params![now, now - 86_400],
        )?;
        Ok(())
    }

    pub fn ip_history(&self, ip: &str, since: i64) -> anyhow::Result<Vec<HourRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT hour, in_packets, in_bytes, syn, blocked, max_score FROM traffic_hourly
             WHERE ip=?1 AND hour>=?2 ORDER BY hour",
        )?;
        let rows = stmt.query_map(params![ip, since], |r| {
            Ok(HourRow {
                hour: r.get(0)?,
                in_packets: r.get(1)?,
                in_bytes: r.get(2)?,
                syn: r.get(3)?,
                blocked: r.get(4)?,
                max_score: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Returns the new id, or None when the same proposal is pending, or was
    /// decided recently (a rejection holds for a day so it isn't re-raised every tick).
    pub fn add_proposal(&self, p: &NewProposal<'_>, now: i64) -> anyhow::Result<Option<i64>> {
        let dup: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT id, status FROM proposals WHERE target=?1 AND action=?2 AND (status='pending'
                   OR (status='rejected' AND decided_at>=?3) OR (status IN ('approved','applied') AND decided_at>=?4))
                 ORDER BY status='pending' DESC LIMIT 1",
                params![p.target, p.action, now - 86_400, now - 3_600],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, status)) = dup {
            // Keep a pending proposal's evidence current; it's what the reviewer reads.
            if status == "pending" {
                self.conn.execute(
                    "UPDATE proposals SET reason=?2, ttl_secs=?3, confidence=MAX(confidence, ?4) WHERE id=?1 AND source=?5",
                    params![id, p.reason, p.ttl_secs, p.confidence, p.source],
                )?;
            }
            return Ok(None);
        }
        self.conn.execute(
            "INSERT INTO proposals (created, target, action, ttl_secs, reason, source, confidence)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                now,
                p.target,
                p.action,
                p.ttl_secs,
                p.reason,
                p.source,
                p.confidence
            ],
        )?;
        Ok(Some(self.conn.last_insert_rowid()))
    }

    pub fn proposals(
        &self,
        pending_only: bool,
        target: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<ProposalRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, created, target, action, ttl_secs, reason, source, confidence, status, decided_at
             FROM proposals WHERE (?1=0 OR status='pending') AND (?2 IS NULL OR target=?2)
             ORDER BY created DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![pending_only as i64, target, limit], |r| {
            Ok(ProposalRow {
                id: r.get(0)?,
                created: r.get(1)?,
                target: r.get(2)?,
                action: r.get(3)?,
                ttl_secs: r.get(4)?,
                reason: r.get(5)?,
                source: r.get(6)?,
                confidence: r.get(7)?,
                status: r.get(8)?,
                decided_at: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn proposal(&self, id: i64) -> anyhow::Result<Option<ProposalRow>> {
        Ok(self
            .proposals(false, None, u32::MAX)?
            .into_iter()
            .find(|p| p.id == id))
    }

    pub fn set_proposal_status(&self, id: i64, status: &str, now: i64) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE proposals SET status=?1, decided_at=?2 WHERE id=?3",
            params![status, now, id],
        )?;
        Ok(())
    }

    /// Returns false when the event was already stored (journal replay after restart).
    pub fn add_ssh_event(&self, e: &SshEventRow) -> anyhow::Result<bool> {
        Ok(self.conn.execute(
            "INSERT OR IGNORE INTO ssh_events (ts, kind, user, ip, method, location) VALUES (?1,?2,?3,?4,?5,?6)",
            params![e.ts, e.kind, e.user, e.ip, e.method, e.location],
        )? > 0)
    }

    pub fn ssh_events(
        &self,
        since: i64,
        ip: Option<&str>,
        limit: u32,
    ) -> anyhow::Result<Vec<SshEventRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, kind, user, ip, method, location FROM ssh_events
             WHERE ts>=?1 AND (?2 IS NULL OR ip=?2) ORDER BY ts DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![since, ip, limit], |r| {
            Ok(SshEventRow {
                ts: r.get(0)?,
                kind: r.get(1)?,
                user: r.get(2)?,
                ip: r.get(3)?,
                method: r.get(4)?,
                location: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn last_ssh_ts(&self) -> anyhow::Result<Option<i64>> {
        Ok(self
            .conn
            .query_row("SELECT MAX(ts) FROM ssh_events", [], |r| r.get(0))?)
    }

    /// Locations ("CC ASn") this user has logged in from before `before`.
    pub fn known_login_locations(&self, user: &str, before: i64) -> anyhow::Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT location FROM ssh_events
             WHERE kind IN ('accepted','tailscale_login') AND user=?1 AND ts<?2 AND ts>=?3",
        )?;
        let rows = stmt.query_map(params![user, before, before - 90 * 86_400], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_llm_run(&self, r: &LlmRunRow) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO llm_runs (ts, kind, model, prompt_tokens, completion_tokens, summary, proposals)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![r.ts, r.kind, r.model, r.prompt_tokens, r.completion_tokens, r.summary, r.proposals],
        )?;
        Ok(())
    }

    pub fn llm_runs(&self, limit: u32) -> anyhow::Result<Vec<LlmRunRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, kind, model, prompt_tokens, completion_tokens, summary, proposals
             FROM llm_runs ORDER BY ts DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok(LlmRunRow {
                ts: r.get(0)?,
                kind: r.get(1)?,
                model: r.get(2)?,
                prompt_tokens: r.get(3)?,
                completion_tokens: r.get(4)?,
                summary: r.get(5)?,
                proposals: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// (calls, tokens) since `since`.
    pub fn llm_usage(&self, since: i64) -> anyhow::Result<(i64, i64)> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(prompt_tokens + completion_tokens), 0) FROM llm_runs WHERE ts>=?1",
            params![since],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn policy(&self) -> anyhow::Result<Option<PolicyRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT text, rules, compiled_at, compiled_by FROM policy WHERE id=1",
                [],
                |r| {
                    Ok(PolicyRow {
                        text: r.get(0)?,
                        rules: r.get(1)?,
                        compiled_at: r.get(2)?,
                        compiled_by: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_policy(&self, p: Option<&PolicyRow>) -> anyhow::Result<()> {
        match p {
            Some(p) => self.conn.execute(
                "INSERT OR REPLACE INTO policy (id, text, rules, compiled_at, compiled_by) VALUES (1,?1,?2,?3,?4)",
                params![p.text, p.rules, p.compiled_at, p.compiled_by],
            )?,
            None => self.conn.execute("DELETE FROM policy", [])?,
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(
        remote: &str,
        dir: &str,
        rport: u16,
        last_seen: i64,
        name: Option<&str>,
        container: Option<&str>,
        process: &str,
    ) -> FlowRow {
        FlowRow {
            iface: "eth0".into(),
            proto: "tcp".into(),
            local: "192.0.2.10".into(),
            lport: 40000,
            remote: remote.into(),
            rport,
            dir: dir.into(),
            first_seen: last_seen - 10,
            last_seen,
            bytes_in: 1000,
            bytes_out: 100,
            pkts_in: 2,
            pkts_out: 2,
            state: "closed".into(),
            connect_ms: None,
            retrans: 0,
            rst_sent: 0,
            rst_recv: 0,
            pid: Some(1),
            process: Some(process.into()),
            exe: None,
            container: container.map(str::to_string),
            unit: None,
            remote_pid: None,
            remote_process: None,
            remote_container: None,
            remote_unit: None,
            remote_name: name.map(str::to_string),
            app: serde_json::Value::Null,
            country: Some("US".into()),
            asn: Some(64500),
            as_org: Some("EXAMPLE".into()),
            service_port: rport,
            service: None,
            active: false,
            rate_in: 0.0,
            rate_out: 0.0,
        }
    }

    #[test]
    fn destinations_group_outbound_flows_by_remote() {
        let mut s = Store::open(Path::new(":memory:")).unwrap();
        s.add_flows(&[
            flow(
                "198.51.100.1",
                "out",
                443,
                1000,
                Some("api.example.com"),
                Some("app"),
                "node",
            ),
            flow("198.51.100.1", "out", 80, 1100, None, None, "curl"),
            flow("198.51.100.2", "out", 4444, 1050, None, None, "sh"),
            // Inbound, and outbound before the window: not destinations.
            flow("198.51.100.3", "in", 22, 1000, None, None, "sshd"),
            flow("198.51.100.4", "out", 443, 100, None, None, "curl"),
        ])
        .unwrap();
        let mut d = s.destinations(500).unwrap();
        d.sort_by(|a, b| a.remote.cmp(&b.remote));
        assert_eq!(
            d.iter().map(|d| d.remote.as_str()).collect::<Vec<_>>(),
            ["198.51.100.1", "198.51.100.2"]
        );
        let a = &d[0];
        assert_eq!(
            (a.flows, a.bytes_in, a.bytes_out, a.first_seen, a.last_seen),
            (2, 2000, 200, 990, 1100)
        );
        assert_eq!(a.name.as_deref(), Some("api.example.com"));
        assert_eq!(a.ports, ["tcp/443", "tcp/80"]);
        assert_eq!(a.processes, ["app/node", "curl"]);
        assert_eq!(d[1].name, None);
    }
}
