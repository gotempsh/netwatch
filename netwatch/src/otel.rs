//! OpenTelemetry export: metrics and security events pushed over OTLP/HTTP
//! (protobuf) to a collector. Outbound only, like Slack, so nothing new
//! listens and the API stays on loopback.
//!
//! Metrics are aggregates (per host, interface, process, direction); never
//! per source address, which would explode a backend's series count. Per-source
//! detail goes out as events (log records) instead. Both are sent from the
//! SDK's own threads: the metrics reader reads one snapshot of the engine per
//! export, and events wait in a bounded queue that drops new ones while the
//! collector can't keep up.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime},
};

use opentelemetry::{
    KeyValue,
    logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity},
    metrics::{Counter, MeterProvider as _},
};
use opentelemetry_otlp::{LogExporter, MetricExporter, Protocol, WithExportConfig as _};
use opentelemetry_sdk::{
    Resource,
    logs::{BatchConfigBuilder, BatchLogProcessor, SdkLogger, SdkLoggerProvider},
    metrics::{PeriodicReader, SdkMeterProvider},
};

use crate::{
    config::OtelConfig,
    daemon::App,
    engine::{AlertDue, IpoptAlert},
    flows::Dir,
    store::{BanRow, ConnEventRow, SshEventRow},
    util::now_unix,
};

/// Processes reported by name in the per-process metrics; the rest add up as "other".
const TOP_PROCESSES: usize = 20;
/// Events waiting to be sent; while the queue is full, new ones are dropped.
const MAX_QUEUED_EVENTS: usize = 2048;
/// Longest the daemon waits for the last export when it stops.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

pub struct Otel {
    logs: Option<(SdkLoggerProvider, SdkLogger)>,
    meters: Option<SdkMeterProvider>,
    failed_connects: Option<Counter<u64>>,
    /// Findings at or above this score are warnings.
    warn_score: u32,
    interval: Duration,
}

impl Otel {
    /// Builds the exporters when `[otel]` is enabled. Bad settings are logged and
    /// leave export off rather than stopping the daemon.
    pub fn start(cfg: &OtelConfig, host: &str, warn_score: u32) -> Option<Self> {
        if !cfg.enabled || !(cfg.metrics || cfg.logs) {
            return None;
        }
        match Self::build(cfg, host, warn_score) {
            Ok(o) => {
                let what = match (cfg.metrics, cfg.logs) {
                    (true, true) => "metrics and events",
                    (true, false) => "metrics",
                    _ => "events",
                };
                log::info!("opentelemetry: sending {what} to {}", cfg.endpoint);
                Some(o)
            }
            Err(e) => {
                log::error!("opentelemetry export is off: {e:#}");
                None
            }
        }
    }

    fn build(cfg: &OtelConfig, host: &str, warn_score: u32) -> anyhow::Result<Self> {
        check_headers(cfg, |v| std::env::var(v).ok())?;
        let resource = Resource::builder()
            .with_service_name("netwatch")
            .with_attributes([
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                KeyValue::new("host.name", host.to_string()),
                KeyValue::new("os.type", std::env::consts::OS),
            ])
            .build();
        let timeout = Duration::from_secs(10);

        let logs = if cfg.logs {
            let exporter = LogExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(signal_url(&cfg.endpoint, "logs")?)
                .with_timeout(timeout)
                .build()?;
            let processor = BatchLogProcessor::builder(exporter)
                .with_batch_config(
                    BatchConfigBuilder::default()
                        .with_max_queue_size(MAX_QUEUED_EVENTS)
                        .with_scheduled_delay(Duration::from_secs(5))
                        .build(),
                )
                .build();
            let provider = SdkLoggerProvider::builder()
                .with_resource(resource.clone())
                .with_log_processor(processor)
                .build();
            let logger = provider.logger("netwatch");
            Some((provider, logger))
        } else {
            None
        };

        let interval = Duration::from_secs(cfg.interval_secs.max(10));
        let (meters, failed_connects) = if cfg.metrics {
            let exporter = MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(signal_url(&cfg.endpoint, "metrics")?)
                .with_timeout(timeout)
                .build()?;
            let reader = PeriodicReader::builder(exporter)
                .with_interval(interval)
                .build();
            let provider = SdkMeterProvider::builder()
                .with_resource(resource)
                .with_reader(reader)
                .build();
            let failed = provider
                .meter("netwatch")
                .u64_counter("netwatch.connects.failed")
                .with_unit("{connection}")
                .with_description("Outbound connections that failed: refused, reset or timed out")
                .build();
            (Some(provider), Some(failed))
        } else {
            (None, None)
        };

        Ok(Self {
            logs,
            meters,
            failed_connects,
            warn_score,
            interval,
        })
    }

    /// Registers the observable instruments. They hold a weak reference, so the
    /// app and the meter provider it owns can still be dropped.
    pub fn register_metrics(&self, app: Weak<App>) {
        let Some(provider) = &self.meters else {
            return;
        };
        let meter = provider.meter("netwatch");
        let snap = Arc::new(Snapshots {
            app,
            // Within one export every callback reads the same snapshot.
            max_age: Duration::from_secs(2).min(self.interval / 2),
            last: Mutex::new(None),
        });

        macro_rules! counter {
            ($name:literal, $unit:literal, $desc:literal, |$s:ident| $value:expr) => {{
                let snap = snap.clone();
                meter
                    .u64_observable_counter($name)
                    .with_unit($unit)
                    .with_description($desc)
                    .with_callback(move |o| {
                        if let Some($s) = snap.get() {
                            o.observe($value, &[]);
                        }
                    })
                    .build();
            }};
        }
        macro_rules! gauge {
            ($name:literal, $unit:literal, $desc:literal, |$s:ident| $value:expr) => {{
                let snap = snap.clone();
                meter
                    .u64_observable_gauge($name)
                    .with_unit($unit)
                    .with_description($desc)
                    .with_callback(move |o| {
                        if let Some($s) = snap.get() {
                            o.observe($value, &[]);
                        }
                    })
                    .build();
            }};
        }

        counter!(
            "netwatch.packets",
            "{packet}",
            "Packets seen on the monitored interface",
            |s| s.packets
        );
        counter!(
            "netwatch.bytes",
            "By",
            "Bytes seen on the monitored interface",
            |s| s.bytes
        );
        counter!(
            "netwatch.packets.inbound",
            "{packet}",
            "Packets from sources that opened connections to this host",
            |s| s.in_packets
        );
        counter!(
            "netwatch.packets.syn",
            "{packet}",
            "Inbound TCP SYNs",
            |s| s.syn
        );
        counter!(
            "netwatch.packets.banned",
            "{packet}",
            "Packets from banned sources",
            |s| s.banned
        );
        counter!(
            "netwatch.packets.dropped",
            "{packet}",
            "Packets dropped by bans",
            |s| s.dropped
        );
        counter!(
            "netwatch.events.lost",
            "{event}",
            "Kernel events lost because a ring buffer was full",
            |s| s.events_lost
        );

        gauge!(
            "netwatch.sources.tracked",
            "{source}",
            "Addresses being tracked",
            |s| s.sources_tracked
        );
        gauge!(
            "netwatch.sources.active",
            "{source}",
            "Addresses that sent inbound traffic in the last 10 minutes",
            |s| s.sources_active
        );
        gauge!(
            "netwatch.sources.flagged",
            "{source}",
            "Addresses scoring at or above ban.review_score",
            |s| s.sources_flagged
        );
        gauge!("netwatch.bans.active", "{ban}", "Active bans", |s| s.bans);
        gauge!(
            "netwatch.proposals.pending",
            "{proposal}",
            "Proposals waiting for approval",
            |s| s.proposals_pending
        );
        gauge!(
            "netwatch.ssh.failures",
            "{attempt}",
            "Failed SSH logins in the last hour",
            |s| s.ssh_failed_1h
        );
        gauge!(
            "netwatch.listeners.exposed",
            "{socket}",
            "Services listening on an address other than loopback",
            |s| s.listeners_exposed
        );

        let s2 = snap.clone();
        meter
            .u64_observable_gauge("netwatch.flows.active")
            .with_unit("{flow}")
            .with_description("Open connections, by transport and direction")
            .with_callback(move |o| {
                if let Some(s) = s2.get() {
                    for ((transport, dir), n) in &s.flows {
                        o.observe(
                            *n,
                            &[
                                KeyValue::new("network.transport", *transport),
                                KeyValue::new("netwatch.direction", *dir),
                            ],
                        );
                    }
                }
            })
            .build();
        let s2 = snap.clone();
        meter
            .f64_observable_gauge("netwatch.interface.throughput")
            .with_unit("bit/s")
            .with_description("Throughput of each monitored interface")
            .with_callback(move |o| {
                if let Some(s) = s2.get() {
                    for i in &s.interfaces {
                        let name = KeyValue::new("network.interface.name", i.name.clone());
                        o.observe(
                            i.rx_bps,
                            &[
                                name.clone(),
                                KeyValue::new("network.io.direction", "receive"),
                            ],
                        );
                        o.observe(
                            i.tx_bps,
                            &[name, KeyValue::new("network.io.direction", "transmit")],
                        );
                    }
                }
            })
            .build();
        let s2 = snap.clone();
        meter
            .u64_observable_gauge("netwatch.process.flows")
            .with_unit("{flow}")
            .with_description("Open connections by owning process or container")
            .with_callback(move |o| {
                if let Some(s) = s2.get() {
                    for p in &s.processes {
                        o.observe(p.flows, &p.attrs());
                    }
                }
            })
            .build();
        let s2 = snap;
        meter
            .f64_observable_gauge("netwatch.process.throughput")
            .with_unit("bit/s")
            .with_description("Throughput of open connections by owning process or container")
            .with_callback(move |o| {
                if let Some(s) = s2.get() {
                    for p in &s.processes {
                        let mut a = p.attrs();
                        a.push(KeyValue::new("network.io.direction", "receive"));
                        o.observe(p.rx_bps, &a);
                        a.pop();
                        a.push(KeyValue::new("network.io.direction", "transmit"));
                        o.observe(p.tx_bps, &a);
                    }
                }
            })
            .build();
    }

    /// Sends what is queued and stops the export threads, waiting at most
    /// `SHUTDOWN_WAIT` so an unreachable collector can't hold up a restart.
    pub fn shutdown(&self) {
        let logs = self.logs.as_ref().map(|(p, _)| p.clone());
        let meters = self.meters.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Some(p) = logs
                && let Err(e) = p.shutdown_with_timeout(SHUTDOWN_WAIT)
            {
                log::warn!("opentelemetry: flushing events: {e}");
            }
            if let Some(p) = meters
                && let Err(e) = p.shutdown()
            {
                log::warn!("opentelemetry: flushing metrics: {e}");
            }
            let _ = tx.send(());
        });
        if rx.recv_timeout(SHUTDOWN_WAIT).is_err() {
            log::warn!(
                "opentelemetry: the collector didn't answer within {}s; unsent data is lost",
                SHUTDOWN_WAIT.as_secs()
            );
        }
    }

    // ---- events ----

    fn emit(&self, ev: Event) {
        let Some((_, logger)) = &self.logs else {
            return;
        };
        let mut rec = logger.create_log_record();
        rec.set_event_name(ev.name);
        rec.set_timestamp(ev.ts.map_or_else(SystemTime::now, |t| {
            SystemTime::UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)
        }));
        rec.set_observed_timestamp(SystemTime::now());
        rec.set_severity_number(ev.severity);
        rec.set_severity_text(severity_text(ev.severity));
        rec.set_body(AnyValue::from(ev.body));
        for (k, v) in ev.attrs {
            rec.add_attribute(k, v);
        }
        logger.emit(rec);
    }

    pub fn started(&self, mode: &str, interface: &str) {
        self.emit(
            Event::new(
                "netwatch.started",
                Severity::Info,
                format!(
                    "netwatch {} started, {mode} mode on {interface}",
                    env!("CARGO_PKG_VERSION")
                ),
            )
            .attr("netwatch.mode", mode.to_string())
            .attr("network.interface.name", interface.to_string()),
        );
    }

    /// A finding that is new, worse, or still active (repeated every 5 minutes).
    pub fn finding(&self, a: &AlertDue) {
        let sev = if a.score >= self.warn_score {
            Severity::Warn
        } else {
            Severity::Info
        };
        self.emit(
            Event::new("netwatch.finding", sev, a.summary.clone())
                .attr("source.address", a.ip.clone())
                .attr("netwatch.finding.kind", a.kind)
                .attr("netwatch.score", a.score as i64)
                .attr("netwatch.location", a.location.clone()),
        );
    }

    /// A TCP SYN with IPv4 options: the CVE-2026-98432 trigger.
    pub fn ipopt(&self, a: &IpoptAlert) {
        self.emit(
            Event::new(
                "netwatch.finding",
                Severity::Error,
                format!(
                    "{} TCP SYN(s) with IPv4 options ({}), the CVE-2026-98432 trigger",
                    a.syn, a.options
                ),
            )
            .attr("source.address", a.ip.to_string())
            .attr("netwatch.finding.kind", "exploit_attempt")
            .attr("netwatch.cve", "CVE-2026-98432")
            .attr("netwatch.location", a.location.clone())
            .attr("netwatch.allowlisted", a.allowlisted)
            .attr("netwatch.banned", a.banned),
        );
    }

    pub fn proposal(&self, p: &ProposalEvent<'_>) {
        let sev = if p.action == "ban" {
            Severity::Warn
        } else {
            Severity::Info
        };
        let mut ev = Event::new(
            "netwatch.proposal",
            sev,
            format!(
                "proposal #{}: {} {}: {}",
                p.id, p.action, p.target, p.reason
            ),
        )
        .attr("netwatch.proposal.id", p.id)
        .attr("netwatch.action", p.action.to_string())
        .attr("netwatch.target", p.target.to_string())
        .attr("netwatch.proposed_by", p.source.to_string())
        .attr("netwatch.confidence", p.confidence);
        if let Some(t) = p.ttl {
            ev = ev.attr("netwatch.ttl", t);
        }
        self.emit(ev);
    }

    pub fn ban(&self, b: &BanRow) {
        let mut ev = Event::new(
            "netwatch.ban",
            Severity::Warn,
            format!("banned {} ({}): {}", b.target, b.source, b.reason),
        )
        .attr("netwatch.target", b.target.clone())
        .attr("netwatch.banned_by", b.source.clone());
        ev.ts = Some(b.created);
        if let Some(x) = b.expires {
            ev = ev.attr("netwatch.ttl", x - b.created);
        }
        self.emit(ev);
    }

    pub fn unban(&self, target: &str, why: &str) {
        self.emit(
            Event::new(
                "netwatch.unban",
                Severity::Info,
                format!("lifted the ban on {target} ({why})"),
            )
            .attr("netwatch.target", target.to_string())
            .attr("netwatch.reason", why.to_string()),
        );
    }

    pub fn ssh(&self, e: &SshEventRow) {
        let mut ev = Event::new(
            "netwatch.ssh",
            Severity::Info,
            format!(
                "ssh {} {}@{}",
                e.kind.replace('_', " "),
                e.user.as_deref().unwrap_or("?"),
                e.ip
            ),
        )
        .attr("netwatch.ssh.event", e.kind.clone())
        .attr("source.address", e.ip.clone())
        .attr("netwatch.location", e.location.clone());
        ev.ts = Some(e.ts);
        if let Some(u) = &e.user {
            ev = ev.attr("user.name", u.clone());
        }
        if let Some(m) = &e.method {
            ev = ev.attr("netwatch.ssh.method", m.clone());
        }
        self.emit(ev);
    }

    /// Failed outbound connects (counted), and new or closed listeners (as events).
    pub fn conn_events(&self, events: &[ConnEventRow]) {
        if let Some(c) = &self.failed_connects {
            let mut by_transport: BTreeMap<&str, u64> = BTreeMap::new();
            for e in events.iter().filter(|e| e.kind == "connect_failed") {
                *by_transport.entry(&e.proto).or_default() += 1;
            }
            for (transport, n) in by_transport {
                c.add(
                    n,
                    &[KeyValue::new("network.transport", transport.to_string())],
                );
            }
        }
        for e in events
            .iter()
            .filter(|e| e.kind == "listen" || e.kind == "unlisten")
        {
            let exposed = listener_exposed(&e.local);
            // WARN where Slack alerts: a public or wildcard address.
            let public = e
                .local
                .parse::<std::net::IpAddr>()
                .is_ok_and(|a| a.is_unspecified() || crate::util::is_public(a));
            let sev = if e.kind == "listen" && public {
                Severity::Warn
            } else {
                Severity::Info
            };
            let verb = if e.kind == "listen" {
                "started listening on"
            } else {
                "stopped listening on"
            };
            let who = e
                .process
                .clone()
                .unwrap_or_else(|| "unknown process".into());
            let mut ev = Event::new(
                "netwatch.listener",
                sev,
                format!("{who} {verb} {}/{}:{}", e.proto, e.local, e.lport),
            )
            .attr("netwatch.listener.event", e.kind.clone())
            .attr("network.transport", e.proto.clone())
            .attr("server.address", e.local.clone())
            .attr("server.port", e.lport as i64)
            .attr("netwatch.exposed", exposed);
            ev.ts = Some(e.ts);
            if let Some(p) = &e.process {
                ev = ev.attr("process.executable.name", p.clone());
            }
            if let Some(pid) = e.pid {
                ev = ev.attr("process.pid", pid as i64);
            }
            if let Some(c) = &e.container {
                ev = ev.attr("container.name", c.clone());
            }
            if let Some(u) = &e.unit {
                ev = ev.attr("netwatch.unit", u.clone());
            }
            self.emit(ev);
        }
    }
}

pub struct ProposalEvent<'a> {
    pub id: i64,
    pub action: &'a str,
    pub target: &'a str,
    pub ttl: Option<i64>,
    pub reason: &'a str,
    pub source: &'a str,
    pub confidence: f64,
}

struct Event {
    name: &'static str,
    severity: Severity,
    body: String,
    ts: Option<i64>,
    attrs: Vec<(&'static str, AnyValue)>,
}

impl Event {
    fn new(name: &'static str, severity: Severity, body: String) -> Self {
        Self {
            name,
            severity,
            body,
            ts: None,
            attrs: Vec::new(),
        }
    }

    fn attr(mut self, key: &'static str, value: impl Into<AnyValue>) -> Self {
        self.attrs.push((key, value.into()));
        self
    }
}

fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Error => "ERROR",
        Severity::Warn => "WARN",
        _ => "INFO",
    }
}

/// `http://collector:4318` → `http://collector:4318/v1/metrics`. A URL that already
/// names the signal path is used as is.
fn signal_url(endpoint: &str, signal: &str) -> anyhow::Result<String> {
    let e = endpoint.trim().trim_end_matches('/');
    anyhow::ensure!(
        e.starts_with("http://") || e.starts_with("https://"),
        "otel.endpoint must start with http:// or https:// (got {endpoint:?})"
    );
    let path = format!("/v1/{signal}");
    if let Some(base) = e
        .strip_suffix("/v1/metrics")
        .or_else(|| e.strip_suffix("/v1/logs"))
    {
        return Ok(format!("{base}{path}"));
    }
    Ok(format!("{e}{path}"))
}

/// Exposed as the API and UI mean it (and `netwatch.listeners.exposed` counts
/// it): bound to anything but loopback, LAN and wildcard addresses included.
fn listener_exposed(local: &str) -> bool {
    local
        .parse::<std::net::IpAddr>()
        .is_ok_and(|a| !a.is_loopback())
}

/// The exporter reads the request headers itself, from the signal's own
/// variable (`OTEL_EXPORTER_OTLP_LOGS_HEADERS`, `..._METRICS_HEADERS`) or else
/// `OTEL_EXPORTER_OTLP_HEADERS`, and drops entries it can't parse without a
/// word. This checks the same variables first, so a bad entry turns export off
/// with an error instead of sending requests the backend rejects.
fn check_headers(cfg: &OtelConfig, var: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
    const ALL: &str = "OTEL_EXPORTER_OTLP_HEADERS";
    for (on, own) in [
        (cfg.logs, "OTEL_EXPORTER_OTLP_LOGS_HEADERS"),
        (cfg.metrics, "OTEL_EXPORTER_OTLP_METRICS_HEADERS"),
    ] {
        if !on {
            continue;
        }
        if let Some((name, v)) = var(own)
            .map(|v| (own, v))
            .or_else(|| var(ALL).map(|v| (ALL, v)))
        {
            check_header_list(&v, name)?;
        }
    }
    Ok(())
}

/// `key=value,key2=value2`, values percent-encoded. The error never quotes an
/// entry: it may hold a token.
fn check_header_list(s: &str, var: &str) -> anyhow::Result<()> {
    for (n, part) in s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .enumerate()
    {
        let bad = |why: &str| {
            anyhow::anyhow!(
                "${var}: entry {} {why} (write `Authorization=Bearer%20...`, not `Authorization: Bearer ...`)",
                n + 1
            )
        };
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| bad("is not key=value"))?;
        let k = k.trim();
        // What the exporter's HeaderName and HeaderValue accept.
        if k.is_empty()
            || !k
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(bad("has a name that isn't a valid header name"));
        }
        if !v.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err(bad(
                "has a value that isn't printable ASCII (percent-encode it)",
            ));
        }
    }
    Ok(())
}

// ---- metrics snapshot ----

struct Snapshots {
    app: Weak<App>,
    max_age: Duration,
    last: Mutex<Option<(Instant, Arc<Snapshot>)>>,
}

impl Snapshots {
    fn get(&self) -> Option<Arc<Snapshot>> {
        let mut last = self.last.lock().unwrap();
        if let Some((at, s)) = &*last
            && at.elapsed() < self.max_age
        {
            return Some(s.clone());
        }
        let app = self.app.upgrade()?;
        let s = Arc::new(Snapshot::take(&app));
        *last = Some((Instant::now(), s.clone()));
        Some(s)
    }
}

#[derive(Default)]
struct Snapshot {
    packets: u64,
    bytes: u64,
    in_packets: u64,
    syn: u64,
    banned: u64,
    dropped: u64,
    events_lost: u64,
    sources_tracked: u64,
    sources_active: u64,
    sources_flagged: u64,
    bans: u64,
    proposals_pending: u64,
    ssh_failed_1h: u64,
    listeners_exposed: u64,
    /// (transport, direction) → open flows.
    flows: BTreeMap<(&'static str, &'static str), u64>,
    interfaces: Vec<IfaceRate>,
    processes: Vec<ProcessRate>,
}

struct IfaceRate {
    name: String,
    rx_bps: f64,
    tx_bps: f64,
}

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProcessKey {
    name: String,
    container: Option<String>,
    unit: Option<String>,
}

struct ProcessRate {
    key: ProcessKey,
    flows: u64,
    rx_bps: f64,
    tx_bps: f64,
}

impl ProcessRate {
    fn attrs(&self) -> Vec<KeyValue> {
        let mut a = vec![KeyValue::new(
            "process.executable.name",
            self.key.name.clone(),
        )];
        if let Some(c) = &self.key.container {
            a.push(KeyValue::new("container.name", c.clone()));
        }
        if let Some(u) = &self.key.unit {
            a.push(KeyValue::new("netwatch.unit", u.clone()));
        }
        a
    }
}

impl Snapshot {
    fn take(app: &App) -> Self {
        let now = now_unix();
        let review = app.cfg.ban.review_score;
        let mut s = {
            let e = app.engine.lock().unwrap();
            let g = &e.global;
            let mut s = Snapshot {
                packets: g.packets,
                bytes: g.bytes,
                in_packets: g.in_packets,
                syn: g.syn,
                banned: g.blocked,
                dropped: g.dropped,
                events_lost: g.events_lost + g.sock_events_lost,
                sources_tracked: e.states.len() as u64,
                sources_active: e
                    .states
                    .values()
                    .filter(|s| s.total.in_packets > 0 && s.last_inbound >= now - 600)
                    .count() as u64,
                sources_flagged: e
                    .states
                    .values()
                    .filter(|s| s.score >= review && !s.allowlisted)
                    .count() as u64,
                bans: e.bans.len() as u64,
                ssh_failed_1h: e
                    .states
                    .values()
                    .map(|s| s.ssh_failed_within(now, 3600))
                    .sum(),
                listeners_exposed: e
                    .flows
                    .listeners
                    .values()
                    .filter(|l| l.exposed && l.role != crate::flows::SockRole::Client)
                    .count() as u64,
                interfaces: e
                    .ifaces
                    .iter()
                    .filter(|i| i.flows || i.xdp)
                    .map(|i| IfaceRate {
                        name: i.info.name.clone(),
                        rx_bps: i.rx_bps,
                        tx_bps: i.tx_bps,
                    })
                    .collect(),
                ..Default::default()
            };
            let mut procs: BTreeMap<ProcessKey, ProcessRate> = BTreeMap::new();
            for f in e.flows.active.values() {
                let dir = match f.dir {
                    Dir::In => "in",
                    Dir::Out => "out",
                    Dir::Unknown => "unknown",
                };
                *s.flows
                    .entry((crate::util::proto_name(f.key.proto), dir))
                    .or_default() += 1;
                let key = match &f.owner {
                    Some(o) => ProcessKey {
                        name: o.comm.clone(),
                        container: o.container.clone(),
                        unit: o.unit.clone(),
                    },
                    None => ProcessKey {
                        name: "unknown".into(),
                        ..Default::default()
                    },
                };
                let p = procs.entry(key.clone()).or_insert(ProcessRate {
                    key,
                    flows: 0,
                    rx_bps: 0.0,
                    tx_bps: 0.0,
                });
                p.flows += 1;
                p.rx_bps += f.rate_in * 8.0;
                p.tx_bps += f.rate_out * 8.0;
            }
            s.processes = top_processes(procs.into_values().collect(), TOP_PROCESSES);
            s
        };
        s.proposals_pending = app
            .store
            .lock()
            .unwrap()
            .proposals(true, None, 10_000)
            .map_or(0, |p| p.len() as u64);
        s
    }
}

/// The `n` busiest processes by name; the others are summed under "other".
fn top_processes(mut all: Vec<ProcessRate>, n: usize) -> Vec<ProcessRate> {
    all.sort_by(|a, b| {
        (b.rx_bps + b.tx_bps)
            .total_cmp(&(a.rx_bps + a.tx_bps))
            .then(b.flows.cmp(&a.flows))
            .then(a.key.cmp(&b.key))
    });
    if all.len() <= n {
        return all;
    }
    let rest = all.split_off(n);
    all.push(ProcessRate {
        key: ProcessKey {
            name: "other".into(),
            ..Default::default()
        },
        flows: rest.iter().map(|p| p.flows).sum(),
        rx_bps: rest.iter().map(|p| p.rx_bps).sum(),
        tx_bps: rest.iter().map(|p| p.tx_bps).sum(),
    });
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = include_str!("../../site/content/opentelemetry.md");

    #[test]
    fn the_documented_headers_are_accepted() {
        let mut n = 0;
        for line in DOC.lines() {
            if let Some((var, value)) = line.split_once('=')
                && var.starts_with("OTEL_EXPORTER_OTLP_")
            {
                check_header_list(value, var).unwrap_or_else(|e| panic!("{line}: {e}"));
                n += 1;
            }
        }
        assert!(n >= 3, "found {n} header examples");
    }

    #[test]
    fn the_documented_settings_exist() {
        let known = toml::Value::try_from(OtelConfig::default()).unwrap();
        let mut n = 0;
        for block in DOC.split("```toml\n").skip(1) {
            let block = block.split("```").next().unwrap();
            let doc: toml::Value = toml::from_str(block).unwrap_or_else(|e| panic!("{block}: {e}"));
            let otel = doc["otel"].as_table().expect("an [otel] table");
            for key in otel.keys() {
                assert!(known.get(key).is_some(), "otel.{key} is not a setting");
            }
            let cfg: crate::config::Config = toml::from_str(block).unwrap();
            assert!(cfg.otel.enabled);
            signal_url(&cfg.otel.endpoint, "logs").unwrap();
            n += 1;
        }
        assert!(n >= 3, "found {n} examples");
    }

    #[test]
    fn signal_urls() {
        let u = |e: &str, s: &str| signal_url(e, s).unwrap();
        assert_eq!(
            u("http://otel:4318", "metrics"),
            "http://otel:4318/v1/metrics"
        );
        assert_eq!(
            u("https://otlp.example.com/otlp/", "logs"),
            "https://otlp.example.com/otlp/v1/logs"
        );
        assert_eq!(
            u("http://otel:4318/v1/metrics", "logs"),
            "http://otel:4318/v1/logs"
        );
        assert!(signal_url("otel:4318", "logs").is_err());
    }

    #[test]
    fn exposed_listeners() {
        for a in [
            "0.0.0.0",
            "::",
            "203.0.113.1",
            "10.0.0.5",
            "172.17.0.1",
            "100.64.0.1",
        ] {
            assert!(listener_exposed(a), "{a}");
        }
        for a in ["127.0.0.1", "::1", ""] {
            assert!(!listener_exposed(a), "{a}");
        }
    }

    #[test]
    fn headers() {
        check_header_list(
            "Authorization=Basic%20dXNlcjpwdw==, x-scope-orgid = tenant1,",
            "H",
        )
        .unwrap();
        let err = |s: &str| check_header_list(s, "H").unwrap_err().to_string();
        let e = err("x=1,Authorization: Bearer s3cret");
        assert!(e.contains("entry 2") && !e.contains("s3cret"), "{e}");
        let e = err("Authorization Bearer=s3cret");
        assert!(e.contains("header name") && !e.contains("s3cret"), "{e}");
        let e = err("t=tok%Aé");
        assert!(e.contains("printable") && !e.contains("tok"), "{e}");
    }

    #[test]
    fn checks_the_variables_the_exporter_reads() {
        fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
            let vars: Vec<(String, String)> = vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
        }
        let cfg = OtelConfig::default();
        assert!(check_headers(&cfg, env(&[])).is_ok());
        let bad = "Authorization: Bearer s3cret";
        let e = check_headers(&cfg, env(&[("OTEL_EXPORTER_OTLP_HEADERS", bad)]))
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("$OTEL_EXPORTER_OTLP_HEADERS:"), "{e}");
        // A signal's own variable wins over the general one, as in the exporter.
        let e = check_headers(
            &cfg,
            env(&[
                ("OTEL_EXPORTER_OTLP_HEADERS", "a=1"),
                ("OTEL_EXPORTER_OTLP_METRICS_HEADERS", bad),
            ]),
        )
        .unwrap_err()
        .to_string();
        assert!(e.starts_with("$OTEL_EXPORTER_OTLP_METRICS_HEADERS:"), "{e}");
        assert!(
            check_headers(
                &cfg,
                env(&[
                    ("OTEL_EXPORTER_OTLP_HEADERS", bad),
                    ("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "a=1"),
                    ("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "b=2"),
                ])
            )
            .is_ok()
        );
        // Signals that are off aren't checked.
        let metrics_only = OtelConfig {
            logs: false,
            ..Default::default()
        };
        assert!(
            check_headers(
                &metrics_only,
                env(&[("OTEL_EXPORTER_OTLP_LOGS_HEADERS", bad)])
            )
            .is_ok()
        );
    }

    /// Accepts OTLP/HTTP requests and keeps (path, content type, body).
    type Requests = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

    fn receiver() -> (String, Requests) {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let got = Arc::new(Mutex::new(Vec::new()));
        let seen = got.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let seen = seen.clone();
                std::thread::spawn(move || {
                    let mut conn = conn.unwrap();
                    let mut r = BufReader::new(conn.try_clone().unwrap());
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                        let (mut len, mut ctype) = (0, String::new());
                        loop {
                            let mut h = String::new();
                            r.read_line(&mut h).unwrap();
                            let h = h.trim_end();
                            if h.is_empty() {
                                break;
                            }
                            let (k, v) = h.split_once(':').unwrap();
                            match k.to_ascii_lowercase().as_str() {
                                "content-length" => len = v.trim().parse().unwrap(),
                                "content-type" => ctype = v.trim().to_string(),
                                _ => {}
                            }
                        }
                        let mut body = vec![0; len];
                        r.read_exact(&mut body).unwrap();
                        seen.lock().unwrap().push((path, ctype, body));
                        conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                            .unwrap();
                    }
                });
            }
        });
        (url, got)
    }

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn exports_events_and_metrics_over_otlp_http() {
        let (url, got) = receiver();
        let cfg = OtelConfig {
            enabled: true,
            endpoint: url,
            ..Default::default()
        };
        let o = Otel::start(&cfg, "edge-01", 70).expect("exporter");
        o.finding(&AlertDue {
            ip: "203.0.113.9".into(),
            kind: "port_scan",
            score: 88,
            summary: "SYN scan of 1,870 ports in 1h".into(),
            location: "RU AS49505".into(),
        });
        let failed = ConnEventRow {
            ts: 1_700_000_000,
            kind: "connect_failed".into(),
            proto: "tcp".into(),
            local: "198.51.100.2".into(),
            lport: 40_000,
            remote: Some("192.0.2.1".into()),
            rport: Some(443),
            pid: Some(42),
            process: Some("curl".into()),
            container: None,
            unit: None,
            detail: String::new(),
        };
        o.conn_events(std::slice::from_ref(&failed));
        o.ban(&BanRow {
            target: "203.0.113.9/32".into(),
            created: 1_700_000_000,
            expires: Some(1_700_086_400),
            reason: "[default:scanner] wide port scan".into(),
            source: "rules".into(),
        });
        o.unban("203.0.113.9/32", "expired");
        o.ssh(&SshEventRow {
            ts: 1_700_000_100,
            kind: "invalid_user".into(),
            user: Some("oracle".into()),
            ip: "198.51.100.66".into(),
            method: Some("password".into()),
            location: "CN AS4134".into(),
        });
        o.conn_events(&[ConnEventRow {
            kind: "listen".into(),
            local: "0.0.0.0".into(),
            lport: 6379,
            rport: None,
            remote: None,
            process: Some("redis-server".into()),
            ..failed.clone()
        }]);
        o.shutdown();

        let got = got.lock().unwrap();
        let logs: Vec<_> = got.iter().filter(|(p, ..)| p == "/v1/logs").collect();
        let metrics: Vec<_> = got.iter().filter(|(p, ..)| p == "/v1/metrics").collect();
        assert!(
            !logs.is_empty() && !metrics.is_empty(),
            "requests: {:?}",
            got.iter().map(|g| &g.0).collect::<Vec<_>>()
        );
        assert_eq!(logs[0].1, "application/x-protobuf");
        let all: Vec<u8> = logs.iter().flat_map(|(.., b)| b.clone()).collect();
        for s in [
            "netwatch.finding",
            "source.address",
            "203.0.113.9",
            "port_scan",
            "service.name",
            "edge-01",
            "netwatch.ban",
            "netwatch.unban",
            "netwatch.ssh",
            "oracle",
            "netwatch.listener",
            "redis-server",
        ] {
            assert!(contains(&all, s), "log export lacks {s:?}");
        }
        assert!(
            metrics
                .iter()
                .any(|(.., b)| contains(b, "netwatch.connects.failed"))
        );
    }

    #[test]
    fn busiest_processes_and_the_rest() {
        let p = |name: &str, bps: f64| ProcessRate {
            key: ProcessKey {
                name: name.into(),
                ..Default::default()
            },
            flows: 1,
            rx_bps: bps,
            tx_bps: 0.0,
        };
        let top = top_processes(vec![p("a", 1.0), p("b", 5.0), p("c", 3.0), p("d", 2.0)], 2);
        let names: Vec<&str> = top.iter().map(|p| p.key.name.as_str()).collect();
        assert_eq!(names, ["b", "c", "other"]);
        assert_eq!(top[2].flows, 2);
        assert_eq!(top[2].rx_bps, 3.0);
        assert_eq!(top_processes(vec![p("a", 1.0)], 2).len(), 1);
    }
}
