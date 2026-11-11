//! Daemon wiring: loads XDP, runs the collection tick, applies bans and
//! proposals, follows SSH logs and drives the optional LLM analysis.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context as _, anyhow, bail};
#[cfg(target_os = "linux")]
use aya::maps::{MapData, RingBuf};
use ipnet::IpNet;
use netwatch_common::{PayloadEvent, ProbeEvent, SockEvent};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;

use crate::{
    config::{Config, Mode},
    engine::{Engine, SshEvent},
    geo::Geo,
    intel,
    kernel::{Kernel, WantIf},
    llm::Llm,
    netif,
    notify::{Level, Notifier},
    policy::{self, Action, Rule},
    procs::OwnerCache,
    store::{BanRow, HourDelta, NewProposal, PolicyRow, SshEventRow, Store},
    util::{is_public, now_unix, parse_duration, parse_target},
};

/// Lock order, when more than one is needed: kernel, engine, store.
pub struct App {
    pub cfg: Arc<Config>,
    pub kernel: Mutex<Kernel>,
    pub engine: Mutex<Engine>,
    pub store: Mutex<Store>,
    pub llm: Option<Llm>,
    pub started: i64,
    pub host: String,
    /// Config allowlist + discovered peers + Cloudflare; DB allow rules are added on top.
    base_allow: Mutex<BTreeSet<IpNet>>,
    /// The last discovered peers, kept for a discovery command that times out.
    peers: Mutex<intel::Peers>,
    llm_last_run: Mutex<Option<i64>>,
    /// Owner lookups for the periodic /proc socket scan (tick thread only).
    scan_owners: Mutex<OwnerCache>,
    /// Interface addresses, refreshed once a minute.
    if_addrs: Mutex<BTreeMap<String, Vec<String>>>,
    pub notify: Notifier,
    /// Hours before this one are compacted already (`Store::compact_window_bytes`).
    window_compacted: AtomicI64,
    /// OpenTelemetry export, when `[otel]` is enabled.
    pub otel: Option<crate::otel::Otel>,
}

/// Interfaces that should carry the flow programs right now.
fn wanted_interfaces(cfg: &Config, list: &[netif::IfInfo]) -> Vec<WantIf> {
    if !cfg.track_flows {
        return Vec::new();
    }
    list.iter()
        .filter(|i| {
            i.name == cfg.interface
                || (i.up
                    && cfg
                        .flow_interfaces
                        .iter()
                        .any(|p| netif::matches(p, &i.name)))
        })
        .filter_map(|i| {
            Some(WantIf {
                name: i.name.clone(),
                ifindex: i.ifindex,
                flags: i.flow_flags()?,
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn ephemeral_range() -> (u16, u16) {
    let first = crate::macos::sysctl_u32("net.inet.ip.portrange.first");
    let last = crate::macos::sysctl_u32("net.inet.ip.portrange.last");
    match (first, last) {
        (Some(a), Some(b)) if a <= b && b <= 65535 => (a as u16, b as u16),
        _ => (49152, 65535),
    }
}

#[cfg(target_os = "linux")]
fn ephemeral_range() -> (u16, u16) {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|s| {
            let mut it = s.split_whitespace().filter_map(|x| x.parse().ok());
            Some((it.next()?, it.next()?))
        })
        .unwrap_or((32768, 60999))
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let store = Store::open(&cfg.db_path)?;
    let geo = Geo::open(&cfg.geoip_city, &cfg.geoip_asn);
    #[cfg(target_os = "linux")]
    crate::host::ensure_tracefs();
    let (mut kernel, rings) = Kernel::load(&cfg.interface, &cfg.xdp_mode)?;
    let eph = ephemeral_range();
    let sampling = cfg.track_flows;
    kernel.configure(
        cfg.drop_banned,
        cfg.drop_syn_ip_options,
        sampling && cfg.sample_dns,
        sampling && cfg.sample_tcp_payload,
        eph,
    )?;
    log::info!(
        "{} attached to {} in {} mode",
        crate::kernel::ENGINE,
        cfg.interface,
        kernel.attach_mode
    );
    let if_addrs = netif::addresses();
    let ifl = netif::list_with(&if_addrs);
    kernel.sync_interfaces(&wanted_interfaces(&cfg, &ifl));
    let attached: BTreeSet<String> = kernel.attached.keys().cloned().collect();

    let mut engine = Engine::new(cfg.clone(), geo, eph);
    // The last hour's byte totals, so short windows survive a restart.
    engine
        .bytes
        .restore(store.window_minutes(now_unix() - 3_600)?);
    engine.observe_ifaces(ifl, &attached, 1.0);
    if let Some(p) = store.policy()? {
        match serde_json::from_str::<Vec<Rule>>(&p.rules) {
            Ok(rules) => engine.user_rules = rules,
            Err(e) => log::error!("stored policy rules are unreadable, ignoring them: {e}"),
        }
    }
    let llm = if cfg.llm.enabled {
        Some(Llm::new(&cfg.llm)?)
    } else {
        None
    };
    let host = crate::host::hostname();
    let notify = Notifier::start(&cfg.slack, &host);
    let otel = crate::otel::Otel::start(&cfg.otel, &host, cfg.ban.recommend_ban_score);

    let app = Arc::new(App {
        cfg: cfg.clone(),
        kernel: Mutex::new(kernel),
        engine: Mutex::new(engine),
        store: Mutex::new(store),
        llm,
        started: now_unix(),
        host: host.clone(),
        base_allow: Mutex::new(BTreeSet::new()),
        peers: Mutex::new(intel::Peers::new()),
        llm_last_run: Mutex::new(None),
        scan_owners: Mutex::new(OwnerCache::default()),
        if_addrs: Mutex::new(if_addrs),
        notify,
        window_compacted: AtomicI64::new(i64::MIN),
        otel,
    });
    if let Some(o) = &app.otel {
        o.register_metrics(Arc::downgrade(&app));
        o.started(&format!("{:?}", cfg.mode).to_lowercase(), &cfg.interface);
    }
    app.notify.send(
        Level::Info,
        format!("netwatch {} started", env!("CARGO_PKG_VERSION")),
        format!(
            "{:?} mode on {} ({} {})",
            cfg.mode,
            cfg.interface,
            crate::kernel::ENGINE,
            app.kernel.lock().unwrap().attach_mode
        ),
        None,
    );

    let result = serve(&app, &cfg, rings).await;
    if let Some(o) = &app.otel {
        // Whatever ended the daemon, send what is queued. The tick thread holds
        // the App, so nothing would be flushed when it is dropped.
        // Flushing makes HTTP requests; keep them off the async workers.
        tokio::task::block_in_place(|| o.shutdown());
    }
    result
}

/// Everything after the App exists: the tasks, waiting for a signal, and the
/// final writes.
async fn serve(app: &Arc<App>, cfg: &Config, rings: crate::kernel::Rings) -> anyhow::Result<()> {
    app.refresh_allowlist().await?;
    app.restore_bans()?;
    app.check_sshd();

    tokio::spawn(read_ring(app.clone(), rings.probes, on_probes));
    tokio::spawn(read_ring(app.clone(), rings.socks, on_socks));
    tokio::spawn(read_ring(app.clone(), rings.payloads, on_payloads));
    tokio::spawn(crate::ssh::follow(app.clone()));
    if cfg.temps.enabled {
        tokio::spawn(crate::temps::serve(app.clone()));
    }
    tokio::spawn(refresh_feeds(app.clone()));
    tokio::spawn({
        let app = app.clone();
        async move {
            loop {
                tokio::time::sleep(Duration::from_secs(600)).await;
                if let Err(e) = app.refresh_allowlist().await {
                    log::warn!("allowlist refresh: {e:#}");
                }
            }
        }
    });
    if app.llm.is_some() {
        tokio::spawn(llm_loop(app.clone()));
    }
    tokio::spawn(crate::control::serve(app.clone()));
    tokio::spawn(crate::api::serve(app.clone()));

    let tick_app = app.clone();
    std::thread::Builder::new()
        .name("tick".into())
        .spawn(move || tick_loop(tick_app))?;

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
    }
    if cfg!(target_os = "macos") {
        log::info!("shutting down; removing the pf rules");
    } else {
        log::info!("shutting down; detaching the XDP and TC programs");
    }
    app.kernel.lock().unwrap().shutdown();
    // Keep what was still open: long-lived connections only reach the store when they end.
    let now = now_unix();
    let (rows, dns, events, minutes) = {
        let mut e = app.engine.lock().unwrap();
        e.fold_bytes(now, true);
        e.bytes.close();
        let (mut rows, dns, events) = e.take_flow_archive(now);
        rows.extend(e.drain_flows(now));
        (rows, dns, events, e.bytes.take_unsaved())
    };
    if let Some(o) = &app.otel {
        o.conn_events(&events);
    }
    let mut store = app.store.lock().unwrap();
    store.add_flows(&rows)?;
    store.add_dns(&dns)?;
    store.add_conn_events(&events)?;
    store.add_window_bytes(&minutes)?;
    Ok(())
}

fn on_probes(app: &App, batch: &[ProbeEvent]) {
    let mut e = app.engine.lock().unwrap();
    for ev in batch {
        e.observe_event(ev);
    }
}

fn on_socks(app: &App, batch: &[SockEvent]) {
    let now = now_unix();
    let mut e = app.engine.lock().unwrap();
    let clock = e.clock;
    for ev in batch {
        e.flows.observe_sock(ev, &clock, now);
    }
}

fn on_payloads(app: &App, batch: &[PayloadEvent]) {
    let now = now_unix();
    let mut e = app.engine.lock().unwrap();
    for ev in batch {
        e.flows.observe_payload(ev, now);
    }
}

/// Hands each batch the capture threads send to `handle`.
#[cfg(target_os = "macos")]
async fn read_ring<T: Send + 'static>(
    app: Arc<App>,
    mut ring: tokio::sync::mpsc::Receiver<Vec<T>>,
    handle: fn(&App, &[T]),
) {
    while let Some(batch) = ring.recv().await {
        handle(&app, &batch);
    }
}

/// Drains a ring buffer of `T` records and hands each batch to `handle`.
#[cfg(target_os = "linux")]
async fn read_ring<T: Copy + Send + 'static>(
    app: Arc<App>,
    ring: RingBuf<MapData>,
    handle: fn(&App, &[T]),
) {
    // SAFETY: the RingBuf owns its map fd, which stays open and unchanged while the AsyncFd owns it.
    let mut fd = match unsafe { AsyncFd::register(ring) } {
        Ok(fd) => fd,
        Err(e) => {
            log::error!("ring buffer: {e}");
            return;
        }
    };
    loop {
        let Ok(mut guard) = fd.readable_mut().await else {
            return;
        };
        let mut batch = Vec::new();
        {
            let rb = guard.get_inner_mut();
            while let Some(item) = rb.next() {
                if item.len() >= size_of::<T>() {
                    batch.push(unsafe { std::ptr::read_unaligned(item.as_ptr() as *const T) });
                }
                // Bound the time the engine lock is held per batch.
                if batch.len() >= 4096 {
                    break;
                }
            }
        }
        if batch.len() < 4096 {
            guard.clear_ready();
        }
        if !batch.is_empty() {
            handle(&app, &batch);
        }
    }
}

async fn refresh_feeds(app: Arc<App>) {
    const EVERY: Duration = Duration::from_secs(6 * 3600);
    // Attaching XDP in driver mode resets some NICs (igb), so the first fetch
    // often fails; retry quickly with backoff instead of waiting a full cycle.
    let mut retry = Duration::from_secs(15);
    loop {
        let mut wait = EVERY;
        if !app.cfg.feeds.is_empty() {
            let feeds = intel::fetch_feeds(&app.cfg.feeds).await;
            if feeds.lists.len() < app.cfg.feeds.len() {
                wait = retry;
                retry = (retry * 2).min(EVERY);
            } else {
                retry = Duration::from_secs(15);
            }
            if !feeds.lists.is_empty() {
                app.engine.lock().unwrap().set_feeds(feeds);
            }
        }
        tokio::time::sleep(wait).await;
    }
}

fn tick_loop(app: Arc<App>) {
    let period = Duration::from_secs(app.cfg.tick_secs);
    let mut last = Instant::now();
    let mut n: u64 = 0;
    loop {
        std::thread::sleep(period.saturating_sub(last.elapsed()));
        let dt = last.elapsed().as_secs_f64().max(0.001);
        last = Instant::now();
        if let Err(e) = app.tick(dt, n) {
            log::error!("tick: {e:#}");
        }
        n += 1;
    }
}

impl App {
    fn tick(&self, dt: f64, n: u64) -> anyhow::Result<()> {
        let now = now_unix();
        let periodic = n.is_multiple_of((60 / self.cfg.tick_secs.max(1)).max(1));
        let tracking = self.cfg.track_flows;
        if periodic {
            let addrs = netif::addresses();
            *self.if_addrs.lock().unwrap() = addrs;
        }
        let ifl = netif::list_with(&self.if_addrs.lock().unwrap());
        // Socket owners from /proc every ~15 s, outside every lock.
        let scan = (tracking && n.is_multiple_of((15 / self.cfg.tick_secs.max(1)).max(1)))
            .then(|| crate::procs::scan(&mut self.scan_owners.lock().unwrap(), now));
        let (sources, probes, global, kflows, health, attached) = {
            let mut k = self.kernel.lock().unwrap();
            if periodic {
                k.sync_interfaces(&wanted_interfaces(&self.cfg, &ifl));
            }
            let (kflows, health) = if tracking {
                (k.flows(), k.tcp_health())
            } else {
                (Vec::new(), Vec::new())
            };
            let attached: BTreeSet<String> = k.attached.keys().cloned().collect();
            (
                k.sources(),
                k.probes(),
                k.global(),
                kflows,
                health,
                attached,
            )
        };
        let (
            alerts,
            ipopt,
            hours,
            decisions,
            subnets,
            flow_delete,
            health_delete,
            archived,
            minutes,
        ) = {
            let mut e = self.engine.lock().unwrap();
            if periodic {
                e.listening = intel::Listening::scan();
                if e.geo.reload_if_changed() {
                    e.bytes.forget_places();
                }
                e.prune(now);
                e.flows.prune(now);
            }
            e.observe_ifaces(ifl, &attached, dt);
            if let Some(scan) = scan {
                e.flows.apply_scan(scan, now);
            }
            let clock = e.clock;
            let flow_delete = e.flows.observe(kflows, &health, &clock, now, dt);
            let health_delete = if periodic {
                e.flows.stale_health(&health, &clock, now)
            } else {
                Vec::new()
            };
            e.fold_bytes(now, false);
            let minutes = e.bytes.take_unsaved();
            let archived = e.take_flow_archive(now);
            e.observe_global(global, now, dt);
            e.observe_sources(sources, now, dt);
            e.observe_probes(probes, now);
            e.evaluate(now);
            let subnets: Vec<(IpNet, String)> = e
                .subnet_candidates()
                .into_iter()
                .map(|(net, members)| {
                    let ips: Vec<String> =
                        members.iter().take(5).map(|s| s.ip.to_string()).collect();
                    (
                        net,
                        format!(
                            "{} flagged sources in {net} ({})",
                            members.len(),
                            ips.join(", ")
                        ),
                    )
                })
                .collect();
            (
                e.alerts_due(now),
                e.ipopt_alerts_due(now),
                e.take_hour_deltas(),
                e.decisions(now),
                subnets,
                flow_delete,
                health_delete,
                archived,
                minutes,
            )
        };
        let mitigation = if ipopt.is_empty() {
            None
        } else {
            crate::insights::ipopt_mitigation(&self.cfg)
        };
        for a in &ipopt {
            let state = match (a.banned, a.allowlisted) {
                (true, _) => " It is already banned.",
                (false, true) => " It is allowlisted, so no ban is proposed: check that machine.",
                _ => "",
            };
            let guard = match &mitigation {
                Some(m) => format!("They didn't reach the TCP stack: {m}."),
                None => "They reached the kernel: make sure it is patched, or set drop_syn_ip_options = true in netwatch.toml and restart netwatch."
                    .to_string(),
            };
            log::warn!(
                "CVE-2026-98432 trigger from {} ({}): {} SYN(s) with IPv4 options",
                a.ip,
                a.location,
                a.syn
            );
            self.notify.send(
                Level::Critical,
                format!("CVE-2026-98432 trigger from {}", a.ip),
                format!(
                    "{} sent {} TCP SYN(s) carrying IPv4 options ({}), the input for the Linux TCP use-after-free. {guard}{state}",
                    a.location, a.syn, a.options
                ),
                Some(format!("netwatch ip {}", a.ip)),
            );
            if let Some(o) = &self.otel {
                o.ipopt(a);
            }
        }
        if !flow_delete.is_empty() || !health_delete.is_empty() {
            let mut k = self.kernel.lock().unwrap();
            k.delete_flows(&flow_delete);
            k.delete_health(&health_delete);
        }

        // A failed write keeps the minutes for the next tick and doesn't stop
        // the rest of this one.
        if !minutes.is_empty() {
            let stored = self.store.lock().unwrap().add_window_bytes(&minutes);
            if let Err(err) = stored {
                let dropped = self.engine.lock().unwrap().bytes.requeue(minutes);
                if dropped > 0 {
                    log::warn!(
                        "couldn't store the byte totals: {err:#}; dropped {dropped} minute(s) over an hour old"
                    );
                } else {
                    log::warn!("couldn't store the byte totals, retrying next tick: {err:#}");
                }
            }
        }
        {
            let mut store = self.store.lock().unwrap();
            let (flows, dns, events) = &archived;
            if !flows.is_empty() {
                store.add_flows(flows)?;
            }
            if !dns.is_empty() {
                store.add_dns(dns)?;
            }
            if !events.is_empty() {
                store.add_conn_events(events)?;
                self.notify_listeners(events);
                if let Some(o) = &self.otel {
                    o.conn_events(events);
                }
            }
            for a in &alerts {
                store.upsert_alert(&a.ip, a.kind, a.score, &a.summary, &a.location, now)?;
                if let Some(o) = &self.otel {
                    o.finding(a);
                }
            }
            if !hours.is_empty() {
                let rows: Vec<HourDelta<'_>> = hours
                    .iter()
                    .map(|h| HourDelta {
                        ip: &h.ip,
                        country: &h.country,
                        location: &h.location,
                        in_packets: h.delta.in_packets,
                        in_bytes: h.delta.in_bytes,
                        syn: h.delta.syn,
                        blocked: h.delta.blocked,
                        score: h.score,
                    })
                    .collect();
                store.record_hourly(now - now % 3600, &rows)?;
            }
            if periodic {
                store.prune(self.cfg.retention_days, now)?;
                store.prune_flows(self.cfg.flow_retention_days, now)?;
                let hour = now - now.rem_euclid(3600);
                let from = self.window_compacted.load(Ordering::Relaxed);
                store.compact_window_bytes(from, hour)?;
                self.window_compacted.store(hour, Ordering::Relaxed);
            }
        }

        for d in decisions {
            let target = IpNet::from(d.ip);
            match d.rule.action {
                Action::Ban if self.cfg.mode == Mode::Enforce => {
                    let ttl = self.escalated_ttl(&d.ip.to_string(), d.rule.ttl_secs)?;
                    match self.ban(target, Some(ttl), &d.reason, "policy", false) {
                        Ok(_) => {
                            log::warn!(
                                "banned {target} for {}: {}",
                                crate::util::fmt_secs(ttl),
                                d.reason
                            );
                            self.notify.send(
                                if d.urgent {
                                    Level::Critical
                                } else {
                                    Level::Warn
                                },
                                format!("Banned {target} for {}", crate::util::fmt_secs(ttl)),
                                format!("[{}] {}", d.rule.id, d.reason),
                                Some(format!("netwatch ip {}", d.ip)),
                            );
                        }
                        Err(e) => log::warn!("auto-ban of {target} skipped: {e:#}"),
                    }
                }
                Action::Ban | Action::Review => {
                    let action = d.rule.action.as_str();
                    let ttl = if d.rule.action == Action::Ban {
                        Some(self.escalated_ttl(&d.ip.to_string(), d.rule.ttl_secs)?)
                    } else {
                        None
                    };
                    let reason = format!("[{}] {}", d.rule.id, d.reason);
                    let conf = if d.rule.action == Action::Ban {
                        0.8
                    } else {
                        0.5
                    };
                    if let Some(id) =
                        self.propose(&target.to_string(), action, ttl, &reason, "rules", conf)?
                    {
                        let level = match (d.urgent, d.rule.action) {
                            (true, _) => Some(Level::Critical),
                            (false, Action::Ban) => Some(Level::Warn),
                            _ if self.notify.cfg.notify_reviews => Some(Level::Info),
                            _ => None,
                        };
                        if let Some(level) = level {
                            let what = if d.rule.action == Action::Ban {
                                "Ban proposed"
                            } else {
                                "Review"
                            };
                            self.notify.send(
                                level,
                                format!("{what} #{id}: {target}"),
                                reason,
                                Some(format!("netwatch ip {} · sudo netwatch approve {id}", d.ip)),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        for (net, reason) in subnets {
            let ttl = parse_duration(&self.cfg.ban.default_ttl)?;
            if let Some(id) =
                self.propose(&net.to_string(), "ban", Some(ttl), &reason, "rules", 0.6)?
            {
                self.notify.send(
                    Level::Warn,
                    format!("Range ban proposed #{id}: {net}"),
                    reason,
                    Some(format!("sudo netwatch approve {id}")),
                );
            }
        }

        self.expire_bans(now)?;
        if n.is_multiple_of((3600 / self.cfg.tick_secs.max(1)).max(1)) && n > 0 {
            self.check_sshd();
        }
        Ok(())
    }

    /// Returns the new proposal's id, None when an equivalent one already exists.
    fn propose(
        &self,
        target: &str,
        action: &str,
        ttl: Option<i64>,
        reason: &str,
        source: &str,
        conf: f64,
    ) -> anyhow::Result<Option<i64>> {
        let p = NewProposal {
            target,
            action,
            ttl_secs: ttl,
            reason,
            source,
            confidence: conf,
        };
        let id = self.store.lock().unwrap().add_proposal(&p, now_unix())?;
        if let Some(id) = id {
            log::info!("proposal #{id}: {action} {target} ({source}): {reason}");
            if let Some(o) = &self.otel {
                o.proposal(&crate::otel::ProposalEvent {
                    id,
                    action,
                    target,
                    ttl,
                    reason,
                    source,
                    confidence: conf,
                });
            }
        }
        Ok(id)
    }

    /// A service that starts listening where the internet can reach it.
    fn notify_listeners(&self, events: &[crate::store::ConnEventRow]) {
        if !self.notify.enabled() {
            return;
        }
        for ev in events.iter().filter(|e| e.kind == "listen") {
            let Ok(addr) = ev.local.parse::<std::net::IpAddr>() else {
                continue;
            };
            if !(addr.is_unspecified() || is_public(addr)) {
                continue;
            }
            let who = match (&ev.container, &ev.unit, &ev.process) {
                (Some(c), _, p) => format!("{c}/{}", p.as_deref().unwrap_or("?")),
                (None, Some(u), p) => format!(
                    "{u}{} ({})",
                    crate::procs::UNIT_SUFFIX,
                    p.as_deref().unwrap_or("?")
                ),
                (None, None, Some(p)) => p.clone(),
                _ => "unknown process".into(),
            };
            let shown = if addr.is_ipv6() {
                format!("[{addr}]:{}", ev.lport)
            } else {
                format!("{addr}:{}", ev.lport)
            };
            self.notify.send(
                Level::Warn,
                format!("New public listener {}/{shown}", ev.proto),
                format!("{who} started listening; check the firewall covers it"),
                Some("netwatch listeners".into()),
            );
        }
    }

    /// Default/rule TTL multiplied for each previous offence, capped at max_ttl.
    fn escalated_ttl(&self, ip: &str, rule_ttl: Option<i64>) -> anyhow::Result<i64> {
        let base = match rule_ttl {
            Some(t) => t,
            None => parse_duration(&self.cfg.ban.default_ttl)?,
        };
        let max = parse_duration(&self.cfg.ban.max_ttl)?;
        let offences = self.store.lock().unwrap().offences(ip)?;
        let mult = self
            .cfg
            .ban
            .repeat_multiplier
            .max(1)
            .saturating_pow(offences.min(10) as u32);
        Ok(base.saturating_mul(mult).min(max))
    }

    pub fn allowlisted(&self, net: &IpNet) -> Option<IpNet> {
        let e = self.engine.lock().unwrap();
        e.allow.iter().find(|a| a.contains(net)).copied()
    }

    /// Adds a ban to the kernel and the store. `ttl` None = permanent.
    pub fn ban(
        &self,
        target: IpNet,
        ttl: Option<i64>,
        reason: &str,
        source: &str,
        force: bool,
    ) -> anyhow::Result<BanRow> {
        if let Some(a) = self.allowlisted(&target) {
            bail!("{target} is inside allowlisted {a}; remove it from the allowlist first");
        }
        let too_broad = match target {
            IpNet::V4(n) => n.prefix_len() < 16,
            IpNet::V6(n) => n.prefix_len() < 32,
        };
        if too_broad && !force {
            bail!("{target} is a very large range; pass --force if you really mean it");
        }
        if !is_public(target.addr()) && !force {
            bail!("{target} is not a public address; pass --force to ban it anyway");
        }
        let now = now_unix();
        let row = BanRow {
            target: target.to_string(),
            created: now,
            expires: ttl.map(|t| now + t),
            reason: reason.to_string(),
            source: source.to_string(),
        };
        self.kernel.lock().unwrap().block(&target)?;
        {
            let mut e = self.engine.lock().unwrap();
            let mut bans = e.bans.clone();
            bans.insert(target, row.clone());
            e.set_bans(bans);
        }
        let store = self.store.lock().unwrap();
        store.put_ban(&row)?;
        store.add_offence(&row.target, now)?;
        store.upsert_alert(
            &row.target,
            "banned",
            0,
            &format!("Banned ({source}): {reason}"),
            "",
            now,
        )?;
        drop(store);
        if let Some(o) = &self.otel {
            o.ban(&row);
        }
        Ok(row)
    }

    /// `why` says what lifted it ("expired", "manual", "proposal #7"), for the event.
    pub fn unban(&self, target: IpNet, why: &str) -> anyhow::Result<bool> {
        self.kernel.lock().unwrap().unblock(&target)?;
        {
            let mut e = self.engine.lock().unwrap();
            let mut bans = e.bans.clone();
            bans.remove(&target);
            e.set_bans(bans);
        }
        let existed = self.store.lock().unwrap().delete_ban(&target.to_string())?;
        if existed && let Some(o) = &self.otel {
            o.unban(&target.to_string(), why);
        }
        Ok(existed)
    }

    fn restore_bans(&self) -> anyhow::Result<()> {
        let now = now_unix();
        let rows = self.store.lock().unwrap().bans()?;
        let mut map = BTreeMap::new();
        {
            let mut k = self.kernel.lock().unwrap();
            for b in rows {
                let Ok(net) = parse_target(&b.target) else {
                    continue;
                };
                if b.expires.is_some_and(|e| e <= now) {
                    // Expired while netwatch was down.
                    self.store.lock().unwrap().delete_ban(&b.target)?;
                    if let Some(o) = &self.otel {
                        o.unban(&b.target, "expired");
                    }
                    continue;
                }
                k.block(&net)?;
                map.insert(net, b);
            }
        }
        log::info!("restored {} bans", map.len());
        self.engine.lock().unwrap().set_bans(map);
        Ok(())
    }

    fn expire_bans(&self, now: i64) -> anyhow::Result<()> {
        let expired: Vec<IpNet> = {
            let e = self.engine.lock().unwrap();
            e.bans
                .iter()
                .filter(|(_, b)| b.expires.is_some_and(|x| x <= now))
                .map(|(n, _)| *n)
                .collect()
        };
        for net in expired {
            self.unban(net, "expired")?;
            log::info!("ban on {net} expired");
        }
        Ok(())
    }

    /// Rebuilds the kernel allowlist from config, discovered peers, Cloudflare and DB rules.
    pub async fn refresh_allowlist(&self) -> anyhow::Result<()> {
        let mut base: BTreeSet<IpNet> = self.cfg.allowlist.iter().copied().collect();
        let cfg = self.cfg.clone();
        let previous = self.peers.lock().unwrap().clone();
        let peers =
            tokio::task::spawn_blocking(move || intel::discover_peers(&cfg, &previous)).await?;
        base.extend(intel::all_peers(&peers));
        *self.peers.lock().unwrap() = peers;
        if self.cfg.allow_cloudflare {
            base.extend(intel::cloudflare_ranges().await);
        }
        *self.base_allow.lock().unwrap() = base;
        self.sync_allow()
    }

    fn sync_allow(&self) -> anyhow::Result<()> {
        let mut all = self.base_allow.lock().unwrap().clone();
        for (t, _) in self.store.lock().unwrap().allow_rules()? {
            if let Ok(n) = parse_target(&t) {
                all.insert(n);
            }
        }
        self.kernel.lock().unwrap().sync_allow(&all)?;
        self.engine
            .lock()
            .unwrap()
            .set_allow(all.into_iter().collect());
        Ok(())
    }

    pub fn allow(&self, target: IpNet, note: &str) -> anyhow::Result<()> {
        self.store
            .lock()
            .unwrap()
            .put_allow(&target.to_string(), note, now_unix())?;
        self.sync_allow()
    }

    pub fn disallow(&self, target: IpNet) -> anyhow::Result<bool> {
        let removed = self
            .store
            .lock()
            .unwrap()
            .delete_allow(&target.to_string())?;
        self.sync_allow()?;
        Ok(removed)
    }

    pub fn approve(&self, id: i64) -> anyhow::Result<String> {
        let p = self
            .store
            .lock()
            .unwrap()
            .proposal(id)?
            .ok_or_else(|| anyhow!("no proposal #{id}"))?;
        if p.status != "pending" {
            bail!("proposal #{id} is already {}", p.status);
        }
        let target = parse_target(&p.target)?;
        let msg = match p.action.as_str() {
            "ban" => {
                let row = self.ban(target, p.ttl_secs, &p.reason, &p.source, false)?;
                match row.expires {
                    Some(_) => format!(
                        "banned {target} for {}",
                        crate::util::fmt_secs(p.ttl_secs.unwrap_or(0))
                    ),
                    None => format!("banned {target} permanently"),
                }
            }
            "unban" => {
                self.unban(target, &format!("proposal #{id}"))?;
                format!("unbanned {target}")
            }
            "allow" => {
                self.allow(target, &p.reason)?;
                format!("allowlisted {target}")
            }
            _ => format!("marked {target} as reviewed"),
        };
        self.store
            .lock()
            .unwrap()
            .set_proposal_status(id, "applied", now_unix())?;
        Ok(msg)
    }

    pub fn reject(&self, id: i64) -> anyhow::Result<()> {
        let store = self.store.lock().unwrap();
        let p = store
            .proposal(id)?
            .ok_or_else(|| anyhow!("no proposal #{id}"))?;
        if p.status != "pending" {
            bail!("proposal #{id} is already {}", p.status);
        }
        store.set_proposal_status(id, "rejected", now_unix())
    }

    pub fn record_ssh(&self, ev: SshEvent) {
        let location = {
            let mut e = self.engine.lock().unwrap();
            e.state(ev.ip, now_unix()).location.clone()
        };
        let row = SshEventRow {
            ts: ev.ts,
            kind: ev.kind.to_string(),
            user: ev.user.clone(),
            ip: ev.ip.to_string(),
            method: ev.method.clone(),
            location,
            port: ev.port,
        };
        let known = {
            let store = self.store.lock().unwrap();
            match store.add_ssh_event(&row) {
                Ok(true) => {
                    if let Some(o) = &self.otel {
                        o.ssh(&row);
                    }
                }
                Ok(false) => return,
                Err(e) => {
                    log::warn!("storing ssh event: {e}");
                    return;
                }
            }
            match (ev.kind, &ev.user) {
                ("accepted" | "tailscale_login", Some(user)) => {
                    store.known_login_locations(user, ev.ts).unwrap_or_default()
                }
                _ => Vec::new(),
            }
        };
        if self.notify.cfg.notify_logins && matches!(ev.kind, "accepted" | "tailscale_login") {
            self.notify.send(
                Level::Info,
                format!("SSH login: {}@{}", ev.user.as_deref().unwrap_or("?"), ev.ip),
                format!("{} {}", ev.method.as_deref().unwrap_or(""), row.location)
                    .trim()
                    .to_string(),
                None,
            );
        }
        self.engine.lock().unwrap().observe_ssh(&ev, &known);
    }

    /// Asks sshd whether it accepts passwords (shown as an insight).
    fn check_sshd(&self) {
        // Remote Login off: nothing accepts SSH, whatever sshd_config says.
        #[cfg(target_os = "macos")]
        if !crate::macos::remote_login_enabled() {
            self.engine.lock().unwrap().sshd_password_auth = None;
            return;
        }
        let out = crate::host::command("sshd").arg("-T").output();
        let pw = out.ok().filter(|o| o.status.success()).map(|o| {
            String::from_utf8_lossy(&o.stdout).lines().any(|l| {
                l == "passwordauthentication yes" || l == "kbdinteractiveauthentication yes"
            })
        });
        self.engine.lock().unwrap().sshd_password_auth = pw;
    }

    pub async fn set_policy(
        &self,
        text: &str,
        dry_run: bool,
    ) -> anyhow::Result<(Vec<Rule>, String)> {
        // Raw JSON rules work without an LLM.
        let (rules, compiled_by) = if text.trim_start().starts_with('{')
            || text.trim_start().starts_with('[')
        {
            let v: serde_json::Value = serde_json::from_str(text).context("parsing rules JSON")?;
            let v = if v.is_array() { v } else { v["rules"].clone() };
            let mut rules: Vec<Rule> =
                serde_json::from_value(v).context("rules JSON does not match the schema")?;
            policy::validate(&mut rules)?;
            (rules, "json".to_string())
        } else {
            let llm = self.llm.as_ref().ok_or_else(|| {
                anyhow!("natural-language policies need [llm] configured; or pass rules as JSON")
            })?;
            let (rules, usage) = llm.compile_policy(text).await?;
            self.store
                .lock()
                .unwrap()
                .add_llm_run(&crate::store::LlmRunRow {
                    ts: now_unix(),
                    kind: "compile_policy".into(),
                    model: llm.cfg.model.clone(),
                    prompt_tokens: usage.prompt_tokens,
                    completion_tokens: usage.completion_tokens,
                    summary: format!(
                        "{} rules from: {}",
                        rules.len(),
                        text.chars().take(120).collect::<String>()
                    ),
                    proposals: 0,
                })?;
            (rules, llm.cfg.model.clone())
        };
        if !dry_run {
            self.store.lock().unwrap().set_policy(Some(&PolicyRow {
                text: text.to_string(),
                rules: serde_json::to_string(&rules)?,
                compiled_at: now_unix(),
                compiled_by: compiled_by.clone(),
            }))?;
            self.engine.lock().unwrap().user_rules = rules.clone();
        }
        Ok((rules, compiled_by))
    }

    pub fn clear_policy(&self) -> anyhow::Result<()> {
        self.store.lock().unwrap().set_policy(None)?;
        self.engine.lock().unwrap().user_rules.clear();
        Ok(())
    }

    /// One LLM analysis pass. Returns a human-readable outcome.
    pub async fn analyze(&self, force: bool) -> anyhow::Result<String> {
        let llm = self
            .llm
            .as_ref()
            .ok_or_else(|| anyhow!("[llm] is not enabled"))?;
        let now = now_unix();
        {
            let store = self.store.lock().unwrap();
            let (_, tokens_today) = store.llm_usage(now - now % 86_400)?;
            if tokens_today as u64 >= llm.cfg.daily_token_budget {
                bail!("daily token budget spent ({tokens_today} tokens)");
            }
            let (calls_hour, _) = store.llm_usage(now - 3600)?;
            if calls_hour as u32 >= llm.cfg.max_calls_per_hour {
                bail!("hourly call limit reached ({calls_hour})");
            }
        }
        let (lines, ctx) = {
            let e = self.engine.lock().unwrap();
            // Sources the rules already ban are settled; spend tokens on the rest.
            let lines: Vec<String> = e
                .flagged(now, 200)
                .into_iter()
                .filter(|s| {
                    !matches!(
                        e.rule_for(s).map(|r| r.action),
                        Some(Action::Ban | Action::Ignore | Action::NeverBan)
                    )
                })
                .take(llm.cfg.max_sources_per_call)
                .map(|s| s.digest_line(now))
                .collect();
            let tcp: Vec<String> = e.listening.tcp.iter().map(u16::to_string).collect();
            let udp: Vec<String> = e.listening.udp.iter().map(u16::to_string).collect();
            let policy_text = self
                .store
                .lock()
                .unwrap()
                .policy()?
                .map(|p| p.text)
                .unwrap_or_else(|| "none".into());
            let ctx = format!(
                "Operator policy: {policy_text}\nHost listens on tcp [{}] udp [{}]; sshd password auth: {}; mode: {:?}\n",
                tcp.join(","),
                udp.join(","),
                e.sshd_password_auth
                    .map_or("unknown", |b| if b { "yes" } else { "no" }),
                self.cfg.mode,
            );
            (lines, ctx)
        };
        if lines.is_empty() {
            return Ok("nothing unresolved to analyze".into());
        }
        let digest = lines.join("\n");
        if !force && !llm.digest_changed(&digest) {
            return Ok("no change since last analysis".into());
        }
        let prompt = format!("{ctx}Sources:\n{digest}");
        let (analysis, usage) = llm.analyze(&prompt).await?;
        *self.llm_last_run.lock().unwrap() = Some(now);

        let mut created = 0;
        let mut applied = Vec::new();
        for a in &analysis.actions {
            let Ok(target) = parse_target(&a.target) else {
                continue;
            };
            if !crate::llm::in_digest(&target, &digest) {
                log::warn!(
                    "llm named {target}, which isn't among the sources it was given; ignored"
                );
                continue;
            }
            if !is_public(target.addr()) || self.allowlisted(&target).is_some() {
                continue;
            }
            let ttl = a.ttl.as_deref().and_then(|t| parse_duration(t).ok());
            let reason = format!("{} (confidence {:.2})", a.reason, a.confidence);
            match a.action.as_str() {
                "ban" => {
                    let auto = llm.cfg.auto_apply
                        && self.cfg.mode == Mode::Enforce
                        && a.confidence >= llm.cfg.min_confidence;
                    if auto && self.ban(target, ttl, &a.reason, "llm", false).is_ok() {
                        self.notify.send(
                            Level::Warn,
                            format!("Banned {target} (LLM)"),
                            reason.clone(),
                            Some(format!("netwatch ip {}", target.addr())),
                        );
                        applied.push(target.to_string());
                    } else {
                        self.propose(
                            &target.to_string(),
                            "ban",
                            ttl,
                            &reason,
                            "llm",
                            a.confidence,
                        )?;
                        created += 1;
                    }
                }
                "review" => {
                    self.propose(
                        &target.to_string(),
                        "review",
                        None,
                        &reason,
                        "llm",
                        a.confidence,
                    )?;
                    created += 1;
                }
                _ => {}
            }
        }
        self.store
            .lock()
            .unwrap()
            .add_llm_run(&crate::store::LlmRunRow {
                ts: now,
                kind: "analyze".into(),
                model: llm.cfg.model.clone(),
                prompt_tokens: usage.prompt_tokens,
                completion_tokens: usage.completion_tokens,
                summary: analysis.summary.clone(),
                proposals: created + applied.len() as i64,
            })?;
        Ok(format!(
            "{} ({} sources, {} tokens): {created} proposals{}",
            analysis.summary,
            lines.len(),
            usage.prompt_tokens + usage.completion_tokens,
            if applied.is_empty() {
                String::new()
            } else {
                format!(", auto-banned {}", applied.join(", "))
            }
        ))
    }

    pub fn llm_last_run(&self) -> Option<i64> {
        *self.llm_last_run.lock().unwrap()
    }
}

async fn llm_loop(app: Arc<App>) {
    let every = Duration::from_secs(app.cfg.llm.interval_secs.max(60));
    // Let a few ticks of data accumulate first.
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
        match app.analyze(false).await {
            Ok(msg) => log::info!("llm: {msg}"),
            Err(e) => log::warn!("llm: {e:#}"),
        }
        tokio::time::sleep(every).await;
    }
}
