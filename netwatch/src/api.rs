//! Read-only HTTP API and embedded UI, bound to loopback only.
//! Shapes match `ui/src/api/types.ts`.

use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::Arc,
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    daemon::App,
    engine::{Engine, Finding, IpState, Rates},
    flows::Dir,
    geo::GeoInfo,
    intel::FeedHit,
    store::{
        AlertRow, BanRow, ConnEventRow, DestinationRow, DnsRow, FlowFilter, FlowRow, ProposalRow,
        SshEventRow, owner_key,
    },
    util::{now_unix, proto_name, service_name},
    window,
};

type AppState = State<Arc<App>>;
type ApiResult<T> = Result<Json<T>, (StatusCode, String)>;

fn internal(e: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
}

#[derive(rust_embed::RustEmbed)]
#[folder = "../ui/dist"]
struct Assets;

pub async fn serve(app: Arc<App>) {
    let addr = app.cfg.api_listen.clone();
    let router = Router::new()
        .route("/api/overview", get(overview))
        .route("/api/sources", get(sources))
        .route("/api/sources/{ip}", get(source_detail))
        .route("/api/alerts", get(alerts))
        .route("/api/bans", get(bans))
        .route("/api/proposals", get(proposals))
        .route("/api/insights", get(insights))
        .route("/api/ssh", get(ssh))
        .route("/api/summary", get(summary))
        .route("/api/events", get(events))
        .route("/api/policy", get(policy))
        .route("/api/llm", get(llm))
        .route("/api/flows", get(flows))
        .route("/api/flows/summary", get(flows_summary))
        .route("/api/destinations", get(destinations))
        .route("/api/interfaces", get(interfaces))
        .route("/api/listeners", get(listeners))
        .route("/api/dns", get(dns))
        .route("/api/conn_events", get(conn_events))
        .fallback(static_file)
        .with_state(app);
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            log::info!("UI and read-only API on http://{addr}");
            if let Err(e) = axum::serve(l, router).await {
                log::error!("api server: {e}");
            }
        }
        Err(e) => log::error!("api: cannot bind {addr}: {e}"),
    }
}

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Assets::get(path).or_else(|| {
        if path.starts_with("api/") {
            None
        } else {
            Assets::get("index.html")
        }
    }) {
        Some(f) => {
            let mime = f.metadata.mimetype().to_string();
            ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[derive(Serialize)]
struct SshCounts {
    failed: u64,
    invalid_users: usize,
    accepted: u64,
}

#[derive(Serialize)]
pub struct SourceView {
    ip: String,
    geo: GeoInfo,
    first_seen: i64,
    last_seen: i64,
    packets: u64,
    bytes: u64,
    in_packets: u64,
    in_bytes: u64,
    syn: u64,
    udp_in: u64,
    icmp_in: u64,
    blocked: u64,
    rate: Rates,
    ports: usize,
    score: u32,
    findings: Vec<Finding>,
    feeds: Vec<String>,
    feed_hits: Vec<FeedHit>,
    allowlisted: bool,
    banned: bool,
    ssh: SshCounts,
}

fn view(st: &IpState, now: i64) -> SourceView {
    SourceView {
        ip: st.ip.to_string(),
        geo: st.geo.clone(),
        first_seen: st.first_seen,
        last_seen: st.last_seen.max(st.ssh.last_event),
        packets: st.total.packets,
        bytes: st.total.bytes,
        in_packets: st.total.in_packets,
        in_bytes: st.total.in_bytes,
        syn: st.total.syn,
        udp_in: st.total.udp_in,
        icmp_in: st.total.icmp_in,
        blocked: st.total.blocked,
        rate: st.rate,
        ports: st.ports_within(now, 3600),
        score: st.score,
        findings: st.findings.clone(),
        feeds: st.feeds.clone(),
        feed_hits: st.feed_hits.clone(),
        allowlisted: st.allowlisted,
        banned: st.banned,
        ssh: SshCounts {
            failed: st.ssh.failed_total,
            invalid_users: st.ssh.invalid_users.len(),
            accepted: st.ssh.accepted,
        },
    }
}

/// Sources worth listing: anything that initiated traffic, was flagged, banned or seen in SSH logs.
fn interesting(st: &IpState) -> bool {
    st.total.in_packets > 0
        || st.score > 0
        || st.banned
        || st.total.blocked > 0
        || st.ssh.last_event > 0
}

#[derive(Deserialize)]
struct SourcesQuery {
    sort: Option<String>,
    limit: Option<usize>,
    q: Option<String>,
    flagged: Option<String>,
    all: Option<String>,
    /// Only sources that touched this local port.
    port: Option<u16>,
}

async fn sources(State(app): AppState, Query(q): Query<SourcesQuery>) -> Json<Vec<SourceView>> {
    let now = now_unix();
    let e = app.engine.lock().unwrap();
    let needle =
        q.q.as_deref()
            .map(str::to_lowercase)
            .filter(|s| !s.is_empty());
    let flagged = q
        .flagged
        .as_deref()
        .is_some_and(|f| f == "1" || f == "true");
    let all = q.all.as_deref().is_some_and(|f| f == "1" || f == "true");
    let mut list: Vec<&IpState> = e
        .states
        .values()
        .filter(|s| all || interesting(s))
        .filter(|s| !flagged || s.score > 0)
        .filter(|s| q.port.is_none_or(|p| s.ports.values().any(|t| t.port == p)))
        .filter(|s| {
            needle.as_ref().is_none_or(|n| {
                s.ip.to_string().contains(n.as_str())
                    || s.location.to_lowercase().contains(n.as_str())
                    || s.geo
                        .country
                        .as_deref()
                        .is_some_and(|c| c.to_lowercase().contains(n.as_str()))
            })
        })
        .collect();
    let key = |s: &IpState| -> f64 {
        match q.sort.as_deref().unwrap_or("score") {
            "syn" => s.total.syn as f64,
            "in_bytes" => s.total.in_bytes as f64,
            "in_pps" => s.rate.in_pps,
            "ports" => s.ports_within(now, 3600) as f64,
            "last_seen" => s.last_seen.max(s.ssh.last_event) as f64,
            _ => s.score as f64 * 1e12 + s.total.syn as f64,
        }
    };
    list.sort_by(|a, b| key(b).total_cmp(&key(a)));
    list.truncate(q.limit.unwrap_or(100).min(2000));
    Json(list.into_iter().map(|s| view(s, now)).collect())
}

#[derive(Serialize)]
struct PortTouch {
    proto: &'static str,
    port: u16,
    service: Option<&'static str>,
    listening: bool,
    first_seen: i64,
    last_seen: i64,
    packets: u64,
    syn: u64,
}

#[derive(Serialize)]
struct ProposalView {
    #[serde(flatten)]
    row: ProposalRow,
    approve_cmd: String,
}

fn proposal_view(row: ProposalRow) -> ProposalView {
    let approve_cmd = format!("sudo netwatch approve {}", row.id);
    ProposalView { row, approve_cmd }
}

#[derive(Serialize)]
struct BanView {
    #[serde(flatten)]
    row: BanRow,
    dropped: u64,
}

fn ban_view(e: &Engine, row: BanRow) -> BanView {
    let dropped = crate::util::parse_target(&row.target)
        .map(|net| {
            e.states
                .values()
                .filter(|s| net.contains(&s.ip))
                .map(|s| s.total.blocked)
                .sum()
        })
        .unwrap_or(0);
    BanView { row, dropped }
}

async fn source_detail(
    State(app): AppState,
    Path(ip): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let addr: IpAddr = ip
        .parse()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid IP".to_string()))?;
    let now = now_unix();
    let (mut base, ports, ban) = {
        let e = app.engine.lock().unwrap();
        match e.states.get(&addr) {
            Some(st) => {
                let mut ports: Vec<PortTouch> = st
                    .ports
                    .values()
                    .map(|p| PortTouch {
                        proto: proto_name(p.proto),
                        port: p.port,
                        service: service_name(p.port),
                        listening: e.listening.has(p.proto, p.port),
                        first_seen: p.first_seen,
                        last_seen: p.last_seen,
                        packets: p.packets,
                        syn: p.syn,
                    })
                    .collect();
                ports.sort_by_key(|p| (p.port, p.proto));
                let ban = e.ban_for(addr).cloned().map(|b| ban_view(&e, b));
                (
                    serde_json::to_value(view(st, now)).map_err(|e| internal(e.into()))?,
                    ports,
                    ban,
                )
            }
            None => {
                // Not in memory any more: still show what the store remembers.
                let geo = e.geo.lookup(addr);
                let v = json!({
                    "ip": ip, "geo": geo, "first_seen": 0, "last_seen": 0, "packets": 0, "bytes": 0,
                    "in_packets": 0, "in_bytes": 0, "syn": 0, "udp_in": 0, "icmp_in": 0, "blocked": 0,
                    "rate": {"in_pps": 0, "in_bps": 0, "syn_ps": 0}, "ports": 0, "score": 0, "findings": [],
                    "feeds": e.feeds.matches(addr), "feed_hits": e.feeds.hits(addr), "allowlisted": e.is_allowed(addr), "banned": e.ban_for(addr).is_some(),
                    "ssh": {"failed": 0, "invalid_users": 0, "accepted": 0},
                });
                let ban = e.ban_for(addr).cloned().map(|b| ban_view(&e, b));
                (v, Vec::new(), ban)
            }
        }
    };
    let (active_flows, names) = {
        let e = app.engine.lock().unwrap();
        let flows: Vec<FlowRow> = e
            .flows
            .active
            .values()
            .filter(|f| f.remote == addr || f.local == addr)
            .map(|f| e.flow_row(f, now, true))
            .collect();
        let names: Vec<String> = e
            .flows
            .name_of(addr, now)
            .map(str::to_string)
            .into_iter()
            .collect();
        (flows, names)
    };
    let store = app.store.lock().unwrap();
    let past_flows = store
        .flows(
            &FlowFilter {
                since: now - 7 * 86_400,
                ip: Some(ip.clone()),
                ..Default::default()
            },
            200,
        )
        .map_err(internal)?;
    let alerts = store.alerts(0, Some(&ip), 200).map_err(internal)?;
    let history = store.ip_history(&ip, now - 7 * 86_400).map_err(internal)?;
    let ssh_events = store.ssh_events(0, Some(&ip), 200).map_err(internal)?;
    let props: Vec<ProposalView> = store
        .proposals(false, Some(&ip), 50)
        .map_err(internal)?
        .into_iter()
        .map(proposal_view)
        .collect();
    if base["last_seen"] == 0
        && alerts.is_empty()
        && history.is_empty()
        && ssh_events.is_empty()
        && ban.is_none()
        && active_flows.is_empty()
        && past_flows.is_empty()
    {
        return Err((StatusCode::NOT_FOUND, format!("{ip} has not been seen")));
    }
    let obj = base.as_object_mut().expect("object");
    obj.insert("port_touches".into(), json!(ports));
    obj.insert("alerts".into(), json!(alerts));
    obj.insert("history".into(), json!(history));
    obj.insert("ssh_events".into(), json!(ssh_events));
    obj.insert("ban".into(), json!(ban));
    obj.insert("proposals".into(), json!(props));
    let mut flows = active_flows;
    flows.extend(past_flows);
    obj.insert("flows".into(), json!(flows));
    obj.insert("dns_names".into(), json!(names));
    Ok(Json(base))
}

#[derive(Deserialize)]
struct ListQuery {
    since: Option<i64>,
    limit: Option<u32>,
    ip: Option<String>,
    status: Option<String>,
    window: Option<String>,
    kind: Option<String>,
}

async fn alerts(State(app): AppState, Query(q): Query<ListQuery>) -> ApiResult<Vec<AlertRow>> {
    let store = app.store.lock().unwrap();
    store
        .alerts(
            q.since.unwrap_or(0),
            q.ip.as_deref(),
            q.limit.unwrap_or(200).min(5000),
        )
        .map(Json)
        .map_err(internal)
}

async fn bans(State(app): AppState) -> ApiResult<Vec<BanView>> {
    let e = app.engine.lock().unwrap();
    let mut list: Vec<BanView> = e.bans.values().cloned().map(|b| ban_view(&e, b)).collect();
    list.sort_by_key(|b| std::cmp::Reverse(b.row.created));
    Ok(Json(list))
}

async fn proposals(
    State(app): AppState,
    Query(q): Query<ListQuery>,
) -> ApiResult<Vec<ProposalView>> {
    let pending = q.status.as_deref() != Some("all");
    let store = app.store.lock().unwrap();
    let rows = store
        .proposals(pending, q.ip.as_deref(), q.limit.unwrap_or(200).min(2000))
        .map_err(internal)?;
    Ok(Json(rows.into_iter().map(proposal_view).collect()))
}

async fn ssh(State(app): AppState, Query(q): Query<ListQuery>) -> ApiResult<Vec<SshEventRow>> {
    let store = app.store.lock().unwrap();
    store
        .ssh_events(
            q.since.unwrap_or(0),
            q.ip.as_deref(),
            q.limit.unwrap_or(300).min(5000),
        )
        .map(Json)
        .map_err(internal)
}

async fn events(State(app): AppState, Query(q): Query<ListQuery>) -> Json<Value> {
    let e = app.engine.lock().unwrap();
    let n = q.limit.unwrap_or(200) as usize;
    Json(json!(e.events.iter().take(n).collect::<Vec<_>>()))
}

async fn insights(State(app): AppState) -> ApiResult<Vec<crate::insights::Insight>> {
    crate::insights::compute(&app).map(Json).map_err(internal)
}

fn llm_status(app: &App) -> anyhow::Result<Value> {
    let now = now_unix();
    let (calls, tokens) = app.store.lock().unwrap().llm_usage(now - now % 86_400)?;
    Ok(match &app.llm {
        Some(l) => json!({
            "enabled": true, "model": l.cfg.model, "base_url": l.cfg.base_url,
            "calls_today": calls, "tokens_today": tokens, "budget_tokens_day": l.cfg.daily_token_budget,
            "last_run": app.llm_last_run(),
        }),
        None => json!({
            "enabled": false, "model": null, "base_url": null, "calls_today": calls,
            "tokens_today": tokens, "budget_tokens_day": 0, "last_run": null,
        }),
    })
}

async fn overview(State(app): AppState) -> ApiResult<Value> {
    let now = now_unix();
    let llm = llm_status(&app).map_err(internal)?;
    let pending = app
        .store
        .lock()
        .unwrap()
        .proposals(true, None, 10_000)
        .map_err(internal)?
        .len();
    let attach_mode = app.kernel.lock().unwrap().attach_mode;
    let e = app.engine.lock().unwrap();
    let review = app.cfg.ban.review_score;
    let g = &e.global;
    let primary = e.ifaces.iter().find(|i| i.xdp);
    let primary_bps = primary.map_or(0.0, |i| i.rx_bps + i.tx_bps);
    let flows = &e.flows.active;
    Ok(Json(json!({
        "host": app.host,
        "version": env!("CARGO_PKG_VERSION"),
        "interface": app.cfg.interface,
        "attach_mode": attach_mode,
        "platform": std::env::consts::OS,
        "mode": app.cfg.mode,
        "drop_banned": app.cfg.drop_banned,
        "started_at": app.started,
        "now": now,
        "rates": {
            "pps": e.rates.pps, "bps": primary_bps, "in_pps": e.rates.in_pps,
            "syn_pps": e.rates.syn_pps, "dropped_pps": e.rates.dropped_pps,
        },
        "totals": {
            "packets": g.packets, "bytes": g.bytes, "in_packets": g.in_packets, "syn": g.syn,
            "blocked": g.blocked, "dropped": g.dropped, "events_lost": g.events_lost,
            "ipopt_syn": g.ipopt_syn, "ipopt_dropped": g.ipopt_dropped,
        },
        "counts": {
            "sources_tracked": e.states.len(),
            "sources_active_10m": e.states.values().filter(|s| s.total.in_packets > 0 && s.last_inbound >= now - 600).count(),
            "flagged": e.states.values().filter(|s| s.score >= review && !s.allowlisted).count(),
            "bans_active": e.bans.len(),
            "proposals_pending": pending,
            "ssh_failed_1h": e.states.values().map(|s| s.ssh_failed_within(now, 3600)).sum::<u64>(),
        },
        "llm": llm,
        "geo_db": e.geo.available(),
        "feeds": e.feeds.lists.iter().map(|l| json!({"name": l.name, "entries": l.entries, "about": l.about})).collect::<Vec<_>>(),
        "series": e.series,
        "flows": {
            "active": flows.len(),
            "in": flows.values().filter(|f| f.dir == Dir::In).count(),
            "out": flows.values().filter(|f| f.dir == Dir::Out).count(),
            "tcp": flows.values().filter(|f| f.key.proto == netwatch_common::PROTO_TCP).count(),
            "udp": flows.values().filter(|f| f.key.proto == netwatch_common::PROTO_UDP).count(),
            "rate_in_bps": flows.values().map(|f| f.rate_in).sum::<f64>() * 8.0,
            "rate_out_bps": flows.values().map(|f| f.rate_out).sum::<f64>() * 8.0,
            "listeners": e.flows.listeners.values().filter(|l| l.exposed && l.role != crate::flows::SockRole::Client).count(),
            "series": e.flows.series,
            "sock_events_lost": g.sock_events_lost,
        },
        "interfaces": e.ifaces.iter().filter(|i| i.flows || i.xdp).map(|i| json!({
            "name": i.info.name, "kind": i.info.kind, "rx_bps": i.rx_bps, "tx_bps": i.tx_bps, "xdp": i.xdp, "flows": i.flows,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Default, Serialize)]
struct CountryAgg {
    country_code: String,
    country: String,
    sources: u64,
    flagged: u64,
    syn: u64,
    in_packets: u64,
}

#[derive(Default, Serialize)]
struct AsnAgg {
    asn: u32,
    org: String,
    sources: u64,
    flagged: u64,
    syn: u64,
}

#[derive(Serialize)]
struct PortAgg {
    proto: &'static str,
    port: u16,
    service: Option<&'static str>,
    listening: bool,
    sources: u64,
    syn: u64,
}

async fn summary(State(app): AppState, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let now = now_unix();
    let window = q.window.unwrap_or_else(|| "1h".into());
    let secs = match window.as_str() {
        "24h" => 86_400,
        "7d" => 7 * 86_400,
        _ => 3_600,
    };
    let review = app.cfg.ban.review_score;
    let (mut countries, mut asns, ports) =
        {
            let e = app.engine.lock().unwrap();
            let mut countries: HashMap<String, CountryAgg> = HashMap::new();
            let mut asns: HashMap<u32, AsnAgg> = HashMap::new();
            let mut ports: BTreeMap<(u8, u16), PortAgg> = BTreeMap::new();
            for s in e.states.values().filter(|s| {
                s.total.in_packets > 0 && !s.allowlisted && s.last_activity() >= now - secs
            }) {
                let flagged = (s.score >= review) as u64;
                let cc = s.geo.country_code.clone().unwrap_or_else(|| "--".into());
                let c = countries.entry(cc.clone()).or_default();
                c.country_code = cc;
                c.country = s.geo.country.clone().unwrap_or_else(|| "Unknown".into());
                c.sources += 1;
                c.flagged += flagged;
                c.syn += s.total.syn;
                c.in_packets += s.total.in_packets;
                if let Some(asn) = s.geo.asn {
                    let a = asns.entry(asn).or_default();
                    a.asn = asn;
                    a.org = s.geo.as_org.clone().unwrap_or_default();
                    a.sources += 1;
                    a.flagged += flagged;
                    a.syn += s.total.syn;
                }
                // Port details are kept in memory for one hour.
                for p in s
                    .ports
                    .values()
                    .filter(|p| p.last_seen >= now - secs.min(3600))
                {
                    let agg = ports.entry((p.proto, p.port)).or_insert_with(|| PortAgg {
                        proto: proto_name(p.proto),
                        port: p.port,
                        service: service_name(p.port),
                        listening: e.listening.has(p.proto, p.port),
                        sources: 0,
                        syn: 0,
                    });
                    agg.sources += 1;
                    agg.syn += p.syn;
                }
            }
            (countries, asns, ports)
        };
    let store = app.store.lock().unwrap();
    let since = now - secs;
    let top_history = store
        .history(since - since % 3600, "syn", 50)
        .map_err(internal)?;
    if secs > 3600 {
        // Longer windows: country totals come from the hourly table.
        for row in store
            .history_countries(since - since % 3600, 100)
            .map_err(internal)?
        {
            let c = countries.entry(row.country.clone()).or_default();
            c.country_code = row.country.clone();
            if c.country.is_empty() {
                c.country = row.country.clone();
            }
            c.sources = c.sources.max(row.sources as u64);
            c.syn = c.syn.max(row.syn as u64);
            c.in_packets = c.in_packets.max(row.in_packets as u64);
        }
    }
    let mut countries: Vec<CountryAgg> = countries.drain().map(|(_, v)| v).collect();
    countries.sort_by_key(|c| std::cmp::Reverse((c.sources, c.syn)));
    countries.truncate(50);
    let mut asns: Vec<AsnAgg> = asns.drain().map(|(_, v)| v).collect();
    asns.sort_by_key(|a| std::cmp::Reverse((a.flagged, a.sources)));
    asns.truncate(50);
    let mut ports: Vec<PortAgg> = ports.into_values().collect();
    ports.sort_by_key(|p| std::cmp::Reverse((p.sources, p.syn)));
    ports.truncate(50);
    Ok(Json(json!({
        "window": window, "countries": countries, "asns": asns, "ports": ports, "top_history": top_history,
    })))
}

async fn policy(State(app): AppState) -> ApiResult<Value> {
    let row = app.store.lock().unwrap().policy().map_err(internal)?;
    let e = app.engine.lock().unwrap();
    Ok(Json(json!({
        "text": row.as_ref().map(|r| r.text.clone()),
        "rules": e.user_rules,
        "defaults": e.default_rules,
        "compiled_at": row.as_ref().map(|r| r.compiled_at),
        "compiled_by": row.as_ref().map(|r| r.compiled_by.clone()),
        "set_cmd": "sudo netwatch policy set \"<describe in plain English what to ban, review or never ban>\"",
    })))
}

async fn llm(State(app): AppState) -> ApiResult<Value> {
    let mut v = llm_status(&app).map_err(internal)?;
    let runs = app.store.lock().unwrap().llm_runs(100).map_err(internal)?;
    v["runs"] = json!(runs);
    Ok(Json(v))
}

// ---------------------------------------------------------------------------
// Flows, interfaces, listeners, DNS

fn window_secs(w: Option<&str>, default: i64) -> i64 {
    match w {
        Some("5m") => 300,
        Some("15m") => 900,
        Some("1h") => 3_600,
        Some("6h") => 6 * 3_600,
        Some("24h") => 86_400,
        Some("7d") => 7 * 86_400,
        Some("30d") => 30 * 86_400,
        _ => default,
    }
}

#[derive(Deserialize)]
struct FlowsQuery {
    /// active (default), history, or all.
    view: Option<String>,
    window: Option<String>,
    ip: Option<String>,
    port: Option<u16>,
    process: Option<String>,
    dir: Option<String>,
    iface: Option<String>,
    proto: Option<String>,
    q: Option<String>,
    /// bytes (default), rate, last, first, retrans
    sort: Option<String>,
    limit: Option<u32>,
}

fn flow_matches(f: &FlowRow, q: &FlowsQuery) -> bool {
    let eq = |want: &Option<String>, have: &str| {
        want.as_deref().is_none_or(|w| w.is_empty() || w == have)
    };
    if !eq(&q.dir, &f.dir) || !eq(&q.iface, &f.iface) || !eq(&q.proto, &f.proto) {
        return false;
    }
    if let Some(ip) = q.ip.as_deref().filter(|s| !s.is_empty())
        && f.remote != ip
        && f.local != ip
    {
        return false;
    }
    if let Some(p) = q.port
        && f.lport != p
        && f.rport != p
    {
        return false;
    }
    if let Some(p) = q.process.as_deref().filter(|s| !s.is_empty())
        && ![&f.process, &f.container, &f.unit]
            .iter()
            .any(|v| v.as_deref() == Some(p))
    {
        return false;
    }
    if let Some(needle) = q.q.as_deref().filter(|s| !s.is_empty()) {
        let needle = needle.to_ascii_lowercase();
        let hay = [
            Some(f.remote.as_str()),
            Some(f.local.as_str()),
            f.remote_name.as_deref(),
            f.process.as_deref(),
            f.container.as_deref(),
            f.unit.as_deref(),
            f.remote_process.as_deref(),
            f.remote_container.as_deref(),
            f.as_org.as_deref(),
            f.country.as_deref(),
            f.service.as_deref(),
        ];
        let app = f.app.to_string().to_ascii_lowercase();
        if !hay
            .iter()
            .flatten()
            .any(|h| h.to_ascii_lowercase().contains(&needle))
            && !app.contains(&needle)
        {
            return false;
        }
    }
    true
}

async fn flows(State(app): AppState, Query(q): Query<FlowsQuery>) -> ApiResult<Vec<FlowRow>> {
    let now = now_unix();
    let limit = q.limit.unwrap_or(500).min(10_000) as usize;
    let view = q.view.as_deref().unwrap_or("active");
    let mut rows: Vec<FlowRow> = Vec::new();
    if view != "history" {
        let e = app.engine.lock().unwrap();
        rows.extend(
            e.flows
                .active
                .values()
                .map(|f| e.flow_row(f, now, true))
                .filter(|f| flow_matches(f, &q)),
        );
    }
    if view != "active" {
        let filter = FlowFilter {
            since: now - window_secs(q.window.as_deref(), 3_600),
            ip: q.ip.clone().filter(|s| !s.is_empty()),
            port: q.port,
            process: None,
            dir: q.dir.clone().filter(|s| !s.is_empty()),
            iface: q.iface.clone().filter(|s| !s.is_empty()),
            proto: q.proto.clone().filter(|s| !s.is_empty()),
            q: None,
        };
        // Free-text and process filters run in Rust so they match the active view exactly.
        let fetch = if q.q.is_some() || q.process.is_some() {
            20_000
        } else {
            limit as u32
        };
        let past = app
            .store
            .lock()
            .unwrap()
            .flows(&filter, fetch)
            .map_err(internal)?;
        rows.extend(past.into_iter().filter(|f| flow_matches(f, &q)));
    }
    match q.sort.as_deref().unwrap_or("bytes") {
        "rate" => {
            rows.sort_by(|a, b| (b.rate_in + b.rate_out).total_cmp(&(a.rate_in + a.rate_out)))
        }
        "last" => rows.sort_by_key(|f| std::cmp::Reverse(f.last_seen)),
        "first" => rows.sort_by_key(|f| std::cmp::Reverse(f.first_seen)),
        "retrans" => rows.sort_by_key(|f| std::cmp::Reverse(f.retrans)),
        _ => rows.sort_by_key(|f| std::cmp::Reverse(f.bytes_in + f.bytes_out)),
    }
    rows.truncate(limit);
    Ok(Json(rows))
}

#[derive(Default, Serialize, Clone)]
struct Group {
    key: String,
    label: Option<String>,
    flows: u64,
    active: u64,
    bytes_in: u64,
    bytes_out: u64,
    rate_bps: f64,
    failed: u64,
    retrans: u64,
    last_seen: i64,
    /// Distinct remotes (process/service/country groups).
    remotes: u64,
    country: Option<String>,
    as_org: Option<String>,
}

fn top(map: HashMap<String, (Group, std::collections::HashSet<String>)>, n: usize) -> Vec<Group> {
    let mut v: Vec<Group> = map
        .into_values()
        .map(|(mut g, remotes)| {
            g.remotes = remotes.len() as u64;
            g
        })
        .collect();
    v.sort_by_key(|g| std::cmp::Reverse(g.bytes_in + g.bytes_out));
    v.truncate(n);
    v
}

async fn flows_summary(State(app): AppState, Query(q): Query<ListQuery>) -> ApiResult<Value> {
    let now = now_unix();
    let secs = window_secs(q.window.as_deref(), 3_600);
    let since = now - secs;
    // Bytes come from the window totals, not from each flow's lifetime counters:
    // by minute within the last hour, by whole hours beyond it.
    let bytes_since = if secs <= 3_600 {
        since - since.rem_euclid(60)
    } else {
        since - since.rem_euclid(3_600)
    };
    // Longer windows: the stored hours first, with the last minute they
    // include, then only the minutes closed after it, so a minute stored in
    // between is counted once.
    let stored = if secs > 3_600 {
        let store = app.store.lock().unwrap();
        let bytes = store.window_bytes(bytes_since).map_err(internal)?;
        Some((bytes, store.window_saved()))
    } else {
        None
    };
    let (rows, series, listening, mut bytes) = {
        let e = app.engine.lock().unwrap();
        let rows: Vec<FlowRow> = e
            .flows
            .active
            .values()
            .map(|f| e.flow_row(f, now, true))
            .collect();
        let bytes = match &stored {
            None => e.bytes.since(bytes_since),
            Some((stored, saved)) => {
                let mut bytes = e.bytes.after(*saved, bytes_since);
                window::merge(&mut bytes, stored);
                bytes
            }
        };
        (rows, e.flows.series.clone(), e.flows.listeners.len(), bytes)
    };
    let (past, failed) = {
        let store = app.store.lock().unwrap();
        // Finished flows in the window; capped so a busy week stays responsive.
        let past = store
            .flows(
                &FlowFilter {
                    since,
                    ..Default::default()
                },
                100_000,
            )
            .map_err(internal)?;
        (past, store.failed_connects(since).map_err(internal)?)
    };
    let mut by: [HashMap<String, (Group, std::collections::HashSet<String>)>; 4] =
        Default::default();
    let (mut n_in, mut n_out) = (0u64, 0u64);
    for f in rows.iter().chain(past.iter()) {
        match f.dir.as_str() {
            "in" => n_in += 1,
            "out" => n_out += 1,
            _ => {}
        }
        for (i, (dim, k, label)) in window::group_keys(f).into_iter().enumerate() {
            let (g, remotes) = by[i].entry(k.clone()).or_default();
            g.key = k;
            g.flows += 1;
            g.active += f.active as u64;
            g.rate_bps += (f.rate_in + f.rate_out) * 8.0;
            g.failed += (f.state == "failed") as u64;
            g.retrans += f.retrans;
            g.last_seen = g.last_seen.max(f.last_seen);
            remotes.insert(f.remote.clone());
            g.label = g.label.take().or(label);
            if dim == window::REMOTE {
                g.country = g.country.take().or_else(|| f.country.clone());
                g.as_org = g.as_org.take().or_else(|| f.as_org.clone());
            }
        }
    }
    // Groups take their bytes from the window totals; a group that moved bytes
    // in the window but whose flows fell past the 100k cap still shows.
    let total = bytes
        .remove(&(window::TOTAL, String::new()))
        .unwrap_or_default();
    for ((dim, key), b) in bytes {
        if key.is_empty() || dim as usize >= by.len() {
            continue;
        }
        let (g, _) = by[dim as usize].entry(key.clone()).or_default();
        g.key = key;
        g.bytes_in = b.bytes_in;
        g.bytes_out = b.bytes_out;
        g.label = g.label.take().or(b.label);
        g.country = g.country.take().or(b.country);
        g.as_org = g.as_org.take().or(b.as_org);
    }
    let [remotes, processes, services, countries] = by;
    Ok(Json(json!({
        "window": q.window.unwrap_or_else(|| "1h".into()),
        "flows": rows.len() + past.len(),
        "active": rows.len(),
        "inbound": n_in,
        "outbound": n_out,
        "failed": failed,
        "bytes_in": total.bytes_in,
        "bytes_out": total.bytes_out,
        "bytes_since": bytes_since,
        "listeners": listening,
        "truncated": past.len() >= 100_000,
        "top_remotes": top(remotes, 25),
        "top_processes": top(processes, 25),
        "top_services": top(services, 25),
        "top_countries": top(countries, 25),
        "series": series,
    })))
}

#[derive(Deserialize)]
struct DestinationsQuery {
    window: Option<String>,
    /// public (default): only internet addresses; all: also private, container and loopback ones.
    scope: Option<String>,
    /// Only remotes reached without a DNS name or TLS SNI.
    unnamed: Option<bool>,
    /// Free text: IP, name, network, country, port or process.
    q: Option<String>,
    /// flows (default), bytes, last, first
    sort: Option<String>,
    limit: Option<u32>,
}

/// Everything this host and its containers connected out to, one row per remote
/// address: finished flows grouped in the store, plus the open ones.
async fn destinations(
    State(app): AppState,
    Query(q): Query<DestinationsQuery>,
) -> ApiResult<Value> {
    let now = now_unix();
    let since = now - window_secs(q.window.as_deref(), 3_600);
    let active: Vec<FlowRow> = {
        let e = app.engine.lock().unwrap();
        e.flows
            .active
            .values()
            .filter(|f| f.dir == Dir::Out)
            .map(|f| e.flow_row(f, now, true))
            .collect()
    };
    let past = app
        .store
        .lock()
        .unwrap()
        .destinations(since)
        .map_err(internal)?;
    let mut by: HashMap<String, DestinationRow> =
        past.into_iter().map(|d| (d.remote.clone(), d)).collect();
    for f in active {
        let d = by
            .entry(f.remote.clone())
            .or_insert_with(|| DestinationRow {
                remote: f.remote.clone(),
                first_seen: f.first_seen,
                ..Default::default()
            });
        d.name = d.name.take().or(f.remote_name);
        d.country = d.country.take().or(f.country);
        d.asn = d.asn.or(f.asn);
        d.as_org = d.as_org.take().or(f.as_org);
        d.flows += 1;
        d.active += 1;
        d.failed += (f.state == "failed") as u64;
        d.bytes_in += f.bytes_in;
        d.bytes_out += f.bytes_out;
        d.first_seen = d.first_seen.min(f.first_seen);
        d.last_seen = d.last_seen.max(f.last_seen);
        let port = format!("{}/{}", f.proto, f.rport);
        if !d.ports.contains(&port) {
            d.ports.push(port);
            d.ports.sort();
        }
        let who = owner_key(
            f.container.as_deref(),
            f.unit.as_deref(),
            f.process.as_deref(),
        );
        if !d.processes.contains(&who) {
            d.processes.push(who);
            d.processes.sort();
        }
    }
    let all_scopes = q.scope.as_deref() == Some("all");
    let mut rows: Vec<DestinationRow> = by
        .into_values()
        .filter(|d| all_scopes || d.remote.parse().is_ok_and(crate::util::is_public))
        .collect();
    let (total, unnamed) = (rows.len(), rows.iter().filter(|d| d.name.is_none()).count());
    if q.unnamed == Some(true) {
        rows.retain(|d| d.name.is_none());
    }
    if let Some(needle) = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let needle = needle.to_ascii_lowercase();
        rows.retain(|d| {
            [
                Some(&d.remote),
                d.name.as_ref(),
                d.as_org.as_ref(),
                d.country.as_ref(),
            ]
            .into_iter()
            .flatten()
            .chain(&d.ports)
            .chain(&d.processes)
            .any(|h| h.to_ascii_lowercase().contains(&needle))
        });
    }
    match q.sort.as_deref().unwrap_or("flows") {
        "bytes" => rows.sort_by_key(|d| std::cmp::Reverse(d.bytes_in + d.bytes_out)),
        "last" => rows.sort_by_key(|d| std::cmp::Reverse(d.last_seen)),
        "first" => rows.sort_by_key(|d| std::cmp::Reverse(d.first_seen)),
        _ => rows.sort_by_key(|d| std::cmp::Reverse(d.flows)),
    }
    let matched = rows.len();
    rows.truncate(q.limit.unwrap_or(500).min(5_000) as usize);
    Ok(Json(json!({
        "window": q.window.unwrap_or_else(|| "1h".into()),
        "destinations": total,
        "unnamed": unnamed,
        "matched": matched,
        "rows": rows,
    })))
}

async fn interfaces(State(app): AppState) -> ApiResult<Value> {
    let (tracepoints, flows_ok) = {
        let k = app.kernel.lock().unwrap();
        (k.tracepoints.clone(), k.flows_ok)
    };
    let e = app.engine.lock().unwrap();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in e.flows.active.values() {
        *counts.entry(f.iface.as_str()).or_default() += 1;
    }
    let ifaces: Vec<Value> = e
        .ifaces
        .iter()
        .map(|i| {
            let mut v = serde_json::to_value(i).unwrap_or_default();
            v["active_flows"] = json!(counts.get(i.info.name.as_str()).copied().unwrap_or(0));
            v
        })
        .collect();
    Ok(Json(json!({
        "interfaces": ifaces,
        "flow_programs": flows_ok,
        "tracepoints": tracepoints.iter().map(|(n, ok)| json!({"name": n, "attached": ok})).collect::<Vec<_>>(),
        "patterns": app.cfg.flow_interfaces,
        "sample_dns": app.cfg.sample_dns,
        "sample_tcp_payload": app.cfg.sample_tcp_payload,
    })))
}

async fn listeners(State(app): AppState) -> ApiResult<Vec<Value>> {
    let now = now_unix();
    let e = app.engine.lock().unwrap();
    let mut inbound: HashMap<(String, u16), (u64, std::collections::HashSet<IpAddr>)> =
        HashMap::new();
    for f in e.flows.active.values().filter(|f| f.dir == Dir::In) {
        let (n, remotes) = inbound
            .entry((proto_name(f.key.proto).to_string(), f.key.lport))
            .or_default();
        *n += 1;
        remotes.insert(f.remote);
    }
    let mut out: Vec<Value> = e
        .flows
        .listeners
        .values()
        .map(|l| {
            let (n, remotes) = inbound.get(&(l.proto.to_string(), l.port)).cloned().unwrap_or_default();
            let public = remotes.iter().filter(|r| crate::util::is_public(**r)).count();
            json!({
                "proto": l.proto, "port": l.port, "service": service_name(l.port),
                "addrs": l.addrs, "exposed": l.exposed, "ephemeral": l.ephemeral,
                "role": l.role.as_str(), "role_reason": l.role_reason,
                "pid": l.owner.as_ref().map(|o| o.pid), "process": l.owner.as_ref().map(|o| &o.comm),
                "exe": l.owner.as_ref().and_then(|o| o.exe.as_ref()),
                "container": l.owner.as_ref().and_then(|o| o.container.as_ref()),
                "unit": l.owner.as_ref().and_then(|o| o.unit.as_ref()),
                "since": l.since, "active_flows": n, "remotes": remotes.len(), "public_remotes": public,
                "age_secs": now - l.since,
            })
        })
        .collect();
    out.sort_by_key(|v| {
        (
            v["proto"].as_str().unwrap_or("").to_string(),
            v["port"].as_u64().unwrap_or(0),
        )
    });
    Ok(Json(out))
}

#[derive(Deserialize)]
struct DnsQuery {
    window: Option<String>,
    q: Option<String>,
    rcode: Option<String>,
    limit: Option<u32>,
}

async fn dns(State(app): AppState, Query(q): Query<DnsQuery>) -> ApiResult<Value> {
    let since = now_unix() - window_secs(q.window.as_deref(), 3_600);
    let store = app.store.lock().unwrap();
    let qs = q.q.as_deref().filter(|s| !s.is_empty());
    let rc = q.rcode.as_deref().filter(|s| !s.is_empty());
    let recent: Vec<DnsRow> = store
        .dns(since, qs, rc, q.limit.unwrap_or(500).min(10_000))
        .map_err(internal)?;
    let top = store.dns_top(since, 50).map_err(internal)?;
    Ok(Json(json!({ "queries": recent, "top": top })))
}

async fn conn_events(
    State(app): AppState,
    Query(q): Query<ListQuery>,
) -> ApiResult<Vec<ConnEventRow>> {
    let since = now_unix() - window_secs(q.window.as_deref(), 86_400);
    let kind = q.kind.as_deref().filter(|s| !s.is_empty());
    app.store
        .lock()
        .unwrap()
        .conn_events(since, kind, q.limit.unwrap_or(500).min(5_000))
        .map(Json)
        .map_err(internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// temps reads `/api/bans` (temps-shield's `netwatch` module): it needs `target` and `expires`.
    #[test]
    fn bans_carry_what_temps_reads() {
        let row = BanRow {
            target: "203.0.113.0/24".into(),
            created: 1,
            expires: Some(86_401),
            reason: "scan".into(),
            source: "auto".into(),
        };
        let v = serde_json::to_value(BanView { row, dropped: 3 }).unwrap();
        assert_eq!(v["target"], "203.0.113.0/24");
        assert_eq!(v["expires"], 86_401);
        let row = BanRow {
            target: "198.51.100.7".into(),
            created: 1,
            expires: None,
            reason: String::new(),
            source: "manual".into(),
        };
        assert!(serde_json::to_value(BanView { row, dropped: 0 }).unwrap()["expires"].is_null());
    }
}
