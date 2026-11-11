mod api;
mod config;
mod control;
mod daemon;
mod dissect;
mod engine;
mod exploits;
mod flows;
mod geo;
mod host;
mod insights;
mod intel;
#[cfg(target_os = "linux")]
mod kernel;
mod llm;
mod netif;
mod notify;
mod otel;
mod policy;
mod procs;
mod skill;
mod ssh;
mod store;
mod temps;
mod update;
mod util;
mod window;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("netwatch runs on Linux (eBPF/XDP) and macOS (/dev/bpf)");

/// macOS: userspace capture behind the same interface as the eBPF loader.
#[cfg(target_os = "macos")]
mod macos;
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
#[cfg(target_os = "macos")]
use macos::kernel;
use serde_json::Value;

use crate::{
    config::Config,
    control::Request,
    util::{flag, fmt_bytes},
};

/// Network monitor (eBPF/XDP on Linux, /dev/bpf and pf on macOS): per-source traffic,
/// geolocation, scan and brute-force detection, SSH log monitoring, bans and optional
/// LLM-assisted triage.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, global = true, env = "NETWATCH_CONFIG", default_value = config::DEFAULT_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (root): attach XDP (macOS: capture), serve the UI on 127.0.0.1.
    Run,
    /// Install this binary as a launchd daemon and start it (root).
    #[cfg(target_os = "macos")]
    Install,
    /// Stop and remove the launchd daemon (root).
    #[cfg(target_os = "macos")]
    Uninstall {
        /// Also delete the config, the database and the log.
        #[arg(long)]
        purge: bool,
    },
    /// Download the DB-IP Lite GeoIP databases (root); install schedules it monthly.
    #[cfg(target_os = "macos")]
    UpdateGeoip,
    /// Overview and current insights.
    Status,
    /// Tracked sources.
    #[command(alias = "top")]
    Sources {
        #[arg(long, default_value = "score", value_parser = ["score", "syn", "in_bytes", "in_pps", "ports", "last_seen"])]
        sort: String,
        #[arg(long)]
        flagged: bool,
        /// Only sources that touched this local port.
        #[arg(long)]
        port: Option<u16>,
        /// Filter by IP, country or ASN substring.
        #[arg(short, long)]
        q: Option<String>,
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: usize,
    },
    /// Everything known about one address.
    Ip { ip: String },
    /// Findings per source: scans, probes, floods, brute force, feed matches.
    Alerts {
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: u32,
    },
    /// SSH log events (sshd + Tailscale SSH).
    Ssh {
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: u32,
    },
    /// What deserves attention now, each with the command that acts on it.
    Insights,
    /// Active bans, with what they dropped and when they expire.
    Bans,
    /// Actions proposed by rules or the LLM.
    Proposals {
        #[arg(long)]
        all: bool,
    },
    /// Ban an IP or CIDR (root).
    Ban {
        target: String,
        /// e.g. 1h, 24h, 7d, or "permanent". Default: ban.default_ttl.
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        reason: Option<String>,
        /// Allow very large ranges and non-public addresses.
        #[arg(long)]
        force: bool,
    },
    /// Lift a ban (root).
    Unban { target: String },
    /// Never ban this IP/CIDR and keep it out of proposals (root).
    Allow {
        target: String,
        #[arg(long)]
        note: Option<String>,
    },
    /// Remove an address added with `allow` (root).
    Disallow { target: String },
    /// Apply proposed actions, by their IDs in `netwatch proposals` (root).
    Approve {
        #[arg(required = true, value_name = "ID")]
        ids: Vec<i64>,
    },
    /// Drop proposed actions, by their IDs in `netwatch proposals` (root).
    Reject {
        #[arg(required = true, value_name = "ID")]
        ids: Vec<i64>,
    },
    /// Show or change the ban policy.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Run an LLM analysis pass now (root).
    Analyze,
    /// Connections: live by default, finished ones with --history.
    #[command(alias = "conns")]
    Flows {
        /// Finished flows from the store instead of live ones.
        #[arg(long)]
        history: bool,
        /// History window: 5m, 15m, 1h, 6h, 24h, 7d, 30d.
        #[arg(long, default_value = "1h")]
        window: String,
        #[arg(long)]
        ip: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Process or container name.
        #[arg(long)]
        process: Option<String>,
        /// in (they connected to us) or out (we connected to them).
        #[arg(long, value_parser = ["in", "out", "unknown"])]
        dir: Option<String>,
        #[arg(long)]
        iface: Option<String>,
        /// Free text: IP, DNS name, SNI, process, ASN org, country.
        #[arg(short, long)]
        q: Option<String>,
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "rate", "last", "first", "retrans"])]
        sort: String,
        #[arg(short = 'n', long, default_value_t = 40)]
        limit: u32,
    },
    /// Listening sockets and who owns them.
    Listeners {
        /// Include loopback-only sockets and UDP sockets seen acting as DNS clients.
        #[arg(long)]
        all: bool,
    },
    /// Interfaces, throughput and what netwatch attached where.
    Ifaces,
    /// DNS queries seen on the wire.
    Dns {
        #[arg(short, long)]
        q: Option<String>,
        /// e.g. NXDOMAIN, SERVFAIL, TIMEOUT
        #[arg(long)]
        rcode: Option<String>,
        #[arg(long, default_value = "1h")]
        window: String,
        /// Most-queried names instead of the query log.
        #[arg(long)]
        top: bool,
        #[arg(short = 'n', long, default_value_t = 40)]
        limit: u32,
    },
    /// Connection events: failed connects, new and closed listeners.
    Events {
        #[arg(long, value_parser = ["connect_failed", "listen", "unlisten"])]
        kind: Option<String>,
        #[arg(long, default_value = "24h")]
        window: String,
        #[arg(short = 'n', long, default_value_t = 40)]
        limit: u32,
    },
    /// Look up an address in the geo databases (no daemon needed).
    Geo { ip: std::net::IpAddr },
    /// Print the default configuration.
    DefaultConfig,
    /// Print the agent skill for this version, or install it (no daemon needed)
    ///
    /// Examples:
    ///   netwatch skill --install                        # Claude Code and Cursor: ~/.claude/skills
    ///   netwatch skill --install --dir ~/.agents/skills # Codex and other agents
    ///   netwatch skill --install --dir .claude/skills   # this project only
    ///   netwatch skill > SKILL.md
    #[command(verbatim_doc_comment)]
    Skill {
        /// Write <dir>/netwatch/SKILL.md instead of printing it.
        #[arg(long)]
        install: bool,
        /// Skills directory to install into, e.g. ~/.agents/skills for Codex [default: ~/.claude/skills]
        #[arg(long, requires = "install")]
        dir: Option<PathBuf>,
    },
    /// Install the latest release over this one and restart the daemon (root)
    ///
    /// It checks the download against the release's SHA256SUMS, and if the new
    /// daemon doesn't start, puts the running version back.
    ///
    ///   netwatch update --check          # is there a newer release? (no root)
    ///   sudo netwatch update             # install it
    ///   sudo netwatch update --auto on   # install new releases daily
    #[command(verbatim_doc_comment)]
    Update {
        /// Only say whether a newer release exists, and whether automatic updates are on.
        #[arg(long, conflicts_with = "auto")]
        check: bool,
        /// Turn daily automatic updates on or off.
        #[arg(long, value_parser = ["on", "off"])]
        auto: Option<String>,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Show,
    /// Plain-English policy (compiled to rules by the LLM), or rules as JSON.
    Set {
        text: String,
        /// Show the compiled rules without installing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the policy; built-in defaults remain.
    Clear,
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    // launchd has no EnvironmentFile; the daemon reads it itself, before any thread starts.
    #[cfg(target_os = "macos")]
    if matches!(cli.cmd, Cmd::Run)
        && let Some(dir) = cli.config.parent()
    {
        macos::load_env_file(&dir.join("env"));
    }
    if !matches!(cli.cmd, Cmd::Run) {
        // Exit quietly when piped into `head` and the like, as other CLI tools do.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    if let Cmd::DefaultConfig = cli.cmd {
        print!("{}", toml::to_string_pretty(&Config::default())?);
        return Ok(());
    }
    if let Cmd::Skill { install, dir } = &cli.cmd {
        if !install {
            print!("{}", skill::SKILL);
            return Ok(());
        }
        let path = match dir {
            Some(d) => skill::install(d)?,
            None => {
                let sudo_user = std::env::var("SUDO_USER")
                    .ok()
                    .filter(|_| unsafe { libc::geteuid() } == 0);
                skill::refuse_sudo(sudo_user.as_deref())?;
                skill::install(&skill::default_dir()?)?
            }
        };
        eprintln!("{}", skill::installed_message(&path));
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    match &cli.cmd {
        Cmd::Install => return macos::launchd::install(&cli.config),
        Cmd::Uninstall { purge } => return macos::launchd::uninstall(&cli.config, *purge),
        Cmd::UpdateGeoip => return macos::launchd::update_geoip(&Config::load(&cli.config)?),
        _ => {}
    }
    // It loads the config the installed daemon runs with, which may not be this one.
    if let Cmd::Update { check, auto } = &cli.cmd {
        return update::run(&cli.config, *check, auto.as_deref()).await;
    }
    let cfg = Config::load(&cli.config)?;
    let api = Client {
        base: cfg.api_url(),
        http: reqwest::Client::new(),
    };
    let ctl = |req: Request| {
        let path = cfg.control_socket.clone();
        async move {
            let resp = control::send(&path, &req).await?;
            if !resp.ok {
                bail!("{}", resp.message);
            }
            Ok::<_, anyhow::Error>(resp)
        }
    };

    match cli.cmd {
        Cmd::Run => daemon::run(cfg).await?,
        Cmd::DefaultConfig | Cmd::Skill { .. } | Cmd::Update { .. } => unreachable!(),
        #[cfg(target_os = "macos")]
        Cmd::Install | Cmd::Uninstall { .. } | Cmd::UpdateGeoip => unreachable!(),
        Cmd::Status => {
            let o = api.get("/api/overview").await?;
            println!(
                "{} · {} ({}) · mode {} · up {}",
                o["host"].as_str().unwrap_or("?"),
                o["interface"].as_str().unwrap_or("?"),
                o["attach_mode"].as_str().unwrap_or("?"),
                o["mode"].as_str().unwrap_or("?"),
                util::fmt_approx(
                    o["now"].as_i64().unwrap_or(0) - o["started_at"].as_i64().unwrap_or(0)
                )
            );
            let r = &o["rates"];
            let c = &o["counts"];
            println!(
                "{:.0} pps · {:.0} inbound pps · {:.1} SYN/s · {:.0} dropped/s",
                f(&r["pps"]),
                f(&r["in_pps"]),
                f(&r["syn_pps"]),
                f(&r["dropped_pps"])
            );
            println!(
                "{} sources ({} active) · {} flagged · {} bans · {} pending proposals · {} SSH failures/1h",
                c["sources_tracked"],
                c["sources_active_10m"],
                c["flagged"],
                c["bans_active"],
                c["proposals_pending"],
                c["ssh_failed_1h"]
            );
            let fl = &o["flows"];
            println!(
                "{} flows ({} in, {} out) · {} in / {} out · {} exposed listeners",
                fl["active"],
                fl["in"],
                fl["out"],
                fmt_bps(f(&fl["rate_in_bps"])),
                fmt_bps(f(&fl["rate_out_bps"])),
                fl["listeners"]
            );
            let ifs: Vec<String> = o["interfaces"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|i| {
                    format!(
                        "{} ↓{} ↑{}",
                        i["name"].as_str().unwrap_or("?"),
                        fmt_bps(f(&i["rx_bps"])),
                        fmt_bps(f(&i["tx_bps"]))
                    )
                })
                .collect();
            if !ifs.is_empty() {
                println!("{}", ifs.join(" · "));
            }
            let l = &o["llm"];
            if l["enabled"].as_bool() == Some(true) {
                println!(
                    "LLM {} · {} tokens today / {}",
                    l["model"].as_str().unwrap_or("?"),
                    l["tokens_today"],
                    l["budget_tokens_day"]
                );
            }
            println!();
            print_insights(&api.get("/api/insights").await?);
        }
        Cmd::Insights => print_insights(&api.get("/api/insights").await?),
        Cmd::Sources {
            sort,
            flagged,
            port,
            q,
            limit,
        } => {
            let mut path = format!("/api/sources?sort={sort}&limit={limit}");
            if flagged {
                path.push_str("&flagged=1");
            }
            if let Some(port) = port {
                path.push_str(&format!("&port={port}"));
            }
            if let Some(q) = q {
                path.push_str(&format!("&q={}", urlencode(&q)));
            }
            let list = api.get(&path).await?;
            let mut rows = Vec::new();
            for s in list.as_array().into_iter().flatten() {
                rows.push(vec![
                    s["ip"].as_str().unwrap_or("").to_string(),
                    location(&s["geo"]),
                    s["score"].to_string(),
                    s["findings"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|f| f["kind"].as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    s["ports"].to_string(),
                    s["syn"].to_string(),
                    fmt_bytes(f(&s["in_bytes"])),
                    ago(s["last_seen"].as_i64().unwrap_or(0)),
                    badges(s),
                ]);
            }
            table(
                &[
                    "IP", "LOCATION", "SCORE", "FINDINGS", "PORTS", "SYN", "IN", "SEEN", "",
                ],
                rows,
            );
        }
        Cmd::Flows {
            history,
            window,
            ip,
            port,
            process,
            dir,
            iface,
            q,
            sort,
            limit,
        } => {
            let mut path = format!(
                "/api/flows?view={}&window={window}&sort={sort}&limit={limit}",
                if history { "history" } else { "active" }
            );
            for (k, v) in [
                ("ip", ip),
                ("process", process),
                ("dir", dir),
                ("iface", iface),
                ("q", q),
            ] {
                if let Some(v) = v {
                    path.push_str(&format!("&{k}={}", urlencode(&v)));
                }
            }
            if let Some(p) = port {
                path.push_str(&format!("&port={p}"));
            }
            print_flows(&api.get(&path).await?, !history);
        }
        Cmd::Listeners { all } => {
            let list = api.get("/api/listeners").await?;
            let mut rows = Vec::new();
            for l in list.as_array().into_iter().flatten() {
                let exposed = l["exposed"].as_bool() == Some(true);
                let role = l["role"].as_str().unwrap_or("unknown");
                if !all && (!exposed || role == "client") {
                    continue;
                }
                let addrs: Vec<&str> = l["addrs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                rows.push(vec![
                    format!("{}/{}", l["port"], l["proto"].as_str().unwrap_or("")),
                    l["service"].as_str().unwrap_or("").to_string(),
                    addrs.join(","),
                    owner(l),
                    l["active_flows"].to_string(),
                    l["public_remotes"].to_string(),
                    match (exposed, role) {
                        (false, _) => "loopback".into(),
                        (true, "client" | "server") if l["proto"] == "udp" => {
                            format!("{role}: {}", l["role_reason"].as_str().unwrap_or(""))
                        }
                        _ => String::new(),
                    },
                ]);
            }
            table(
                &[
                    "PORT",
                    "SERVICE",
                    "BOUND",
                    "PROCESS",
                    "FLOWS",
                    "PUBLIC PEERS",
                    "",
                ],
                rows,
            );
        }
        Cmd::Ifaces => {
            let v = api.get("/api/interfaces").await?;
            let mut rows = Vec::new();
            for i in v["interfaces"].as_array().into_iter().flatten() {
                let mut tags = Vec::new();
                if i["xdp"].as_bool() == Some(true) {
                    tags.push(if cfg!(target_os = "macos") {
                        "accounting"
                    } else {
                        "xdp"
                    });
                }
                if i["flows"].as_bool() == Some(true) {
                    tags.push("flows");
                }
                rows.push(vec![
                    i["name"].as_str().unwrap_or("").to_string(),
                    i["kind"].as_str().unwrap_or("").to_string(),
                    if i["up"].as_bool() == Some(true) {
                        "up".into()
                    } else {
                        "down".into()
                    },
                    fmt_bps(f(&i["rx_bps"])),
                    fmt_bps(f(&i["tx_bps"])),
                    fmt_bytes(f(&i["rx_bytes"])),
                    fmt_bytes(f(&i["tx_bytes"])),
                    i["active_flows"].to_string(),
                    tags.join(","),
                ]);
            }
            table(
                &[
                    "IFACE", "KIND", "STATE", "RX", "TX", "RX TOTAL", "TX TOTAL", "FLOWS",
                    "NETWATCH",
                ],
                rows,
            );
            let tps: Vec<String> = v["tracepoints"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| {
                    format!(
                        "{} {}",
                        if t["attached"].as_bool() == Some(true) {
                            "✓"
                        } else {
                            "✗"
                        },
                        t["name"].as_str().unwrap_or("")
                    )
                })
                .collect();
            println!("\ntracepoints: {}", tps.join("  "));
        }
        Cmd::Dns {
            q,
            rcode,
            window,
            top,
            limit,
        } => {
            let mut path = format!("/api/dns?window={window}&limit={limit}");
            if let Some(q) = q {
                path.push_str(&format!("&q={}", urlencode(&q)));
            }
            if let Some(r) = rcode {
                path.push_str(&format!("&rcode={}", urlencode(&r.to_ascii_uppercase())));
            }
            let v = api.get(&path).await?;
            if top {
                let rows = v["top"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(limit as usize)
                    .map(|t| {
                        vec![
                            t["qname"].as_str().unwrap_or("").to_string(),
                            t["queries"].to_string(),
                            t["nxdomain"].to_string(),
                            t["clients"].to_string(),
                            ago(t["last_ts"].as_i64().unwrap_or(0)),
                        ]
                    })
                    .collect();
                table(&["NAME", "QUERIES", "NXDOMAIN", "CLIENTS", "LAST"], rows);
            } else {
                let rows = v["queries"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|d| {
                        let answers: Vec<&str> = d["answers"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                            .collect();
                        vec![
                            ago(d["ts"].as_i64().unwrap_or(0)),
                            d["client"].as_str().unwrap_or("").to_string(),
                            d["server"].as_str().unwrap_or("").to_string(),
                            d["qtype"].as_str().unwrap_or("").to_string(),
                            d["qname"].as_str().unwrap_or("").to_string(),
                            d["rcode"].as_str().unwrap_or("").to_string(),
                            d["latency_ms"]
                                .as_f64()
                                .map(|l| format!("{l:.0}ms"))
                                .unwrap_or_default(),
                            truncate(&answers.join(" "), 60),
                        ]
                    })
                    .collect();
                table(
                    &[
                        "WHEN", "CLIENT", "SERVER", "TYPE", "NAME", "RCODE", "RTT", "ANSWERS",
                    ],
                    rows,
                );
            }
        }
        Cmd::Events {
            kind,
            window,
            limit,
        } => {
            let mut path = format!("/api/conn_events?window={window}&limit={limit}");
            if let Some(k) = kind {
                path.push_str(&format!("&kind={k}"));
            }
            let rows = api
                .get(&path)
                .await?
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| {
                    vec![
                        ago(e["ts"].as_i64().unwrap_or(0)),
                        e["kind"].as_str().unwrap_or("").to_string(),
                        e["detail"].as_str().unwrap_or("").to_string(),
                    ]
                })
                .collect();
            table(&["WHEN", "EVENT", "DETAIL"], rows);
        }
        Cmd::Ip { ip } => {
            let s = api.get(&format!("/api/sources/{ip}")).await?;
            println!(
                "{}  {}  score {}  {}",
                ip,
                location(&s["geo"]),
                s["score"],
                badges(&s)
            );
            let g = &s["geo"];
            if let Some(city) = g["city"].as_str() {
                println!("  {city}, {}", g["country"].as_str().unwrap_or(""));
            }
            println!(
                "  in {} pkts / {} · {} SYN · {} UDP · {} ICMP · {} blocked · first {} · last {}",
                s["in_packets"],
                fmt_bytes(f(&s["in_bytes"])),
                s["syn"],
                s["udp_in"],
                s["icmp_in"],
                s["blocked"],
                ago(s["first_seen"].as_i64().unwrap_or(0)),
                ago(s["last_seen"].as_i64().unwrap_or(0))
            );
            for f in s["findings"].as_array().into_iter().flatten() {
                println!(
                    "  ! [{}] {} — {}",
                    f["score"],
                    f["kind"].as_str().unwrap_or(""),
                    f["summary"].as_str().unwrap_or("")
                );
            }
            for h in s["feed_hits"].as_array().into_iter().flatten() {
                let about = h["about"]
                    .as_str()
                    .filter(|a| !a.is_empty())
                    .map(|a| format!(" — {a}"))
                    .unwrap_or_default();
                println!(
                    "  listed on {} as {}{about}",
                    h["name"].as_str().unwrap_or(""),
                    h["range"].as_str().unwrap_or("?")
                );
            }
            let (open, closed): (Vec<&serde_json::Value>, Vec<&serde_json::Value>) =
                s["port_touches"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .partition(|p| p["listening"].as_bool() == Some(true));
            let fmt = |p: &&serde_json::Value| {
                format!("{}/{}", p["port"], p["proto"].as_str().unwrap_or(""))
            };
            if !open.is_empty() {
                println!(
                    "  open ports touched: {}",
                    open.iter().map(fmt).collect::<Vec<_>>().join(" ")
                );
            }
            if !closed.is_empty() {
                let shown: Vec<String> = closed.iter().take(24).map(fmt).collect();
                let more = closed.len().saturating_sub(shown.len());
                let more = if more > 0 {
                    format!(" +{more} more")
                } else {
                    String::new()
                };
                println!(
                    "  closed ports probed ({}): {}{more}",
                    closed.len(),
                    shown.join(" ")
                );
            }
            for e in s["ssh_events"].as_array().into_iter().flatten().take(10) {
                println!(
                    "  ssh {} {} user={} {}",
                    ago(e["ts"].as_i64().unwrap_or(0)),
                    e["kind"].as_str().unwrap_or(""),
                    e["user"].as_str().unwrap_or("-"),
                    e["method"].as_str().unwrap_or("")
                );
            }
            let names: Vec<&str> = s["dns_names"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            if !names.is_empty() {
                println!("  dns names: {}", names.join(" "));
            }
            if s["flows"].as_array().is_some_and(|a| !a.is_empty()) {
                println!();
                print_flows(
                    &Value::Array(
                        s["flows"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .take(20)
                            .cloned()
                            .collect(),
                    ),
                    false,
                );
            }
            for p in s["proposals"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|p| p["status"] == "pending")
            {
                println!(
                    "  proposal #{} {}: {}  → {}",
                    p["id"],
                    p["action"].as_str().unwrap_or(""),
                    p["reason"].as_str().unwrap_or(""),
                    p["approve_cmd"].as_str().unwrap_or("")
                );
            }
        }
        Cmd::Alerts { limit } => {
            let list = api.get(&format!("/api/alerts?limit={limit}")).await?;
            let rows = list
                .as_array()
                .into_iter()
                .flatten()
                .map(|a| {
                    vec![
                        ago(a["last_ts"].as_i64().unwrap_or(0)),
                        a["ip"].as_str().unwrap_or("").into(),
                        a["kind"].as_str().unwrap_or("").into(),
                        a["score"].to_string(),
                        a["count"].to_string(),
                        a["summary"]
                            .as_str()
                            .unwrap_or("")
                            .chars()
                            .take(90)
                            .collect(),
                    ]
                })
                .collect();
            table(&["WHEN", "IP", "KIND", "SCORE", "N", "SUMMARY"], rows);
        }
        Cmd::Ssh { limit } => {
            let list = api.get(&format!("/api/ssh?limit={limit}")).await?;
            let rows = list
                .as_array()
                .into_iter()
                .flatten()
                .map(|e| {
                    vec![
                        ago(e["ts"].as_i64().unwrap_or(0)),
                        e["kind"].as_str().unwrap_or("").into(),
                        e["user"].as_str().unwrap_or("-").into(),
                        e["ip"].as_str().unwrap_or("").into(),
                        e["method"].as_str().unwrap_or("").into(),
                        e["location"].as_str().unwrap_or("").into(),
                    ]
                })
                .collect();
            table(&["WHEN", "EVENT", "USER", "IP", "METHOD", "LOCATION"], rows);
        }
        Cmd::Bans => {
            let list = api.get("/api/bans").await?;
            let now = util::now_unix();
            let rows = list
                .as_array()
                .into_iter()
                .flatten()
                .map(|b| {
                    vec![
                        b["target"].as_str().unwrap_or("").into(),
                        b["source"].as_str().unwrap_or("").into(),
                        b["expires"].as_i64().map_or("never".into(), |e| {
                            format!("in {}", util::fmt_approx(e - now))
                        }),
                        b["dropped"].to_string(),
                        truncate(b["reason"].as_str().unwrap_or(""), 80),
                    ]
                })
                .collect();
            table(&["TARGET", "SOURCE", "EXPIRES", "DROPPED", "REASON"], rows);
        }
        Cmd::Proposals { all } => {
            let list = api
                .get(if all {
                    "/api/proposals?status=all"
                } else {
                    "/api/proposals"
                })
                .await?;
            let rows = list
                .as_array()
                .into_iter()
                .flatten()
                .map(|p| {
                    vec![
                        p["id"].to_string(),
                        ago(p["created"].as_i64().unwrap_or(0)),
                        p["action"].as_str().unwrap_or("").into(),
                        p["target"].as_str().unwrap_or("").into(),
                        p["ttl_secs"].as_i64().map_or("-".into(), util::fmt_secs),
                        p["source"].as_str().unwrap_or("").into(),
                        p["status"].as_str().unwrap_or("").into(),
                        truncate(p["reason"].as_str().unwrap_or(""), 80),
                    ]
                })
                .collect();
            table(
                &[
                    "ID", "WHEN", "ACTION", "TARGET", "TTL", "BY", "STATUS", "REASON",
                ],
                rows,
            );
            if !all {
                println!(
                    "\napprove: sudo netwatch approve <ID>...   reject: sudo netwatch reject <ID>..."
                );
            }
        }
        Cmd::Ban {
            target,
            ttl,
            reason,
            force,
        } => println!(
            "{}",
            ctl(Request::Ban {
                target,
                ttl,
                reason,
                force
            })
            .await?
            .message
        ),
        Cmd::Unban { target } => println!("{}", ctl(Request::Unban { target }).await?.message),
        Cmd::Allow { target, note } => {
            println!("{}", ctl(Request::Allow { target, note }).await?.message)
        }
        Cmd::Disallow { target } => {
            println!("{}", ctl(Request::Disallow { target }).await?.message)
        }
        Cmd::Approve { ids } => each_proposal(ids, |id| ctl(Request::Approve { id })).await?,
        Cmd::Reject { ids } => each_proposal(ids, |id| ctl(Request::Reject { id })).await?,
        Cmd::Analyze => println!("{}", ctl(Request::Analyze).await?.message),
        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => {
                let p = api.get("/api/policy").await?;
                match p["text"].as_str() {
                    Some(t) => println!(
                        "Policy ({}): {t}\n",
                        p["compiled_by"].as_str().unwrap_or("?")
                    ),
                    None => println!("No custom policy; built-in defaults apply.\n"),
                }
                print_rules("Your rules (checked first)", &p["rules"]);
                print_rules("Built-in defaults", &p["defaults"]);
            }
            PolicyCmd::Set { text, dry_run } => {
                let resp = ctl(Request::PolicySet { text, dry_run }).await?;
                println!("{}\n", resp.message);
                print_rules("Rules", resp.data.as_ref().unwrap_or(&Value::Null));
                if dry_run {
                    println!("(dry run: nothing installed)");
                }
            }
            PolicyCmd::Clear => println!("{}", ctl(Request::PolicyClear).await?.message),
        },
        Cmd::Geo { ip } => {
            let g = geo::Geo::open(&cfg.geoip_city, &cfg.geoip_asn);
            if !g.available() {
                bail!(
                    "no GeoIP database at {} or {}; download them with: {}",
                    cfg.geoip_city.display(),
                    cfg.geoip_asn.display(),
                    insights::UPDATE_GEOIP
                );
            }
            println!("{}", serde_json::to_string_pretty(&g.lookup(ip))?);
        }
    }
    Ok(())
}

struct Client {
    base: String,
    http: reqwest::Client,
}

impl Client {
    async fn get(&self, path: &str) -> anyhow::Result<Value> {
        let url = format!("{}{path}", self.base);
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            // The usual first-run case: say what to do, not the socket error chain.
            Err(e) if e.is_connect() => bail!("{}", not_running(&self.base)),
            Err(e) => {
                return Err(e).with_context(|| format!("asking the daemon at {}", self.base));
            }
        };
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            bail!("{status}: {text}");
        }
        Ok(serde_json::from_str(&text)?)
    }
}

/// Sends one approve or reject per proposal, in order and once each, so a
/// stale ID doesn't stop the rest; fails at the end if any did. With a single
/// ID it prints the daemon's message alone, as before.
async fn each_proposal<F, Fut>(mut ids: Vec<i64>, send: F) -> anyhow::Result<()>
where
    F: Fn(i64) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<control::Response>>,
{
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(*id));
    if let [id] = ids[..] {
        println!("{}", send(id).await?.message);
        return Ok(());
    }
    let mut failed = 0;
    for &id in &ids {
        match send(id).await {
            Ok(r) => println!("#{id}: {}", r.message),
            Err(e) => {
                failed += 1;
                eprintln!("#{id}: {e:#}");
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} proposals failed", ids.len());
    }
    Ok(())
}

fn not_running(base: &str) -> String {
    let check = if cfg!(target_os = "macos") {
        "sudo launchctl print system/dev.netwatch, and /var/log/netwatch.log"
    } else {
        "systemctl status netwatch"
    };
    format!(
        "nothing answers at {base}, so the netwatch daemon isn't running there. Check: {check}. Not installed yet: https://gotempsh.github.io/netwatch/installation/"
    )
}

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(0.0)
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b':' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn location(g: &Value) -> String {
    let cc = g["country_code"].as_str().unwrap_or("--");
    let mut s = format!("{} {cc}", flag(cc));
    if let Some(asn) = g["asn"].as_u64() {
        s.push_str(&format!(" AS{asn}"));
        if let Some(org) = g["as_org"].as_str() {
            s.push(' ');
            s.extend(org.chars().take(24));
        }
    }
    s.trim().to_string()
}

fn badges(s: &Value) -> String {
    let mut b = Vec::new();
    if s["banned"].as_bool() == Some(true) {
        b.push("BANNED".to_string());
    }
    if s["allowlisted"].as_bool() == Some(true) {
        b.push("allow".to_string());
    }
    if let Some(feeds) = s["feeds"].as_array().filter(|f| !f.is_empty()) {
        b.push(format!(
            "feed:{}",
            feeds
                .iter()
                .filter_map(|x| x.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    b.join(" ")
}

fn fmt_bps(bits: f64) -> String {
    match bits.max(0.0) {
        b if b >= 1e9 => format!("{:.1} Gb/s", b / 1e9),
        b if b >= 1e6 => format!("{:.1} Mb/s", b / 1e6),
        b if b >= 1e3 => format!("{:.0} kb/s", b / 1e3),
        b => format!("{b:.0} b/s"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn owner(v: &Value) -> String {
    let p = v["process"].as_str().unwrap_or("?");
    let pid = v["pid"]
        .as_u64()
        .map(|p| format!("[{p}]"))
        .unwrap_or_default();
    match v["container"].as_str().or(v["unit"].as_str()) {
        Some(c) => format!("{c}/{p}{pid}"),
        None if v["process"].is_null() => String::new(),
        None => format!("{p}{pid}"),
    }
}

fn hostport(ip: &str, port: &Value) -> String {
    if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn print_flows(list: &Value, live: bool) {
    let mut rows = Vec::new();
    for fl in list.as_array().into_iter().flatten() {
        let remote = fl["remote"].as_str().unwrap_or("");
        let mut who = hostport(remote, &fl["rport"]);
        if let Some(n) = fl["remote_name"].as_str() {
            who = format!("{who} ({})", truncate(n, 40));
        }
        let cc = fl["country"].as_str().unwrap_or("");
        let dir = match fl["dir"].as_str() {
            Some("in") => "←",
            Some("out") => "→",
            _ => "?",
        };
        let app = &fl["app"];
        let detail = app["sni"]
            .as_str()
            .map(|s| format!("tls {s}"))
            .or_else(|| {
                app["http_host"].as_str().map(|h| {
                    format!(
                        "http {} {h}{}",
                        app["http_method"].as_str().unwrap_or(""),
                        app["http_path"].as_str().unwrap_or("")
                    )
                })
            })
            .or_else(|| app["ssh_client"].as_str().map(|b| b.to_string()))
            .or_else(|| app["dns_qname"].as_str().map(|q| format!("dns {q}")))
            .unwrap_or_default();
        let detail = match app["exploit"].as_str() {
            Some(x) => {
                format!("⚠ {} {x} · {detail}", app["cve"].as_str().unwrap_or("")).replace("  ", " ")
            }
            None => detail,
        };
        let rate = f(&fl["rate_in"]) + f(&fl["rate_out"]);
        rows.push(vec![
            ago(fl["last_seen"].as_i64().unwrap_or(0)),
            dir.to_string(),
            fl["proto"].as_str().unwrap_or("").to_string(),
            hostport(fl["local"].as_str().unwrap_or(""), &fl["lport"]),
            format!("{} {who}", util::flag(cc)).trim().to_string(),
            owner(fl),
            fl["state"].as_str().unwrap_or("").to_string(),
            fmt_bytes(f(&fl["bytes_in"])),
            fmt_bytes(f(&fl["bytes_out"])),
            if live {
                fmt_bps(rate * 8.0)
            } else {
                util::fmt_approx(
                    fl["last_seen"].as_i64().unwrap_or(0) - fl["first_seen"].as_i64().unwrap_or(0),
                )
            },
            fl["iface"].as_str().unwrap_or("").to_string(),
            truncate(&detail, 50),
        ]);
    }
    table(
        &[
            "SEEN",
            "",
            "PROTO",
            "LOCAL",
            "REMOTE",
            "PROCESS",
            "STATE",
            "IN",
            "OUT",
            if live { "RATE" } else { "DURATION" },
            "IFACE",
            "APP",
        ],
        rows,
    );
}

fn ago(ts: i64) -> String {
    if ts <= 0 {
        return "-".into();
    }
    let d = (util::now_unix() - ts).max(0);
    match d {
        0..60 => format!("{d}s ago"),
        60..3600 => format!("{}m ago", d / 60),
        3600..86400 => format!("{}h ago", d / 3600),
        _ => format!("{}d ago", d / 86400),
    }
}

fn table(headers: &[&str], rows: Vec<Vec<String>>) {
    if rows.is_empty() {
        println!("(none)");
        return;
    }
    let width = |s: &str| s.chars().count();
    let mut w: Vec<usize> = headers.iter().map(|h| width(h)).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(width(c));
        }
    }
    let line = |cells: Vec<&str>| {
        let parts: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c}{}", " ".repeat(w[i] - width(c))))
            .collect();
        println!("{}", parts.join("  ").trim_end());
    };
    line(headers.to_vec());
    for r in &rows {
        line(r.iter().map(String::as_str).collect());
    }
}

fn print_insights(list: &Value) {
    for i in list.as_array().into_iter().flatten() {
        let icon = match i["level"].as_str() {
            Some("critical") => "✖",
            Some("warn") => "▲",
            _ => "•",
        };
        println!("{icon} {}", i["title"].as_str().unwrap_or(""));
        if let Some(d) = i["detail"].as_str().filter(|d| !d.is_empty()) {
            println!("    {d}");
        }
        if let Some(a) = i["action"].as_str() {
            println!("    $ {a}");
        }
    }
}

fn print_rules(title: &str, rules: &Value) {
    let rules = rules.as_array().cloned().unwrap_or_default();
    if rules.is_empty() {
        return;
    }
    println!("{title}:");
    for r in rules {
        let ttl = r["ttl_secs"]
            .as_i64()
            .map(|t| format!(" for {}", util::fmt_secs(t)))
            .unwrap_or_default();
        println!(
            "  {:<10} {}{ttl}  when {}",
            r["action"].as_str().unwrap_or(""),
            r["description"].as_str().unwrap_or(""),
            serde_json::to_string(&r["when"]).unwrap_or_default()
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn sent(ids: Vec<i64>, failing: &[i64]) -> (Vec<i64>, anyhow::Result<()>) {
        let calls = Mutex::new(Vec::new());
        let result = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(each_proposal(ids, |id| {
                calls.lock().unwrap().push(id);
                let fail = failing.contains(&id);
                async move {
                    if fail {
                        bail!("no proposal #{id}");
                    }
                    Ok(control::Response {
                        ok: true,
                        message: format!("banned 192.0.2.{id}/32 for 7d"),
                        data: None,
                    })
                }
            }));
        (calls.into_inner().unwrap(), result)
    }

    #[test]
    fn approve_sends_each_id_once_and_reports_failures_at_the_end() {
        let (calls, result) = sent(vec![2, 3, 5], &[]);
        assert_eq!(calls, [2, 3, 5]);
        assert!(result.is_ok());

        let (calls, result) = sent(vec![2, 3, 2, 5], &[3]);
        assert_eq!(calls, [2, 3, 5], "keeps going past #3, and #2 goes once");
        assert_eq!(result.unwrap_err().to_string(), "1 of 3 proposals failed");

        let (_, result) = sent(vec![7], &[7]);
        assert_eq!(result.unwrap_err().to_string(), "no proposal #7");
    }

    #[test]
    fn approve_and_reject_take_several_ids() {
        let cli = Cli::try_parse_from(["netwatch", "approve", "2", "3", "5"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Approve { ids } if ids == [2, 3, 5]));
        let cli = Cli::try_parse_from(["netwatch", "reject", "4"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::Reject { ids } if ids == [4]));
        assert!(Cli::try_parse_from(["netwatch", "approve"]).is_err());
    }
}
