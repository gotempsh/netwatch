use std::path::{Path, PathBuf};

use anyhow::Context as _;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/netwatch/netwatch.toml";

/// State (database, GeoIP files) and runtime sockets.
#[cfg(target_os = "linux")]
const DATA_DIR: &str = "/var/lib/netwatch";
#[cfg(target_os = "linux")]
const RUN_DIR: &str = "/run/netwatch";
#[cfg(target_os = "macos")]
const DATA_DIR: &str = "/var/db/netwatch";
#[cfg(target_os = "macos")]
const RUN_DIR: &str = "/var/run/netwatch";

/// Tailscale/WireGuard tunnels and Docker bridges. On macOS every tunnel is a
/// utun device, and VMs (UTM, Lima, Virtualization.framework) sit on bridgeN.
#[cfg(target_os = "linux")]
const FLOW_INTERFACES: &[&str] = &["tailscale*", "wg*", "docker0", "br-*"];
#[cfg(target_os = "macos")]
const FLOW_INTERFACES: &[&str] = &["utun*", "bridge*"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Detect and recommend; only manual bans are applied.
    Observe,
    /// Also ban automatically when a source crosses `ban.auto_ban_score`.
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Where XDP attaches (macOS: the interface captured for per-source
    /// accounting); "auto" = the interface of the default route.
    pub interface: String,
    /// "auto" (driver, falling back to skb), "driver" or "skb". Ignored on macOS.
    pub xdp_mode: String,
    pub mode: Mode,
    /// When false, bans are counted in the kernel but packets still pass (dry run).
    /// On macOS bans are dropped by pf, in the anchor com.apple/netwatch.
    pub drop_banned: bool,
    /// Drop IPv4 TCP SYNs carrying IP options in XDP, from any source. Mitigates
    /// CVE-2026-98432 on unpatched kernels; almost no legitimate client sets them.
    /// Linux only (the bug is in the Linux TCP stack).
    pub drop_syn_ip_options: bool,
    /// Read-only API + UI. Must be a loopback address.
    pub api_listen: String,
    /// Root-only control socket used by the CLI for bans, approvals and policy.
    pub control_socket: PathBuf,
    pub db_path: PathBuf,
    pub geoip_city: PathBuf,
    pub geoip_asn: PathBuf,
    pub tick_secs: u64,
    pub retention_days: u32,
    /// Record every conversation (both directions) with TC programs and TCP tracepoints.
    pub track_flows: bool,
    /// Interfaces to record flows on besides `interface`: exact names or
    /// prefixes ending in `*`. Tailscale/WireGuard show decrypted tailnet
    /// traffic; Docker bridges show per-container traffic.
    pub flow_interfaces: Vec<String>,
    /// Parse DNS packets to log queries and name the remote side of flows.
    pub sample_dns: bool,
    /// Parse the first payload of each TCP direction for TLS SNI, HTTP Host/User-Agent
    /// and SSH banners. Only those fields are kept, never payload bytes.
    pub sample_tcp_payload: bool,
    /// How long finished flows, DNS queries and connection events are kept.
    pub flow_retention_days: u32,
    pub allowlist: Vec<IpNet>,
    /// Never ban current WireGuard peer endpoints (`wg show all endpoints`).
    pub allow_wireguard_peers: bool,
    /// Never ban current Tailscale peer endpoints and DERP relays.
    pub allow_tailscale_peers: bool,
    /// Never ban Cloudflare ranges (cloudflared tunnels terminate there).
    pub allow_cloudflare: bool,
    pub feeds: Vec<Feed>,
    /// ISO country codes that add a small score bump and are called out in insights.
    pub watch_countries: Vec<String>,
    /// Ports where repeated connection attempts mean password guessing.
    pub auth_ports: Vec<u16>,
    /// Ports that should never be reachable from the internet; probing them is a scanner tell.
    pub sensitive_ports: Vec<u16>,
    /// systemd units whose journal carries SSH logins (sshd and Tailscale SSH).
    /// macOS reads sshd from the unified log instead.
    pub ssh_units: Vec<String>,
    pub thresholds: Thresholds,
    pub ban: BanPolicy,
    pub llm: LlmConfig,
    pub slack: SlackConfig,
    pub temps: TempsConfig,
    pub otel: OtelConfig,
}

/// Pushes metrics and security events to an OpenTelemetry collector over
/// OTLP/HTTP. Outbound only, like Slack: nothing new listens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtelConfig {
    pub enabled: bool,
    /// OTLP/HTTP endpoint; /v1/metrics and /v1/logs are appended.
    pub endpoint: String,
    /// Seconds between metric exports.
    pub interval_secs: u64,
    /// Export metrics: traffic, flows, sources, bans, proposals.
    pub metrics: bool,
    /// Export events as log records: findings, proposals, bans, SSH logins, listeners.
    pub logs: bool,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:4318".into(),
            interval_secs: 60,
            metrics: true,
            logs: true,
        }
    }
}

/// Request lines from temps (its proxy decrypts HTTPS, which the payload
/// sampler can't read). temps finds the socket on its own; with nothing
/// sending, it costs nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TempsConfig {
    pub enabled: bool,
    /// Unix datagram socket temps sends to; root-only, like the control socket.
    pub socket: PathBuf,
}

impl Default for TempsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: format!("{RUN_DIR}/requests.sock").into(),
        }
    }
}

/// Posts to a Slack incoming webhook. Outbound only: nothing in Slack can
/// change netwatch, so approving a ban stays a CLI action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackConfig {
    pub enabled: bool,
    /// Environment variable holding the webhook URL (put it in /etc/netwatch/env).
    pub webhook_env: String,
    /// Also post "review" proposals; off by default, they are the noisiest.
    pub notify_reviews: bool,
    /// Post every successful SSH/Tailscale login, not only suspicious ones.
    pub notify_logins: bool,
    /// Messages per hour; the rest are counted and summarised in the next one.
    pub max_per_hour: u32,
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            webhook_env: "NETWATCH_SLACK_WEBHOOK".into(),
            notify_reviews: false,
            notify_logins: false,
            max_per_hour: 20,
        }
    }
}

/// Any OpenAI-compatible chat completions endpoint (OpenAI, OpenRouter, Groq,
/// Ollama, vLLM, LiteLLM...). Optional: detection and rules work without it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LlmConfig {
    pub enabled: bool,
    /// Base URL up to and including /v1.
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    /// Environment variable holding the key when `api_key` is unset.
    pub api_key_env: String,
    /// Minimum seconds between analysis calls.
    pub interval_secs: u64,
    pub max_calls_per_hour: u32,
    /// Prompt + completion tokens per UTC day; analysis stops when spent.
    pub daily_token_budget: u64,
    /// Most suspicious sources included per call.
    pub max_sources_per_call: usize,
    pub max_output_tokens: u32,
    /// Ask for `response_format: json_object` (dropped automatically if unsupported).
    pub json_mode: bool,
    /// Apply LLM "ban" proposals without approval (enforce mode only).
    pub auto_apply: bool,
    pub min_confidence: f64,
    pub timeout_secs: u64,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://api.openai.com/v1".into(),
            model: String::new(),
            api_key: None,
            api_key_env: "NETWATCH_LLM_API_KEY".into(),
            interval_secs: 600,
            max_calls_per_hour: 6,
            daily_token_budget: 200_000,
            max_sources_per_call: 15,
            max_output_tokens: 600,
            json_mode: true,
            auto_apply: false,
            min_confidence: 0.9,
            timeout_secs: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feed {
    pub name: String,
    pub url: String,
    /// One line on what the feed lists, shown next to a match. Known feeds have a built-in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Thresholds {
    /// Distinct local ports touched within 10 minutes.
    pub scan_ports: usize,
    /// Closed (non-listening) ports probed within 10 minutes.
    pub probe_closed_ports: usize,
    /// SYNs to one listening auth port within 5 minutes.
    pub brute_force_syn_5m: u64,
    /// SYNs to any single listening port within 5 minutes.
    pub conn_flood_syn_5m: u64,
    /// Per-source SYN packets per second.
    pub syn_flood_pps: f64,
    /// Per-source inbound packets per second.
    pub flood_pps: f64,
    /// Per-source ICMP echo requests per second.
    pub icmp_flood_pps: f64,
    /// Interface-wide SYNs per second (distributed attack).
    pub global_syn_pps: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BanPolicy {
    pub default_ttl: String,
    pub max_ttl: String,
    /// Each previous offence multiplies the TTL by this factor.
    pub repeat_multiplier: i64,
    /// Score at which a source shows up as "review".
    pub review_score: u32,
    /// Score at which the recommendation becomes "ban".
    pub recommend_ban_score: u32,
    /// Score at which enforce mode bans automatically.
    pub auto_ban_score: u32,
    /// Flagged sources in one /24 (or /64) before recommending a range ban.
    pub subnet_min_sources: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "auto".into(),
            xdp_mode: "auto".into(),
            mode: Mode::Observe,
            drop_banned: true,
            drop_syn_ip_options: false,
            api_listen: "127.0.0.1:9180".into(),
            control_socket: format!("{RUN_DIR}/control.sock").into(),
            db_path: format!("{DATA_DIR}/netwatch.db").into(),
            geoip_city: format!("{DATA_DIR}/dbip-city-lite.mmdb").into(),
            geoip_asn: format!("{DATA_DIR}/dbip-asn-lite.mmdb").into(),
            tick_secs: 5,
            retention_days: 30,
            track_flows: true,
            flow_interfaces: FLOW_INTERFACES.iter().map(|s| s.to_string()).collect(),
            sample_dns: true,
            sample_tcp_payload: true,
            flow_retention_days: 7,
            allowlist: [
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "::1/128",
                "fc00::/7",
                "fe80::/10",
            ]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect(),
            allow_wireguard_peers: true,
            allow_tailscale_peers: true,
            allow_cloudflare: true,
            // The parts of FireHOL level 1, loaded separately so a match names its source.
            feeds: [
                ("spamhaus_drop", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset"),
                ("dshield", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset"),
                ("feodo", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/feodo.ipset"),
                ("fullbogons", "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt"),
            ]
            .iter()
            .map(|(name, url)| Feed { name: name.to_string(), url: url.to_string(), about: None })
            .collect(),
            watch_countries: vec![],
            auth_ports: vec![21, 22, 23, 25, 110, 143, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900],
            ssh_units: vec!["ssh.service".into(), "sshd.service".into(), "tailscaled.service".into()],
            sensitive_ports: vec![
                23, 135, 139, 445, 1433, 1521, 2375, 2376, 3306, 3389, 5432, 5555, 5900, 5984, 6379,
                6443, 7547, 9200, 10250, 11211, 27017,
            ],
            thresholds: Thresholds::default(),
            ban: BanPolicy::default(),
            llm: LlmConfig::default(),
            slack: SlackConfig::default(),
            temps: TempsConfig::default(),
            otel: OtelConfig::default(),
        }
    }
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            scan_ports: 12,
            probe_closed_ports: 3,
            brute_force_syn_5m: 30,
            conn_flood_syn_5m: 600,
            syn_flood_pps: 200.0,
            flood_pps: 20_000.0,
            icmp_flood_pps: 100.0,
            global_syn_pps: 2_000.0,
        }
    }
}

impl Default for BanPolicy {
    fn default() -> Self {
        Self {
            default_ttl: "24h".into(),
            max_ttl: "30d".into(),
            repeat_multiplier: 4,
            review_score: 40,
            recommend_ban_score: 70,
            auto_ban_score: 80,
            subnet_min_sources: 3,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut cfg = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            toml::from_str::<Self>(&text).with_context(|| format!("parsing {}", path.display()))?
        } else {
            log::warn!("{} not found, using built-in defaults", path.display());
            Self::default()
        };
        if cfg.interface.is_empty() || cfg.interface == "auto" {
            match crate::netif::default_route_interface() {
                Some(i) => cfg.interface = i,
                None => log::warn!("no default route; set `interface` in {}", path.display()),
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        crate::util::parse_duration(&self.ban.default_ttl)?;
        crate::util::parse_duration(&self.ban.max_ttl)?;
        anyhow::ensure!(self.tick_secs >= 1, "tick_secs must be >= 1");
        let addr: std::net::SocketAddr = self
            .api_listen
            .parse()
            .with_context(|| format!("api_listen {:?}", self.api_listen))?;
        anyhow::ensure!(
            addr.ip().is_loopback(),
            "api_listen must be a loopback address (the UI is local-only; use an SSH tunnel to reach it)"
        );
        if self.llm.enabled {
            anyhow::ensure!(
                !self.llm.model.is_empty(),
                "llm.model must be set when llm.enabled = true"
            );
        }
        Ok(())
    }

    pub fn api_url(&self) -> String {
        format!("http://{}", self.api_listen)
    }
}
