//! Request lines from temps over a Unix datagram socket. temps' proxy
//! decrypts HTTPS, so it sees the requests the payload sampler can't; each
//! line goes through the same exploit matching and per-source request
//! history as a plaintext request, served by "temps".
//!
//! One JSON object per datagram, versioned by `v` (the sender, temps-shield's
//! `netwatch` module, documents the format). Lines with an unknown `v` are
//! ignored. Version 1:
//!
//! ```json
//! {"v":1,"ts_ms":1793000000000,"ip":"203.0.113.7","method":"GET","host":"app.example.com",
//!  "path":"/.env","user_agent":"curl/8.5.0","status":404,"tls":true,"ja4":"t13d…",
//!  "verdict":"log","acted":null,"signature":"secrets-probe"}
//! ```

use std::{
    collections::BTreeSet, io::ErrorKind, net::IpAddr, os::unix::fs::PermissionsExt, sync::Arc,
};

use anyhow::Context as _;
use serde::Deserialize;
use tokio::net::UnixDatagram;

use crate::{
    daemon::App,
    exploits::{self, SIGNATURES, Signature},
    flows::InboundRequest,
    util::now_unix,
};

/// The line version this netwatch reads.
pub const WIRE_VERSION: u32 = 1;
/// temps cuts its fields to 512 characters; anything larger is not a line.
const MAX_DATAGRAM: usize = 16 * 1024;
/// Lines handled per engine lock.
const BATCH: usize = 256;

/// One request temps served. Fields not listed here are ignored, so temps
/// can add some without a new version.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct RequestLine {
    pub ts_ms: i64,
    pub ip: IpAddr,
    pub method: String,
    pub host: String,
    /// The path with its query.
    pub path: String,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub ja4: Option<String>,
    /// What temps' lists and signals said: pass, log, challenge or block.
    #[serde(default)]
    pub verdict: Option<String>,
    /// What temps did about it (block, challenge), when it answered itself.
    #[serde(default)]
    pub acted: Option<String>,
    /// The exploit signature temps matched, as the CVE or the signature id.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Why a datagram was not taken.
#[derive(Debug, PartialEq)]
pub enum Skipped {
    UnknownVersion(u32),
    Invalid,
}

#[derive(Deserialize)]
struct Version {
    v: u32,
}

pub fn parse(data: &[u8]) -> Result<RequestLine, Skipped> {
    let data = data.trim_ascii_end();
    let Version { v } = serde_json::from_slice(data).map_err(|_| Skipped::Invalid)?;
    if v != WIRE_VERSION {
        return Err(Skipped::UnknownVersion(v));
    }
    serde_json::from_slice(data).map_err(|_| Skipped::Invalid)
}

fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).filter(|c| !c.is_control()).collect()
}

/// The signature temps named, when the request as rebuilt here matches none
/// (temps also reads headers it doesn't send). Both tables share ids and CVEs.
fn named_signature(name: &str) -> Option<&'static Signature> {
    SIGNATURES
        .iter()
        .find(|s| s.id == name || s.cve == Some(name))
}

/// The line as the engine takes a sampled request. `ts` is clamped to `now`.
pub fn to_request(line: &RequestLine, now: i64) -> InboundRequest {
    let method = clip(&line.method, 16);
    let host = clip(&line.host, 255);
    let path = clip(&line.path, 1024);
    let user_agent = clip(&line.user_agent, 256);
    // The same text the sampler would have seen in a plaintext request.
    let sample =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\r\n");
    let exploit = exploits::match_request(sample.as_bytes())
        .or_else(|| line.signature.as_deref().and_then(named_signature));
    InboundRequest {
        ts: (line.ts_ms.div_euclid(1000)).min(now),
        remote: line.ip,
        port: if line.tls { 443 } else { 80 },
        what: format!("{method} {host}{path}"),
        served_by: Some("temps".into()),
        exploit,
        via_temps: true,
    }
}

pub async fn serve(app: Arc<App>) {
    if let Err(e) = serve_inner(app).await {
        log::error!("temps socket: {e:#}");
    }
}

async fn serve_inner(app: Arc<App>) -> anyhow::Result<()> {
    let path = &app.cfg.temps.socket;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    log::info!("taking request lines from temps on {}", path.display());
    receive(&sock, |batch| {
        let now = now_unix();
        let mut e = app.engine.lock().unwrap();
        for line in batch {
            e.observe_temps(to_request(line, now));
        }
    })
    .await
}

/// Reads lines off `sock` and hands them to `take` in batches, until the
/// socket fails.
async fn receive(sock: &UnixDatagram, mut take: impl FnMut(&[RequestLine])) -> anyhow::Result<()> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut warned: BTreeSet<u32> = BTreeSet::new();
    loop {
        sock.readable().await?;
        let mut batch = Vec::new();
        while batch.len() < BATCH {
            match sock.try_recv(&mut buf) {
                Ok(n) => match parse(&buf[..n]) {
                    Ok(line) => batch.push(line),
                    Err(Skipped::UnknownVersion(v)) => {
                        if warned.insert(v) {
                            log::warn!(
                                "temps sends request lines of version {v}; this netwatch reads {WIRE_VERSION}, ignoring them"
                            );
                        }
                    }
                    Err(Skipped::Invalid) => {
                        log::debug!("temps socket: unreadable line ({n} bytes)")
                    }
                },
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("reading the temps socket"),
            }
        }
        if !batch.is_empty() {
            take(&batch);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{config::Config, engine::Engine, geo::Geo};

    const NOW: i64 = 1_793_000_000;

    fn line(path: &str) -> String {
        format!(
            r#"{{"v":1,"ts_ms":{}123,"ip":"203.0.113.7","method":"GET","host":"app.example.com","path":"{path}","user_agent":"curl/8.5.0","status":404,"tls":true,"ja4":null,"verdict":"log","acted":null,"signature":null,"later_field":1}}"#,
            NOW
        )
    }

    fn parsed(text: &str) -> RequestLine {
        match parse(text.as_bytes()) {
            Ok(l) => l,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parses_v1_and_ignores_the_rest() {
        let l = parsed(&format!("{}\n", line("/.env")));
        assert_eq!(l.ip, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(
            (l.method.as_str(), l.host.as_str(), l.path.as_str()),
            ("GET", "app.example.com", "/.env")
        );
        assert_eq!(
            (l.status, l.tls, l.verdict.as_deref()),
            (404, true, Some("log"))
        );
        // Only the required fields.
        let min =
            parsed(r#"{"v":1,"ts_ms":1,"ip":"2001:db8::1","method":"GET","host":"h","path":"/"}"#);
        assert_eq!(
            (min.user_agent.as_str(), min.status, min.tls),
            ("", 0, false)
        );

        assert_eq!(
            parse(br#"{"v":2,"anything":"else"}"#),
            Err(Skipped::UnknownVersion(2))
        );
        assert_eq!(parse(br#"{"ts_ms":1}"#), Err(Skipped::Invalid));
        assert_eq!(parse(br#"{"v":1,"ip":"not an ip"}"#), Err(Skipped::Invalid));
        assert_eq!(parse(b"GET / HTTP/1.1"), Err(Skipped::Invalid));
    }

    #[test]
    fn a_line_becomes_a_sampled_request() {
        let r = to_request(&parsed(&line("/cgi-bin/.%2e/.%2e/bin/sh")), NOW + 60);
        assert_eq!(r.ts, NOW);
        assert_eq!(r.port, 443);
        assert_eq!(r.what, "GET app.example.com/cgi-bin/.%2e/.%2e/bin/sh");
        assert_eq!(r.served_by.as_deref(), Some("temps"));
        assert!(r.via_temps);
        assert_eq!(r.exploit.map(|s| s.id), Some("apache-traversal"));

        // A timestamp from the future is not trusted.
        assert_eq!(to_request(&parsed(&line("/")), NOW - 5).ts, NOW - 5);
        assert!(to_request(&parsed(&line("/")), NOW).exploit.is_none());

        // Headers temps read but doesn't send: its signature stands in, by id or CVE.
        let mut l = parsed(&line("/_next/data"));
        l.signature = Some("CVE-2025-29927".into());
        assert_eq!(
            to_request(&l, NOW).exploit.map(|s| s.id),
            Some("nextjs-middleware")
        );
        l.signature = Some("nextjs-middleware".into());
        assert_eq!(
            to_request(&l, NOW).exploit.map(|s| s.id),
            Some("nextjs-middleware")
        );
        l.signature = Some("not-a-signature".into());
        assert!(to_request(&l, NOW).exploit.is_none());

        // Fields are clipped and lose control characters.
        let mut l = parsed(&line("/"));
        l.host = format!("evil\r\n{}", "h".repeat(400));
        let r = to_request(&l, NOW);
        assert!(!r.what.contains('\r') && r.what.len() < 300);
    }

    #[test]
    fn reported_requests_feed_the_exploit_findings() {
        let cfg = Arc::new(Config::default());
        let geo = Geo::open(
            Path::new("/nonexistent/city.mmdb"),
            Path::new("/nonexistent/asn.mmdb"),
        );
        let mut e = Engine::new(cfg, geo, (32768, 60999));
        let now = now_unix();
        let mut l = parsed(&line("/.env"));
        l.ts_ms = now * 1000;
        e.observe_temps(to_request(&l, now));
        e.evaluate(now);
        let st = &e.states[&l.ip];
        assert_eq!(st.requests.len(), 1);
        assert_eq!(st.exploits.len(), 1);
        let f = st
            .findings
            .iter()
            .find(|f| f.kind == "recon_probe")
            .expect("no finding");
        assert!(
            f.summary.contains("GET app.example.com/.env"),
            "{}",
            f.summary
        );
        assert!(f.summary.contains("temps"), "{}", f.summary);
        assert!(e.temps_requests.is_empty());
    }

    #[tokio::test]
    async fn lines_are_read_off_the_socket() {
        let path =
            std::env::temp_dir().join(format!("netwatch-temps-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let sock = UnixDatagram::bind(&path).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            receive(&sock, |batch| {
                for l in batch {
                    let _ = tx.send(l.path.clone());
                }
            })
            .await
        });
        let client = std::os::unix::net::UnixDatagram::unbound().unwrap();
        for msg in [
            line("/first"),
            r#"{"v":7,"path":"/future"}"#.to_string(),
            "garbage".to_string(),
            line("/second"),
        ] {
            client
                .send_to(format!("{msg}\n").as_bytes(), &path)
                .unwrap();
        }
        let mut got = Vec::new();
        while got.len() < 2 {
            let path = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("no line")
                .unwrap();
            got.push(path);
        }
        assert_eq!(got, ["/first", "/second"]);
        reader.abort();
        let _ = std::fs::remove_file(&path);
    }
}
