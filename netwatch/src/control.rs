//! Root-only Unix socket for state-changing commands. The HTTP API is
//! read-only; every ban, approval and policy change goes through here.

use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};

use crate::{
    daemon::App,
    util::{fmt_secs, parse_duration, parse_target},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ban {
        target: String,
        ttl: Option<String>,
        reason: Option<String>,
        force: bool,
    },
    Unban {
        target: String,
    },
    Allow {
        target: String,
        note: Option<String>,
    },
    Disallow {
        target: String,
    },
    Approve {
        id: i64,
    },
    Reject {
        id: i64,
    },
    PolicySet {
        text: String,
        dry_run: bool,
    },
    PolicyClear,
    Analyze,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    pub message: String,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

pub async fn serve(app: Arc<App>) {
    if let Err(e) = serve_inner(app).await {
        log::error!("control socket: {e:#}");
    }
}

async fn serve_inner(app: Arc<App>) -> anyhow::Result<()> {
    let path = &app.cfg.control_socket;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    log::info!("control socket at {}", path.display());
    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(app, stream).await {
                log::warn!("control client: {e:#}");
            }
        });
    }
}

async fn handle(app: Arc<App>, stream: UnixStream) -> anyhow::Result<()> {
    let (r, mut w) = stream.into_split();
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await?;
    let resp = match serde_json::from_str::<Request>(&line) {
        Ok(req) => {
            log::info!("control: {req:?}");
            match execute(&app, req).await {
                Ok((message, data)) => Response {
                    ok: true,
                    message,
                    data,
                },
                Err(e) => Response {
                    ok: false,
                    message: format!("{e:#}"),
                    data: None,
                },
            }
        }
        Err(e) => Response {
            ok: false,
            message: format!("bad request: {e}"),
            data: None,
        },
    };
    w.write_all(serde_json::to_string(&resp)?.as_bytes())
        .await?;
    w.write_all(b"\n").await?;
    Ok(())
}

async fn execute(
    app: &Arc<App>,
    req: Request,
) -> anyhow::Result<(String, Option<serde_json::Value>)> {
    Ok(match req {
        Request::Ban {
            target,
            ttl,
            reason,
            force,
        } => {
            let net = parse_target(&target)?;
            let ttl = match ttl.as_deref() {
                None => Some(parse_duration(&app.cfg.ban.default_ttl)?),
                Some("permanent" | "forever" | "0") => None,
                Some(t) => Some(parse_duration(t)?),
            };
            let reason = reason.unwrap_or_else(|| "manual".into());
            app.ban(net, ttl, &reason, "manual", force)?;
            (
                format!(
                    "banned {net} {}",
                    ttl.map_or("permanently".into(), |t| format!("for {}", fmt_secs(t)))
                ),
                None,
            )
        }
        Request::Unban { target } => {
            let net = parse_target(&target)?;
            let existed = app.unban(net)?;
            (
                if existed {
                    format!("unbanned {net}")
                } else {
                    format!("{net} was not banned")
                },
                None,
            )
        }
        Request::Allow { target, note } => {
            let net = parse_target(&target)?;
            app.allow(net, note.as_deref().unwrap_or("manual"))?;
            (
                format!("{net} allowlisted (never banned, kept out of proposals)"),
                None,
            )
        }
        Request::Disallow { target } => {
            let net = parse_target(&target)?;
            let removed = app.disallow(net)?;
            (
                if removed {
                    format!("{net} removed from the allowlist")
                } else {
                    format!(
                        "{net} has no manual allow rule (config and discovered entries can't be removed here)"
                    )
                },
                None,
            )
        }
        Request::Approve { id } => (app.approve(id)?, None),
        Request::Reject { id } => {
            app.reject(id)?;
            (
                format!("proposal #{id} rejected; it won't be raised again for 24h"),
                None,
            )
        }
        Request::PolicySet { text, dry_run } => {
            let (rules, by) = app.set_policy(&text, dry_run).await?;
            let verb = if dry_run {
                "would install"
            } else {
                "installed"
            };
            (
                format!("{verb} {} rules (compiled by {by})", rules.len()),
                Some(serde_json::to_value(rules)?),
            )
        }
        Request::PolicyClear => {
            app.clear_policy()?;
            ("policy cleared; built-in defaults apply".into(), None)
        }
        Request::Analyze => (app.analyze(true).await?, None),
    })
}

/// Client side, used by the CLI.
pub async fn send(socket: &Path, req: &Request) -> anyhow::Result<Response> {
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "connecting to {} (is the daemon running, and are you root?)",
            socket.display()
        )
    })?;
    let (r, mut w) = stream.into_split();
    w.write_all(serde_json::to_string(req)?.as_bytes()).await?;
    w.write_all(b"\n").await?;
    let mut line = String::new();
    BufReader::new(r).read_line(&mut line).await?;
    Ok(serde_json::from_str(&line)?)
}
