//! Bans as a pf table. macOS's stock /etc/pf.conf evaluates `anchor
//! "com.apple/*"`, so rules loaded into com.apple/netwatch take effect without
//! editing it. Allowlisted networks go in the same table negated (`!net`):
//! pf matches tables by longest prefix, so an allowlisted /32 inside a banned
//! /24 passes, as it does with the XDP tries.
//!
//! pf drops after the capture tap, so the sensor still counts banned packets.

use std::{collections::BTreeSet, process::Command};

use anyhow::{Context as _, bail};
use ipnet::IpNet;

pub const ANCHOR: &str = "com.apple/netwatch";
const TABLE: &str = "netwatch_block";

const RULES: &str =
    "table <netwatch_block> persist\nblock drop in quick from <netwatch_block> to any\n";

pub struct Pf {
    /// Reference from `pfctl -E`; pf stays enabled while anyone holds one.
    token: Option<String>,
    /// The main ruleset doesn't reach our anchor (a custom pf.conf).
    pub unreferenced: bool,
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> anyhow::Result<(String, String)> {
    use std::io::Write;
    let mut child = Command::new("/sbin/pfctl")
        .args(args)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("running pfctl")?;
    if let (Some(input), Some(mut w)) = (stdin, child.stdin.take()) {
        w.write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        bail!("pfctl {}: {}", args.join(" "), stderr.trim());
    }
    Ok((stdout, stderr))
}

/// The token in `pfctl -E` output ("Token : 1234567890").
fn parse_token(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Token :")
                .map(|t| t.trim().to_string())
        })
        .filter(|t| !t.is_empty())
}

/// Table contents for the bans and the allowlist.
pub fn entries(block: &BTreeSet<IpNet>, allow: &BTreeSet<IpNet>) -> Vec<String> {
    if block.is_empty() {
        return Vec::new();
    }
    // Negations only matter inside a ban; leaving the rest out keeps the table small.
    block
        .iter()
        .map(IpNet::to_string)
        .chain(
            allow
                .iter()
                .filter(|a| block.iter().any(|b| b.contains(*a)))
                .map(|a| format!("!{a}")),
        )
        .collect()
}

impl Pf {
    pub fn start() -> anyhow::Result<Self> {
        if !super::is_root() {
            bail!("pf needs root");
        }
        let (_, stderr) = pfctl(&["-E"], None)?;
        let token = parse_token(&stderr);
        pfctl(&["-a", ANCHOR, "-f", "-"], Some(RULES))?;
        let (main, _) = pfctl(&["-s", "rules"], None).unwrap_or_default();
        let unreferenced = !main.contains("anchor \"com.apple/*\"");
        Ok(Self {
            token,
            unreferenced,
        })
    }

    pub fn sync(&self, block: &BTreeSet<IpNet>, allow: &BTreeSet<IpNet>) -> anyhow::Result<()> {
        let list = entries(block, allow);
        if list.is_empty() {
            pfctl(&["-a", ANCHOR, "-t", TABLE, "-T", "flush"], None)?;
            return Ok(());
        }
        let mut args = vec!["-a", ANCHOR, "-t", TABLE, "-T", "replace", "--"];
        args.extend(list.iter().map(String::as_str));
        pfctl(&args, None)?;
        Ok(())
    }

    /// Removes the rules and releases pf: bans only hold while netwatch runs,
    /// as XDP programs detach with the process on Linux.
    pub fn stop(&mut self) {
        let _ = pfctl(&["-a", ANCHOR, "-F", "all"], None);
        if let Some(t) = self.token.take() {
            let _ = pfctl(&["-X", &t], None);
        }
    }
}

impl Drop for Pf {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        let out = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 13897485627162543\n";
        assert_eq!(parse_token(out).as_deref(), Some("13897485627162543"));
        assert_eq!(parse_token("pf already enabled\n"), None);
    }

    #[test]
    fn allowlist_holes_only_inside_bans() {
        let block: BTreeSet<IpNet> = ["203.0.113.0/24".parse().unwrap()].into();
        let allow: BTreeSet<IpNet> = [
            "203.0.113.9/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ]
        .into();
        assert_eq!(
            entries(&block, &allow),
            ["203.0.113.0/24", "!203.0.113.9/32"]
        );
        assert!(entries(&BTreeSet::new(), &allow).is_empty());
    }
}
