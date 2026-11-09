//! Ban policy as structured rules. User rules come from a natural-language
//! policy compiled once by the LLM; evaluating them never calls the LLM.

use std::net::IpAddr;

use anyhow::{bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Ban,
    Review,
    /// Don't raise proposals for matching sources (still shown in the UI).
    Ignore,
    /// Never ban matching sources, whatever other rules say.
    NeverBan,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Ban => "ban",
            Action::Review => "review",
            Action::Ignore => "ignore",
            Action::NeverBan => "never_ban",
        }
    }
}

/// All present conditions must hold.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cond {
    /// Matches if the source has any of these finding kinds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings_any: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score: Option<u32>,
    /// ISO country codes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_countries: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub asns: Vec<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<IpNet>,
    /// Matches if the source touched any of these local ports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ports_any: Vec<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_feed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ssh_failed: Option<u64>,
}

impl Cond {
    fn is_empty(&self) -> bool {
        self.findings_any.is_empty()
            && self.min_score.is_none()
            && self.countries.is_empty()
            && self.not_countries.is_empty()
            && self.asns.is_empty()
            && self.cidrs.is_empty()
            && self.ports_any.is_empty()
            && self.in_feed.is_none()
            && self.min_ssh_failed.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub action: Action,
    #[serde(default)]
    pub ttl_secs: Option<i64>,
    #[serde(default)]
    pub when: Cond,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

/// What the rules see about a source.
pub struct Subject<'a> {
    pub ip: IpAddr,
    pub score: u32,
    pub kinds: Vec<&'a str>,
    pub country: Option<&'a str>,
    pub asn: Option<u32>,
    pub ports: Vec<u16>,
    pub in_feed: bool,
    pub ssh_failed: u64,
}

impl Rule {
    pub fn matches(&self, s: &Subject<'_>) -> bool {
        let w = &self.when;
        if !self.enabled || w.is_empty() {
            return false;
        }
        let cc = s.country.unwrap_or("");
        (w.findings_any.is_empty() || w.findings_any.iter().any(|k| s.kinds.contains(&k.as_str())))
            && w.min_score.is_none_or(|m| s.score >= m)
            && (w.countries.is_empty() || w.countries.iter().any(|c| c.eq_ignore_ascii_case(cc)))
            && !w.not_countries.iter().any(|c| c.eq_ignore_ascii_case(cc))
            && (w.asns.is_empty() || s.asn.is_some_and(|a| w.asns.contains(&a)))
            && (w.cidrs.is_empty() || w.cidrs.iter().any(|n| n.contains(&s.ip)))
            && (w.ports_any.is_empty() || w.ports_any.iter().any(|p| s.ports.contains(p)))
            && w.in_feed.is_none_or(|f| f == s.in_feed)
            && w.min_ssh_failed.is_none_or(|m| s.ssh_failed >= m)
    }
}

/// Built-in rules, used after (and overridable by) user rules.
pub fn defaults() -> Vec<Rule> {
    let r = |id: &str, desc: &str, action, ttl: Option<i64>, when: Cond| Rule {
        id: format!("default:{id}"),
        description: desc.into(),
        action,
        ttl_secs: ttl,
        when,
        enabled: true,
    };
    let kinds = |k: &[&str]| k.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    const H: i64 = 3600;
    vec![
        r(
            "compromise",
            "A login that follows many failures, or from a never-seen location: a human must look",
            Action::Review,
            None,
            Cond {
                findings_any: kinds(&["login_after_failures", "new_login_location"]),
                ..Default::default()
            },
        ),
        r(
            "bruteforce",
            "Password guessing against SSH or another auth service",
            Action::Ban,
            Some(7 * 24 * H),
            Cond {
                findings_any: kinds(&["ssh_bruteforce", "brute_force"]),
                min_score: Some(60),
                ..Default::default()
            },
        ),
        r(
            "flood",
            "SYN / packet / ICMP flood from a single source",
            Action::Ban,
            Some(H),
            Cond {
                findings_any: kinds(&["syn_flood", "flood", "icmp_flood"]),
                ..Default::default()
            },
        ),
        r(
            "exploit",
            "Sent a known exploit (a named CVE, command injection or path traversal) to a service here",
            Action::Ban,
            Some(7 * 24 * H),
            Cond {
                findings_any: kinds(&["exploit_attempt"]),
                ..Default::default()
            },
        ),
        r(
            "listed-prober",
            "Listed on a threat feed and probing this host",
            Action::Ban,
            Some(7 * 24 * H),
            Cond {
                in_feed: Some(true),
                findings_any: kinds(&[
                    "port_scan",
                    "closed_probe",
                    "sensitive_probe",
                    "recon_probe",
                    "brute_force",
                    "ssh_bruteforce",
                ]),
                ..Default::default()
            },
        ),
        r(
            "scanner",
            "Wide port scan (many ports in 10 minutes)",
            Action::Ban,
            Some(24 * H),
            Cond {
                findings_any: kinds(&["port_scan"]),
                min_score: Some(75),
                ..Default::default()
            },
        ),
        r(
            "high-score",
            "Anything scoring 85 or more",
            Action::Ban,
            Some(24 * H),
            Cond {
                min_score: Some(85),
                ..Default::default()
            },
        ),
        r(
            "review",
            "Suspicious but not conclusive",
            Action::Review,
            None,
            Cond {
                min_score: Some(40),
                ..Default::default()
            },
        ),
    ]
}

/// never_ban rules win wherever they are; otherwise the first match (user rules
/// first, then defaults) decides.
pub fn decide<'r>(user: &'r [Rule], defaults: &'r [Rule], s: &Subject<'_>) -> Option<&'r Rule> {
    if let Some(r) = user
        .iter()
        .chain(defaults)
        .find(|r| r.action == Action::NeverBan && r.matches(s))
    {
        return Some(r);
    }
    user.iter().chain(defaults).find(|r| r.matches(s))
}

pub const FINDING_KINDS: &[(&str, &str)] = &[
    (
        "port_scan",
        "touched many distinct local ports in 10 minutes",
    ),
    ("closed_probe", "probed several ports with no listener"),
    (
        "sensitive_probe",
        "probed services that should never be public (RDP, SMB, Redis, Docker API...)",
    ),
    (
        "brute_force",
        "many connection attempts to a listening auth port (SSH, SMTP, DB...)",
    ),
    ("conn_flood", "very many connections to one listening port"),
    ("syn_flood", "high SYN rate"),
    ("flood", "high packet rate"),
    ("icmp_flood", "high ICMP echo rate"),
    (
        "exploit_attempt",
        "sent a known exploit (CVE, command injection, path traversal) in a plaintext request, or an HTTPS one temps reported, or a TCP SYN with IPv4 options (CVE-2026-98432)",
    ),
    (
        "recon_probe",
        "requested leaked-secret paths (.env, .git, cloud keys)",
    ),
    ("threat_feed", "listed on a threat-intel blocklist"),
    (
        "outbound_to_listed",
        "this host connected to a listed address",
    ),
    ("watched_country", "from a country on the watch list"),
    (
        "ssh_bruteforce",
        "failed SSH logins / invalid users in sshd logs",
    ),
    (
        "login_after_failures",
        "successful SSH login after many failures",
    ),
    (
        "new_login_location",
        "successful SSH login from a never-seen country/ASN",
    ),
];

/// Checks LLM-produced rules before they are trusted.
pub fn validate(rules: &mut [Rule]) -> anyhow::Result<()> {
    ensure!(rules.len() <= 50, "too many rules ({})", rules.len());
    for (i, r) in rules.iter_mut().enumerate() {
        if r.id.is_empty() || r.id.starts_with("default:") {
            r.id = format!("user:{}", i + 1);
        }
        if r.when.is_empty() {
            bail!(
                "rule {:?} has no conditions; it would match every source",
                r.description
            );
        }
        for k in &r.when.findings_any {
            if !FINDING_KINDS.iter().any(|(kind, _)| kind == k) {
                bail!("rule {:?} uses unknown finding kind {k:?}", r.description);
            }
        }
        for n in &r.when.cidrs {
            let broad = match n {
                IpNet::V4(n) => n.prefix_len() < 8,
                IpNet::V6(n) => n.prefix_len() < 16,
            };
            if broad && r.action == Action::Ban {
                bail!("rule {:?} bans {n}, which is too broad", r.description);
            }
        }
        if let Some(t) = r.ttl_secs {
            ensure!(t > 0, "rule {:?} has a non-positive ttl", r.description);
        }
        for c in r
            .when
            .countries
            .iter_mut()
            .chain(r.when.not_countries.iter_mut())
        {
            *c = c.to_ascii_uppercase();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject<'a>(kinds: Vec<&'a str>, score: u32, cc: &'a str) -> Subject<'a> {
        Subject {
            ip: "203.0.113.9".parse().unwrap(),
            score,
            kinds,
            country: Some(cc),
            asn: Some(64500),
            ports: vec![22],
            in_feed: false,
            ssh_failed: 0,
        }
    }

    #[test]
    fn defaults_order() {
        let d = defaults();
        let s = subject(vec!["ssh_bruteforce"], 70, "CN");
        assert_eq!(decide(&[], &d, &s).unwrap().id, "default:bruteforce");
        let s = subject(vec!["closed_probe"], 45, "CN");
        assert_eq!(decide(&[], &d, &s).unwrap().action, Action::Review);
        let s = subject(vec![], 0, "CN");
        assert!(decide(&[], &d, &s).is_none());
    }

    #[test]
    fn never_ban_wins() {
        let user = vec![Rule {
            id: "u1".into(),
            description: "never ban ES".into(),
            action: Action::NeverBan,
            ttl_secs: None,
            when: Cond {
                countries: vec!["ES".into()],
                ..Default::default()
            },
            enabled: true,
        }];
        let s = subject(vec!["ssh_bruteforce"], 90, "es");
        assert_eq!(
            decide(&user, &defaults(), &s).unwrap().action,
            Action::NeverBan
        );
    }

    #[test]
    fn empty_rules_rejected() {
        let mut rules = vec![Rule {
            id: String::new(),
            description: "everything".into(),
            action: Action::Ban,
            ttl_secs: None,
            when: Cond::default(),
            enabled: true,
        }];
        assert!(validate(&mut rules).is_err());
    }
}
