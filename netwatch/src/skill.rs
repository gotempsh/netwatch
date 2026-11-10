//! The agent skill (skills/netwatch/SKILL.md at the repository root), embedded
//! so an installed copy always matches the installed binary.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

pub const SKILL: &str = include_str!("../../skills/netwatch/SKILL.md");

/// Where Claude Code looks for personal skills.
pub fn default_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .context("HOME is not set; pass --dir with the skills directory")?;
    Ok(Path::new(&home).join(".claude/skills"))
}

/// Writes `<dir>/netwatch/SKILL.md`, replacing an older copy.
pub fn install(dir: &Path) -> anyhow::Result<PathBuf> {
    let skill_dir = dir.join("netwatch");
    std::fs::create_dir_all(&skill_dir)
        .with_context(|| format!("creating {}", skill_dir.display()))?;
    let path = skill_dir.join("SKILL.md");
    let tmp = skill_dir.join(".SKILL.md.tmp");
    std::fs::write(&tmp, SKILL).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Refuses to install into a home directory as root through sudo. Depending
/// on sudoers, HOME is root's or still the caller's; in the caller's home the
/// files would belong to root and a later install without sudo couldn't
/// replace them.
pub fn refuse_sudo(sudo_user: Option<&str>) -> anyhow::Result<()> {
    match sudo_user {
        Some(user) => anyhow::bail!(
            "not installing the skill through sudo: run `netwatch skill --install` \
             without sudo to install it for {user}, or pass --dir to choose where \
             root installs it"
        ),
        None => Ok(()),
    }
}

/// The one line `netwatch skill --install` prints.
pub fn installed_message(path: &Path) -> String {
    format!(
        "installed the netwatch {} skill at {}",
        env!("CARGO_PKG_VERSION"),
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    fn frontmatter() -> (String, String) {
        let rest = SKILL.strip_prefix("---\n").expect("starts with ---");
        let (head, _) = rest.split_once("\n---\n").expect("frontmatter closes");
        let field = |name: &str| {
            head.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}: ")))
                .unwrap_or_else(|| panic!("no {name}"))
                .to_string()
        };
        (field("name"), field("description"))
    }

    #[test]
    fn frontmatter_follows_the_skill_rules() {
        let (name, description) = frontmatter();
        assert_eq!(name, "netwatch");
        assert!(
            name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        );
        assert!(!description.is_empty() && description.len() <= 1024);
        assert!(!description.contains('<') && !description.contains('>'));
    }

    /// Every netwatch command the skill shows, as written.
    fn commands() -> Vec<String> {
        let mut out = Vec::new();
        let mut in_code = false;
        for line in SKILL.lines() {
            if line.starts_with("```") {
                in_code = !in_code;
                continue;
            }
            if in_code {
                let cmd = line.split(" #").next().unwrap_or("").trim();
                let cmd = cmd.strip_prefix("sudo ").unwrap_or(cmd);
                if cmd.starts_with("netwatch ") {
                    out.push(cmd.to_string());
                }
                continue;
            }
            for (i, span) in line.split('`').enumerate() {
                if i % 2 == 1 && span.starts_with("netwatch ") {
                    out.push(span.to_string());
                }
            }
        }
        out
    }

    fn words(cmd: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut quoted = None::<String>;
        for w in cmd.split_whitespace() {
            match (&mut quoted, w.strip_prefix('"')) {
                (None, Some(rest)) if rest.ends_with('"') => {
                    out.push(rest.trim_end_matches('"').to_string())
                }
                (None, Some(rest)) => quoted = Some(rest.to_string()),
                (Some(q), _) => {
                    q.push(' ');
                    q.push_str(w.trim_end_matches('"'));
                    if w.ends_with('"') {
                        out.push(quoted.take().expect("open quote"));
                    }
                }
                (None, None) => out.push(w.to_string()),
            }
        }
        out
    }

    #[test]
    fn every_command_in_the_skill_parses() {
        let cmds = commands();
        assert!(cmds.len() > 20, "found only {cmds:?}");
        for cmd in cmds {
            if cmd.contains('<') {
                // A placeholder such as `netwatch ip <address>`.
                continue;
            }
            if let Err(e) = crate::Cli::try_parse_from(words(&cmd)) {
                panic!("{cmd}: {e}");
            }
        }
    }

    #[test]
    fn what_the_skill_quotes_is_still_true() {
        let main = include_str!("main.rs");
        let control = include_str!("control.rs");
        let api = include_str!("api.rs");
        assert!(
            main.contains("nothing answers at {base}, so the netwatch daemon isn't running there")
        );
        assert!(control.contains("(is the daemon running, and are you root?)"));
        assert!(SKILL.contains(&format!(
            "http://{}",
            crate::config::Config::default().api_listen
        )));
        assert!(include_str!("macos/launchd.rs").contains("LABEL: &str = \"dev.netwatch\""));
        for (i, part) in SKILL.split("/api/").enumerate().skip(1) {
            let name: String = part
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            assert!(
                api.contains(&format!("\"/api/{name}")),
                "/api/{name} (mention {i}) is not a route"
            );
        }
    }

    #[test]
    fn installs_and_replaces() {
        let dir = std::env::temp_dir().join(format!("netwatch-skill-{}", std::process::id()));
        let path = install(&dir).unwrap();
        assert_eq!(path, dir.join("netwatch/SKILL.md"));
        std::fs::write(&path, "old").unwrap();
        install(&dir).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), SKILL);
        assert!(!dir.join("netwatch/.SKILL.md.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_message() {
        let p = Path::new("/home/ana/.claude/skills/netwatch/SKILL.md");
        assert_eq!(
            installed_message(p),
            format!(
                "installed the netwatch {} skill at {}",
                env!("CARGO_PKG_VERSION"),
                p.display()
            )
        );
    }

    #[test]
    fn refuses_to_install_through_sudo() {
        assert!(refuse_sudo(None).is_ok());
        assert_eq!(
            refuse_sudo(Some("ana")).unwrap_err().to_string(),
            "not installing the skill through sudo: run `netwatch skill --install` \
             without sudo to install it for ana, or pass --dir to choose where root \
             installs it"
        );
    }
}
