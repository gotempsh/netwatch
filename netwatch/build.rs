fn main() -> anyhow::Result<()> {
    // The UI (ui/, built with Vite) is embedded into the binary. Build it first with
    // `npm --prefix ui ci && npm --prefix ui run build`; without it a placeholder is served.
    let dist = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ui/dist");
    if !dist.join("index.html").exists() {
        std::fs::create_dir_all(&dist)?;
        std::fs::write(
            dist.join("index.html"),
            "<!doctype html><title>netwatch</title><p>UI not built. Run <code>npm --prefix ui ci &amp;&amp; \
             npm --prefix ui run build</code> and rebuild netwatch. The JSON API is under <a href=api/overview>/api</a>.",
        )?;
    }
    println!("cargo:rerun-if-changed={}", dist.display());
    build_ebpf()
}

/// macOS has no eBPF: the daemon captures with /dev/bpf instead.
#[cfg(not(target_os = "linux"))]
fn build_ebpf() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_ebpf() -> anyhow::Result<()> {
    use anyhow::{Context as _, anyhow};
    use aya_build::Toolchain;

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "netwatch-ebpf")
        .ok_or_else(|| anyhow!("netwatch-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())
}
