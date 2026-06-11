use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // If METIS_EBPF_PATH is set, use the pre-built object instead of building
    if let Ok(ebpf_path) = std::env::var("METIS_EBPF_PATH") {
        let out_dir = std::env::var("OUT_DIR").context("OUT_DIR not set")?;
        let out_path = std::path::PathBuf::from(&out_dir).join("metis");
        std::fs::copy(&ebpf_path, &out_path)
            .with_context(|| format!("failed to copy {ebpf_path} to {out_path:?}"))?;
        println!("cargo:rerun-if-changed={ebpf_path}");
        return Ok(());
    }

    // Otherwise build normally (for local dev)
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "metis-ebpf")
        .ok_or_else(|| anyhow!("metis-ebpf package not found"))?;
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