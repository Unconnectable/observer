// use anyhow::{Context as _, anyhow};
// use aya_build::Toolchain;

// fn main() -> anyhow::Result<()> {
//     let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
//         .no_deps()
//         .exec()
//         .context("MetadataCommand::exec")?;
//     let ebpf_package = packages
//         .into_iter()
//         .find(|cargo_metadata::Package { name, .. }| name.as_str() == "observer-ebpf")
//         .ok_or_else(|| anyhow!("observer-ebpf package not found"))?;
//     let cargo_metadata::Package {
//         name,
//         manifest_path,
//         ..
//     } = ebpf_package;
//     let ebpf_package = aya_build::Package {
//         name: name.as_str(),
//         root_dir: manifest_path
//             .parent()
//             .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
//             .as_str(),
//         ..Default::default()
//     };
//     aya_build::build_ebpf([ebpf_package], Toolchain::default())
// }

fn main() {
    // 这里故意留空，只打印一条消息告诉 Cargo 文件依赖关系
    // 我们将手动编译内核态 eBPF 代码
    println!("cargo:rerun-if-changed=../observer-ebpf/src");
}
