#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct SemverTriplet {
    pub(super) major: u64,
    pub(super) minor: u64,
    pub(super) patch: u64,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ArchiveKind {
    Zip,
    TarGz,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TargetAssetSpec {
    pub(super) suffix: &'static str,
    pub(super) archive_kind: ArchiveKind,
    pub(super) binary_name: &'static str,
}

#[derive(Debug)]
pub(super) struct ReleaseInfo {
    pub(super) version_text: String,
    pub(super) version: SemverTriplet,
    pub(super) asset_url: String,
    pub(super) archive_kind: ArchiveKind,
    pub(super) binary_name: &'static str,
}

impl ReleaseInfo {
    pub(super) fn archive_file_name(&self) -> &'static str {
        match self.archive_kind {
            ArchiveKind::Zip => "fe203.zip",
            ArchiveKind::TarGz => "fe203.tar.gz",
        }
    }
}

pub(super) fn current_target_asset_spec() -> Option<TargetAssetSpec> {
    target_asset_spec(std::env::consts::OS, std::env::consts::ARCH)
}

pub(super) fn target_asset_spec(os: &str, arch: &str) -> Option<TargetAssetSpec> {
    match (os, arch) {
        ("windows", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-pc-windows-msvc.zip",
            archive_kind: ArchiveKind::Zip,
            binary_name: "fe203.exe",
        }),
        ("linux", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-unknown-linux-gnu.tar.gz",
            archive_kind: ArchiveKind::TarGz,
            binary_name: "fe203",
        }),
        ("macos", "x86_64") => Some(TargetAssetSpec {
            suffix: "x86_64-apple-darwin.tar.gz",
            archive_kind: ArchiveKind::TarGz,
            binary_name: "fe203",
        }),
        _ => None,
    }
}
