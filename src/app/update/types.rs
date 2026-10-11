use std::cmp::Ordering;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SemverTriplet {
    pub(super) major: u64,
    pub(super) minor: u64,
    pub(super) patch: u64,
    pub(super) prerelease: Option<String>,
}

impl Ord for SemverTriplet {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| compare_prerelease(&self.prerelease, &other.prerelease))
    }
}

impl PartialOrd for SemverTriplet {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(left: &Option<String>, right: &Option<String>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => {
            let left = left.split('.').collect::<Vec<_>>();
            let right = right.split('.').collect::<Vec<_>>();
            for (left, right) in left.iter().zip(&right) {
                let left_is_numeric = left.bytes().all(|byte| byte.is_ascii_digit());
                let right_is_numeric = right.bytes().all(|byte| byte.is_ascii_digit());
                let order = match (left_is_numeric, right_is_numeric) {
                    (true, true) => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
                    (true, false) => Ordering::Less,
                    (false, true) => Ordering::Greater,
                    (false, false) => left.cmp(right),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
            left.len().cmp(&right.len())
        }
    }
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
