//! Opt-in, process-local profile selection. Install only after authenticating and
//! pinning the launcher's private directory, before any configuration is read.
use std::{
    path::{Component, Path, PathBuf},
    sync::OnceLock,
};

#[derive(Debug)]
pub struct ProfileRejected;

struct PrivateProfile {
    root: PathBuf,
    nonce: String,
}

static PROFILE: OnceLock<Option<PrivateProfile>> = OnceLock::new();

impl PrivateProfile {
    fn new(root: PathBuf, nonce: String) -> Result<Self, ProfileRejected> {
        if !root.is_absolute()
            || nonce.len() != 64
            || !nonce
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(ProfileRejected);
        }
        let metadata = std::fs::symlink_metadata(&root).map_err(|_| ProfileRejected)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(ProfileRejected);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                // FILE_ATTRIBUTE_REPARSE_POINT
                return Err(ProfileRejected);
            }
        }
        // Filesystem ownership/ACLs, ancestry and the pinned directory handle
        // remain the authenticated host's responsibility. A path is not trust.
        Ok(Self { root, nonce })
    }

    fn resolve(&self, relative: &Path) -> PathBuf {
        if relative
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        {
            self.root.join(relative)
        } else {
            // A NUL makes filesystem access fail even if the caller appends
            // Config's .toml extension; returning the root could name a sibling.
            self.root.join("\0")
        }
    }
}

/// The mode is immutable. Even an earlier ordinary-profile lookup prevents a
/// later switch, since already-loaded settings must never bleed into a child.
pub fn install(root: PathBuf, nonce: String) -> Result<(), ProfileRejected> {
    let profile = PrivateProfile::new(root, nonce)?;
    PROFILE.set(Some(profile)).map_err(|_| ProfileRejected)
}

fn current() -> Option<&'static PrivateProfile> {
    PROFILE.get_or_init(|| None).as_ref()
}

pub(crate) fn path(relative: &Path) -> Option<PathBuf> {
    current().map(|profile| profile.resolve(relative))
}

pub(crate) fn home() -> Option<PathBuf> {
    current().map(|profile| profile.root.clone())
}

pub(crate) fn log() -> Option<PathBuf> {
    current().map(|profile| profile.root.join("logs"))
}

pub(crate) fn ipc(postfix: &str) -> Option<String> {
    current().map(|profile| {
        // Existing internal postfixes may contain hyphens/underscores. Refuse separators,
        // embedded NULs and other syntax instead of escaping the namespace.
        if postfix.len() > 64
            || !postfix
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return "\0".to_owned();
        }
        if cfg!(windows) {
            format!(
                r"\\.\pipe\mtg-quick-support-profile-{}\query{}",
                profile.nonce, postfix
            )
        } else {
            profile
                .root
                .join(format!("query{postfix}"))
                .to_string_lossy()
                .into_owned()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "qs-profile-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn profile_selection_is_early_immutable_and_scoped() {
        for mode in ["private", "ordinary"] {
            let directory = Directory::new();
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "profile_subprocess", "--nocapture"])
                .env("QS_PROFILE_FIXTURE_MODE", mode)
                .env("QS_PROFILE_FIXTURE_ROOT", &directory.0)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    #[test]
    #[ignore = "owned subprocess entry for immutable profile selection"]
    fn profile_subprocess() {
        let root = PathBuf::from(std::env::var_os("QS_PROFILE_FIXTURE_ROOT").unwrap());
        let nonce = "a".repeat(64);
        assert!(install(PathBuf::from("relative"), nonce.clone()).is_err());
        assert!(install(root.clone(), "not-a-namespace".to_owned()).is_err());
        if std::env::var("QS_PROFILE_FIXTURE_MODE").unwrap() == "ordinary" {
            assert_eq!(home(), None);
            assert!(install(root, nonce).is_err());
            return;
        }
        install(root.clone(), nonce.clone()).unwrap();
        assert_eq!(home(), Some(root.clone()));
        assert_eq!(
            path(Path::new("settings.toml")),
            Some(root.join("settings.toml"))
        );
        let denied = path(Path::new("../outside")).unwrap();
        assert_eq!(denied, root.join("\0"));
        assert!(std::fs::write(denied.with_extension("toml"), b"denied").is_err());
        assert_eq!(path(&std::env::temp_dir()), Some(root.join("\0")));
        assert_eq!(log(), Some(root.join("logs")));
        let endpoint = ipc("_cm").unwrap();
        assert!(endpoint.contains(&nonce) || endpoint.starts_with(root.to_str().unwrap()));
        assert_ne!(endpoint, r"\\.\pipe\RustDesk\query-cm");
        assert_eq!(ipc("/outside"), Some("\0".to_owned()));
        assert!(install(root, "b".repeat(64)).is_err());
    }
}
