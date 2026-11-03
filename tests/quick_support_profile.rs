#![cfg(feature = "quick-support-profile")]

use hbb_common::{config::Config, private_profile};
use std::{path::PathBuf, process::Command};

#[test]
fn real_config_hooks_select_one_profile_before_first_use() {
    for mode in ["private", "ordinary"] {
        let root =
            std::env::temp_dir().join(format!("qs-config-hooks-{}-{mode}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "config_profile_subprocess", "--nocapture"])
            .env("QS_CONFIG_FIXTURE_MODE", mode)
            .env("QS_CONFIG_FIXTURE_ROOT", &root)
            .status();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(result.unwrap().success());
    }
}

#[test]
#[ignore = "owned subprocess entry for actual Config isolation"]
fn config_profile_subprocess() {
    let root = PathBuf::from(std::env::var_os("QS_CONFIG_FIXTURE_ROOT").unwrap());
    let nonce = "c".repeat(64);
    if std::env::var("QS_CONFIG_FIXTURE_MODE").unwrap() == "ordinary" {
        let original = Config::path("fixture.toml");
        assert!(private_profile::install(root, nonce).is_err());
        assert_eq!(Config::path("fixture.toml"), original);
        return;
    }
    private_profile::install(root.clone(), nonce.clone()).unwrap();
    assert_eq!(Config::get_home(), root);
    assert_eq!(Config::path("fixture.toml"), root.join("fixture.toml"));
    assert!(Config::file().starts_with(&root));
    assert_eq!(Config::log_path(), root.join("logs"));
    let denied = Config::path("../escape.toml");
    assert_eq!(denied, root.join("\0"));
    assert!(std::fs::write(denied.with_extension("toml"), b"denied").is_err());
    let ipc = Config::ipc_path("_cm");
    #[cfg(windows)]
    assert_eq!(
        ipc,
        format!(r"\\.\pipe\mtg-quick-support-profile-{nonce}\query_cm")
    );
    #[cfg(not(windows))]
    assert_eq!(ipc, root.join("query_cm").to_string_lossy());
    assert!(private_profile::install(root, "d".repeat(64)).is_err());
}
