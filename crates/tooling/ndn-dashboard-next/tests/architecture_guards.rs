//! Architecture guardrails for the rewrite.
//!
//! These tests make the intended boundary cheap to enforce: dashboard-next
//! consumes typed clients and view models, not the legacy dashboard's global
//! command/state monolith.

use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn dashboard_next_does_not_import_legacy_dashboard_monolith() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let files = rust_files(&root);
    assert!(
        !files.is_empty(),
        "expected Rust source files under {root:?}"
    );

    let forbidden = [
        "DashCmd",
        "ACTIVE_VIEW",
        "AppCtx",
        "GlobalSignal",
        "crate::app::",
        "ndn_dashboard::",
        "tooling/ndn-dashboard/src",
    ];

    let mut violations = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).expect("read source");
        for needle in forbidden {
            if text.contains(needle) {
                violations.push(format!("{} contains `{needle}`", file.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "dashboard-next must stay split-ready:\n{}",
        violations.join("\n")
    );
}

#[test]
fn shell_keeps_accessibility_and_design_token_baseline() {
    let app = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app.rs"))
        .expect("read app shell");

    for needle in [
        "skip-link",
        "dashboard-next-main",
        "aria-label",
        "aria-current",
        "focus-visible",
        "prefers-reduced-motion",
        "color-scheme: dark",
        "--accent",
        "--focus",
        "density-compact",
        "density-comfortable",
    ] {
        assert!(
            app.contains(needle),
            "dashboard-next shell lost required UI/a11y baseline `{needle}`"
        );
    }
}

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let entries = fs::read_dir(&path).expect("read dir");
        for entry in entries {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out
}
