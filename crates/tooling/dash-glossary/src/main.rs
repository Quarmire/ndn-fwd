//! `dash-glossary check [<repo-root>]` — CI guard for the dashboard
//! education seam. Scans `crates/tooling/ndn-dashboard/src/**.rs` for
//! `EduGloss { term: "X", ... }` callsites and exits 1 when `X` is missing
//! from `crates/tooling/ndn-dashboard/glossary.toml`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GlossaryFile {
    entries: Vec<GlossaryEntry>,
}

#[derive(Debug, Deserialize)]
struct GlossaryEntry {
    term: String,
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    if cmd != "check" {
        eprintln!("usage: dash-glossary check [<repo-root>]");
        return ExitCode::from(2);
    }
    let repo_root = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dashboard_dir = repo_root.join("crates/tooling/ndn-dashboard");
    let glossary_path = dashboard_dir.join("glossary.toml");
    let src_dir = dashboard_dir.join("src");

    let glossary_bytes = match std::fs::read_to_string(&glossary_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {e}", glossary_path.display());
            return ExitCode::from(1);
        }
    };
    let parsed: GlossaryFile = match toml::from_str(&glossary_bytes) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: parse {}: {e}", glossary_path.display());
            return ExitCode::from(1);
        }
    };
    let known: HashSet<String> = parsed.entries.iter().map(|e| e.term.clone()).collect();

    let mut used: Vec<(PathBuf, usize, String)> = Vec::new();
    let mut scan_errors: Vec<String> = Vec::new();
    walk_rust_sources(&src_dir, &mut |path| {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                scan_errors.push(format!("read {}: {e}", path.display()));
                return;
            }
        };
        for (line_no, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for term in extract_terms(line) {
                used.push((path.to_path_buf(), line_no + 1, term));
            }
        }
    });

    if !scan_errors.is_empty() {
        for e in &scan_errors {
            eprintln!("warning: {e}");
        }
    }

    let mut missing: Vec<(PathBuf, usize, String)> = used
        .iter()
        .filter(|(_, _, t)| !known.contains(t))
        .cloned()
        .collect();
    missing.sort();
    missing.dedup();

    if missing.is_empty() {
        let distinct: HashSet<&str> = used.iter().map(|(_, _, t)| t.as_str()).collect();
        println!(
            "dash-glossary: ok — {} known terms, {} distinct EduGloss callsites checked",
            known.len(),
            distinct.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "dash-glossary: missing entries in {}:",
            glossary_path.display()
        );
        for (path, line, term) in &missing {
            eprintln!("  {}:{} EduGloss term {term:?}", path.display(), line);
        }
        eprintln!(
            "\nAdd matching `[[entries]]` blocks to glossary.toml, or remove the EduGloss callsite."
        );
        ExitCode::from(1)
    }
}

fn walk_rust_sources(dir: &Path, visit: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.is_dir() {
            walk_rust_sources(&path, visit);
        } else if path.extension().is_some_and(|e| e == "rs") {
            visit(&path);
        }
    }
}

/// Hand-rolled scanner: extracts every `EduGloss { term: "<X>" }` on a
/// line. Plain double-quoted string literals only; no escape unescaping.
fn extract_terms(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "EduGloss";
    let bytes = line.as_bytes();
    let mut search_from = 0;
    while let Some(start) = line[search_from..].find(needle) {
        let abs = search_from + start;
        let after = abs + needle.len();
        // Require `EduGloss` + ws + `{` + `term` + `:` + quoted string so
        // identifiers like `EduGlossSomething` don't false-positive.
        let rest = &line[after..];
        let rest_trim = rest.trim_start();
        if !rest_trim.starts_with('{') {
            search_from = after;
            continue;
        }
        let after_brace = &rest_trim[1..];
        let inner = after_brace.trim_start();
        if !inner.starts_with("term") {
            search_from = after;
            continue;
        }
        let after_term = inner["term".len()..].trim_start();
        if !after_term.starts_with(':') {
            search_from = after;
            continue;
        }
        let after_colon = after_term[1..].trim_start();
        if !after_colon.starts_with('"') {
            search_from = after;
            continue;
        }
        let body = &after_colon[1..];
        if let Some(end) = body.find('"') {
            out.push(body[..end].to_string());
        }
        search_from = after;
        let _ = bytes;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_basic_term() {
        let line = r#"        rsx! { EduGloss { term: "Trust anchor" } }"#;
        assert_eq!(extract_terms(line), vec!["Trust anchor".to_string()]);
    }

    #[test]
    fn extracts_term_with_display_prop() {
        let line = r#"EduGloss { term: "KeyLocator", display: Some("KL") }"#;
        assert_eq!(extract_terms(line), vec!["KeyLocator".to_string()]);
    }

    #[test]
    fn handles_extra_whitespace_around_colon() {
        let line = r#"EduGloss {  term  :  "Cert"  }"#;
        assert_eq!(extract_terms(line), vec!["Cert".to_string()]);
    }

    #[test]
    fn ignores_similar_identifiers() {
        let line = r#"// EduGlossary is not the same; EduGlossWidget either"#;
        assert!(extract_terms(line).is_empty());
    }

    #[test]
    fn finds_multiple_on_one_line() {
        let line = r#"EduGloss { term: "A" } and later EduGloss { term: "B" }"#;
        assert_eq!(extract_terms(line), vec!["A".to_string(), "B".to_string()]);
    }
}
