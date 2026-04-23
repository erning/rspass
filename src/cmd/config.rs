//! `rspass config` — print the effective config.
//!
//! Output is YAML. Mounts are sorted alphabetically so the dump is
//! deterministic across runs (the in-memory HashMap has no stable order).
//! `include:` is never emitted because it's fully resolved by the time we
//! get here; empty `mounts` / `identities` fields are dropped too so the
//! output only shows what's actually in play.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::Config;
use crate::error::RspassError;

pub fn run(config: &Config) -> Result<(), RspassError> {
    let yaml = render(config)?;
    print!("{yaml}");
    Ok(())
}

fn render(config: &Config) -> Result<String, RspassError> {
    let view = ConfigView {
        mounts: config
            .mounts
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        identities: config.identities.clone(),
    };
    let raw = serde_yaml_ng::to_string(&view)
        .map_err(|e| RspassError::Io(std::io::Error::other(format!("yaml serialize: {e}"))))?;
    Ok(indent_block_sequences(&raw))
}

/// serde_yaml_ng emits top-level list items flush-left (`- item`) under
/// their parent key. That's legal YAML but visually ambiguous, so shift each
/// flush-left `- ` line two spaces right to match the common hand-written
/// style. Our output shape (a top-level map with only a `mounts` mapping and
/// an `identities` list) means we only ever see such lines as direct children
/// of `identities:`, so this is safe without a real YAML parser.
fn indent_block_sequences(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 32);
    for line in raw.split_inclusive('\n') {
        if line.starts_with("- ") {
            out.push_str("  ");
        }
        out.push_str(line);
    }
    out
}

#[derive(Serialize)]
struct ConfigView {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    mounts: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    identities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(mounts: &[(&str, &str)], identities: &[&str]) -> Config {
        Config {
            mounts: mounts
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
            identities: identities.iter().map(|s| s.to_string()).collect(),
            include: Vec::new(),
        }
    }

    #[test]
    fn mounts_are_sorted_alphabetically() {
        // Repeat to make the order-dependence of HashMap actually bite if we
        // ever accidentally regress to HashMap serialization.
        for _ in 0..5 {
            let c = cfg(&[("work", "/w"), ("", "/root"), ("team", "/t")], &[]);
            let out = render(&c).unwrap();
            let lines: Vec<&str> = out
                .lines()
                .filter(|l| l.starts_with("  "))
                .collect();
            assert_eq!(
                lines,
                vec![r#"  '': /root"#, "  team: /t", "  work: /w"],
                "got:\n{out}"
            );
        }
    }

    #[test]
    fn include_never_emitted() {
        let mut c = cfg(&[("", "/r")], &[]);
        // Even if the in-memory Config somehow still carried `include`, the
        // view struct doesn't have that field so it can't leak out.
        c.include = vec!["leftover.yaml".into()];
        let out = render(&c).unwrap();
        assert!(!out.contains("include"), "got:\n{out}");
    }

    #[test]
    fn empty_fields_omitted() {
        let c = cfg(&[], &[]);
        let out = render(&c).unwrap();
        assert!(!out.contains("mounts"), "got:\n{out}");
        assert!(!out.contains("identities"), "got:\n{out}");
    }

    #[test]
    fn identities_emitted_in_order() {
        let c = cfg(&[], &["/id/a.txt", "/id/b.txt", "/id/c.txt"]);
        let out = render(&c).unwrap();
        let a = out.find("/id/a.txt").unwrap();
        let b = out.find("/id/b.txt").unwrap();
        let c_ = out.find("/id/c.txt").unwrap();
        assert!(a < b && b < c_, "got:\n{out}");
    }

    #[test]
    fn identities_list_items_are_indented() {
        let c = cfg(&[], &["/id/a.txt"]);
        let out = render(&c).unwrap();
        assert!(
            out.contains("\n  - /id/a.txt"),
            "list items should be indented under the field; got:\n{out}"
        );
        assert!(
            !out.contains("\n- /id/a.txt"),
            "no flush-left list items; got:\n{out}"
        );
    }
}
