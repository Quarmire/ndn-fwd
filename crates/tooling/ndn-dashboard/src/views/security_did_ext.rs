//! §4.8 DID Document extension renderer registry.
//!
//! DID Documents may carry arbitrary extension fields beyond the
//! W3C-canonical core (`verificationMethod`, `controller`, `service`).
//! The dashboard exposes a startup-time renderer registry so a built
//! or installed extension renderer can declare itself for a given
//! extension key. When the §4.7 inspector encounters an extension key
//! that the registry knows about, it calls that renderer; unknown
//! keys render as a collapsed "no renderer for X" affordance showing
//! the raw JSON.
//!
//! Per the design doc §4.8: v1 ships **zero specific renderers**.
//! The registry is the hook, not content. Specific renderers
//! (substrate-defined extensions, deployment posture fields, …) live
//! outside the dashboard's committed code and register at startup.
//!
//! Out of scope for v1 (and not built here): a renderer marketplace,
//! dynamic loading from files, sandboxing of registered renderers.

use crate::edu_gloss::EduGloss;
use dioxus::prelude::*;
use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

/// Renderer for a single DID Document extension key. The dashboard
/// calls `render` with the raw JSON value associated with the
/// extension key in a resolved DID Document.
///
/// Implementors must be `Send + Sync` because the registry is a
/// process-wide `OnceLock<RwLock<…>>` so renderers can be registered
/// once at startup and looked up from any view.
pub trait DidExtensionRenderer: Send + Sync {
    /// Extension key in the DID Document this renderer handles.
    /// Typically a registered URI or short identifier; the registry
    /// does an exact-string match against the JSON object's keys.
    #[allow(dead_code)]
    fn key(&self) -> &str;

    /// Render the extension value as a Dioxus element.
    fn render(&self, value: &serde_json::Value) -> Element;

    /// One-line gloss for the §9 education seam. The §4.7 inspector
    /// surfaces this above the rendered block so an operator who
    /// doesn't know the extension can read what it is.
    fn gloss(&self) -> &str;
}

/// Process-wide registry of extension renderers, keyed by the
/// extension's DID-Document key. Holds a `RwLock` so plugins can
/// register from any thread during startup; v1 ships **no** built-in
/// registrations.
pub struct DidExtensionRegistry {
    inner: RwLock<BTreeMap<String, Box<dyn DidExtensionRenderer>>>,
}

// Per §4.8, v1 ships zero registered renderers. `register` / `has` /
// `keys` are the *public* API deployments use at startup to install
// their own renderers — the committed dashboard never calls them
// itself. `#[allow(dead_code)]` documents the dormant-by-design
// surface so a future deployment can wire registrations without the
// dashboard's own code growing a dependency on a specific renderer.
#[allow(dead_code)]
impl DidExtensionRegistry {
    fn new() -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a renderer. Returns whether a previous renderer for
    /// the same key was replaced — useful for tests and for
    /// deployments that intentionally override a default renderer.
    pub fn register(&self, renderer: Box<dyn DidExtensionRenderer>) -> bool {
        let key = renderer.key().to_owned();
        let mut guard = self
            .inner
            .write()
            .expect("DidExtensionRegistry lock poisoned");
        guard.insert(key, renderer).is_some()
    }

    /// True when a renderer is registered for `key`.
    pub fn has(&self, key: &str) -> bool {
        self.inner
            .read()
            .expect("DidExtensionRegistry lock poisoned")
            .contains_key(key)
    }

    /// Look up + render in one pass. Returns `None` when no renderer
    /// is registered for the key, so the caller can render the
    /// "no renderer for X" affordance. Cloning out the renderer's
    /// element keeps the lock window short.
    pub fn render(&self, key: &str, value: &serde_json::Value) -> Option<Element> {
        let guard = self
            .inner
            .read()
            .expect("DidExtensionRegistry lock poisoned");
        let renderer = guard.get(key)?;
        Some(renderer.render(value))
    }

    /// Gloss for an extension key. Used by `DidExtensionPanel` to
    /// surface the renderer's one-line education above the rendered
    /// block.
    pub fn gloss(&self, key: &str) -> Option<String> {
        let guard = self
            .inner
            .read()
            .expect("DidExtensionRegistry lock poisoned");
        guard.get(key).map(|r| r.gloss().to_owned())
    }

    /// Sorted list of currently-registered extension keys. Useful
    /// for the §4.7 "what does this dashboard know how to render"
    /// surfacing.
    pub fn keys(&self) -> Vec<String> {
        let guard = self
            .inner
            .read()
            .expect("DidExtensionRegistry lock poisoned");
        guard.keys().cloned().collect()
    }
}

static REGISTRY: OnceLock<DidExtensionRegistry> = OnceLock::new();

/// Global registry accessor. Lazy-initialized on first access; safe
/// to call from any view.
pub fn registry() -> &'static DidExtensionRegistry {
    REGISTRY.get_or_init(DidExtensionRegistry::new)
}

/// Render the extension-fields section of a DID Document.
///
/// For each (key, value) pair in `extensions`:
///   * If a renderer is registered, call it with the value and surface
///     the renderer's gloss above the rendered block.
///   * Otherwise render the §4.8 "no renderer for X" affordance —
///     collapsed by default; an operator can expand to read the raw
///     JSON value.
///
/// `extensions` is an ordered map so the rendered surface is
/// deterministic; the §4.7 inspector passes the document's extension
/// map directly.
#[component]
pub fn DidExtensionPanel(extensions: BTreeMap<String, serde_json::Value>) -> Element {
    if extensions.is_empty() {
        return rsx! {};
    }
    let reg = registry();
    rsx! {
        div { style: "margin-bottom:12px;",
            div { style: "font-size:11px;font-weight:600;color:var(--text);margin-bottom:6px;",
                EduGloss { term: "DID extension" }
                span { style: "color:var(--text-muted);margin-left:6px;",
                    "{extensions.len()}"
                }
            }
            for (key, value) in extensions.iter() {
                {
                    let key_owned = key.clone();
                    let value_owned = value.clone();
                    let gloss = reg.gloss(key);
                    let rendered = reg.render(key, value);
                    rsx! {
                        ExtensionRow {
                            key_str: key_owned,
                            value: value_owned,
                            gloss,
                            rendered,
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ExtensionRow(
    key_str: String,
    value: serde_json::Value,
    gloss: Option<String>,
    rendered: Option<Element>,
) -> Element {
    let mut expanded = use_signal(|| false);
    let raw_pretty = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    rsx! {
        div { style: "border:1px solid var(--border-subtle);border-radius:4px;padding:8px;margin-bottom:6px;",
            div { style: "display:flex;justify-content:space-between;align-items:center;gap:8px;",
                div {
                    div { class: "mono", style: "font-size:11px;color:var(--text);",
                        "{key_str}"
                    }
                    if let Some(g) = gloss.as_ref() {
                        div { style: "font-size:10px;color:var(--text-muted);margin-top:2px;",
                            "{g}"
                        }
                    } else {
                        div { style: "font-size:10px;color:var(--yellow,#f5c518);margin-top:2px;",
                            "No renderer registered for ", span { class: "mono", "{key_str}" },
                            " — install a DID extension renderer to surface this field."
                        }
                    }
                }
                if rendered.is_none() {
                    button {
                        class: "btn btn-secondary btn-sm",
                        style: "padding:3px 8px;font-size:10px;",
                        onclick: move |_| {
                            let v = *expanded.read();
                            expanded.set(!v);
                        },
                        if *expanded.read() { "Hide raw" } else { "Show raw" }
                    }
                }
            }
            if let Some(el) = rendered {
                div { style: "margin-top:8px;",
                    { el }
                }
            } else if *expanded.read() {
                pre { style: "margin-top:8px;padding:8px;background:var(--surface);border:1px solid var(--border-subtle);border-radius:4px;font-size:10px;color:var(--text-muted);overflow-x:auto;",
                    "{raw_pretty}"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct DummyRenderer {
        key: &'static str,
        gloss: &'static str,
    }

    impl DidExtensionRenderer for DummyRenderer {
        fn key(&self) -> &str {
            self.key
        }
        fn render(&self, _value: &serde_json::Value) -> Element {
            rsx! { div { "rendered" } }
        }
        fn gloss(&self) -> &str {
            self.gloss
        }
    }

    #[test]
    fn registry_starts_empty_and_register_populates() {
        let reg = DidExtensionRegistry::new();
        assert!(!reg.has("nope"));
        assert!(reg.keys().is_empty());
        let replaced = reg.register(Box::new(DummyRenderer {
            key: "ext:foo",
            gloss: "foo gloss",
        }));
        assert!(!replaced, "first register must not report replacement");
        assert!(reg.has("ext:foo"));
        assert_eq!(reg.keys(), vec!["ext:foo".to_owned()]);
        assert_eq!(reg.gloss("ext:foo").as_deref(), Some("foo gloss"));
    }

    #[test]
    fn register_replaces_returns_true_when_overriding() {
        let reg = DidExtensionRegistry::new();
        reg.register(Box::new(DummyRenderer {
            key: "ext:foo",
            gloss: "old",
        }));
        let replaced = reg.register(Box::new(DummyRenderer {
            key: "ext:foo",
            gloss: "new",
        }));
        assert!(replaced, "second register must report replacement");
        assert_eq!(reg.gloss("ext:foo").as_deref(), Some("new"));
    }

    #[test]
    fn keys_are_sorted_for_deterministic_render_order() {
        let reg = DidExtensionRegistry::new();
        reg.register(Box::new(DummyRenderer {
            key: "ext:z",
            gloss: "",
        }));
        reg.register(Box::new(DummyRenderer {
            key: "ext:a",
            gloss: "",
        }));
        reg.register(Box::new(DummyRenderer {
            key: "ext:m",
            gloss: "",
        }));
        assert_eq!(reg.keys(), vec!["ext:a", "ext:m", "ext:z"]);
    }

    #[test]
    fn lookup_returns_none_for_unknown_keys() {
        let reg = DidExtensionRegistry::new();
        let value = json!({"any": "thing"});
        assert!(reg.render("ext:missing", &value).is_none());
        assert!(reg.gloss("ext:missing").is_none());
    }

    #[test]
    fn global_registry_is_singleton() {
        let r1 = registry() as *const DidExtensionRegistry;
        let r2 = registry() as *const DidExtensionRegistry;
        assert_eq!(r1, r2);
    }

    #[test]
    fn v1_global_registry_ships_empty() {
        // §4.8 explicitly: zero specific renderers ship with the
        // committed code. If this fails, someone added a default
        // renderer to the dashboard — push it out of the dashboard's
        // committed code and into deployment-side startup wiring.
        assert!(
            registry().keys().is_empty(),
            "v1 dashboard ships with zero registered renderers; found: {:?}",
            registry().keys()
        );
    }
}
