//! Platform-specific service selection.

use crate::core::AttachTarget;
use crate::core::{DashboardPreferences, Density, PlatformKind};

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformServices {
    pub kind: PlatformKind,
    pub persistence: &'static str,
    pub clipboard: &'static str,
    pub notifications: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferenceSnapshot {
    pub key: String,
    pub preferences: DashboardPreferences,
}

pub trait PreferenceStore {
    fn load(&self) -> Option<PreferenceSnapshot>;
    fn save(&mut self, preferences: DashboardPreferences) -> PreferenceSnapshot;
}

#[derive(Clone, Debug)]
pub struct MemoryPreferenceStore {
    key: String,
    snapshot: Option<PreferenceSnapshot>,
}

impl MemoryPreferenceStore {
    pub fn new(platform: PlatformKind) -> Self {
        Self {
            key: preference_key(platform),
            snapshot: None,
        }
    }
}

impl PreferenceStore for MemoryPreferenceStore {
    fn load(&self) -> Option<PreferenceSnapshot> {
        self.snapshot.clone()
    }

    fn save(&mut self, preferences: DashboardPreferences) -> PreferenceSnapshot {
        let snapshot = PreferenceSnapshot {
            key: self.key.clone(),
            preferences,
        };
        self.snapshot = Some(snapshot.clone());
        snapshot
    }
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Debug)]
pub struct BrowserPreferenceStore {
    key: String,
}

#[cfg(target_arch = "wasm32")]
impl BrowserPreferenceStore {
    pub fn new(platform: PlatformKind) -> Self {
        Self {
            key: preference_key(platform),
        }
    }

    fn storage(&self) -> Option<web_sys::Storage> {
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    }
}

#[cfg(target_arch = "wasm32")]
impl PreferenceStore for BrowserPreferenceStore {
    fn load(&self) -> Option<PreferenceSnapshot> {
        let raw = self.storage()?.get_item(&self.key).ok().flatten()?;
        let preferences = serde_json::from_str(&raw).ok()?;
        Some(PreferenceSnapshot {
            key: self.key.clone(),
            preferences,
        })
    }

    fn save(&mut self, preferences: DashboardPreferences) -> PreferenceSnapshot {
        let snapshot = PreferenceSnapshot {
            key: self.key.clone(),
            preferences,
        };
        if let Some(storage) = self.storage()
            && let Ok(raw) = serde_json::to_string(&snapshot.preferences)
        {
            let _ = storage.set_item(&snapshot.key, &raw);
        }
        snapshot
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct FilePreferenceStore {
    key: String,
    path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
impl FilePreferenceStore {
    pub fn new(platform: PlatformKind) -> Self {
        Self::with_path(platform, desktop_preference_path(platform))
    }

    pub fn with_path(platform: PlatformKind, path: PathBuf) -> Self {
        Self {
            key: preference_key(platform),
            path,
        }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PreferenceStore for FilePreferenceStore {
    fn load(&self) -> Option<PreferenceSnapshot> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        let preferences = serde_json::from_str(&raw).ok()?;
        Some(PreferenceSnapshot {
            key: self.key.clone(),
            preferences,
        })
    }

    fn save(&mut self, preferences: DashboardPreferences) -> PreferenceSnapshot {
        let snapshot = PreferenceSnapshot {
            key: self.key.clone(),
            preferences,
        };
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(raw) = serde_json::to_string_pretty(&snapshot.preferences) {
            let _ = std::fs::write(&self.path, raw);
        }
        snapshot
    }
}

pub fn load_or_default_preferences(
    platform: PlatformKind,
    targets: Vec<AttachTarget>,
) -> DashboardPreferences {
    load_preferences(platform).unwrap_or_else(|| DashboardPreferences::defaults(platform, targets))
}

pub fn load_preferences(platform: PlatformKind) -> Option<DashboardPreferences> {
    platform_store(platform)
        .load()
        .map(|snapshot| snapshot.preferences)
}

pub fn save_preferences(preferences: DashboardPreferences) -> PreferenceSnapshot {
    platform_store(preferences.platform).save(preferences)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn download_text(filename: &str, text: &str) -> Result<String, String> {
    let safe_name = filename
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let path = std::env::temp_dir().join(safe_name);
    std::fs::write(&path, text).map_err(|err| err.to_string())?;
    Ok(path.display().to_string())
}

#[cfg(target_arch = "wasm32")]
pub fn download_text(filename: &str, text: &str) -> Result<String, String> {
    use wasm_bindgen::JsCast;

    let window = web_sys::window().ok_or_else(|| "window unavailable".to_string())?;
    let document = window
        .document()
        .ok_or_else(|| "document unavailable".to_string())?;
    let chunks = js_sys::Array::new();
    chunks.push(&wasm_bindgen::JsValue::from_str(text));
    let blob = web_sys::Blob::new_with_str_sequence(&chunks)
        .map_err(|_| "failed to create export blob".to_string())?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)
        .map_err(|_| "failed to create export URL".to_string())?;
    let anchor = document
        .create_element("a")
        .map_err(|_| "failed to create download anchor".to_string())?
        .dyn_into::<web_sys::HtmlAnchorElement>()
        .map_err(|_| "download anchor unavailable".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    let anchor_el = anchor
        .clone()
        .dyn_into::<web_sys::HtmlElement>()
        .map_err(|_| "download anchor element unavailable".to_string())?;
    anchor_el
        .style()
        .set_property("display", "none")
        .map_err(|_| "failed to hide download anchor".to_string())?;
    let body = document
        .body()
        .ok_or_else(|| "document body unavailable".to_string())?;
    body.append_child(&anchor)
        .map_err(|_| "failed to attach download anchor".to_string())?;
    anchor_el.click();
    let _ = body.remove_child(&anchor);
    let _ = web_sys::Url::revoke_object_url(&url);
    Ok(filename.to_string())
}

fn platform_store(platform: PlatformKind) -> Box<dyn PreferenceStore> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = platform;
        Box::new(BrowserPreferenceStore::new(PlatformKind::Browser))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Box::new(FilePreferenceStore::new(platform))
    }
}

pub fn preference_key(platform: PlatformKind) -> String {
    let suffix = match platform {
        PlatformKind::Browser => "browser",
        PlatformKind::Desktop => "desktop",
    };
    format!("ndn-dashboard-next:{suffix}:preferences:v1")
}

#[cfg(not(target_arch = "wasm32"))]
pub fn desktop_preference_path(platform: PlatformKind) -> PathBuf {
    let file_name = match platform {
        PlatformKind::Browser => "preferences-browser.json",
        PlatformKind::Desktop => "preferences-desktop.json",
    };
    config_home().join("ndn-dashboard-next").join(file_name)
}

#[cfg(not(target_arch = "wasm32"))]
fn config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| std::env::temp_dir().join("ndn-dashboard-next-config"))
}

pub fn density_storage_label(density: Density) -> &'static str {
    match density {
        Density::Compact => "stored compact",
        Density::Comfortable => "stored comfortable",
    }
}

pub fn current_platform() -> PlatformKind {
    #[cfg(target_arch = "wasm32")]
    {
        PlatformKind::Browser
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        PlatformKind::Desktop
    }
}

pub fn services(kind: PlatformKind) -> PlatformServices {
    match kind {
        PlatformKind::Browser => PlatformServices {
            kind,
            persistence: "browser localStorage",
            clipboard: "web clipboard",
            notifications: "web notifications",
        },
        PlatformKind::Desktop => PlatformServices {
            kind,
            persistence: "local JSON config",
            clipboard: "system clipboard",
            notifications: "desktop notifications",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{DashboardClient, MockDashboardClient};

    #[test]
    fn browser_services_do_not_claim_private_key_storage() {
        let services = services(PlatformKind::Browser);
        assert_eq!(services.persistence, "browser localStorage");
    }

    #[test]
    fn preference_keys_are_scoped_by_platform() {
        assert_ne!(
            preference_key(PlatformKind::Browser),
            preference_key(PlatformKind::Desktop)
        );
    }

    #[test]
    fn memory_preference_store_round_trips_density_and_targets() {
        let client = MockDashboardClient::new(PlatformKind::Desktop);
        let mut prefs =
            DashboardPreferences::defaults(PlatformKind::Desktop, client.attach_targets());
        prefs.density = Density::Comfortable;
        let mut store = MemoryPreferenceStore::new(PlatformKind::Desktop);

        let saved = store.save(prefs.clone());
        let loaded = store.load().expect("snapshot");

        assert_eq!(saved.key, preference_key(PlatformKind::Desktop));
        assert_eq!(loaded.preferences.density, Density::Comfortable);
        assert_eq!(loaded.preferences.saved_targets, prefs.saved_targets);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn file_preference_store_round_trips_json() {
        let client = MockDashboardClient::new(PlatformKind::Desktop);
        let mut prefs =
            DashboardPreferences::defaults(PlatformKind::Desktop, client.attach_targets());
        prefs.density = Density::Comfortable;
        let path = std::env::temp_dir().join(format!(
            "ndn-dashboard-next-preferences-{}.json",
            std::process::id()
        ));
        let mut store = FilePreferenceStore::with_path(PlatformKind::Desktop, path.clone());

        store.save(prefs.clone());
        let loaded = store.load().expect("preferences");

        assert_eq!(loaded.preferences.density, Density::Comfortable);
        assert_eq!(
            loaded.preferences.selected_target_id,
            prefs.selected_target_id
        );
        let _ = std::fs::remove_file(path);
    }
}
