//! Typed dashboard and router configuration view models.

use serde::{Deserialize, Serialize};

use crate::core::{Density, PlatformKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigPreset {
    LocalLab,
    BrowserSandbox,
    CompatReadOnly,
}

impl ConfigPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalLab => "local lab",
            Self::BrowserSandbox => "browser sandbox",
            Self::CompatReadOnly => "compat read-only",
        }
    }

    pub const ALL: [Self; 3] = [Self::LocalLab, Self::BrowserSandbox, Self::CompatReadOnly];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardSettingsDraft {
    pub platform: PlatformKind,
    pub density: Density,
    pub node_prefix: String,
    pub max_tool_results: usize,
    pub auto_start_ping_server: bool,
    pub auto_start_iperf_server: bool,
    pub browser_config_read_only: bool,
}

impl DashboardSettingsDraft {
    pub fn for_platform(platform: PlatformKind, density: Density) -> Self {
        Self {
            platform,
            density,
            node_prefix: "/local/operator".into(),
            max_tool_results: 200,
            auto_start_ping_server: platform == PlatformKind::Desktop,
            auto_start_iperf_server: false,
            browser_config_read_only: platform == PlatformKind::Browser,
        }
    }

    pub fn export_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|err| err.to_string())
    }

    pub fn import_json(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|err| err.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterConfigDraft {
    pub router_name: String,
    pub management_socket: String,
    pub cs_capacity_bytes: u64,
    pub faces: Vec<StartupFaceDraft>,
    pub routes: Vec<StartupRouteDraft>,
    pub discovery: DiscoveryDraft,
    pub security: SecurityDraft,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupFaceDraft {
    pub uri: String,
    pub persist: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupRouteDraft {
    pub prefix: String,
    pub face_uri: String,
    pub cost: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryDraft {
    pub enabled: bool,
    pub service_prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityDraft {
    pub require_signed_commands: bool,
    pub trust_context: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigDiff {
    pub field: &'static str,
    pub current: String,
    pub draft: String,
    pub restart_required: bool,
}

impl RouterConfigDraft {
    pub fn preset(preset: ConfigPreset) -> Self {
        match preset {
            ConfigPreset::LocalLab => Self {
                router_name: "/local/operator/router".into(),
                management_socket: "unix:///run/ndn-fwd/mgmt.sock".into(),
                cs_capacity_bytes: 65_536,
                faces: vec![StartupFaceDraft {
                    uri: "udp4://127.0.0.1:6363".into(),
                    persist: true,
                }],
                routes: vec![StartupRouteDraft {
                    prefix: "/local/operator".into(),
                    face_uri: "udp4://127.0.0.1:6363".into(),
                    cost: 10,
                }],
                discovery: DiscoveryDraft {
                    enabled: true,
                    service_prefix: "/local/operator/services".into(),
                },
                security: SecurityDraft {
                    require_signed_commands: true,
                    trust_context: "/local/operator".into(),
                },
            },
            ConfigPreset::BrowserSandbox => Self {
                router_name: "/browser/sandbox/router".into(),
                management_socket: "browser-engine://in-page".into(),
                cs_capacity_bytes: 16_384,
                faces: Vec::new(),
                routes: Vec::new(),
                discovery: DiscoveryDraft {
                    enabled: false,
                    service_prefix: "/browser/sandbox/services".into(),
                },
                security: SecurityDraft {
                    require_signed_commands: false,
                    trust_context: "/browser/sandbox".into(),
                },
            },
            ConfigPreset::CompatReadOnly => Self {
                router_name: "/compat/forwarder".into(),
                management_socket: "unix:///run/nfd/nfd.sock".into(),
                cs_capacity_bytes: 0,
                faces: Vec::new(),
                routes: Vec::new(),
                discovery: DiscoveryDraft {
                    enabled: false,
                    service_prefix: "/localhop/ndn-autoconf".into(),
                },
                security: SecurityDraft {
                    require_signed_commands: false,
                    trust_context: "/".into(),
                },
            },
        }
    }

    pub fn can_write(platform: PlatformKind) -> bool {
        platform == PlatformKind::Desktop
    }

    pub fn render_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|err| err.to_string())
    }

    pub fn parse_toml(raw: &str) -> Result<Self, String> {
        toml::from_str(raw).map_err(|err| err.to_string())
    }

    pub fn diff_from(&self, current: &Self) -> Vec<ConfigDiff> {
        let mut diffs = Vec::new();
        push_diff(
            &mut diffs,
            "router_name",
            &current.router_name,
            &self.router_name,
            true,
        );
        push_diff(
            &mut diffs,
            "management_socket",
            &current.management_socket,
            &self.management_socket,
            true,
        );
        push_diff(
            &mut diffs,
            "cs_capacity_bytes",
            &current.cs_capacity_bytes.to_string(),
            &self.cs_capacity_bytes.to_string(),
            false,
        );
        push_diff(
            &mut diffs,
            "faces",
            &current.faces.len().to_string(),
            &self.faces.len().to_string(),
            true,
        );
        push_diff(
            &mut diffs,
            "routes",
            &current.routes.len().to_string(),
            &self.routes.len().to_string(),
            true,
        );
        push_diff(
            &mut diffs,
            "discovery.enabled",
            &current.discovery.enabled.to_string(),
            &self.discovery.enabled.to_string(),
            false,
        );
        push_diff(
            &mut diffs,
            "security.require_signed_commands",
            &current.security.require_signed_commands.to_string(),
            &self.security.require_signed_commands.to_string(),
            true,
        );
        diffs
    }
}

fn push_diff(
    diffs: &mut Vec<ConfigDiff>,
    field: &'static str,
    current: &str,
    draft: &str,
    restart_required: bool,
) {
    if current != draft {
        diffs.push(ConfigDiff {
            field,
            current: current.into(),
            draft: draft.into(),
            restart_required,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_config_round_trips_toml() {
        let draft = RouterConfigDraft::preset(ConfigPreset::LocalLab);
        let toml = draft.render_toml().expect("toml");
        let parsed = RouterConfigDraft::parse_toml(&toml).expect("parse");

        assert_eq!(parsed, draft);
    }

    #[test]
    fn config_diff_marks_restart_boundaries() {
        let current = RouterConfigDraft::preset(ConfigPreset::LocalLab);
        let mut draft = current.clone();
        draft.router_name = "/local/operator/router-2".into();
        draft.cs_capacity_bytes = 131_072;

        let diffs = draft.diff_from(&current);

        assert!(
            diffs
                .iter()
                .any(|diff| diff.field == "router_name" && diff.restart_required)
        );
        assert!(
            diffs
                .iter()
                .any(|diff| diff.field == "cs_capacity_bytes" && !diff.restart_required)
        );
    }

    #[test]
    fn dashboard_settings_round_trip_json() {
        let settings =
            DashboardSettingsDraft::for_platform(PlatformKind::Browser, Density::Compact);
        let raw = settings.export_json().expect("json");
        let parsed = DashboardSettingsDraft::import_json(&raw).expect("parse");

        assert_eq!(parsed, settings);
        assert!(parsed.browser_config_read_only);
    }
}
