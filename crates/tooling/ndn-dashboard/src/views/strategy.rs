use dioxus::prelude::*;

use crate::app::{AppCtx, DashCmd};

/// Well-known strategy names for the dropdown.
const STRATEGIES: &[(&str, &str)] = &[
    ("/ndn/strategy/best-route/v5", "Best Route"),
    ("/ndn/strategy/multicast/v5", "Multicast"),
    ("/ndn/strategy/ncc/v1", "NCC"),
    ("/ndn/strategy/access/v1", "Access"),
    ("/ndn/strategy/self-learning", "Self-Learning"),
];

#[component]
pub fn Strategy() -> Element {
    let ctx = use_context::<AppCtx>();
    let strategies = ctx.strategies.read();

    let mut set_prefix: Signal<String> = use_signal(String::new);
    let mut set_strategy: Signal<String> = use_signal(|| STRATEGIES[0].0.to_string());
    let mut custom_strat: Signal<String> = use_signal(String::new);

    rsx! {
        // ── Strategy table ───────────────────────────────────────────────────
        div { class: "section",
            div { class: "section-title", "Strategy Assignments" }
            if strategies.is_empty() {
                div { class: "empty", "No strategy assignments." }
            } else {
                table {
                    thead {
                        tr {
                            th { "Prefix" }
                            th { "Strategy" }
                            th { "" }
                        }
                    }
                    tbody {
                        for entry in strategies.iter() {
                            {
                                let prefix = entry.prefix.clone();
                                rsx! {
                                    tr {
                                        td { class: "mono", "{entry.prefix}" }
                                        td { class: "mono", "{entry.short_name()}" }
                                        td {
                                            button {
                                                class: "btn btn-secondary btn-sm",
                                                onclick: move |_| {
                                                    ctx.cmd.send(DashCmd::StrategyUnset(prefix.clone()));
                                                },
                                                "Unset"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ── Set strategy form ────────────────────────────────────────────
            div { class: "form-row",
                div { class: "form-group",
                    label { r#for: "st-prefix", "Prefix" }
                    input {
                        id: "st-prefix",
                        r#type: "text",
                        placeholder: "/",
                        value: "{set_prefix}",
                        style: "width:160px",
                        oninput: move |e| set_prefix.set(e.value()),
                    }
                }
                div { class: "form-group",
                    label { r#for: "st-strat", "Strategy" }
                    select {
                        id: "st-strat",
                        onchange: move |e| set_strategy.set(e.value()),
                        for (name, label) in STRATEGIES.iter() {
                            option {
                                value: "{name}",
                                selected: *set_strategy.read() == *name,
                                "{label}"
                            }
                        }
                        option { value: "__custom__", "Custom…" }
                    }
                }
                if *set_strategy.read() == "__custom__" {
                    div { class: "form-group", style: "flex:1;",
                        label { r#for: "st-custom", "Custom strategy name" }
                        input {
                            id: "st-custom",
                            r#type: "text",
                            placeholder: "/ndn/strategy/my-strategy/v1",
                            value: "{custom_strat}",
                            oninput: move |e| custom_strat.set(e.value()),
                        }
                    }
                }
                button {
                    class: "btn btn-primary",
                    onclick: move |_| {
                        let prefix = set_prefix.read().trim().to_string();
                        let strategy = if *set_strategy.read() == "__custom__" {
                            custom_strat.read().trim().to_string()
                        } else {
                            set_strategy.read().clone()
                        };
                        if !prefix.is_empty() && !strategy.is_empty() {
                            ctx.cmd.send(DashCmd::StrategySet { prefix, strategy });
                            set_prefix.set(String::new());
                        }
                    },
                    "Set Strategy"
                }
            }
        }
    }
}
