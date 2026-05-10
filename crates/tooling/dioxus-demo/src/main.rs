fn main() {
    #[cfg(all(target_arch = "wasm32", feature = "web"))]
    dioxus_demo::launch();
}
