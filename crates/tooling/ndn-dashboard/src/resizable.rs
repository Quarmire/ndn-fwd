//! Reusable resizable table columns.
//!
//! Column widths live in a Dioxus signal — **not** the DOM — so they survive
//! the dashboard's periodic poll re-renders. A CSS `resize` grip would reset
//! on every 3s refresh because the re-render replaces the `<th>`; holding the
//! widths in a signal means each re-render re-applies the operator's sizes.
//!
//! Usage in a table view:
//! ```ignore
//! let cols = use_col_widths(&[70.0, 90.0, 280.0, 280.0, 120.0, 90.0]);
//! rsx! {
//!     {cols.overlay()}                       // once, near the table
//!     table { class: "resizable",
//!         {cols.colgroup()}                  // defines each column width
//!         thead { tr {
//!             th { "ID" {cols.handle(0)} }   // a drag grip per column
//!             // ...
//!         } }
//!         tbody { /* unchanged */ }
//!     }
//! }
//! ```
//! The table needs `class:"resizable"` (`table-layout:fixed`) and the grip
//! CSS lives in `styles.rs` (`.col-resize`, `.col-resize-overlay`).

use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq)]
struct Drag {
    col: usize,
    start_x: f64,
    start_w: f64,
}

/// Per-column widths (px) for one table. Cheap to copy — it is just signals.
#[derive(Clone, Copy)]
pub struct ColWidths {
    widths: Signal<Vec<f64>>,
    drag: Signal<Option<Drag>>,
    min: f64,
    max: f64,
}

/// Seed resizable-column state with one default px width per column.
/// Call at the top of the table's component (it is a hook). Drag is clamped
/// to `[48, 960]` px so a column can't collapse to nothing or be dragged
/// arbitrarily wide; the `.resizable-wrap` container scrolls if the whole
/// table still overflows.
pub fn use_col_widths(defaults: &[f64]) -> ColWidths {
    let widths = use_signal(|| defaults.to_vec());
    let drag = use_signal(|| None);
    ColWidths {
        widths,
        drag,
        min: 48.0,
        max: 960.0,
    }
}

impl ColWidths {
    /// `<colgroup>` defining each column's width. Pair with the `resizable`
    /// class so `table-layout:fixed` honours the widths.
    pub fn colgroup(&self) -> Element {
        let widths = self.widths;
        rsx! {
            colgroup {
                for w in widths.read().iter() {
                    col { style: "width:{w}px" }
                }
            }
        }
    }

    /// A drag grip for column `col`, placed inside that column's `<th>`
    /// (the `resizable` class makes the `<th>` `position:relative`).
    pub fn handle(&self, col: usize) -> Element {
        let mut drag = self.drag;
        let widths = self.widths;
        rsx! {
            div {
                class: "col-resize",
                title: "Drag to resize column",
                onmousedown: move |e| {
                    e.stop_propagation();
                    let start_w = widths.read().get(col).copied().unwrap_or(0.0);
                    drag.set(Some(Drag {
                        col,
                        start_x: e.client_coordinates().x,
                        start_w,
                    }));
                },
            }
        }
    }

    /// Transparent full-viewport overlay, mounted only while a drag is active,
    /// that tracks the pointer so resizing continues outside the grip. Render
    /// it once near the table.
    pub fn overlay(&self) -> Element {
        let mut drag = self.drag;
        let mut widths = self.widths;
        let min = self.min;
        let max = self.max;
        if drag.read().is_none() {
            return rsx! {};
        }
        rsx! {
            div {
                class: "col-resize-overlay",
                onmousemove: move |e| {
                    if let Some(d) = *drag.read() {
                        let dx = e.client_coordinates().x - d.start_x;
                        let mut w = widths.write();
                        if let Some(cw) = w.get_mut(d.col) {
                            *cw = (d.start_w + dx).clamp(min, max);
                        }
                    }
                },
                onmouseup: move |_| drag.set(None),
                onmouseleave: move |_| drag.set(None),
            }
        }
    }
}
