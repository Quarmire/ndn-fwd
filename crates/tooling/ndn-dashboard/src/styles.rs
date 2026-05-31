/// Global stylesheet injected into the Dioxus desktop window.
/// Colors are defined as CSS custom properties so light/dark mode can be
/// toggled by adding/removing the `light-mode` class on the layout root
/// element (Rust-managed via a reactive Dioxus signal; no JS).
pub const CSS: &str = "
*{box-sizing:border-box;margin:0;padding:0}
html{height:100%}

/* ── Design tokens — IBM Carbon Design System ───────────────────────
   Color tokens map onto the dashboard's existing variable names so every
   rule inherits the Carbon palette. Dark = Carbon Gray-100 (`g100`);
   `.light-mode` below = Carbon White. Spacing/type/font tokens follow the
   Carbon scales for component migration. https://carbondesignsystem.com */
:root{
  /* Carbon g100 (dark) */
  --bg:#161616;            /* $background */
  --surface:#262626;       /* $layer-01 */
  --surface2:#393939;      /* $layer-02 */
  --border:#525252;        /* $border-strong-01 */
  --border-subtle:#393939; /* $border-subtle-02 */
  --text:#f4f4f4;          /* $text-primary */
  --text-muted:#a8a8a8;    /* $text-secondary (gray-40) */
  --text-faint:#6f6f6f;    /* $text-placeholder */
  --accent:#78a9ff;        /* $link-primary (blue-40) */
  --accent-solid:#4589ff;  /* $interactive (blue-50) */
  --accent-dim:#4589ff29;  /* interactive @ ~16% — hover/selected fill */
  --accent-bg:#001d6c;     /* blue-90 — selected/info chip fill */
  --green:#42be65;         /* $support-success (green-40) */
  --green-bg:#022d0d;
  --green-dark:#071f0e;
  --yellow:#f1c21b;        /* $support-warning (yellow-30) */
  --yellow-bg:#302400;
  --red:#fa4d56;           /* $support-error (red-40) */
  --red-bg:#3a0b0d;
  --orange:#ff832b;        /* orange-40 */
  --orange-bg:#3a1c00;
  --purple:#be95ff;        /* purple-40 */
  --purple-bg:#1f1144;
  --btn-p:#0f62fe;         /* $button-primary (blue-60) */
  --btn-p-h:#0353e9;       /* $button-primary-hover */
  --btn-d:#da1e28;         /* $button-danger-primary (red-60) */
  --btn-d-h:#b81921;       /* $button-danger-hover */
  --shadow:rgba(0,0,0,.6);

  /* Carbon spacing scale */
  --cds-spacing-01:0.125rem; --cds-spacing-02:0.25rem; --cds-spacing-03:0.5rem;
  --cds-spacing-04:0.75rem;  --cds-spacing-05:1rem;    --cds-spacing-06:1.5rem;
  --cds-spacing-07:2rem;     --cds-spacing-08:2.5rem;  --cds-spacing-09:3rem;
  --cds-spacing-10:4rem;

  /* Carbon type scale (font sizes) */
  --cds-label-01:0.75rem;   --cds-body-01:0.875rem;   --cds-body-02:1rem;
  --cds-heading-01:0.875rem; --cds-heading-03:1.25rem; --cds-heading-04:1.75rem;

  /* IBM Plex (Carbon's typeface), bundled as base64 `@font-face` in
     `fonts.rs`; the system stack is the fallback if a face is missing. */
  --font-sans:'IBM Plex Sans','IBM Plex Sans Var',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;
  --font-mono:'IBM Plex Mono','SF Mono',ui-monospace,SFMono-Regular,Consolas,monospace;
}

/* ── Light mode — Carbon White theme ─────────────────────────────── */
.light-mode{
  --bg:#ffffff;            /* $background */
  --surface:#f4f4f4;       /* $layer-01 */
  --surface2:#e0e0e0;      /* $layer-02 */
  --border:#c6c6c6;        /* $border-strong-01 */
  --border-subtle:#e0e0e0; /* $border-subtle-02 */
  --text:#161616;          /* $text-primary */
  --text-muted:#525252;    /* $text-secondary */
  --text-faint:#8d8d8d;    /* $text-placeholder */
  --accent:#0f62fe;        /* $link-primary (blue-60) */
  --accent-solid:#0f62fe;  /* $interactive */
  --accent-dim:#0f62fe14;
  --accent-bg:#d0e2ff;     /* blue-20 */
  --green:#24a148;         /* $support-success (green-50) */
  --green-bg:#defbe6;      /* green-10 */
  --green-dark:#a7f0ba;
  --yellow:#b28600;        /* darkened yellow-30 for light-bg contrast */
  --yellow-bg:#fcf4d6;     /* yellow-10 */
  --red:#da1e28;           /* $support-error (red-60) */
  --red-bg:#fff1f1;        /* red-10 */
  --orange:#ba4e00;
  --orange-bg:#ffe8d6;
  --purple:#8a3ffc;        /* purple-60 */
  --purple-bg:#f6f2ff;     /* purple-10 */
  --btn-p:#0f62fe;         /* $button-primary */
  --btn-p-h:#0353e9;
  --btn-d:#da1e28;         /* $button-danger-primary */
  --btn-d-h:#b81921;
  --shadow:rgba(0,0,0,.16);
}

body{font-family:var(--font-sans);-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;background:var(--bg);color:var(--text);display:flex;height:100%;overflow:hidden}
/* Dioxus desktop mounts into a bare <div> inside body with no size — override it. */
body>div{height:100%;width:100%;overflow:hidden}
/* `.app-root` is the single ancestor of every overlay (modals,
   toasts, gate, drawer backdrop) in the web build. Carries the
   `light-mode` class so CSS variables override across the whole
   subtree, including position:fixed siblings. */
.app-root{display:flex;width:100%;height:100%;background:var(--bg);color:var(--text)}
.layout{display:flex;width:100%;height:100%}
.sidebar{width:200px;min-width:200px;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column}
.sidebar-logo{padding:16px;font-size:15px;font-weight:600;color:var(--accent);border-bottom:1px solid var(--border);letter-spacing:.5px}
.nav-section{display:flex;flex-direction:column}
.nav-section-header{display:flex;align-items:center;gap:6px;padding:12px 16px 6px;cursor:pointer;color:var(--text-muted);font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;user-select:none}
.nav-section-header:hover{color:var(--text)}
.nav-section-caret{font-size:9px;width:10px;display:inline-block}
/* Live tally per bucket (design note §2). */
.nav-count{font-size:10px;font-weight:600;color:var(--text-faint);background:var(--surface2);border-radius:0;padding:1px 6px;min-width:18px;text-align:center}
/* Trust-schema rule rendered as a plain-English sentence (permissions view). */
.schema-rule{display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border-subtle);border-left:3px solid var(--accent);margin-bottom:6px;background:var(--surface2)}
.schema-rule-text{flex:1;font-size:13px;line-height:1.5;color:var(--text)}
/* Read-only capability notice (operator can observe but not change). */
.readonly-banner{display:flex;align-items:center;gap:10px;padding:10px 14px;margin-bottom:16px;background:var(--yellow-bg);border:1px solid var(--yellow);border-left:3px solid var(--yellow);font-size:13px;color:var(--text)}
.readonly-banner-icon{flex-shrink:0}
.nav-section .nav-item{padding-left:30px}
.nav-item{padding:10px 16px;cursor:pointer;color:var(--text-muted);font-size:13px;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{background:var(--border-subtle);color:var(--text)}
.nav-item.active{background:var(--accent-dim);color:var(--accent);border-left-color:var(--accent)}
/* Hamburger button — hidden by default (desktop); revealed on
   phones via the mobile media query. */
.hamburger{display:none;background:none;border:none;color:var(--text);font-size:22px;line-height:1;padding:4px 10px;cursor:pointer;font-family:inherit}
.hamburger:hover{color:var(--accent)}
/* Backdrop for the mobile drawer; hidden when SIDEBAR_OPEN is false
   (Dioxus simply doesn't render it). When mounted, it covers the
   whole viewport and dismisses the drawer on tap. */
.sidebar-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:80;display:none}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-height:0}
/* The conn-bar is a flex column containing one status row + one
   optional config row. Desktop renders both inline on the status
   row via wider .conn-bar-status flex-flow; mobile stacks them. */
/* Horizontal toolbar: the markup places every status control directly in
   `.conn-bar`, so it lays them out as a single wrapping row (was
   `flex-direction:column`, which stacked each control full-width). */
.conn-bar{display:flex;flex-direction:row;flex-wrap:wrap;align-items:center;gap:var(--cds-spacing-03);padding:var(--cds-spacing-03) var(--cds-spacing-05);background:var(--surface);border-bottom:1px solid var(--border-subtle);font-size:var(--cds-body-01);flex-shrink:0}
.conn-bar-status{display:flex;align-items:center;gap:10px;padding:10px 20px}
.conn-bar-config{display:flex;align-items:center;gap:10px;padding:0 20px 10px 20px}
.conn-bar-config input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:0;font-size:13px;font-family:var(--font-mono);min-width:0}
.conn-bar-config input:focus{outline:none;border-color:var(--accent)}
.conn-bar-spacer{flex:1}
/* Attach-bar axis framing (note section 8): the Engine axis and the
   Acting-as identity axis are independent; a faint divider separates them. */
.axis-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted);flex-shrink:0}
.axis-divider{width:1px;align-self:stretch;min-height:18px;background:var(--border);flex-shrink:0;margin:0 var(--cds-spacing-02,4px)}
.axis-select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:0;font-size:13px;font-family:var(--font-mono)}
.axis-select:focus{outline:none;border-color:var(--accent)}
/* Conn-state badge becomes a clickable button on mobile (the
   toggle for the config row). Keep the inherited badge styling
   and just normalise the button defaults. */
.conn-state-toggle{background:transparent;border:none;font:inherit;padding:0;cursor:pointer;color:inherit;display:inline-flex;align-items:center;gap:4px}
.conn-state-caret{display:inline-block;transition:transform .15s;font-size:10px;opacity:.7}
.conn-bar input{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:0;font-size:13px;font-family:var(--font-mono);flex:1;max-width:280px;min-width:120px}
.conn-bar input:focus{outline:none;border-color:var(--accent)}
.content,.content-area{flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch;padding:24px;min-height:0}
/* Master-detail shell (design note section 3): center content + right-hand
   inspector laid out as a row; the inspector is absent (zero width) until a
   row is selected. */
.content-host{display:flex;flex-direction:row;flex:1;min-height:0;min-width:0}
.content-host .content,.content-host .content-area{flex:1;min-width:0}
.inspector{width:320px;flex-shrink:0;border-left:1px solid var(--border);background:var(--surface);display:flex;flex-direction:column;overflow:hidden}
.inspector-header{display:flex;align-items:center;justify-content:space-between;padding:var(--cds-spacing-04) var(--cds-spacing-05);border-bottom:1px solid var(--border-subtle)}
.inspector-title{font-size:14px;font-weight:600;color:var(--text)}
.inspector-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:14px;padding:2px 6px}
.inspector-close:hover{color:var(--text)}
.inspector-body{flex:1;overflow-y:auto;padding:var(--cds-spacing-05);display:flex;flex-direction:column;gap:var(--cds-spacing-06)}
.inspector-empty{color:var(--text-muted);font-size:13px}
.inspector-section{display:flex;flex-direction:column;gap:var(--cds-spacing-03)}
.inspector-section-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--text-muted)}
.inspector-kv{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0;font-size:13px}
.inspector-kv dt{color:var(--text-muted)}
.inspector-kv dd{margin:0;color:var(--text);word-break:break-all}
.inspector-kv dd.flag-on{color:var(--green);font-weight:600}
.inspector-kv dd.flag-off{color:var(--text-faint)}
.inspector-counters{width:100%;font-size:13px}
.inspector-counters th{text-align:right;color:var(--text-muted);font-weight:500;padding:2px 6px}
.inspector-counters th:first-child{text-align:left}
.inspector-counters td{padding:2px 6px}
.inspector-counters td:not(:first-child){text-align:right}
.inspector-footer{padding:var(--cds-spacing-04) var(--cds-spacing-05);border-top:1px solid var(--border-subtle)}
/* Cross-navigation links (route prefixes, nexthop faces) — clickable, accent. */
.inspector-links{display:flex;flex-direction:column;gap:2px}
.inspector-link{background:none;border:none;text-align:left;padding:2px 0;color:var(--accent);cursor:pointer;font-size:13px;word-break:break-all}
.inspector-link:hover{text-decoration:underline}
.inspector-nh{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:13px}
.inspector-nh .inspector-link{flex:1}
.inspector-addnh{display:flex;gap:6px;align-items:center}
.inspector-addnh input{flex:1;min-width:0;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:0;font-size:13px;font-family:var(--font-mono)}
.inspector-addnh input:focus{outline:none;border-color:var(--accent)}
/* Selectable rows feed the inspector. */
.row-selectable{cursor:pointer}
.row-selectable.selected{background:var(--accent-dim)}
.row-selectable.selected td:first-child{box-shadow:inset 3px 0 0 var(--accent)}
@media (max-width:768px){
  /* On narrow widths the inspector is a bottom sheet: the entity list stays
     visible above it instead of the pane taking the whole screen. Capped
     height, anchored to the bottom, with its own scroll. */
  .inspector{position:fixed;left:0;right:0;bottom:0;top:auto;width:100%;max-width:none;max-height:62vh;border-left:none;border-top:1px solid var(--border);box-shadow:0 -6px 20px rgba(0,0,0,.45);z-index:90}
  .inspector-header{position:sticky;top:0;background:var(--surface)}
  /* The bottom sheet is fixed (out of flow), so without this the list can't
     scroll past it and rows behind the sheet are unreachable — you'd have to
     close the inspector to pick another row. Reserve the sheet's height as
     bottom padding so every row scrolls into the visible strip above it. */
  .inspector-open .content,.inspector-open .content-area{padding-bottom:64vh}
}
/* Sticky sub-nav inside a view's content area — keeps the tab
   bar + adjacent persistent controls pinned to the top of the
   scroll viewport. The container caps its height to a fraction
   of the visible content area so the body still has room. */
.view-sticky-nav{position:sticky;top:0;z-index:30;background:var(--bg);margin:-12px -12px 12px -12px;padding:8px 12px 0 12px;border-bottom:1px solid var(--border-subtle);max-height:42vh;overflow-y:auto}
.view-sticky-nav .tab-bar{display:flex;gap:6px;flex-wrap:wrap;padding-bottom:8px}
.badge{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600}
.badge-green{background:var(--green-bg);color:var(--green)}
.badge-red{background:var(--red-bg);color:var(--red)}
.badge-yellow{background:var(--yellow-bg);color:var(--yellow)}
.badge-blue{background:var(--accent-bg);color:var(--accent)}
.badge-gray{background:var(--border-subtle);color:var(--text-muted)}
.badge-purple{background:var(--purple-bg);color:var(--purple)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:16px}
.card-label{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.card-value{font-size:30px;font-weight:600;color:var(--text);line-height:1}
.card-sub{font-size:12px;color:var(--text-muted);margin-top:6px}
.section{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:16px;margin-bottom:16px}
.section-title{font-size:13px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:6px 12px;font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--border)}
td{padding:8px 12px;border-bottom:1px solid var(--border-subtle);color:var(--text);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--surface2)}
/* ── Resizable table columns (resizable.rs) ──────────────────── */
/* The table lives in a scroll container so a widened column scrolls
   horizontally instead of pushing content off-screen. */
.resizable-wrap{overflow-x:auto;max-width:100%}
.resizable{table-layout:fixed;width:100%}
.resizable th{position:relative}
.resizable th,.resizable td{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* Drag grip on the right edge of a resizable column header. The always-on
   faint divider advertises that the column can be resized; it brightens to
   the accent colour on hover. */
.col-resize{position:absolute;top:0;right:0;width:7px;height:100%;cursor:col-resize;user-select:none}
.col-resize::after{content:'';position:absolute;right:2px;top:28%;bottom:28%;width:2px;background:var(--border)}
.col-resize:hover::after{background:var(--accent);width:3px;right:2px}
.col-resize-overlay{position:fixed;inset:0;z-index:9000;cursor:col-resize}
.form-row{display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;margin-top:14px;padding-top:14px;border-top:1px solid var(--border-subtle)}
.form-group{display:flex;flex-direction:column;gap:4px}
label{font-size:11px;color:var(--text-muted)}
input,select,textarea{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:0;font-size:13px;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
.btn{padding:7px 14px;border-radius:0;border:none;cursor:pointer;font-size:13px;font-weight:500;font-family:inherit;transition:background .15s;white-space:nowrap;line-height:1.2}
.btn-primary{background:var(--btn-p);color:#fff}
.btn-primary:hover{background:var(--btn-p-h)}
.btn-danger{background:var(--btn-d);color:#fff}
.btn-danger:hover{background:var(--btn-d-h)}
.btn-secondary{background:var(--border-subtle);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{background:var(--border)}
.btn-sm{padding:4px 10px;font-size:12px}
.error-banner{background:var(--red-bg);border:1px solid var(--red);border-radius:0;padding:10px 16px;margin-bottom:16px;color:var(--red);font-size:13px;display:flex;justify-content:space-between;align-items:center}
.mono{font-family:var(--font-mono);font-size:12px}
.empty{color:var(--text-muted);font-size:13px;padding:20px 0;text-align:center}
[data-tooltip]{position:relative;cursor:help}
[data-tooltip]::after{content:attr(data-tooltip);position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--surface2);border:1px solid var(--border);border-radius:0;padding:5px 10px;font-size:11px;color:var(--text);white-space:pre-wrap;max-width:280px;pointer-events:none;opacity:0;transition:opacity .15s;z-index:200;line-height:1.5;text-align:left}
[data-tooltip]:hover::after{opacity:1}
.restart-banner{background:var(--yellow-bg);border:1px solid var(--yellow);border-radius:0;padding:8px 14px;margin-bottom:14px;color:var(--yellow);font-size:12px;display:flex;align-items:center;gap:8px}
/* ── Onboarding overlay ─────────────────────────────────────────── */
.onboarding-overlay{position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:1000;display:flex;align-items:center;justify-content:center;animation:fade-in .25s ease}
.onboarding-card{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:40px 44px;width:580px;max-width:92vw;position:relative;animation:slide-up .3s ease}
@keyframes slide-up{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes fade-in{from{opacity:0}to{opacity:1}}
.onboarding-step{animation:step-in .25s ease}
@keyframes step-in{from{opacity:0;transform:translateX(18px)}to{opacity:1;transform:translateX(0)}}
.step-dots{display:flex;gap:8px;margin-top:28px;justify-content:center}
.step-dot{width:8px;height:8px;border-radius:50%;background:var(--border);transition:background .25s,transform .25s}
.step-dot.active{background:var(--accent);transform:scale(1.3)}
.step-dot.done{background:var(--green)}
/* ── Packet flow animation ─────────────────────────────────────── */
@keyframes packet-fly{0%{left:-60px;opacity:0}15%{opacity:1}85%{opacity:1}100%{left:calc(100% + 20px);opacity:0}}
.packet-lane{position:relative;height:28px;overflow:hidden;background:var(--bg);border-radius:0;margin:6px 0}
.packet-bubble{position:absolute;top:4px;background:var(--accent-solid);color:#fff;border-radius:3px;padding:2px 8px;font-size:10px;font-family:var(--font-mono);white-space:nowrap;animation:packet-fly 2.8s ease-in-out infinite}
.packet-bubble.data{background:var(--green-bg);color:var(--green);animation-delay:.9s}
.packet-bubble.nack{background:var(--red-bg);color:var(--red);animation-delay:1.8s}
.light-mode .packet-bubble.data{background:var(--green);color:#fff}
.light-mode .packet-bubble.nack{background:var(--red);color:#fff}
/* ── Trust chain ────────────────────────────────────────────────── */
.trust-chain{display:flex;align-items:center;gap:0;margin:16px 0;flex-wrap:wrap}
.chain-node{background:var(--surface2);border:1px solid var(--border);border-radius:0;padding:10px 14px;text-align:center;min-width:110px;transition:border-color .2s}
.chain-node.ok{border-color:var(--green)}
.chain-node.warn{border-color:var(--yellow)}
.chain-node.missing{border-color:var(--border);opacity:.5}
.chain-arrow{font-size:18px;color:var(--border);padding:0 4px;flex-shrink:0}
/* ── Education snippets ────────────────────────────────────────── */
.edu-card{background:linear-gradient(135deg,#0c2d6b1a,#1a472a1a);border:1px solid #1f4f8a44;border-radius:0;padding:14px 16px;margin-bottom:16px;position:relative;overflow:hidden}
.light-mode .edu-card{background:linear-gradient(135deg,#cce5ff22,#ccffd822);border-color:#0969da33}
.edu-dismiss{position:absolute;top:8px;right:10px;background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:16px;padding:0;line-height:1}
.edu-dismiss:hover{color:var(--text)}
@keyframes sig-glow{0%,100%{box-shadow:0 0 0 0 transparent}50%{box-shadow:0 0 8px 3px #3fb95044}}
.signed-packet{display:inline-flex;align-items:center;gap:5px;background:var(--green-dark);border:1px solid var(--green);border-radius:0;padding:3px 9px;font-size:11px;font-family:var(--font-mono);animation:sig-glow 2.4s ease infinite}
@keyframes trust-pulse{0%,100%{opacity:.4}50%{opacity:1}}
.trust-link{display:inline-block;width:28px;height:2px;background:var(--accent);border-radius:1px;animation:trust-pulse 1.8s ease infinite;margin:0 4px;vertical-align:middle}
/* ── Progress steps ────────────────────────────────────────────── */
.enroll-steps{display:flex;align-items:center;gap:0;margin:14px 0;font-size:11px;flex-wrap:wrap}
.enroll-step{display:flex;flex-direction:column;align-items:center;gap:4px;min-width:64px;text-align:center}
.enroll-step-dot{width:11px;height:11px;border-radius:50%;background:var(--border);flex-shrink:0;transition:background .3s}
.enroll-step-dot.done{background:var(--green)}
.enroll-step-dot.active{background:var(--accent);box-shadow:0 0 0 3px var(--accent-dim);animation:ping .9s ease infinite}
@keyframes ping{0%,100%{box-shadow:0 0 0 3px var(--accent-dim)}50%{box-shadow:0 0 0 6px var(--accent-dim)}}
.enroll-step-line{flex:1;height:2px;background:var(--border);min-width:24px}
.enroll-step-line.done{background:var(--green)}
/* ── YubiKey ───────────────────────────────────────────────────── */
.yk-seed{background:var(--bg);border:1px solid var(--border);border-radius:0;padding:10px 12px;font-family:var(--font-mono);font-size:11px;color:var(--green);word-break:break-all;margin:8px 0;line-height:1.7}
.yk-cmd{background:var(--bg);border:1px solid var(--border);border-radius:0;padding:8px 12px;font-family:var(--font-mono);font-size:11px;color:var(--accent);word-break:break-all;margin:6px 0;user-select:all}
/* ── DID ───────────────────────────────────────────────────────── */
.did-value{background:var(--bg);border:1px solid var(--border);border-radius:0;padding:8px 12px;font-family:var(--font-mono);font-size:12px;color:var(--purple);word-break:break-all;margin:6px 0}
.did-copy-btn{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:0;padding:3px 8px;font-size:11px;cursor:pointer}
.did-copy-btn:hover{border-color:var(--accent);color:var(--accent)}
/* ── Fleet edu animation ───────────────────────────────────────── */
.edu-flow-row{display:flex;align-items:center;justify-content:center;gap:6px;margin:4px 0}
.edu-flow-label{font-size:8px;color:var(--text-muted);text-align:center;letter-spacing:.5px}
.edu-router{width:24px;height:20px;background:var(--surface2);border:1px solid var(--border);border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:8px;font-weight:600;color:var(--text)}
.edu-router-ca{border-color:var(--accent-solid);color:var(--accent)}
.edu-cert-glow{border-color:var(--green);color:var(--green)}
@keyframes arrow-pulse{0%,100%{opacity:.3}50%{opacity:1}}
.edu-arrow{font-size:10px;color:var(--text-muted);animation:arrow-pulse 1.6s ease infinite}
.edu-arrow-right{color:var(--accent-solid)}
.edu-anim-delay1{animation-delay:.4s}
/* ── Overview edu animation ────────────────────────────────────── */
@keyframes drop-packet{0%{transform:translateY(-10px);opacity:0}30%{opacity:1}60%{transform:translateY(0);opacity:1}80%{opacity:0;filter:blur(2px)}100%{opacity:0}}
.drop-packet{font-size:11px;background:var(--red-bg);border:1px solid var(--red)66;border-radius:3px;padding:2px 7px;display:inline-block;animation:drop-packet 2.2s ease infinite;font-family:var(--font-mono)}
/* ── Log view ──────────────────────────────────────────────────── */
.log-entry{display:flex;align-items:flex-start;gap:8px;padding:3px 4px;border-bottom:1px solid var(--surface2);font-size:12px;font-family:var(--font-mono);min-width:0}
.log-entry:last-child{border-bottom:none}
.log-ts{color:var(--text-faint);font-size:10px;white-space:nowrap;flex-shrink:0}
.log-lvl{padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;min-width:44px;text-align:center;flex-shrink:0;white-space:nowrap}
.log-target{color:var(--text-muted);flex-shrink:0;white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis}
.log-msg{color:var(--text);flex:1;min-width:0;white-space:pre-wrap;word-break:break-word}
.log-list{display:flex;flex-direction:column;overflow-y:auto;overflow-x:hidden;flex:1;min-height:0}
.log-toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.filter-controls-section{background:var(--bg);border:1px solid var(--border-subtle);border-radius:0;padding:12px;margin-bottom:12px}
.col-toggle{padding:2px 7px;border-radius:0;border:1px solid var(--border);background:var(--bg);color:var(--text-muted);font-size:10px;cursor:pointer;font-family:inherit;transition:all .15s}
.col-toggle.on{background:var(--accent-dim);border-color:var(--accent);color:var(--accent)}
/* ── Split / floating panes ────────────────────────────────────── */
.split-divider{background:var(--border-subtle);flex-shrink:0;transition:background .15s}
.split-divider:hover{background:var(--accent)}
.split-divider-h{width:4px;cursor:col-resize}
.split-divider-v{height:4px;cursor:row-resize}
.log-pane{display:flex;flex-direction:column;flex:1;min-width:0;min-height:0;overflow:hidden;padding:12px}
.floating-pane{position:fixed;z-index:200;background:var(--surface);border:1px solid var(--border);border-radius:0;box-shadow:0 12px 40px var(--shadow);display:flex;flex-direction:column;resize:both;overflow:hidden;min-width:420px;min-height:280px}
.floating-title{background:var(--border-subtle);border-bottom:1px solid var(--border);padding:6px 10px;display:flex;align-items:center;justify-content:space-between;cursor:move;user-select:none;flex-shrink:0;font-size:12px;color:var(--text)}
.floating-body{flex:1;min-height:0;overflow:hidden;display:flex;flex-direction:column}
/* ── Overview expandable cards ─────────────────────────────── */
.overview-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px}
.ov-card{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:14px 16px;cursor:pointer;transition:all .15s;user-select:none}
.ov-card:hover{background:var(--surface2);border-color:var(--accent)44}
.ov-card-active{background:var(--accent-dim);border-color:var(--accent);box-shadow:0 0 0 1px var(--accent-dim)}
.ov-card-static{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:14px 16px;cursor:default}
/* Carbon KPI tile (design note §2): label-01 caps label + heading-04 number. */
.ov-card-label{font-size:var(--cds-label-01);color:var(--text-muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:var(--cds-spacing-03)}
.ov-card-value{font-size:var(--cds-heading-04);font-weight:600;color:var(--text);line-height:1.2}
.ov-card-hint{font-size:var(--cds-label-01);color:var(--text-faint);margin-top:var(--cds-spacing-02)}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.mini-stat{background:var(--bg);border:1px solid var(--border-subtle);border-radius:0;padding:10px 12px}
.mini-stat-label{font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px}
.mini-stat-value{font-size:20px;font-weight:600;color:var(--text)}
.mini-stat-sub{font-size:11px;color:var(--text-muted);margin-top:3px}
/* ── Modals ────────────────────────────────────────────────── */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:500;display:flex;align-items:center;justify-content:center}
.light-mode .modal-overlay{background:rgba(0,0,0,.45)}
.modal-card{background:var(--surface);border:1px solid var(--border);border-radius:0;padding:24px;width:520px;max-width:92vw;max-height:86vh;overflow-y:auto;animation:slide-up .2s ease}
.modal-card-wide{width:620px}
.modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.modal-title{font-size:15px;font-weight:600;color:var(--text)}
.modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:18px;padding:0;line-height:1}
.modal-close:hover{color:var(--text)}
.modal-footer{display:flex;justify-content:flex-end;gap:8px;margin-top:20px;padding-top:14px;border-top:1px solid var(--border-subtle)}
/* ── Tab pills ─────────────────────────────────────────────── */
/* Carbon underline tabs: a rail with the active tab marked by a 2px accent
   underline (was rounded pills). The container's bottom border is the rail;
   each tab's transparent bottom border overlaps it via the -1px margin. */
.tab-pills{display:flex;gap:0;margin-bottom:16px;flex-wrap:wrap;border-bottom:1px solid var(--border-subtle)}
.tab-pill{padding:10px 16px;border:none;border-bottom:2px solid transparent;margin-bottom:-1px;background:transparent;color:var(--text-muted);font-size:13px;cursor:pointer;transition:color .15s,border-color .15s;font-family:inherit}
.tab-pill:hover{color:var(--text);border-bottom-color:var(--border)}
.tab-pill.active{color:var(--text);border-bottom-color:var(--accent);font-weight:600}
/* ── Face type grid ────────────────────────────────────────── */
.face-type-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px}
.face-type-btn{padding:10px 8px;border:1px solid var(--border);border-radius:0;background:var(--bg);color:var(--text-muted);cursor:pointer;text-align:center;font-size:12px;transition:all .15s;font-family:inherit}
.face-type-btn:hover{border-color:var(--accent);color:var(--text)}
.face-type-btn.selected{border-color:var(--accent);background:var(--accent-dim);color:var(--accent);font-weight:500}
/* ── Face monitor toggles ──────────────────────────────────── */
.face-toggle-row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.face-toggle{padding:3px 10px;border-radius:12px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-size:11px;cursor:pointer;transition:all .15s;font-family:var(--font-mono)}
.face-toggle:hover{border-color:var(--accent);color:var(--text)}
.face-toggle.on{border-color:var(--accent);background:var(--accent-dim);color:var(--accent)}
/* ── Icon buttons ──────────────────────────────────────────── */
.icon-btn{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:0;padding:4px 8px;cursor:pointer;font-size:14px;line-height:1;transition:all .15s;font-family:inherit}
.icon-btn:hover{background:var(--border-subtle);color:var(--text);border-color:var(--accent)}
/* ── Theme toggle ──────────────────────────────────────────── */
.theme-toggle{background:none;border:1px solid var(--border);color:var(--text-muted);border-radius:0;padding:4px 8px;cursor:pointer;font-size:14px;line-height:1;transition:all .15s;font-family:inherit;flex-shrink:0}
.theme-toggle:hover{background:var(--border-subtle);color:var(--text);border-color:var(--accent)}
/* ── §3.2 Security sidebar dot ─────────────────────────────── */
/* Glyph-style dot (was a plain colour dot pre-§3.2). Width auto so the
   emoji isn't clipped; preserves the original .sec-dot-* colour modifier
   classes so callers that haven't migrated to the typed ChipState still
   render. */
.sec-dot{display:inline-flex;align-items:center;justify-content:center;font-size:12px;line-height:1;flex-shrink:0;margin-left:8px;cursor:default;transition:opacity .15s;min-width:14px;color:var(--text)}
.sec-dot:hover{opacity:.7}
.sec-dot-green{color:var(--green)}
.sec-dot-yellow{color:var(--yellow)}
.sec-dot-amber{color:var(--yellow)}
.sec-dot-red{color:var(--red)}
.sec-dot-gray{color:var(--text-faint)}

/* ── §3.1 Identity chip ────────────────────────────────────── */
.id-chip{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:12px;font-size:11px;font-weight:600;font-family:var(--font-mono);border:1px solid transparent;background:var(--surface2);color:var(--text);cursor:default;transition:opacity .15s}
.id-chip:hover{opacity:.85}
.id-chip-green{background:var(--green-bg);color:var(--green);border-color:var(--green)}
.id-chip-yellow{background:var(--yellow-bg);color:var(--yellow);border-color:var(--yellow)}
.id-chip-amber{background:var(--yellow-bg);color:var(--yellow);border-color:var(--yellow)}
.id-chip-red{background:var(--red-bg);color:var(--red);border-color:var(--red)}
.id-chip-icon{font-size:12px;line-height:1}
.id-chip-label{letter-spacing:.02em;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
/* ── Sidebar bottom + gear ─────────────────────────────────── */
.sidebar-spacer{flex:1}
.sidebar-bottom{padding:12px 14px;border-top:1px solid var(--border);position:relative}
.gear-menu{position:absolute;bottom:calc(100% + 4px);left:12px;background:var(--surface2);border:1px solid var(--border);border-radius:0;min-width:170px;box-shadow:0 8px 24px var(--shadow);z-index:300;overflow:hidden}
.gear-menu-item{padding:9px 14px;font-size:13px;color:var(--text);cursor:pointer;transition:background .15s}
.gear-menu-item:hover{background:var(--border)}
/* ── Range slider ──────────────────────────────────────────── */
input[type=range]{-webkit-appearance:none;height:4px;background:var(--border);border-radius:2px;border:none;padding:0;width:100%}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;width:14px;height:14px;border-radius:50%;background:var(--accent);cursor:pointer}
input[type=range]:focus{outline:none;border-color:transparent}
/* Neutralize Dioxus's dev-mode toast overlay. In 0.7.x desktop *debug*
   builds the harness injects `#__dx-toast` (class `.dx-toast`) at
   z-index:2147483647; under our `body{display:flex}` its absolutely-
   positioned box ends up spanning the whole window with
   pointer-events:auto, so it silently swallows every click and hover and
   the entire UI appears frozen. Disable pointer events on the container
   (keep them on the inner card so a real rebuild/error toast stays
   clickable). Harmless in release builds, where the element is absent. */
.dx-toast{pointer-events:none!important}
.dx-toast .dx-toast-inner{pointer-events:auto}

/* ── Toasts ────────────────────────────────────────────────── */
@keyframes toast-in{from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:translateX(0)}}
.toast-container{position:fixed;bottom:20px;right:20px;z-index:600;display:flex;flex-direction:column;gap:8px;max-width:340px;pointer-events:none}
.toast{background:var(--surface2);border:1px solid var(--border);border-radius:0;padding:10px 14px;display:flex;align-items:flex-start;justify-content:space-between;gap:10px;pointer-events:all;animation:toast-in .2s ease;box-shadow:0 4px 16px var(--shadow);min-width:240px}
.toast-success{border-color:var(--green);background:var(--green-bg)}
.toast-warning{border-color:var(--yellow);background:var(--yellow-bg)}
.toast-error{border-color:var(--red);background:var(--red-bg)}
.toast-info{border-color:var(--accent);background:var(--accent-bg)}
.light-mode .toast-success{background:var(--green-bg)}
.light-mode .toast-warning{background:var(--yellow-bg)}
.light-mode .toast-error{background:var(--red-bg)}
.light-mode .toast-info{background:var(--accent-bg)}
.toast-body{display:flex;align-items:flex-start;gap:8px;flex:1;min-width:0}
.toast-icon{font-size:13px;flex-shrink:0;line-height:1.5}
.toast-msg{font-size:12px;color:var(--text);line-height:1.5;word-break:break-word}
.toast-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:14px;padding:0;line-height:1;flex-shrink:0;align-self:flex-start}
.toast-close:hover{color:var(--text)}
/* ── Autocomplete ──────────────────────────────────────────── */
.autocomplete-wrap{position:relative}
.autocomplete-list{background:var(--surface2);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;overflow:hidden;margin-top:-1px}
.autocomplete-item{padding:5px 10px;font-size:12px;font-family:var(--font-mono);color:var(--text-muted);cursor:pointer;transition:background .1s}
.autocomplete-item:hover{background:var(--border);color:var(--accent)}
/* ── Face templates ────────────────────────────────────────── */
.face-templates{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border-subtle)}
.face-tpl-btn{padding:3px 9px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--text-muted);font-size:11px;cursor:pointer;transition:all .15s;white-space:nowrap;font-family:inherit}
.face-tpl-btn:hover{border-color:var(--accent);color:var(--text)}
/* ── Build config section ──────────────────────────────────── */
.bc-section{background:var(--bg);border:1px solid var(--border-subtle);border-radius:0;padding:12px 14px;margin-bottom:12px}
.bc-section-title{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;font-weight:600}
.bc-face-row{display:flex;align-items:center;gap:8px;padding:5px 8px;background:var(--surface2);border-radius:0;margin-bottom:4px;font-size:12px;font-family:var(--font-mono)}
.bc-face-row:last-child{margin-bottom:0}
/* ── Responsive (phones + small tablets) ─────────────────────── */
/* The dashboard's primary layout assumes a desktop window. On
   viewports narrower than ~768px the sidebar collapses to a
   horizontally-scrolling top strip, the conn-bar wraps onto
   multiple rows, fixed-width floating panes drop their min-width,
   and chip labels truncate harder so the conn-bar still fits.
   No JS — pure CSS media queries; Dioxus renders DOM, the
   browser handles layout. */
@media (max-width: 768px) {
  /* Sidebar becomes a slide-out drawer. Default state: off-screen
     to the left, full layout collapses to single-column. The
     hamburger button (always visible on this width) toggles
     SIDEBAR_OPEN, which adds `sidebar-open` to .layout. */
  .hamburger{display:inline-flex;align-items:center;justify-content:center;min-width:44px;min-height:44px}
  .layout{flex-direction:column;position:relative}
  .sidebar{
    position:fixed;top:0;left:0;bottom:0;
    width:min(280px,80vw);min-width:0;max-width:none;
    flex-direction:column;border-right:1px solid var(--border);
    border-bottom:none;overflow-x:hidden;overflow-y:auto;
    -webkit-overflow-scrolling:touch;
    transform:translateX(-100%);
    transition:transform .22s ease;
    z-index:100;
    box-shadow:6px 0 24px rgba(0,0,0,.35);
  }
  .layout.sidebar-open .sidebar{transform:translateX(0)}
  .layout.sidebar-open .sidebar-backdrop{display:block}
  .sidebar-logo{padding:14px 16px;font-size:14px;white-space:nowrap}
  .nav-item{padding:12px 16px;min-height:44px;display:flex;align-items:center;white-space:nowrap}
  .nav-item.active{border-left-color:var(--accent)}
  .sidebar-spacer{flex:1}
  .sidebar-bottom{padding:12px 14px;border-top:1px solid var(--border)}
  .gear-menu{
    bottom:calc(100% + 4px);top:auto;left:12px;right:auto;
  }
  /* Tight conn-bar: single-row status that won't wrap. The
     status row gets the icon-buttons squeezed to 32×32 and the
     identity chip + engine pill capped via overflow-hidden so
     the refresh + theme-toggle stay on the same row. The config
     row is hidden until the conn-state caret is tapped. */
  .conn-bar-status{padding:6px 8px;gap:4px;flex-wrap:nowrap;overflow:hidden}
  .conn-bar-status .icon-btn,.conn-bar-status .theme-toggle{
    min-width:36px;min-height:36px;padding:4px 6px;flex-shrink:0
  }
  .conn-bar-status .hamburger{min-width:40px;min-height:40px;padding:4px 8px;flex-shrink:0}
  .conn-bar-status .id-chip,.conn-bar-status .engine-pill{
    flex-shrink:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%
  }
  .id-chip-label{max-width:80px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .engine-pill span:last-child{max-width:0;overflow:hidden;display:inline-block}
  .conn-bar-config{display:none;padding:0 8px 8px 8px}
  .conn-bar-config.open{display:flex;gap:6px}
  .conn-bar-config input{min-width:0;width:100%}
  .conn-state-toggle{padding:4px 6px;border-radius:0;background:var(--surface2);flex-shrink:0;min-height:32px;max-width:160px;overflow:hidden;text-overflow:ellipsis}
  /* Sticky-nav on phones — flush with the conn-bar's bottom
     edge thanks to .content-area's padding-top:0 above. The
     sticky element owns its own 8px top padding. Horizontal
     margins extend the background into the .content-area's
     side padding so scroll bleed-through doesn't show at the
     edges either. */
  .view-sticky-nav{
    margin:0 -12px 8px -12px;
    padding:8px 12px 0 12px;
    max-height:38vh;
    background:var(--bg);
    border-bottom:1px solid var(--border);
    box-shadow:0 4px 8px -4px var(--shadow);
  }
  /* Tab bar inside the sticky nav: single horizontal scroller
     instead of wrapping. Buttons stay compact, fingers can pan. */
  .view-sticky-nav .tab-bar{
    flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;
    -webkit-overflow-scrolling:touch;
    scrollbar-width:none;
    padding-bottom:6px;margin:0 -8px;padding-left:8px;padding-right:8px;
  }
  .view-sticky-nav .tab-bar::-webkit-scrollbar{display:none}
  .view-sticky-nav .tab-bar .btn{flex-shrink:0}
  .floating-pane{
    min-width:0;min-height:0;
    left:0!important;right:0!important;
    width:100vw;max-width:100vw;
    border-radius:0;
  }
  .toast-container{
    bottom:10px;right:10px;left:10px;
    max-width:none;
  }
  .toast{min-width:0}
  /* Modals already use max-width:92vw — but their fixed inner
     padding gets cramped on phones; trim it. The security gate's
     inline-styled .gate-modal needs the same treatment so the
     checkbox + bottom buttons reach into the safe inset area. */
  .modal-card,.onboarding-card,.gate-modal{padding:18px 16px}
  /* Trim the inner-content padding so phone viewports don't
     waste 48px on horizontal gutters. Padding-top is zero so the
     sticky sub-nav sits flush with the conn-bar — no gap for
     scrolling content to peek through. The sub-nav's own
     `padding-top:8px` provides breathing room. */
  .content,.content-area{padding:0 12px 12px 12px}
  /* Tooltip arrows can overflow the screen edge; clamp width. */
  [data-tooltip]::after{max-width:88vw}
  /* Tables scroll horizontally instead of overflowing the viewport
     (Carbon DataTable responsive pattern; CSS-only, mobile-scoped so the
     desktop table layout is untouched). */
  .content table,.content-area table,.section table{
    display:block;overflow-x:auto;white-space:nowrap;max-width:100%;
    -webkit-overflow-scrolling:touch;
  }
}
";

#[cfg(test)]
mod tests {
    use super::CSS;

    /// Pins the Carbon Design System token foundation so a future edit can't
    /// silently revert the palette/scale back to the ad-hoc theme.
    #[test]
    fn carbon_token_foundation_present() {
        // Carbon g100 anchors + signature blue-60 button primary.
        for needle in [
            "#161616", // $background (g100)
            "#0f62fe", // $button-primary (blue-60)
            "#da1e28", // $button-danger-primary (red-60)
            "#42be65", // $support-success (green-40)
        ] {
            assert!(CSS.contains(needle), "Carbon color token missing: {needle}");
        }
        // Scales + typeface wired as custom properties.
        for needle in [
            "--cds-spacing-05",
            "--cds-body-01",
            "--font-sans",
            "--font-mono",
            "IBM Plex Sans",
            "IBM Plex Mono",
        ] {
            assert!(
                CSS.contains(needle),
                "Carbon scale/font token missing: {needle}"
            );
        }
        // The conn-bar must lay its controls out as a row, not stack them.
        assert!(
            CSS.contains(".conn-bar{display:flex;flex-direction:row"),
            "conn-bar should be a horizontal toolbar"
        );
    }

    /// Phase-2 component pass: Carbon square corners on containers/controls,
    /// responsive tables, and IBM Plex Mono wired for monospace surfaces.
    #[test]
    fn carbon_component_pass_present() {
        // Containers/controls are squared (Carbon). The rounded 8/6/4px radii
        // are gone; tag/pill radii (10/12/20px) are intentionally kept.
        for gone in [
            "border-radius:8px",
            "border-radius:6px",
            "border-radius:4px",
        ] {
            assert!(!CSS.contains(gone), "container radius not squared: {gone}");
        }
        // Tables go horizontally scrollable on narrow viewports.
        assert!(
            CSS.contains("overflow-x:auto"),
            "responsive table scroll missing"
        );
        // Tabs are Carbon underline tabs, not rounded pills.
        assert!(
            !CSS.contains("border-radius:20px"),
            "tab pill radius should be gone"
        );
        // Monospace surfaces route through the token, not rule-level literals.
        // (`'SF Mono'` still appears inside the `--font-mono` fallback list,
        // which is correct — we only forbid it as a `font-family:` value.)
        assert!(
            CSS.contains("font-family:var(--font-mono)"),
            "mono token unused"
        );
        assert!(
            !CSS.contains("font-family:'SF Mono'"),
            "stray 'SF Mono' font-family literal remains"
        );
        assert!(
            !CSS.contains("font-family:monospace"),
            "stray bare monospace literal remains"
        );
    }
}
