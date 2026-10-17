// brainwallet.js — makes every page of the Brainwallet section work, for all 11
// coins (Bitcoin, Bitcoin Testnet/Cash/SV/Gold, Litecoin, Dogecoin, Dash, Zcash,
// Clams, Ethereum). The mirror only captured page 1 of each coin. The full, ordered
// list of brainwallet private keys is /brainwallets.txt (one 64-hex key per line);
// page N shows keys (N-1)*45+1 .. N*45, so 19,705 keys = 438 pages.
//
// For /brainwallet/<coin>/<page>[?type=...] this takes that page's keys from the
// txt, derives the coin's addresses in the browser (legacy C/U; SegWit / Script /
// Taproot for BTC & LTC; the 0x address for ETH), renders the rows exactly like
// the site does, then lets app.js load the balances. First / Previous / Random /
// Next / Last, the address-type dropdown, Jump and Export as CSV are handled
// client-side (pushState, no reload), so they work the same on serve.py, cPanel
// and GitHub Pages.
//
// Loaded as a module BEFORE app.js: when the mirrored page-1 rows aren't the ones
// requested, they're swapped for a placeholder right away so app.js doesn't spend
// balance-API calls on rows that are about to be replaced.
import { deriveForCoin, deriveTyped, typesForCoin, exportCSV, COINS } from "./keygen-core.js";
// GitHub Pages project sites serve the mirror from a sub-path
// (https://<user>.github.io/<repo>/). Pages set window.__siteBase before these
// modules run; on a domain root (cPanel) or the local server it is empty, so every
// path below stays exactly as before.
const BASE = (window.__siteBase || "").replace(/\/$/, "");
const sitePath = (p) => BASE + p;
const localPath = () => location.pathname.slice(BASE.length) || "/";


const PER_PAGE = 45;
const DATA_URL = sitePath("/brainwallets.txt");
const TYPE_LABELS = {
  "": "Legacy (P2PKH)",
  "segwit": "SegWit (P2WPKH)",
  "segwit-p2sh": "Script (P2WPKH-in-P2SH)",
  "taproot": "Taproot (P2TR)",
};
const TYPE_BADGES = {
  "segwit": ["W", "SegWit"],
  "segwit-p2sh": ["S", "Script"],
  "taproot": ["T", "Taproot"],
};
const PLACEHOLDER = `<tr><td colspan="2" class="text-center text-secondary py-4">
  <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Loading…</td></tr>`;

let COIN = null;   // coin of this template (from its total-balance span)
let KEYS = null;   // all keys from the txt, lowercase hex
let LAST = 1;      // last page number
let cur = null;    // {page, type} currently shown

/* ---------- URL <-> state ---------- */

function templateCoin() {
  const el = document.querySelector('[class*="js-balances-"]');
  const m = el && el.className.match(/js-balances-([a-z0-9-]+)/);
  return m && m[1] in COINS ? m[1] : null;
}

// "/brainwallet/<coin>/<page>[/export][?type=..&page=..]" -> {page, type, exp}
function parseURL(url) {
  const u = new URL(url, location.href);
  const m = u.pathname.slice(BASE.length).match(/^\/brainwallet\/([a-z0-9-]+)\/([^\/]+)(\/export)?/);
  if (!m) return null;
  const q = u.searchParams;
  let page = /^\d+$/.test(m[2]) ? parseInt(m[2], 10) : 1;
  if (/^\d+$/.test(q.get("page") || "")) page = parseInt(q.get("page"), 10); // Jump form
  let type = q.get("type") || "";
  if (!typesForCoin(COIN).includes(type)) type = "";
  return { page, type, exp: !!m[3], jump: q.has("page") };
}

function clampPage(p) {
  return Math.min(Math.max(1, Math.floor(p) || 1), LAST);
}

// Link to a page, in the site's own format: /brainwallet/bitcoin/2?type=segwit&next=1
function pageURL(page, type, flag) {
  const q = [type && "type=" + type, flag && flag + "=1"].filter(Boolean).join("&");
  return sitePath(`/brainwallet/${COIN}/${page}`) + (q ? "?" + q : "");
}

const attr = (s) => s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");

/* ---------- data ---------- */

let keysPromise = null;
function loadKeys() {
  if (!keysPromise) {
    keysPromise = fetch(DATA_URL).then((r) => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.text();
    }).then((text) => {
      // One key per line; take the first 64-hex token so stray columns are ignored.
      const keys = [];
      for (const line of text.split("\n")) {
        const m = line.match(/[0-9a-fA-F]{64}/);
        if (m) keys.push(m[0].toLowerCase());
      }
      return keys;
    });
    keysPromise.catch(() => { keysPromise = null; }); // allow a retry later
  }
  return keysPromise;
}

const pageKeys = (page) => KEYS.slice((page - 1) * PER_PAGE, page * PER_PAGE);

// Resolves once app.js has finished its own page-load setup (tooltips, blockies,
// the first balance load), so our render + re-hydrate never doubles it up.
function appReady() {
  return new Promise((resolve) => {
    if (window.__ptkReady) return resolve();
    document.addEventListener("ptk:ready", () => resolve(), { once: true });
    setTimeout(resolve, 5000); // app.js missing/broken: still show the rows
  });
}

/* ---------- rows ---------- */

function addrBlock(coin, badge, addr) {
  return `<div>
    <span class="d-flex">
      <span class="me-1">${badge}</span>
      <span class="d-flex flex-wrap">
        <span class="hover me-1">
          <span class="wrap">${addr}</span>
          <span class="buttons">
            <a href="${sitePath(`/address/${coin}/${addr}`)}" title="Info" data-bs-toggle="tooltip"><i class="fas fa-info"></i></a>
            <button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="${addr}"><i class="far fa-copy"></i></button>
          </span>
        </span>
        <span class="js-balance-${coin}" data-address="${addr}"></span>
      </span>
    </span>
  </div>`;
}

function letterBadge(letter, title) {
  return `<span class="icon" title="${title}" data-bs-toggle="tooltip">${letter}</span>`;
}

function valueCell(n, type) {
  let d;
  try {
    d = type ? deriveTyped(n, COIN, type) : deriveForCoin(n, COIN);
  } catch (e) {
    return ""; // not a valid secp256k1 key (0 or >= n): show the key without addresses
  }
  if (d.eth) {
    const badge = `<span class="js-blockies" data-seed="${d.addr.toLowerCase()}" title="Ethereum" data-bs-toggle="tooltip"></span>`;
    return addrBlock("ethereum", badge, d.addr);
  }
  if (type) {
    const [letter, title] = TYPE_BADGES[type];
    return addrBlock(COIN, letterBadge(letter, title), d.addr);
  }
  return addrBlock(COIN, letterBadge("C", "Legacy (compressed)"), d.addrC) +
         addrBlock(COIN, letterBadge("U", "Legacy (uncompressed)"), d.addrU);
}

// The key cell's "Navigate" link points at the key's page in the keys directory.
function rowHTML(hex, type) {
  const n = BigInt("0x" + hex);
  const keysPage = n > 0n ? (n + BigInt(PER_PAGE - 1)) / BigInt(PER_PAGE) : 1n;
  return `<tr>
    <td>
      <span class="d-flex">
        <span class="me-1"><i class="fas fa-key" aria-hidden="true" title="Private Key" data-bs-toggle="tooltip"></i></span>
        <span class="d-flex flex-column">
          <span class="hover">
            <a href="${sitePath(`/key/${hex}`)}" class="wrap">${hex}</a>
            <span class="buttons">
              <a href="${sitePath(`/keys/${COIN}/${keysPage}`)}#${hex}" title="Navigate" data-bs-toggle="tooltip"><i class="fas fa-link"></i></a>
              <button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="${hex}"><i class="far fa-copy"></i></button>
            </span>
          </span>
          <span></span>
        </span>
      </span>
    </td>
    <td>${valueCell(n, type)}</td>
  </tr>`;
}

function renderRows(tbody, page, type) {
  tbody.innerHTML = pageKeys(page).map((h) => rowHTML(h, type)).join("");
}

/* ---------- page chrome ---------- */

function updateHeader(page) {
  for (const p of document.querySelectorAll("main p")) {
    const b = p.querySelectorAll(":scope > span.fw-bold");
    if (b.length >= 2 && /^\s*Page\b/.test(p.textContent)) {
      b[0].textContent = "#" + page;
      b[1].textContent = String(LAST);
      return;
    }
  }
}

function randomPage(page) {
  if (LAST <= 1) return 1;
  let r;
  do { r = 1 + Math.floor(Math.random() * LAST); } while (r === page);
  return r;
}

function navItem(label, icon, target, flag, type, disabled) {
  const href = disabled ? "#" : attr(pageURL(target, type, flag));
  return `<li class="page-item flex-fill${disabled ? " disabled" : ""}">
    <a class="page-link text-center" href="${href}">
      <i class="fa ${icon}" aria-hidden="true"></i> ${label}
    </a></li>`;
}

function updateNav(page, type) {
  const atFirst = page <= 1, atLast = page >= LAST;
  document.querySelectorAll("ul.pagination").forEach((ul) => {
    ul.innerHTML =
      navItem("First", "fa-fast-backward", 1, "first", type, atFirst) +
      navItem("Previous", "fa-step-backward", page - 1, "prev", type, atFirst) +
      navItem("Random", "fa-random", randomPage(page), "random", type, false) +
      navItem("Next", "fa-step-forward", page + 1, "next", type, atLast) +
      navItem("Last", "fa-fast-forward", LAST, "last", type, atLast);
  });
}

// Coin tabs keep the page number (like the site); they're normal links, since
// each coin has its own template.
function updateTabs(page) {
  document.querySelectorAll(`main ul.nav a.nav-link[href^="${BASE}/brainwallet/"]`).forEach((a) => {
    const m = a.getAttribute("href").slice(BASE.length).match(/^\/brainwallet\/([a-z0-9-]+)\//);
    if (m) a.setAttribute("href", sitePath(`/brainwallet/${m[1]}/${page}`));
  });
}

// Address-type dropdown in the table header (Bitcoin, Litecoin).
function updateTypeMenu(page, type) {
  const dd = document.querySelector("table thead .dropdown");
  if (!dd) return;
  dd.querySelectorAll("a.dropdown-item").forEach((a) => {
    const t = new URL(a.getAttribute("href"), location.href).searchParams.get("type") || "";
    a.setAttribute("href", pageURL(page, t));
    a.classList.toggle("active", t === type);
  });
  const toggle = dd.querySelector(".dropdown-toggle");
  if (toggle) toggle.textContent = TYPE_LABELS[type] || TYPE_LABELS[""];
}

function exportLink() {
  return document.querySelector(`main a[href^="${BASE}/brainwallet/"][href*="/export"]`);
}

function updateExport(page, type) {
  const a = exportLink();
  if (a) a.setAttribute("href", sitePath(`/brainwallet/${COIN}/${page}/export`) + (type ? "?type=" + type : ""));
}

function jumpForm() {
  return document.querySelector(`main form[action^="${BASE}/brainwallet/"]`);
}

function updateJump(page, type) {
  const f = jumpForm();
  if (!f) return;
  f.setAttribute("action", pageURL(page, type));
  f.querySelectorAll('input[type="hidden"]:not([name="jump"])').forEach((i) => i.remove());
  if (type) {
    const h = document.createElement("input");
    h.type = "hidden"; h.name = "type"; h.value = type;
    const num = f.querySelector('input[name="page"]');
    num ? num.before(h) : f.prepend(h);
  }
}

/* ---------- render / navigate ---------- */

function render(page, type, rows = true) {
  cur = { page, type };
  if (rows) renderRows(document.querySelector("table tbody"), page, type);
  updateHeader(page);
  updateNav(page, type);
  updateTabs(page);
  updateTypeMenu(page, type);
  updateExport(page, type);
  updateJump(page, type);
}

// Balances, tooltips and Ethereum blockies for freshly rendered rows, via the
// hooks app.js exposes (it only does this by itself once, on page load).
function hydrate() {
  try { if (typeof window.__ptkRehydrate === "function") window.__ptkRehydrate(); } catch (e) {}
  try { if (typeof window.__ptkInit === "function") window.__ptkInit(document.querySelector("table tbody")); } catch (e) {}
}

function go(url, page, type) {
  history.pushState({}, "", url);
  render(page, type);
  hydrate();
  window.scrollTo(0, 0);
}

function downloadCSV(page) {
  const blob = new Blob([exportCSV(pageKeys(page), COIN)], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `export-brainwallet-${COIN}-${page}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}

function bindEvents() {
  document.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    const a = e.target.closest && e.target.closest("a");
    if (!a) return;
    const href = a.getAttribute("href") || "";

    // First / Previous / Random / Next / Last (top and bottom bars)
    if (a.closest("ul.pagination")) {
      e.preventDefault();
      const loc = href.startsWith(BASE + "/brainwallet/") && parseURL(href);
      if (loc) go(href, clampPage(loc.page), loc.type);
      return;
    }
    // Address type (Legacy / SegWit / Script / Taproot)
    if (a.matches("table thead .dropdown-item")) {
      const loc = parseURL(href);
      if (!loc) return;
      e.preventDefault();
      go(href, clampPage(loc.page), loc.type);
      return;
    }
    // Export as CSV
    if (a === exportLink()) {
      e.preventDefault();
      downloadCSV(cur.page);
    }
  });

  const f = jumpForm();
  if (f) f.addEventListener("submit", (e) => {
    const input = f.querySelector('input[name="page"]');
    const v = parseInt(input && input.value, 10);
    if (!(v >= 1)) return; // let the browser's own validation message show
    e.preventDefault();
    const page = clampPage(v);
    input.value = "";
    input.blur();
    go(pageURL(page, cur.type), page, cur.type);
  });

  window.addEventListener("popstate", () => {
    const loc = parseURL(location.href);
    if (!loc) return;
    render(clampPage(loc.page), loc.type);
    hydrate();
  });
}

/* ---------- start ---------- */

function mirroredRowsMatch(tbody, page) {
  const shown = [...tbody.querySelectorAll(`a[href^="${BASE}/key/"]`)].map((a) => a.textContent.trim());
  const want = pageKeys(page);
  return shown.length === want.length && shown.every((h, i) => h === want[i]);
}

function init() {
  COIN = templateCoin();
  const tbody = document.querySelector("table tbody");
  if (!COIN || !tbody) return;

  // GitHub Pages can't rewrite URLs: a deep link lands on 404.html, which bounces
  // to this coin's real page-1 file and leaves the wanted path here for us.
  try {
    const goto = sessionStorage.getItem("bw_goto");
    if (goto) { sessionStorage.removeItem("bw_goto"); history.replaceState({}, "", sitePath(goto)); }
  } catch (e) { /* sessionStorage unavailable */ }

  const loc = parseURL(location.href);
  if (!loc) return;

  // The mirrored rows are page 1, legacy. Anything else: hide them right now,
  // before app.js starts loading their balances.
  const mirrored = loc.page === 1 && !loc.type;
  if (!mirrored) tbody.innerHTML = PLACEHOLDER;

  Promise.all([loadKeys(), appReady()]).then(([keys]) => {
    KEYS = keys;
    LAST = Math.max(1, Math.ceil(KEYS.length / PER_PAGE));
    const page = clampPage(loc.page);
    const fresh = !mirrored || !mirroredRowsMatch(tbody, page);
    render(page, loc.type, fresh);
    if (fresh) hydrate();
    bindEvents();

    // Settle the address bar on the page actually shown (out-of-range numbers,
    // Jump-form "?page=N", "/export" deep links).
    const pathPage = (localPath().match(/^\/brainwallet\/[a-z0-9-]+\/(\d+)/) || [])[1];
    if (loc.exp || loc.jump || String(page) !== pathPage) {
      history.replaceState({}, "", pageURL(page, loc.type));
    }
    if (loc.exp) downloadCSV(page);
  }).catch(() => {
    tbody.innerHTML = `<tr><td colspan="2" class="text-center text-danger py-4">
      Could not load the brainwallet key list (${DATA_URL}). Please refresh the page.</td></tr>`;
  });
}

init();
