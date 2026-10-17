// keygen.js — makes the "keys directory" pagination actually work on a static
// host, for every coin (Bitcoin, Bitcoin Cash/SV/Gold/Testnet, Litecoin,
// Dogecoin, Dash, Zcash, Clams, Ethereum). The original site generated each page
// server-side; our mirror only captured page 1 of each coin. This reads the coin
// and page number from the URL and regenerates the 45 keys for that page in the
// browser (same secp256k1 math + per-coin address scheme the site uses), so
// First / Previous / Random / Next / Last and the progress bar all work.
//
// Navigation is done client-side (pushState + in-place re-render), so the buttons
// work identically on local serve.py, cPanel and GitHub Pages — no document reload
// is needed, and no deep-link file has to exist on the host for a click to land.
//
// Loaded as a module BEFORE app.js, so app.js hydrates balances on fresh rows for
// direct page loads.
import { deriveForCoin, deriveTyped, typesForCoin, COINS } from "./keygen-core.js";
// GitHub Pages project sites serve the mirror from a sub-path
// (https://<user>.github.io/<repo>/). Pages set window.__siteBase before these
// modules run; on a domain root (cPanel) or the local server it is empty, so every
// path below stays exactly as before.
const BASE = (window.__siteBase || "").replace(/\/$/, "");
const sitePath = (p) => BASE + p;
const localPath = () => location.pathname.slice(BASE.length) || "/";


const PER_PAGE = 45n;
// secp256k1 group order; valid private keys are 1 .. n-1
const CURVE_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
const MAX_KEY = CURVE_N - 1n;
// ceil(MAX_KEY / 45) — matches the site's "Last" page number exactly
const LAST_PAGE = 2573157538607026564968244111304175730063056983979442319613448069811514699875n;

function randomPage() {
  const buf = new Uint8Array(40); // > bits of LAST_PAGE, keeps modulo bias negligible
  crypto.getRandomValues(buf);
  let r = 0n;
  for (const b of buf) r = (r << 8n) | BigInt(b);
  return (r % LAST_PAGE) + 1n;
}

function clampPage(p) {
  if (p < 1n) return 1n;
  if (p > LAST_PAGE) return LAST_PAGE;
  return p;
}

// Parse "/keys/<coin>/<page>[?type=..]" from the current URL -> {coin, page,
// random, type} or null. type is only kept when that coin supports it
// (Bitcoin: segwit / segwit-p2sh / taproot, Litecoin: segwit / segwit-p2sh).
function parseLoc() {
  const m = localPath().match(/\/keys\/([a-z0-9-]+)\/([^\/?#]+)/);
  if (!m || !(m[1] in COINS)) return null;
  const seg = decodeURIComponent(m[2]);
  const numeric = /^\d+$/.test(seg);
  const type = new URLSearchParams(location.search).get("type") || "";
  return {
    coin: m[1],
    page: numeric ? clampPage(BigInt(seg)) : randomPage(),
    random: !numeric,
    type: typesForCoin(m[1]).includes(type) ? type : "",
  };
}

// "/keys/<coin>/<page>?type=.."
function keyURL(coin, page, type) {
  return sitePath(`/keys/${coin}/${page}`) + (type ? "?type=" + type : "");
}

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

function keysForPage(page) {
  const start = (page - 1n) * PER_PAGE + 1n;
  let end = page * PER_PAGE;
  if (end > MAX_KEY) end = MAX_KEY;
  const out = [];
  for (let k = start; k <= end; k++) out.push(k);
  return out;
}

// One address block in the value cell. base58/cashaddr coins show a C/U letter
// badge; Ethereum shows a blockies swatch seeded with the lowercased address.
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

function valueCell(coin, d, type) {
  if (d.eth) {
    const badge = `<span class="js-blockies" data-seed="${d.addr.toLowerCase()}" title="Ethereum" data-bs-toggle="tooltip"></span>`;
    return addrBlock("ethereum", badge, d.addr);
  }
  if (type) {
    const [letter, title] = TYPE_BADGES[type];
    return addrBlock(coin, letterBadge(letter, title), deriveTyped(BigInt("0x" + d.hex), coin, type).addr);
  }
  return addrBlock(coin, letterBadge("C", "Legacy (compressed)"), d.addrC) +
         addrBlock(coin, letterBadge("U", "Legacy (uncompressed)"), d.addrU);
}

function rowHTML(coin, d, page, type) {
  const h = d.hex;
  return `<tr id="${h}">
    <td>
      <span class="d-flex">
        <span class="me-1"><i class="fas fa-key" aria-hidden="true" title="Private Key" data-bs-toggle="tooltip"></i></span>
        <span class="d-flex flex-column">
          <span class="hover">
            <a href="${sitePath(`/key/${h}`)}" class="wrap">${h}</a>
            <span class="buttons">
              <a href="${keyURL(coin, page, type)}#${h}" title="Navigate" data-bs-toggle="tooltip"><i class="fas fa-link"></i></a>
              <button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="${h}"><i class="far fa-copy"></i></button>
            </span>
          </span>
          <span></span>
        </span>
      </span>
    </td>
    <td>${valueCell(coin, d, type)}</td>
  </tr>`;
}

function renderRows(coin, tbody, page, type) {
  tbody.innerHTML = keysForPage(page).map((k) => rowHTML(coin, deriveForCoin(k, coin), page, type)).join("");
}

function fmtPage(page) {
  if (page <= 999999999n) return "#" + page.toString();
  const s = page.toString();
  return `#${s[0]}.${s.slice(1, 4)}×10^${s.length - 1}…${s.slice(-3)}`;
}

function updateHeader(page) {
  const spans = document.querySelectorAll('span.fw-bold[data-bs-toggle="tooltip"]');
  if (spans[0]) {
    spans[0].setAttribute("title", page.toString());
    spans[0].textContent = fmtPage(page);
  }
}

function navItem(coin, label, icon, target, disabled, type) {
  const href = disabled ? "#" : keyURL(coin, target, type);
  return `<li class="page-item flex-fill${disabled ? " disabled" : ""}">
    <a class="page-link text-center" href="${href}">
      <i class="fa ${icon}" aria-hidden="true"></i> ${label}
    </a></li>`;
}

function updateNav(coin, page, type) {
  const atFirst = page <= 1n;
  const atLast = page >= LAST_PAGE;
  const html =
    navItem(coin, "First", "fa-fast-backward", 1n, atFirst, type) +
    navItem(coin, "Previous", "fa-step-backward", page - 1n, atFirst, type) +
    navItem(coin, "Random", "fa-random", randomPage(), false, type) +
    navItem(coin, "Next", "fa-step-forward", page + 1n, atLast, type) +
    navItem(coin, "Last", "fa-fast-forward", LAST_PAGE, atLast, type);
  document.querySelectorAll("ul.pagination").forEach((ul) => { ul.innerHTML = html; });
}

// Position in the whole key space (page / last page) as a 0..100 number. Done in
// BigInt first — page numbers are up to 75 digits — then narrowed to a float only
// for display, so there's no precision loss.
function pct(page) {
  if (page >= LAST_PAGE) return 100;
  const bp = (page * 1000000n) / LAST_PAGE; // 0 .. 1_000_000 (0.0001% units)
  return Number(bp) / 10000;
}

function fmtPct(p) {
  if (p <= 0) return "0%";
  if (p >= 100) return "100%";
  return parseFloat(p.toFixed(2)) + "%"; // 65.47%, 50%, 0.12%
}

// The thin blue line under the pagination: a Bootstrap progress bar showing how
// far through the key space this page is. The mirror baked it at 0% and nothing
// ever updated it; drive it from the current page here.
function updateProgress(page) {
  const p = pct(page);
  const text = fmtPct(p);
  document.querySelectorAll("div.progress").forEach((el) => {
    const bar = el.querySelector(".progress-bar");
    if (!bar) return;
    el.setAttribute("aria-valuenow", String(p));
    el.setAttribute("title", text);
    el.setAttribute("data-bs-original-title", text); // if the tooltip is already live
    bar.style.width = p + "%";
  });
}

// Address-type dropdown in the table header (Bitcoin, Litecoin): keep the page
// number in its links and mark the selected type.
function updateTypeMenu(coin, page, type) {
  const dd = document.querySelector("table thead .dropdown");
  if (!dd) return;
  const types = typesForCoin(coin);
  dd.querySelectorAll("a.dropdown-item").forEach((a) => {
    const t = new URL(a.getAttribute("href"), location.href).searchParams.get("type") || "";
    a.setAttribute("href", keyURL(coin, page, types.includes(t) ? t : ""));
    a.classList.toggle("active", t === type);
  });
  const toggle = dd.querySelector(".dropdown-toggle");
  if (toggle) toggle.textContent = TYPE_LABELS[type] || TYPE_LABELS[""];
}

// Re-render everything for one coin/page (rows + header + nav + progress bar).
function render(coin, page, type = "") {
  const tbody = document.querySelector("table tbody");
  if (tbody) renderRows(coin, tbody, page, type);
  updateHeader(page);
  updateNav(coin, page, type);
  updateProgress(page);
  updateTypeMenu(coin, page, type);
}

// Balances are filled in by the site's own script (app.js), which runs its
// per-coin loaders once on page load. After a client-side navigation there's no
// page load, so the freshly generated rows start empty. app.js exposes its
// hydrator as window.__ptkRehydrate; call it so every page loads balances exactly
// like the first page does. (On the initial load app.js handles this itself.)
function rehydrateBalances() {
  try {
    if (typeof window.__ptkRehydrate === "function") window.__ptkRehydrate();
  } catch (e) { /* app.js not present / not ready — rows still render fine */ }
  // Tooltips + Ethereum blockies for the new rows (app.js only does these on load).
  try {
    if (typeof window.__ptkInit === "function") window.__ptkInit(document.querySelector("table tbody"));
  } catch (e) {}
}

// Navigate client-side: update the URL, then re-render in place. No document
// reload, so this behaves the same on serve.py, cPanel and GitHub Pages.
function go(coin, page, type = "") {
  history.pushState({}, "", keyURL(coin, page, type));
  render(coin, page, type);
  rehydrateBalances();
  window.scrollTo(0, 0);
}

let navBound = false;
function bindNav() {
  if (navBound) return;
  navBound = true;
  // Address type (Legacy / SegWit / Script / Taproot) in the table header.
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("table thead .dropdown-item");
    if (!a) return;
    const href = a.getAttribute("href") || "";
    const m = href.match(/\/keys\/([a-z0-9-]+)\/(\d+)/);
    if (!m || !(m[1] in COINS)) return;
    e.preventDefault();
    const t = new URL(href, location.href).searchParams.get("type") || "";
    go(m[1], clampPage(BigInt(m[2])), typesForCoin(m[1]).includes(t) ? t : "");
  });
  document.addEventListener("click", (e) => {
    const a = e.target.closest && e.target.closest("a.page-link");
    if (!a || !a.closest("ul.pagination")) return;
    const href = a.getAttribute("href") || "";
    if (!href.startsWith(BASE + "/keys/")) { e.preventDefault(); return; } // disabled "#"
    const m = href.match(/\/keys\/([a-z0-9-]+)\/([^\/?#]+)/);
    if (!m || !(m[1] in COINS)) return;
    e.preventDefault();
    const page = /^\d+$/.test(m[2]) ? clampPage(BigInt(m[2])) : randomPage();
    const cur = parseLoc();
    go(m[1], page, cur && cur.coin === m[1] ? cur.type : "");
  });
  window.addEventListener("popstate", () => {
    const loc = parseLoc();
    if (loc) { render(loc.coin, loc.page, loc.type); rehydrateBalances(); }
  });
}

// This script is a module (deferred): the DOM is already parsed when it runs.
function init() {
  // On GitHub's 404.html the guard may be bouncing to another template right now;
  // leave its stashed path for the page we're bouncing to.
  if (window.__kgBounce) return;

  // GitHub Pages can't rewrite, so a deep link to page>1 of a non-Bitcoin coin
  // hits 404.html, which bounces to that coin's real page-1 file and leaves the
  // wanted path here for us to restore (gives correct per-coin chrome).
  try {
    const goto = sessionStorage.getItem("kg_goto");
    if (goto) { sessionStorage.removeItem("kg_goto"); history.replaceState({}, "", sitePath(goto)); }
  } catch (e) { /* sessionStorage may be unavailable */ }

  const loc = parseLoc();
  if (loc === null) return;                        // not a keys page we handle
  const tbody = document.querySelector("table tbody");
  if (!tbody) return;

  bindNav();

  const first = tbody.querySelector("tr[id]");
  const start = (loc.page - 1n) * PER_PAGE + 1n;
  const domStart = first && /^[0-9a-f]{64}$/.test(first.id) ? BigInt("0x" + first.id) : null;

  // Keep the mirrored page-1 rows (their badges + app.js balance hydration) when
  // they already match the requested page; otherwise regenerate for this coin/page.
  if (domStart !== start || loc.type) renderRows(loc.coin, tbody, loc.page, loc.type);

  updateHeader(loc.page);
  updateNav(loc.coin, loc.page, loc.type);
  updateProgress(loc.page);
  updateTypeMenu(loc.coin, loc.page, loc.type);

  // Stabilise non-numeric URLs (e.g. /keys/litecoin/random) so a refresh stays put.
  if (loc.random) history.replaceState({}, "", keyURL(loc.coin, loc.page, loc.type) + location.hash);
}

init();
