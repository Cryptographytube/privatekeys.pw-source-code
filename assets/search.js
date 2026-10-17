// search.js — makes the Search section and the site-wide Quick Search work
// entirely in the browser (no backend, no reCAPTCHA).
//
//  /search/<coin>   the form captured from privatekeys.pw: each line is turned
//                   into one private key (Auto / HEX / Decimal / WIF / Mini /
//                   Extended / BIP39 / BIP39 (Electrum) / Passphrase / Electrum
//                   legacy), then rows are rendered below the form exactly like
//                   the site's results table, with balances loaded by app.js.
//  /quick-search    results for the navbar search box: every interpretation of
//                   the query (HEX, binary, WIF, HD wallet, brainwallet ...).
//
// Both share the row markup of brainwallet.js, and the derivations come from
// keygen-core.js, so addresses match the rest of the mirror byte-for-byte.
import { deriveForCoin, deriveTyped, typesForCoin } from "./keygen-core.js";
import { searchLine, quickSearch, parsePath, FORMATS, MAX_KEYS } from "./search-core.js";
// GitHub Pages project sites serve the mirror from a sub-path
// (https://<user>.github.io/<repo>/). Pages set window.__siteBase before these
// modules run; on a domain root (cPanel) or the local server it is empty, so every
// path below stays exactly as before.
const BASE = (window.__siteBase || "").replace(/\/$/, "");
const sitePath = (p) => BASE + p;
const localPath = () => location.pathname.slice(BASE.length) || "/";


const COIN_LABELS = {
  "bitcoin": "Bitcoin",
  "bitcoin-testnet": "Bitcoin Testnet",
  "bitcoin-cash": "Bitcoin Cash",
  "bitcoin-sv": "Bitcoin SV",
  "bitcoin-gold": "Bitcoin Gold",
  "litecoin": "Litecoin",
  "dogecoin": "Dogecoin",
  "dash": "Dash",
  "zcash": "Zcash",
  "clams": "Clams",
  "ethereum": "Ethereum",
};
const COINS = Object.keys(COIN_LABELS);
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
const PER_PAGE = 45;

const attr = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/* ---------- app.js hand-off ---------- */

function appReady() {
  return new Promise((resolve) => {
    if (window.__ptkReady) return resolve();
    document.addEventListener("ptk:ready", () => resolve(), { once: true });
    setTimeout(resolve, 5000);
  });
}
function hydrate(root) {
  try { if (typeof window.__ptkRehydrate === "function") window.__ptkRehydrate(); } catch (e) {}
  try { if (typeof window.__ptkInit === "function") window.__ptkInit(root || document); } catch (e) {}
}

/* ---------- rows (same markup as brainwallet.js / the reference) ---------- */

function addrBlock(coin, badge, addr) {
  return `<div>
    <span class="d-flex">
      <span class="me-1">${badge}</span>
      <span class="d-flex flex-wrap">
        <span class="hover me-1">
          <span class="wrap">${attr(addr)}</span>
          <span class="buttons">
            <a href="${sitePath(`/address/${coin}/${attr(addr)}`)}" title="Info" data-bs-toggle="tooltip"><i class="fas fa-info"></i></a>
            <button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="${attr(addr)}"><i class="far fa-copy"></i></button>
          </span>
        </span>
        <span class="js-balance-${coin}" data-address="${attr(addr)}"></span>
      </span>
    </span>
  </div>`;
}

function letterBadge(letter, title) {
  return `<span class="icon" title="${title}" data-bs-toggle="tooltip">${letter}</span>`;
}

function valueCell(n, coin, type) {
  let d;
  try {
    d = type ? deriveTyped(n, coin, type) : deriveForCoin(n, coin);
  } catch (e) {
    return "";
  }
  if (d.eth) {
    const badge = `<span class="js-blockies" data-seed="${d.addr.toLowerCase()}" title="Ethereum" data-bs-toggle="tooltip"></span>`;
    return addrBlock("ethereum", badge, d.addr);
  }
  if (type) {
    const [letter, title] = TYPE_BADGES[type];
    return addrBlock(coin, letterBadge(letter, title), d.addr);
  }
  return addrBlock(coin, letterBadge("C", "Legacy (compressed)"), d.addrC) +
         addrBlock(coin, letterBadge("U", "Legacy (uncompressed)"), d.addrU);
}

function rowHTML(hex, n, coin, type, label) {
  const keysPage = n > 0n ? (n + BigInt(PER_PAGE - 1)) / BigInt(PER_PAGE) : 1n;
  return `<tr>
    <td>${label ? attr(label) + ": " : ""}<span class="d-flex">
        <span class="me-1"><i class="fas fa-key" aria-hidden="true" title="Private Key" data-bs-toggle="tooltip"></i></span>
        <span class="d-flex flex-column">
          <span class="hover">
            <a href="${sitePath(`/key/${hex}`)}" class="wrap">${hex}</a>
            <span class="buttons">
              <a href="${sitePath(`/keys/${coin}/${keysPage}`)}#${hex}" title="Navigate" data-bs-toggle="tooltip"><i class="fas fa-link"></i></a>
              <button class="copy" title="Copy" data-bs-toggle="tooltip" data-clipboard-text="${hex}"><i class="far fa-copy"></i></button>
            </span>
          </span>
          <span></span>
        </span>
      </span></td>
    <td>${valueCell(n, coin, type)}</td>
  </tr>`;
}

// <div class="d-flex ..."> Bitcoin Address [dropdown] </div>
function headerCell(coin, type, linkFor) {
  const types = typesForCoin(coin);
  const label = `${COIN_LABELS[coin] || "Bitcoin"} Address`;
  if (!types.length) return `<div class="d-flex align-items-center gap-2">${label}</div>`;
  const items = [""].concat(types).map((t) => `<li>
                        <a class="dropdown-item ${t === type ? "active" : ""}" href="${attr(linkFor(t))}">
                            ${TYPE_LABELS[t]}
                        </a>
                    </li>`).join("\n");
  return `<div class="d-flex align-items-center gap-2">
    ${label}
            <div class="dropdown">
            <a class="dropdown-toggle fw-normal text-decoration-none" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                ${TYPE_LABELS[type] || TYPE_LABELS[""]}
            </a>
            <ul class="dropdown-menu">
                ${items}
            </ul>
        </div>
    </div>`;
}

function resultsHTML(coin, type, rows, linkFor) {
  return `
                <div class="py-2" style="display: none">
    Total balance on the page: <span class="js-balances-${coin}"></span>
</div>

                <div class="table-adaptive">
    <table class="table table-borderless table-striped table-hover">
        <thead>
        <tr>
            <th>Type / Private Key (HEX)</th>
            <th>${headerCell(coin, type, linkFor)}</th>
        </tr>
        </thead>
        <tbody>
${rows.map((r) => rowHTML(r.hex, r.n, coin, type, r.label)).join("\n")}
                </tbody>
    </table>
</div>`;
}

/* ---------- /search/<coin> ---------- */

function searchPage() {
  const form = document.querySelector("main form");
  if (!form) return;
  const coin = (localPath().match(/^\/search\/([a-z0-9-]+)/) || [])[1] || "bitcoin";
  const coinName = coin in COIN_LABELS ? coin : "bitcoin";

  const textarea = form.querySelector('textarea[name="query"]');
  const formatSel = form.querySelector('select[name="format"]');
  const pathInput = form.querySelector('input[name="path"]');
  const typeSel = form.querySelector('select[name="address_type"]');
  const publicBox = form.querySelector('input[name="public"]');
  const errors = [...form.querySelectorAll(".mb-3")]
    .map((b) => b.querySelector(":scope > .text-danger"))
    .filter(Boolean);

  const errBox = (i) => errors[i] || errors[0] || null;
  const setErrors = (msgs) => errors.forEach((d, i) => { d.textContent = msgs[i] || ""; });
  const clean = (s) => String(s || "").trim();

  let box = document.getElementById("search-results");
  if (!box) {
    box = document.createElement("div");
    box.id = "search-results";
    form.closest(".card").after(box);
  }
  const results = box;

  function shareURL(fields) {
    const q = new URLSearchParams();
    q.set("query", fields.query);
    if (fields.format && fields.format !== "auto") q.set("format", fields.format);
    if (fields.path) q.set("path", fields.path);
    if (fields.type) q.set("address_type", fields.type);
    if (publicBox && publicBox.checked) q.set("public", "1");
    return sitePath(`/search/${coinName}?`) + q.toString();
  }

  function render(rows, invalid, fields) {
    const total = rows.length;
    const m = fields.queries;
    const lines = [];
    if (m === 1) {
      lines.push(`<p>
                    <strong>${total}</strong> private ${total === 1 ? "key" : "keys"}
                    found for query "<strong>${attr(fields.query.split("\n").filter((l) => l.trim())[0] || "")}</strong>":
                </p>`);
    } else {
      lines.push(`<p>
                    <strong>${total}</strong> private ${total === 1 ? "key" : "keys"}
                    found for <strong>${m}</strong> queries:
                </p>`);
    }
    if (invalid.length) {
      lines.push(`<div class="alert alert-warning"><strong>${invalid.length}</strong>
        ${invalid.length === 1 ? "line is" : "lines are"} not a valid private key and ${invalid.length === 1 ? "was" : "were"} skipped:
        <code>${invalid.map(attr).join("</code>, <code>")}</code></div>`);
    }
    if (publicBox && publicBox.checked) {
      const url = location.origin + shareURL(fields);
      lines.push(`<div class="mb-3">
        <label class="form-label">Share link:</label>
        <input class="form-control font-monospace" type="text" readonly value="${attr(url)}" onclick="this.select()">
      </div>`);
    }
    results.innerHTML = lines.join("\n") +
      resultsHTML(coinName, fields.type, rows,
        (t) => shareURL({ ...fields, type: t, query: fields.query }));
    hydrate(results);

    // header dropdown: switch address type in place
    results.querySelectorAll("table thead .dropdown-item").forEach((a) => {
      a.addEventListener("click", (e) => {
        e.preventDefault();
        const url = new URL(a.getAttribute("href"), location.href);
        const t = url.searchParams.get("address_type") || "";
        if (typeSel) typeSel.value = t;
        run();
      });
    });
  }

  function run() {
    const raw = textarea ? textarea.value : "";
    const format = formatSel ? formatSel.value : "auto";
    const path = pathInput ? clean(pathInput.value) : "";
    const type = typeSel && typesForCoin(coinName).includes(typeSel.value) ? typeSel.value : "";
    const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);

    setErrors([]);
    if (!lines.length) {
      setErrors(["The query field is required."]);
      results.innerHTML = "";
      return;
    }
    if (lines.length > MAX_KEYS) {
      setErrors([`Too many private keys. A maximum of ${MAX_KEYS} private keys per request is allowed.`]);
      results.innerHTML = "";
      return;
    }
    if (path && !parsePath(path)) {
      setErrors(["", "", "The path format is invalid."]);
      results.innerHTML = "";
      return;
    }
    if (!FORMATS.includes(format)) {
      setErrors(["The selected private key format is invalid."]);
      results.innerHTML = "";
      return;
    }

    const rows = [], invalid = [];
    for (const line of lines) {
      let r = null;
      try { r = searchLine(line, format, { coin: coinName, type, path }); } catch (e) { r = null; }
      if (r) rows.push(r); else invalid.push(line);
    }

    const fields = { query: lines.join("\n"), format, path, type, queries: lines.length };
    render(rows, invalid, fields);

    // Remember the search in the address bar only when it may be shared.
    if (publicBox && publicBox.checked) {
      history.replaceState({}, "", shareURL(fields));
    } else {
      history.replaceState({}, "", sitePath(`/search/${coinName}`));
    }
    return fields;
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    run();
  });

  // A shared /search/<coin>?query=... link fills the form and searches at once.
  const q = new URLSearchParams(location.search);
  if (q.has("query")) {
    if (textarea) textarea.value = q.get("query") || "";
    if (formatSel && FORMATS.includes(q.get("format") || "")) formatSel.value = q.get("format");
    if (pathInput) pathInput.value = q.get("path") || "";
    if (typeSel && typesForCoin(coinName).includes(q.get("address_type") || "")) typeSel.value = q.get("address_type");
    if (publicBox) publicBox.checked = q.get("public") === "1";
    appReady().then(run);
  }
}

/* ---------- /quick-search ---------- */

function quickPage() {
  const main = document.querySelector("main .container");
  if (!main) return;
  const q = new URLSearchParams(location.search);
  const raw = q.get("query") || "";
  const network = q.get("network") in COIN_LABELS ? q.get("network") : "bitcoin";
  let type = q.get("type") || "";
  if (!typesForCoin(network).includes(type)) type = "";

  const url = (net, t, query) => {
    const p = new URLSearchParams();
    p.set("network", net);
    p.set("query", query);
    if (t) p.set("type", t);
    return sitePath("/quick-search?") + p.toString();
  };

  let host = document.getElementById("quick-results");
  if (!host) {
    host = document.createElement("div");
    host.id = "quick-results";
    main.appendChild(host);
  }

  const tabs = `<ul class="nav nav-underline mb-3">` + COINS.map((c) => `<li class="nav-item">
            <a class="nav-link ${c === network ? " active " : ""}" href="${attr(url(c, type, raw))}">
                ${COIN_LABELS[c]}
            </a>
        </li>`).join("\n") + `</ul>`;

  if (!raw) {
    host.innerHTML = tabs + `<p>Nothing to search for.</p>`;
    return;
  }

  const rows = quickSearch(raw, network);
  const count = rows.length;
  host.innerHTML = tabs + `
                <p>
                    <strong>${count}</strong> private ${count === 1 ? "key" : "keys"}
                    found for query "<strong>${attr(raw)}</strong>":
                </p>` +
    resultsHTML(network, type, rows, (t) => url(network, t, raw));

  hydrate(host);

  host.querySelectorAll("table thead .dropdown-item").forEach((a) => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      location.href = a.getAttribute("href");
    });
  });
}

/* ---------- start ---------- */

if (/^\/search\//.test(localPath())) searchPage();
else if (/^\/quick-search\/?$/.test(localPath())) quickPage();
