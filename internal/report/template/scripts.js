const html = document.documentElement;
function applyTheme(t) {
  html.setAttribute("data-theme", t);
  document.getElementById("iconSun").style.display = t === "dark" ? "none" : "block";
  document.getElementById("iconMoon").style.display = t === "dark" ? "block" : "none";
  localStorage.setItem("zt-theme", t);
}
document.getElementById("themeToggle").addEventListener("click", () => {
  applyTheme(html.getAttribute("data-theme") === "dark" ? "light" : "dark");
});
const saved = localStorage.getItem("zt-theme");
if (saved) applyTheme(saved);
else if (window.matchMedia("(prefers-color-scheme: light)").matches) applyTheme("light");

function toggleCard(header) {
  header.closest(".finding-card").classList.toggle("expanded");
}

function switchTab(btn, tabName) {
  const body = btn.closest(".finding-body");
  body.querySelectorAll(".ftab").forEach((t) => t.classList.remove("active"));
  body.querySelectorAll(".ftab-panel").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  body.querySelector(`.ftab-panel[data-tab="${tabName}"]`).classList.add("active");
}

const sevOrder = { BLOCK: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SUPPRESSED: 4 };
let activeSev = "all";
let activeFile = "all";
let activePath = "all";
let currentPage = 1;
let perPage = 25;

function renderFindings() {
  const search = document.getElementById("searchInput").value.toLowerCase();
  const allCards = [...document.querySelectorAll(".finding-card")];
  const list = document.getElementById("findingsList");

  let visible = allCards.filter((c) => {
    const sevOk = activeSev === "all" || c.dataset.sev === activeSev;
    const fileOk = activeFile === "all" || c.dataset.file === activeFile;
    const pathOk = activePath === "all" || c.dataset.path === activePath;
    const srchOk = !search || c.textContent.toLowerCase().includes(search);
    return sevOk && fileOk && pathOk && srchOk;
  });

  const sortBy = document.getElementById("sortSelect").value;
  visible.sort((a, b) => {
    if (sortBy === "severity") return (sevOrder[a.dataset.sev] ?? 9) - (sevOrder[b.dataset.sev] ?? 9);
    if (sortBy === "confidence") return parseFloat(b.dataset.conf || 0) - parseFloat(a.dataset.conf || 0);
    if (sortBy === "file") return (a.dataset.file || "").localeCompare(b.dataset.file || "");
    return 0;
  });

  const total = visible.length;
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  if (currentPage > totalPages) currentPage = totalPages;
  const start = (currentPage - 1) * perPage;
  const end = Math.min(start + perPage, total);
  const pageCards = visible.slice(start, end);

  allCards.forEach((c) => { c.style.display = "none"; });
  pageCards.forEach((c) => { list.appendChild(c); c.style.display = ""; });

  const countEl = document.getElementById("findingsCount");
  if (total === 0) {
    countEl.innerHTML = "<strong>0</strong> findings";
  } else {
    countEl.innerHTML = `Showing <strong>${start + 1}&ndash;${end}</strong> of <strong>${total}</strong> findings`;
  }

  updatePagination(currentPage, totalPages);
}

function updatePagination(current, total) {
  const showNav = total > 1;
  document.getElementById("prevPage").style.display = showNav ? "" : "none";
  document.getElementById("nextPage").style.display = showNav ? "" : "none";
  document.getElementById("pageNumbers").style.display = showNav ? "" : "none";
  document.getElementById("prevPage").disabled = current <= 1;
  document.getElementById("nextPage").disabled = current >= total;

  let html = "";
  const maxVisible = 5;
  let s = Math.max(1, current - Math.floor(maxVisible / 2));
  let e = Math.min(total, s + maxVisible - 1);
  if (e - s + 1 < maxVisible) s = Math.max(1, e - maxVisible + 1);
  if (s > 1) html += `<button class="page-btn" data-page="1">1</button>`;
  if (s > 2) html += '<span class="page-ellipsis">&hellip;</span>';
  for (let i = s; i <= e; i++) {
    html += `<button class="page-btn${i === current ? " active" : ""}" data-page="${i}">${i}</button>`;
  }
  if (e < total - 1) html += '<span class="page-ellipsis">&hellip;</span>';
  if (e < total) html += `<button class="page-btn" data-page="${total}">${total}</button>`;

  document.getElementById("pageNumbers").innerHTML = html;
  document.querySelectorAll("#pageNumbers .page-btn").forEach((btn) => {
    btn.addEventListener("click", () => { currentPage = parseInt(btn.dataset.page); renderFindings(); });
  });
}

document.getElementById("prevPage").addEventListener("click", () => {
  if (currentPage > 1) { currentPage--; renderFindings(); }
});
document.getElementById("nextPage").addEventListener("click", () => {
  const total = document.querySelectorAll(".finding-card").length;
  if (currentPage < Math.ceil(total / perPage)) { currentPage++; renderFindings(); }
});
document.getElementById("perPageSelect").addEventListener("change", function () {
  perPage = parseInt(this.value); currentPage = 1; renderFindings();
});

let fileViewMode = "flat";

document.querySelectorAll(".file-view-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    const view = btn.dataset.view;
    if (view === fileViewMode) return;
    fileViewMode = view;
    document.querySelectorAll(".file-view-btn").forEach(b => b.classList.toggle("active", b.dataset.view === view));
    if (fileViewMode === "tree") renderTreeView();
    else renderFlatView();
  });
});

function renderFlatView() {
  const section = document.querySelector(".sidebar-files");
  section.querySelectorAll(".file-item").forEach(el => el.style.display = "");
  section.querySelectorAll(".file-tree").forEach(el => el.remove());
}

function buildFileTree() {
  const items = [...document.querySelectorAll(".file-item[data-file]")].filter(el => el.dataset.file !== "all");
  const tree = {};
  items.forEach(item => {
    const parts = item.dataset.file.split("/");
    let node = tree;
    parts.forEach((part, i) => {
      if (!node[part]) {
        node[part] = i === parts.length - 1
          ? { type: "file", item }
          : { type: "dir", children: {} };
      }
      if (node[part].type === "dir") node = node[part].children;
    });
  });
  return tree;
}

function renderTreeView() {
  const section = document.querySelector(".sidebar-files");
  section.querySelectorAll(".file-item[data-file]").forEach(el => {
    if (el.dataset.file !== "all") el.style.display = "none";
  });
  section.querySelectorAll(".file-tree").forEach(el => el.remove());

  const tree = buildFileTree();
  const container = document.createElement("div");
  container.className = "file-tree";
  container.appendChild(buildTreeNodes(tree));
  section.appendChild(container);
}

function buildTreeNodes(node) {
  const frag = document.createDocumentFragment();
  const entries = Object.entries(node).sort((a, b) => {
    const aDir = a[1].type === "dir";
    const bDir = b[1].type === "dir";
    return aDir !== bDir ? (aDir ? -1 : 1) : a[0].localeCompare(b[0]);
  });
  entries.forEach(([name, child]) => {
    if (child.type === "dir") {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.className = "tree-folder";
      summary.innerHTML = `<span class="folder-indicator"></span><span class="tree-name">${name}</span>`;
      details.appendChild(summary);
      const childWrap = document.createElement("div");
      childWrap.className = "tree-children";
      childWrap.appendChild(buildTreeNodes(child.children));
      details.appendChild(childWrap);
      frag.appendChild(details);
    } else {
      const div = document.createElement("div");
      div.className = "tree-file";
      div.dataset.file = child.item.dataset.file;
      const badge = child.item.querySelector(".file-badge");
      const badgeHtml = badge ? badge.outerHTML : "";
      div.innerHTML = `<span class="tree-name">${name}</span>${badgeHtml}`;
      div.addEventListener("click", (e) => {
        e.stopPropagation();
        setFileFilter(child.item.dataset.file);
        child.item.classList.add("active");
        document.querySelectorAll(".file-tree .tree-file.active").forEach(el => el.classList.remove("active"));
        div.classList.add("active");
        renderFindings();
      });
      frag.appendChild(div);
    }
  });
  return frag;
}

function resetAllFilters() {
  activeSev = "all"; activeFile = "all"; activePath = "all"; currentPage = 1;
  document.querySelectorAll(".summary-cell").forEach((c) => c.classList.toggle("active", c.dataset.filter === "all"));
  document.querySelectorAll(".filter-btn[data-sev]").forEach((b) => b.classList.toggle("active", b.dataset.sev === "all"));
  document.querySelectorAll(".file-item[data-file]").forEach((i) => i.classList.toggle("active", i.dataset.file === "all"));
  document.querySelectorAll(".filter-btn[data-path]").forEach((b) => b.classList.toggle("active", b.dataset.path === "all"));
  renderFindings();
}

// Each filter dimension resets the other two so clicks never silently stack.
function setSevFilter(sev) {
  activeSev = sev; activeFile = "all"; activePath = "all"; currentPage = 1;
  document.querySelectorAll(".summary-cell").forEach((c) => c.classList.toggle("active", c.dataset.filter === sev));
  document.querySelectorAll(".filter-btn[data-sev]").forEach((b) => b.classList.toggle("active", b.dataset.sev === sev));
  document.querySelectorAll(".file-item[data-file]").forEach((i) => i.classList.toggle("active", i.dataset.file === "all"));
  document.querySelectorAll(".filter-btn[data-path]").forEach((b) => b.classList.toggle("active", b.dataset.path === "all"));
}
function setFileFilter(file) {
  activeFile = file; activeSev = "all"; activePath = "all"; currentPage = 1;
  document.querySelectorAll(".summary-cell").forEach((c) => c.classList.toggle("active", c.dataset.filter === "all"));
  document.querySelectorAll(".filter-btn[data-sev]").forEach((b) => b.classList.toggle("active", b.dataset.sev === "all"));
  document.querySelectorAll(".file-item[data-file]").forEach((i) => i.classList.toggle("active", i.dataset.file === file));
  document.querySelectorAll(".filter-btn[data-path]").forEach((b) => b.classList.toggle("active", b.dataset.path === "all"));
}
function setPathFilter(path) {
  activePath = path; activeSev = "all"; activeFile = "all"; currentPage = 1;
  document.querySelectorAll(".summary-cell").forEach((c) => c.classList.toggle("active", c.dataset.filter === "all"));
  document.querySelectorAll(".filter-btn[data-sev]").forEach((b) => b.classList.toggle("active", b.dataset.sev === "all"));
  document.querySelectorAll(".file-item[data-file]").forEach((i) => i.classList.toggle("active", i.dataset.file === "all"));
  document.querySelectorAll(".filter-btn[data-path]").forEach((b) => b.classList.toggle("active", b.dataset.path === path));
}

document.querySelectorAll(".summary-cell[data-filter]").forEach((cell) => {
  cell.addEventListener("click", () => {
    if (cell.dataset.filter === "all") { resetAllFilters(); return; }
    setSevFilter(cell.dataset.filter);
    renderFindings();
  });
});

document.querySelectorAll(".filter-btn[data-sev]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.sev === "all") { resetAllFilters(); return; }
    setSevFilter(btn.dataset.sev);
    renderFindings();
  });
});

document.querySelectorAll(".file-item[data-file]").forEach((item) => {
  item.addEventListener("click", () => {
    if (item.dataset.file === "all") { resetAllFilters(); return; }
    setFileFilter(item.dataset.file);
    renderFindings();
  });
});

document.querySelectorAll(".filter-btn[data-path]").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.path === "all") { resetAllFilters(); return; }
    setPathFilter(btn.dataset.path);
    renderFindings();
  });
});

document.getElementById("searchInput").addEventListener("input", () => { currentPage = 1; renderFindings(); });
document.getElementById("sortSelect").addEventListener("change", () => { currentPage = 1; renderFindings(); });

renderFindings();

const acked = new Map();

function toggleAck(btn) {
  const id = btn.dataset.id;
  const path = btn.dataset.path;
  const cwe = btn.dataset.cwe;
  const just = btn.dataset.just;
  if (acked.has(id)) {
    acked.delete(id);
    btn.classList.remove("acked");
    btn.textContent = "ACK";
  } else {
    acked.set(id, { path, cwe, justification: just });
    btn.classList.add("acked");
    btn.textContent = "✓";
  }
  updateSuppressBar();
}

function clearAcks() {
  acked.clear();
  document.querySelectorAll(".ack-btn.acked").forEach((b) => {
    b.classList.remove("acked");
    b.textContent = "ACK";
  });
  updateSuppressBar();
}

function updateSuppressBar() {
  const bar = document.getElementById("suppressBar");
  document.getElementById("suppressCount").textContent = acked.size;
  bar.classList.toggle("visible", acked.size > 0);
}

document.getElementById("suppressDl").addEventListener("click", function () {
  let yaml = "suppressions:\n";
  acked.forEach(function (v, id) {
    yaml += "  - id: " + id + "\n";
    if (v.path) yaml += "    path: " + JSON.stringify(v.path) + "\n";
    if (v.cwe) yaml += "    cwe: " + v.cwe + "\n";
    yaml += "    reason: user_acknowledged\n";
    yaml += "    # " + (v.justification || "").slice(0, 80) + "\n";
  });
  const blob = new Blob([yaml], { type: "text/yaml" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = ".zerotrust-suppressions.yaml";
  a.click();
  URL.revokeObjectURL(a.href);
});