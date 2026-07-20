// ── Theme Manager ───────────────────────────────────────
class ThemeManager {
  constructor() {
    this.html = document.documentElement;
    this.toggle = document.getElementById('themeToggle');
    this.iconSun = document.getElementById('iconSun');
    this.iconMoon = document.getElementById('iconMoon');

    if (this.toggle) {
      this.toggle.addEventListener('click', () => {
        this.apply(this.html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
      });
    }

    const saved = localStorage.getItem('zt-theme');
    if (saved) this.apply(saved);
    else if (window.matchMedia('(prefers-color-scheme: light)').matches) this.apply('light');
  }

  apply(t) {
    this.html.setAttribute('data-theme', t);
    if (this.iconSun) this.iconSun.style.display = t === 'dark' ? 'none' : 'block';
    if (this.iconMoon) this.iconMoon.style.display = t === 'dark' ? 'block' : 'none';
    localStorage.setItem('zt-theme', t);
  }
}

// ── Findings Manager ────────────────────────────────────
class FindingsManager {
  constructor() {
    this.sevOrder = { BLOCK: 0, HIGH: 1, MEDIUM: 2, LOW: 3, SUPPRESSED: 4 };
    this.activeSev = 'all';
    this.activeFile = 'all';
    this.activePath = 'all';
    this.currentPage = 1;
    this.perPage = 25;

    this._wireFilters();
    this._wirePagination();
    this._wireSearchSort();
    this._wireCardKeyboard();
    this.render();
  }

  toggleCard(el) {
    const card = el.closest('.finding-card');
    if (card) card.classList.toggle('expanded');
  }

  _wireCardKeyboard() {
    document.getElementById('findingsList').addEventListener('keydown', (e) => {
      const header = e.target.closest('.finding-header');
      if (!header) return;
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        this.toggleCard(header);
      }
    });
  }

  switchTab(btn, tabName) {
    const body = btn.closest('.finding-body');
    body.querySelectorAll('.ftab').forEach((t) => t.classList.remove('active'));
    body.querySelectorAll('.ftab-panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    body.querySelector(`.ftab-panel[data-tab="${tabName}"]`).classList.add('active');
  }

  render() {
    const search = document.getElementById('searchInput').value.toLowerCase();
    const allCards = [...document.querySelectorAll('.finding-card')];
    const list = document.getElementById('findingsList');

    let visible = allCards.filter((c) => {
      const sevOk = this.activeSev === 'all' || c.dataset.sev === this.activeSev;
      const fileOk = this.activeFile === 'all' || c.dataset.file === this.activeFile;
      const pathOk = this.activePath === 'all' || c.dataset.path === this.activePath;
      const srchOk = !search || c.textContent.toLowerCase().includes(search);
      return sevOk && fileOk && pathOk && srchOk;
    });

    const sortBy = document.getElementById('sortSelect').value;
    visible.sort((a, b) => {
      if (sortBy === 'severity') return (this.sevOrder[a.dataset.sev] ?? 9) - (this.sevOrder[b.dataset.sev] ?? 9);
      if (sortBy === 'confidence') return parseFloat(b.dataset.conf || 0) - parseFloat(a.dataset.conf || 0);
      if (sortBy === 'file') return (a.dataset.file || '').localeCompare(b.dataset.file || '');
      return 0;
    });

    const total = visible.length;
    const totalPages = Math.max(1, Math.ceil(total / this.perPage));
    if (this.currentPage > totalPages) this.currentPage = totalPages;
    const start = (this.currentPage - 1) * this.perPage;
    const end = Math.min(start + this.perPage, total);
    const pageCards = visible.slice(start, end);

    allCards.forEach((c) => { c.style.display = 'none'; });
    pageCards.forEach((c) => { list.appendChild(c); c.style.display = ''; });

    const countEl = document.getElementById('findingsCount');
    if (total === 0) {
      countEl.innerHTML = '<strong>0</strong> findings';
    } else {
      countEl.innerHTML = `Showing <strong>${start + 1}&ndash;${end}</strong> of <strong>${total}</strong> findings`;
    }

    this._updatePagination(this.currentPage, totalPages);
  }

  setSevFilter(sev) {
    this.activeSev = sev; this.activeFile = 'all'; this.activePath = 'all'; this.currentPage = 1;
    document.querySelectorAll('.summary-cell').forEach((c) => c.classList.toggle('active', c.dataset.filter === sev));
    document.querySelectorAll('.filter-btn[data-sev]').forEach((b) => b.classList.toggle('active', b.dataset.sev === sev));
    document.querySelectorAll('.file-item[data-file]').forEach((i) => i.classList.toggle('active', i.dataset.file === 'all'));
    document.querySelectorAll('.filter-btn[data-path]').forEach((b) => b.classList.toggle('active', b.dataset.path === 'all'));
  }

  setFileFilter(file) {
    this.activeFile = file; this.activeSev = 'all'; this.activePath = 'all'; this.currentPage = 1;
    document.querySelectorAll('.summary-cell').forEach((c) => c.classList.toggle('active', c.dataset.filter === 'all'));
    document.querySelectorAll('.filter-btn[data-sev]').forEach((b) => b.classList.toggle('active', b.dataset.sev === 'all'));
    document.querySelectorAll('.file-item[data-file]').forEach((i) => i.classList.toggle('active', i.dataset.file === file));
    document.querySelectorAll('.filter-btn[data-path]').forEach((b) => b.classList.toggle('active', b.dataset.path === 'all'));
  }

  setPathFilter(path) {
    this.activePath = path; this.activeSev = 'all'; this.activeFile = 'all'; this.currentPage = 1;
    document.querySelectorAll('.summary-cell').forEach((c) => c.classList.toggle('active', c.dataset.filter === 'all'));
    document.querySelectorAll('.filter-btn[data-sev]').forEach((b) => b.classList.toggle('active', b.dataset.sev === 'all'));
    document.querySelectorAll('.file-item[data-file]').forEach((i) => i.classList.toggle('active', i.dataset.file === 'all'));
    document.querySelectorAll('.filter-btn[data-path]').forEach((b) => b.classList.toggle('active', b.dataset.path === path));
  }

  resetAllFilters() {
    this.activeSev = 'all'; this.activeFile = 'all'; this.activePath = 'all'; this.currentPage = 1;
    document.querySelectorAll('.summary-cell').forEach((c) => c.classList.toggle('active', c.dataset.filter === 'all'));
    document.querySelectorAll('.filter-btn[data-sev]').forEach((b) => b.classList.toggle('active', b.dataset.sev === 'all'));
    document.querySelectorAll('.file-item[data-file]').forEach((i) => i.classList.toggle('active', i.dataset.file === 'all'));
    document.querySelectorAll('.filter-btn[data-path]').forEach((b) => b.classList.toggle('active', b.dataset.path === 'all'));
    this.render();
  }

  _updatePagination(current, total) {
    const showNav = total > 1;
    document.getElementById('prevPage').style.display = showNav ? '' : 'none';
    document.getElementById('nextPage').style.display = showNav ? '' : 'none';
    document.getElementById('pageNumbers').style.display = showNav ? '' : 'none';
    document.getElementById('prevPage').disabled = current <= 1;
    document.getElementById('nextPage').disabled = current >= total;

    let html = '';
    const maxVisible = 5;
    let s = Math.max(1, current - Math.floor(maxVisible / 2));
    let e = Math.min(total, s + maxVisible - 1);
    if (e - s + 1 < maxVisible) s = Math.max(1, e - maxVisible + 1);
    if (s > 1) html += `<button class="page-btn" data-page="1">1</button>`;
    if (s > 2) html += '<span class="page-ellipsis">&hellip;</span>';
    for (let i = s; i <= e; i++) {
      html += `<button class="page-btn${i === current ? ' active' : ''}" data-page="${i}">${i}</button>`;
    }
    if (e < total - 1) html += '<span class="page-ellipsis">&hellip;</span>';
    if (e < total) html += `<button class="page-btn" data-page="${total}">${total}</button>`;

    document.getElementById('pageNumbers').innerHTML = html;
    document.querySelectorAll('#pageNumbers .page-btn').forEach((btn) => {
      btn.addEventListener('click', () => { this.currentPage = parseInt(btn.dataset.page); this.render(); });
    });
  }

  _wireFilters() {
    document.querySelectorAll('.summary-cell[data-filter]').forEach((cell) => {
      cell.addEventListener('click', () => {
        if (cell.dataset.filter === 'all') { this.resetAllFilters(); return; }
        this.setSevFilter(cell.dataset.filter);
        this.render();
      });
    });

    document.querySelectorAll('.filter-btn[data-sev]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.sev === 'all') { this.resetAllFilters(); return; }
        this.setSevFilter(btn.dataset.sev);
        this.render();
      });
    });

    document.querySelectorAll('.file-item[data-file]').forEach((item) => {
      item.addEventListener('click', () => {
        if (item.dataset.file === 'all') { this.resetAllFilters(); return; }
        this.setFileFilter(item.dataset.file);
        this.render();
      });
    });

    document.querySelectorAll('.filter-btn[data-path]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.dataset.path === 'all') { this.resetAllFilters(); return; }
        this.setPathFilter(btn.dataset.path);
        this.render();
      });
    });
  }

  _wirePagination() {
    document.getElementById('prevPage').addEventListener('click', () => {
      if (this.currentPage > 1) { this.currentPage--; this.render(); }
    });
    document.getElementById('nextPage').addEventListener('click', () => {
      const visible = [...document.querySelectorAll('.finding-card')].filter(
        (c) => c.style.display !== 'none'
      );
      const totalPages = Math.max(1, Math.ceil(visible.length / this.perPage));
      if (this.currentPage < totalPages) { this.currentPage++; this.render(); }
    });
    document.getElementById('perPageSelect').addEventListener('change', (e) => {
      this.perPage = parseInt(e.target.value); this.currentPage = 1; this.render();
    });
  }

  _wireSearchSort() {
    document.getElementById('searchInput').addEventListener('input', () => { this.currentPage = 1; this.render(); });
    document.getElementById('sortSelect').addEventListener('change', () => { this.currentPage = 1; this.render(); });
  }
}

// ── File Sidebar ────────────────────────────────────────
class FileSidebar {
  constructor() {
    this.fileViewMode = 'flat';

    document.querySelectorAll('.file-view-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        if (view === this.fileViewMode) return;
        this.fileViewMode = view;
        document.querySelectorAll('.file-view-btn').forEach(b => b.classList.toggle('active', b.dataset.view === view));
        if (this.fileViewMode === 'tree') this.renderTree();
        else this.renderFlat();
      });
    });
  }

  renderFlat() {
    const section = document.querySelector('.sidebar-files');
    section.querySelectorAll('.file-item').forEach(el => el.style.display = '');
    section.querySelectorAll('.file-tree').forEach(el => el.remove());
  }

  renderTree() {
    const section = document.querySelector('.sidebar-files');
    const scrollEl = section.querySelector('.sidebar-files-scroll');
    scrollEl.querySelectorAll('.file-item[data-file]').forEach(el => {
      if (el.dataset.file !== 'all') el.style.display = 'none';
    });
    scrollEl.querySelectorAll('.file-tree').forEach(el => el.remove());

    const tree = this._buildTree();
    const container = document.createElement('div');
    container.className = 'file-tree';
    container.appendChild(this._buildTreeNodes(tree));
    scrollEl.appendChild(container);
  }

  _buildTree() {
    const items = [...document.querySelectorAll('.file-item[data-file]')].filter(el => el.dataset.file !== 'all');
    const tree = {};
    items.forEach(item => {
      const parts = item.dataset.file.split('/');
      let node = tree;
      parts.forEach((part, i) => {
        if (!node[part]) {
          node[part] = i === parts.length - 1
            ? { type: 'file', item }
            : { type: 'dir', children: {} };
        }
        if (node[part].type === 'dir') node = node[part].children;
      });
    });
    return tree;
  }

  _buildTreeNodes(node) {
    const frag = document.createDocumentFragment();
    const entries = Object.entries(node).sort((a, b) => {
      const aDir = a[1].type === 'dir';
      const bDir = b[1].type === 'dir';
      return aDir !== bDir ? (aDir ? -1 : 1) : a[0].localeCompare(b[0]);
    });
    entries.forEach(([name, child]) => {
      if (child.type === 'dir') {
        const details = document.createElement('details');
        const summary = document.createElement('summary');
        summary.className = 'tree-folder';
        summary.appendChild(Object.assign(document.createElement('span'), {className:'folder-indicator'}));
        summary.appendChild(Object.assign(document.createElement('span'), {className:'tree-name', textContent: name}));
        details.appendChild(summary);
        const childWrap = document.createElement('div');
        childWrap.className = 'tree-children';
        childWrap.appendChild(this._buildTreeNodes(child.children));
        details.appendChild(childWrap);
        frag.appendChild(details);
      } else {
        const div = document.createElement('div');
        div.className = 'tree-file';
        div.dataset.file = child.item.dataset.file;
        const badge = child.item.querySelector('.file-badge');
        const nameSpan = document.createElement('span');
        nameSpan.className = 'tree-name';
        nameSpan.textContent = name;
        div.append(nameSpan);
        if (badge) div.append(badge.cloneNode(true));
        div.addEventListener('click', (e) => {
          e.stopPropagation();
          findings.setFileFilter(child.item.dataset.file);
          child.item.classList.add('active');
          document.querySelectorAll('.file-tree .tree-file.active').forEach(el => el.classList.remove('active'));
          div.classList.add('active');
          findings.render();
        });
        frag.appendChild(div);
      }
    });
    return frag;
  }
}

// ── Suppression Manager ─────────────────────────────────
class SuppressionManager {
  constructor() {
    this.acked = new Map();

    document.getElementById('suppressDl').addEventListener('click', () => this._download());
  }

  toggle(btn) {
    const id = btn.dataset.id;
    const path = btn.dataset.path;
    const cwe = btn.dataset.cwe;
    const just = btn.dataset.just;
    if (this.acked.has(id)) {
      this.acked.delete(id);
      btn.classList.remove('acked');
      btn.textContent = 'ACK';
    } else {
      this.acked.set(id, { path, cwe, justification: just });
      btn.classList.add('acked');
      btn.textContent = '\u2713';
    }
    this._updateBar();
  }

  clear() {
    this.acked.clear();
    document.querySelectorAll('.ack-btn.acked').forEach((b) => {
      b.classList.remove('acked');
      b.textContent = 'ACK';
    });
    this._updateBar();
  }

  _updateBar() {
    const bar = document.getElementById('suppressBar');
    document.getElementById('suppressCount').textContent = this.acked.size;
    bar.classList.toggle('visible', this.acked.size > 0);
  }

  _download() {
    let yaml = 'suppressions:\n';
    this.acked.forEach(function (v, id) {
      yaml += '  - id: ' + id + '\n';
      if (v.path) yaml += '    path: ' + JSON.stringify(v.path) + '\n';
      if (v.cwe) yaml += '    cwe: ' + v.cwe + '\n';
      yaml += '    reason: user_acknowledged\n';
      yaml += '    # ' + (v.justification || '').slice(0, 80) + '\n';
    });
    const blob = new Blob([yaml], { type: 'text/yaml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = '.zerotrust-suppressions.yaml';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}

// ── Instantiation ───────────────────────────────────────
const theme = new ThemeManager();
const findings = new FindingsManager();
const sidebar = new FileSidebar();
const suppression = new SuppressionManager();

// Global aliases for inline onclick handlers in layout.html (Go template)
window.toggleCard = function(el) { findings.toggleCard(el); };
window.switchTab = function(btn, tab) { findings.switchTab(btn, tab); };
window.toggleAck = function(btn) { suppression.toggle(btn); };
window.clearAcks = function() { suppression.clear(); };
