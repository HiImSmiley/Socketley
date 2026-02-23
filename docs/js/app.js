'use strict';

// ─── Tab / Sub-tab Switching ───
const tabBtns    = document.querySelectorAll('.tab-btn');
const subTabBtns = document.querySelectorAll('.sub-tab-btn');
const luaSubTabs = document.getElementById('luaSubTabs');
const skSubTabs  = document.getElementById('skSubTabs');
const exSubTabs  = document.getElementById('exSubTabs');

let currentTab       = 'socketley';
let currentLuaSubTab = 'api';     // 'api' | 'addons'
let currentSkSubTab  = 'cli';     // 'cli' | 'sdk'
let currentExSubTab  = 'cli';     // 'cli' | 'sdk'

function navEl(id)     { return document.getElementById('navList-' + id); }
function contentEl(id) { return document.getElementById('content-' + id); }

function _resolvePane() {
  if (currentTab === 'socketley') {
    return currentSkSubTab === 'sdk' ? 'socketley-sdk' : 'socketley';
  }
  if (currentTab === 'lua') {
    return currentLuaSubTab === 'addons' ? 'addons' : 'lua';
  }
  if (currentTab === 'examples') {
    return currentExSubTab === 'sdk' ? 'examples-sdk' : 'examples';
  }
  return 'socketley';
}

function getActiveNav()     { return navEl(_resolvePane()); }
function getActiveContent() { return contentEl(_resolvePane()); }

function _applyVisibility() {
  const panes = ['socketley', 'socketley-sdk', 'lua', 'addons', 'examples', 'examples-sdk'];
  const active = _resolvePane();
  panes.forEach(id => {
    const n = navEl(id), c = contentEl(id);
    const show = id === active ? '' : 'none';
    if (n) n.style.display = show;
    if (c) c.style.display = show;
  });
  skSubTabs.style.display  = currentTab === 'socketley' ? '' : 'none';
  luaSubTabs.style.display = currentTab === 'lua'       ? '' : 'none';
  exSubTabs.style.display  = currentTab === 'examples'  ? '' : 'none';
}

function activateTab(tab) {
  currentTab = tab;
  tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  _applyVisibility();
  localStorage.setItem('sk-tab', tab);
  window.scrollTo(0, 0);
  const si = document.getElementById('search');
  if (si) si.value = '';
  resetSearch();
  updateActiveNav();
}

function activateSubTab(subtab, group) {
  if (group === 'lua') {
    currentLuaSubTab = subtab;
    localStorage.setItem('sk-lua-subtab', subtab);
  } else if (group === 'sk') {
    currentSkSubTab = subtab;
    localStorage.setItem('sk-sk-subtab', subtab);
  } else if (group === 'ex') {
    currentExSubTab = subtab;
    localStorage.setItem('sk-ex-subtab', subtab);
  }
  // Update active class within this group only
  subTabBtns.forEach(b => {
    if (b.dataset.subtabGroup === group)
      b.classList.toggle('active', b.dataset.subtab === subtab);
  });
  _applyVisibility();
  window.scrollTo(0, 0);
  const si = document.getElementById('search');
  if (si) si.value = '';
  resetSearch();
  updateActiveNav();
}

tabBtns.forEach(b    => b.addEventListener('click', () => activateTab(b.dataset.tab)));
subTabBtns.forEach(b => b.addEventListener('click', () => activateSubTab(b.dataset.subtab, b.dataset.subtabGroup)));

// ─── Sidebar Nav (active state on scroll) ───
function updateActiveNav() {
  const content = getActiveContent();
  const nav     = getActiveNav();
  if (!content || !nav) return;

  const sections = content.querySelectorAll('h2[id], h3[id], h4[id], .method-card[id], .callback-card[id], .cli-card[id]');
  let current = '';
  const scrollY = window.scrollY + 80;
  sections.forEach(s => { if (s.offsetTop <= scrollY) current = s.id; });

  const navItems  = nav.querySelectorAll(':scope > li > a');
  const subItems  = nav.querySelectorAll(':scope > li > ul > li > a');
  const deepItems = nav.querySelectorAll(':scope > li > ul > li > ul > li > a');

  navItems.forEach(a => {
    a.classList.remove('active');
    const href = a.getAttribute('href');
    if (href && current) {
      const t = href.slice(1);
      const li = a.parentElement;
      let match = t === current;
      li.querySelectorAll('ul a').forEach(cl => {
        if (cl.getAttribute('href') && cl.getAttribute('href').slice(1) === current) match = true;
      });
      if (match) { a.classList.add('active'); }
    }
  });
  subItems.forEach(a => {
    a.classList.remove('active');
    const href = a.getAttribute('href');
    if (href && current) {
      const t = href.slice(1);
      let match = t === current;
      const li = a.parentElement;
      li.querySelectorAll('ul a').forEach(cl => {
        if (cl.getAttribute('href') && cl.getAttribute('href').slice(1) === current) match = true;
      });
      if (match) a.classList.add('active');
    }
  });
  deepItems.forEach(a => {
    a.classList.remove('active');
    if (a.getAttribute('href') && a.getAttribute('href').slice(1) === current) a.classList.add('active');
  });
}

window.addEventListener('scroll', updateActiveNav);

// ─── Search ───
function resetSearch() {
  ['socketley', 'socketley-sdk', 'lua', 'addons', 'examples', 'examples-sdk'].forEach(id => {
    const nav = navEl(id);
    if (!nav) return;
    nav.querySelectorAll(':scope > li').forEach(li => {
      li.style.display = '';
      li.querySelectorAll('ul > li').forEach(s => s.style.display = '');
    });
  });
}

const searchInput = document.getElementById('search');
searchInput.addEventListener('input', function() {
  const q = this.value.toLowerCase().trim();
  const nav = getActiveNav();
  const allLis = nav.querySelectorAll(':scope > li');
  if (!q) { resetSearch(); return; }
  allLis.forEach(li => {
    const top = li.querySelector(':scope > a').textContent.toLowerCase();
    const subs = li.querySelectorAll('ul > li');
    let any = top.includes(q);
    subs.forEach(s => {
      const m = s.textContent.toLowerCase().includes(q);
      s.style.display = m ? '' : 'none';
      if (m) any = true;
    });
    li.style.display = any ? '' : 'none';
  });
});

// ─── Mobile Sidebar ───
const menuToggle = document.getElementById('menuToggle');
const sidebar    = document.getElementById('sidebar');
const overlay    = document.getElementById('overlay');
menuToggle.addEventListener('click', () => { sidebar.classList.toggle('open'); overlay.classList.toggle('open'); });
overlay.addEventListener('click',    () => { sidebar.classList.remove('open'); overlay.classList.remove('open'); });
document.querySelectorAll('.sidebar a[href]').forEach(a => {
  a.addEventListener('click', () => {
    if (window.innerWidth <= 768) { sidebar.classList.remove('open'); overlay.classList.remove('open'); }
  });
});

// ─── Copy Buttons ───
document.querySelectorAll('pre').forEach(pre => {
  const btn = document.createElement('button');
  btn.className = 'copy-btn';
  btn.textContent = 'Copy';
  btn.addEventListener('click', () => {
    navigator.clipboard.writeText((pre.querySelector('code') || pre).textContent).then(() => {
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
  });
  pre.appendChild(btn);
});

// ─── Init ───
const savedTab       = localStorage.getItem('sk-tab') || 'socketley';
const savedLuaSubTab = localStorage.getItem('sk-lua-subtab') || 'api';
const savedSkSubTab  = localStorage.getItem('sk-sk-subtab') || 'cli';
const savedExSubTab  = localStorage.getItem('sk-ex-subtab') || 'cli';

// migrate old top-level addons tab
currentTab       = savedTab === 'addons' ? 'lua' : savedTab;
currentLuaSubTab = savedTab === 'addons' ? 'addons' : savedLuaSubTab;
currentSkSubTab  = savedSkSubTab;
currentExSubTab  = savedExSubTab;

// Restore sub-tab active classes per group
subTabBtns.forEach(b => {
  const g = b.dataset.subtabGroup;
  if (g === 'lua') b.classList.toggle('active', b.dataset.subtab === currentLuaSubTab);
  else if (g === 'sk') b.classList.toggle('active', b.dataset.subtab === currentSkSubTab);
  else if (g === 'ex') b.classList.toggle('active', b.dataset.subtab === currentExSubTab);
});
activateTab(currentTab);
