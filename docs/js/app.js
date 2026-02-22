'use strict';

// ─── Theme Toggle ───
const themeToggle = document.getElementById('themeToggle');
const html = document.documentElement;
const savedTheme = localStorage.getItem('sk-theme');
if (savedTheme === 'light') { html.setAttribute('data-theme', 'light'); themeToggle.textContent = '\u2600'; }
themeToggle.addEventListener('click', () => {
  const isLight = html.getAttribute('data-theme') === 'light';
  if (isLight) {
    html.removeAttribute('data-theme');
    themeToggle.textContent = '\u263E';
    localStorage.setItem('sk-theme', 'dark');
  } else {
    html.setAttribute('data-theme', 'light');
    themeToggle.textContent = '\u2600';
    localStorage.setItem('sk-theme', 'light');
  }
});

// ─── Tab Switching ───
const tabBtns = document.querySelectorAll('.tab-btn');
const tabs    = ['socketley', 'lua', 'addons'];

function navEl(t)     { return document.getElementById('navList-' + t); }
function contentEl(t) { return document.getElementById('content-' + t); }

function getActiveNav()     { return tabs.map(navEl).find(el => el && el.style.display !== 'none') || navEl('socketley'); }
function getActiveContent() { return tabs.map(contentEl).find(el => el && el.style.display !== 'none') || contentEl('socketley'); }

function activateTab(tab) {
  tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  tabs.forEach(t => {
    const n = navEl(t), c = contentEl(t);
    const show = t === tab ? '' : 'none';
    if (n) n.style.display = show;
    if (c) c.style.display = show;
  });
  localStorage.setItem('sk-tab', tab);
  window.scrollTo(0, 0);
  // reset search
  const si = document.getElementById('search');
  if (si) { si.value = ''; }
  resetSearch();
  updateActiveNav();
}

tabBtns.forEach(b => b.addEventListener('click', () => activateTab(b.dataset.tab)));

// ─── Sidebar Nav (active state on scroll) ───
function updateActiveNav() {
  const content = getActiveContent();
  const nav     = getActiveNav();
  if (!content || !nav) return;

  const sections = content.querySelectorAll('h2[id], h3[id], .method-card[id], .callback-card[id], .cli-card[id]');
  let current = '';
  const scrollY = window.scrollY + 80;
  sections.forEach(s => { if (s.offsetTop <= scrollY) current = s.id; });

  const navItems = nav.querySelectorAll(':scope > li > a');
  const subItems = nav.querySelectorAll(':scope > li > ul > li > a');

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
    if (a.getAttribute('href') && a.getAttribute('href').slice(1) === current) a.classList.add('active');
  });
}

window.addEventListener('scroll', updateActiveNav);

// ─── Search ───
function resetSearch() {
  tabs.forEach(t => {
    const nav = navEl(t);
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
const savedTab = localStorage.getItem('sk-tab') || 'socketley';
activateTab(savedTab);
