/* ============================================================
   The Local Plate — SPA JavaScript
   ============================================================ */

// Backend API runs on a separate port from the frontend
const API_BASE = 'http://localhost:4443';

const CATEGORY_ICONS = {
  Pizza: '🍕', Pasta: '🍝', Mains: '🥩', Salads: '🥗',
  Burgers: '🍔', Starters: '🫙', Soups: '🍲', Desserts: '🍰',
};

const LAB_REQUESTS = {
  uploadImage: 'curl -X POST http://localhost:4443/api/admin/menu/upload-image -b cookies.txt -F menu_item_id=1 -F image=@menu-admin.html',
  invoiceExport: 'curl http://localhost:4443/api/orders/1/invoice/export -b cookies.txt',
  recipeViewer: 'curl "http://localhost:4443/api/kitchen/recipes/view?source=pasta.txt"',
  staffSession: `curl -X POST http://localhost:4443/api/staff/session -H "Content-Type: application/json" -d '{"email":"admin@thelocalplate.com","password":"Admin@2024!"}'`,
  inventoryAdjust: `curl -X POST http://localhost:4443/api/kitchen/inventory/adjust -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"menu_item_id":6,"set_to":-25,"reason":"manual correction"}'`,
  dispatch: 'POST http://localhost:4443/api/kitchen/dispatch',
};

let currentUser = null;
let currentItemID = null;
let selectedRating = 0;
let searchTimer = null;

/* ======================== INIT ======================== */
document.addEventListener('DOMContentLoaded', async () => {
  await checkAuth();
  renderCurrentRoute();
});

window.addEventListener('popstate', () => {
  renderCurrentRoute(false);
});

/* ======================== AUTH CHECK ======================== */
async function checkAuth() {
  try {
    const res = await fetch(API_BASE + '/api/me', { credentials: 'include' });
    if (res.ok) {
      const data = await res.json();
      currentUser = data;
      updateNavForAuth(data);
    } else {
      currentUser = null;
      updateNavForGuest();
    }
  } catch { updateNavForGuest(); }
}

function updateNavForAuth(user) {
  document.getElementById('nav-auth').style.display = 'none';
  document.getElementById('nav-user').style.display = 'flex';
  document.getElementById('nav-username').textContent = `Welcome, ${user.username}`;
  document.getElementById('nav-orders').style.display = 'block';
  if (user.role === 'admin') {
    document.getElementById('nav-admin').style.display = 'block';
  }
}

function updateNavForGuest() {
  document.getElementById('nav-auth').style.display = 'flex';
  document.getElementById('nav-user').style.display = 'none';
  document.getElementById('nav-orders').style.display = 'none';
  document.getElementById('nav-admin').style.display = 'none';
}

/* ======================== NAVIGATION ======================== */
function renderCurrentRoute(pushHistory = false) {
  const path = window.location.pathname;
  if (path === '/menu') navigate('menu', null, { pushHistory });
  else if (path.startsWith('/menu/')) {
    const id = path.split('/').pop();
    navigate('item', id, { pushHistory });
  } else if (path === '/login') navigate('login', null, { pushHistory });
  else if (path === '/register') navigate('register', null, { pushHistory });
  else if (path === '/orders') navigate('orders', null, { pushHistory });
  else if (path === '/reviews') navigate('reviews', null, { pushHistory });
  else if (path === '/admin') navigate('admin', null, { pushHistory });
  else if (path === '/lab') navigate('lab', null, { pushHistory });
  else navigate('home', null, { pushHistory });
}

function routeFor(page, params) {
  switch (page) {
    case 'home': return '/';
    case 'menu': return '/menu';
    case 'login': return '/login';
    case 'register': return '/register';
    case 'orders': return '/orders';
    case 'reviews': return '/reviews';
    case 'admin': return '/admin';
    case 'lab': return '/lab';
    case 'item': return `/menu/${params}`;
    default: return '/';
  }
}

function navigate(page, params, options = {}) {
  const { pushHistory = true } = options;
  switch(page) {
    case 'home':     renderHome(); break;
    case 'menu':     renderMenu(); break;
    case 'login':    renderLogin(); break;
    case 'register': renderRegister(); break;
    case 'orders':   renderOrders(); break;
    case 'reviews':  renderReviews(); break;
    case 'admin':    renderAdmin(); break;
    case 'lab':      renderLab(); break;
    case 'item':     renderItem(params); break;
    default: renderHome();
  }
  if (pushHistory) {
    const target = routeFor(page, params);
    if (window.location.pathname !== target) {
      window.history.pushState({ page, params }, '', target);
    }
  }
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function navigateItem(id) {
  currentItemID = id;
  navigate('item', id);
}

function tpl(id) {
  return document.getElementById(id).innerHTML;
}

/* ======================== HOME ======================== */
function renderHome() {
  document.getElementById('app').innerHTML = tpl('tpl-home');
  loadFeaturedItems();
  loadHomeReviews();
}

async function loadFeaturedItems() {
  const grid = document.getElementById('featured-grid');
  if (!grid) return;
  try {
    const res = await fetch(API_BASE + '/api/menu', { credentials: 'include' });
    const items = await res.json();
    const featured = items.slice(0, 3);
    grid.innerHTML = featured.map(menuCardHTML).join('');
  } catch {
    grid.innerHTML = '<div class="empty-state"><span class="empty-icon">🍽</span><h3 class="empty-title">Menu unavailable</h3></div>';
  }
}

async function loadHomeReviews() {
  const el = document.getElementById('home-reviews');
  if (!el) return;
  try {
    const res = await fetch(API_BASE + '/api/reviews', { credentials: 'include' });
    const reviews = await res.json();
    el.innerHTML = reviews.slice(0, 3).map(reviewCardHTML).join('');
  } catch {
    el.innerHTML = '';
  }
}

/* ======================== MENU ======================== */
function renderMenu() {
  document.getElementById('app').innerHTML = tpl('tpl-menu');
  loadMenu();
}

async function loadMenu(category, search) {
  const grid = document.getElementById('menu-grid');
  if (!grid) return;
  grid.innerHTML = '<div class="skeleton-card"></div><div class="skeleton-card"></div><div class="skeleton-card"></div><div class="skeleton-card"></div>';

  try {
    let url = API_BASE + '/api/menu';
    if (search) {
      url = API_BASE + `/api/search?q=${encodeURIComponent(search)}`;
    } else if (category) {
      url = API_BASE + `/api/menu?category=${encodeURIComponent(category)}`;
    }
    const res = await fetch(url, { credentials: 'include' });
    const items = await res.json();
    if (!items.length) {
      grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><span class="empty-icon">🍽</span><h3 class="empty-title">No dishes found</h3><p class="empty-text">Try a different search or category</p></div>`;
      return;
    }
    grid.innerHTML = items.map(menuCardHTML).join('');
  } catch {
    grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1"><span class="empty-icon">⚠️</span><h3 class="empty-title">Failed to load menu</h3></div>`;
  }
}

function menuCardHTML(item) {
  const icon = CATEGORY_ICONS[item.category] || '🍽';
  return `
    <div class="menu-card" onclick="navigateItem(${item.id})" id="menu-item-${item.id}">
      <div class="menu-card-img">${icon}</div>
      <div class="menu-card-body">
        <p class="menu-card-category">${item.category}</p>
        <h3 class="menu-card-name">${item.name}</h3>
        <p class="menu-card-desc">${item.description}</p>
        <div class="menu-card-footer">
          <span class="menu-card-price">$${item.price.toFixed(2)}</span>
          <button class="btn btn-primary" onclick="event.stopPropagation(); quickOrder(${item.id})">Order</button>
        </div>
      </div>
    </div>
  `;
}

function filterCategory(cat) {
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('chip-active'));
  event.target.classList.add('chip-active');
  loadMenu(cat);
}

function debounceSearch(val) {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => loadMenu(null, val), 350);
}

/* ======================== ITEM DETAIL ======================== */
async function renderItem(id) {
  currentItemID = id;
  document.getElementById('app').innerHTML = tpl('tpl-item');
  try {
    const res = await fetch(API_BASE + `/api/menu/${id}`, { credentials: 'include' });
    if (!res.ok) throw new Error('Not found');
    const item = await res.json();
    const icon = CATEGORY_ICONS[item.category] || '🍽';
    document.getElementById('item-img').textContent = icon;
    document.getElementById('item-info').innerHTML = `
      <p class="item-category">${item.category}</p>
      <h1 class="item-title">${item.name}</h1>
      <p class="item-price">$${item.price.toFixed(2)}</p>
      <p class="item-desc">${item.description}</p>
      <div class="item-actions">
        <div class="qty-control">
          <button class="qty-btn" onclick="adjustQty(-1)">−</button>
          <span class="qty-val" id="qty-val">1</span>
          <button class="qty-btn" onclick="adjustQty(1)">+</button>
        </div>
        <button class="btn btn-primary btn-lg" onclick="addToOrder(${item.id}, ${item.price})">Add to Order</button>
      </div>
    `;
    loadItemReviews(id);
  } catch {
    document.getElementById('item-info').innerHTML = '<div class="empty-state"><span class="empty-icon">⚠️</span><h3 class="empty-title">Item not found</h3></div>';
  }
}

function adjustQty(delta) {
  const v = document.getElementById('qty-val');
  if (!v) return;
  let n = parseInt(v.textContent) + delta;
  if (n < 1) n = 1;
  if (n > 20) n = 20;
  v.textContent = n;
}

async function loadItemReviews(id) {
  const el = document.getElementById('item-reviews');
  const formWrap = document.getElementById('review-form-wrap');
  if (!el) return;
  try {
    const res = await fetch(API_BASE + `/api/reviews?item_id=${id}`, { credentials: 'include' });
    const reviews = await res.json();
    el.innerHTML = reviews.length
      ? reviews.map(reviewCardHTML).join('')
      : '<p style="color:var(--text-muted);margin-bottom:24px">No reviews yet — be the first!</p>';
    if (currentUser) {
      formWrap.innerHTML = reviewFormHTML(id);
    } else {
      formWrap.innerHTML = `<p style="color:var(--text-muted);margin-top:24px"><a href="#" onclick="navigate('login');return false;">Sign in</a> to leave a review.</p>`;
    }
  } catch {}
}

function reviewFormHTML(itemId) {
  return `
    <div class="review-form">
      <h4>Write a Review</h4>
      <div class="star-select" id="stars">
        <span onclick="setRating(1)">⭐</span>
        <span onclick="setRating(2)">⭐</span>
        <span onclick="setRating(3)">⭐</span>
        <span onclick="setRating(4)">⭐</span>
        <span onclick="setRating(5)">⭐</span>
      </div>
      <div class="form-group">
        <textarea id="review-comment" class="input-field" placeholder="Share your experience…"></textarea>
      </div>
      <button class="btn btn-primary" onclick="submitReview(${itemId})">Submit Review</button>
    </div>
  `;
}

function setRating(n) {
  selectedRating = n;
  const stars = document.querySelectorAll('#stars span');
  stars.forEach((s, i) => s.classList.toggle('active', i < n));
}

async function submitReview(itemId) {
  if (!selectedRating) { showToast('Please select a star rating', 'error'); return; }
  const comment = document.getElementById('review-comment').value;
  try {
    const res = await fetch(API_BASE + '/api/reviews', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ menu_item_id: itemId, rating: selectedRating, comment }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast('Review submitted! Thank you.', 'success');
      loadItemReviews(itemId);
    } else {
      showToast(data.error || 'Failed to submit review', 'error');
    }
  } catch { showToast('Network error', 'error'); }
}

function reviewCardHTML(r) {
  const stars = '⭐'.repeat(r.rating) + '☆'.repeat(5 - r.rating);
  const initial = String(r.user_id).padStart(2, '0');
  const date = r.created_at ? r.created_at.substring(0, 10) : '';
  // V03: comment rendered via innerHTML (unescaped — stored XSS)
  return `
    <div class="review-card">
      <div class="review-stars">${stars}</div>
      <p class="review-text">${r.comment}</p>
      <div class="review-author">
        <div class="review-avatar">U${initial}</div>
        <div>
          <p class="review-name">Guest #${r.user_id}</p>
          <p class="review-date">${date}</p>
        </div>
      </div>
    </div>
  `;
}

/* ======================== ORDERS ======================== */
async function addToOrder(menuItemId, price) {
  if (!currentUser) { showToast('Please sign in to place an order', 'error'); navigate('login'); return; }
  const qty = parseInt(document.getElementById('qty-val')?.textContent || '1');
  try {
    const res = await fetch(API_BASE + '/api/orders', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: [{ menu_item_id: menuItemId, quantity: qty }],
        note: '',
      }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast(`Order placed! Total: $${data.total.toFixed(2)}`, 'success');
    } else {
      showToast(data.error || 'Failed to place order', 'error');
    }
  } catch { showToast('Network error', 'error'); }
}

async function quickOrder(menuItemId) {
  if (!currentUser) { showToast('Please sign in to place an order', 'error'); navigate('login'); return; }
  try {
    const res = await fetch(API_BASE + '/api/orders', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: [{ menu_item_id: menuItemId, quantity: 1 }], note: '' }),
    });
    const data = await res.json();
    if (res.ok) showToast(`Order placed! $${data.total.toFixed(2)}`, 'success');
    else showToast(data.error || 'Failed', 'error');
  } catch { showToast('Network error', 'error'); }
}

async function renderOrders() {
  document.getElementById('app').innerHTML = tpl('tpl-orders');
  if (!currentUser) { navigate('login'); return; }
  try {
    const res = await fetch(API_BASE + '/api/user/orders', { credentials: 'include' });
    const orders = await res.json();
    const el = document.getElementById('orders-list');
    if (!orders.length) {
      el.innerHTML = `<div class="empty-state"><span class="empty-icon">🧾</span><h3 class="empty-title">No orders yet</h3><p class="empty-text">Browse the menu and place your first order!</p><button class="btn btn-primary" style="margin-top:20px" onclick="navigate('menu')">View Menu</button></div>`;
      return;
    }
    el.innerHTML = orders.map(orderCardHTML).join('');
  } catch {
    document.getElementById('orders-list').innerHTML = '<div class="empty-state">Failed to load orders</div>';
  }
}

function orderCardHTML(o) {
  const statusClass = `status-${o.status}`;
  return `
    <div class="order-card">
      <div class="order-header">
        <div>
          <p class="order-id">Order #${o.id}</p>
          <p class="order-date">${o.created_at ? o.created_at.substring(0, 16).replace('T', ' ') : ''}</p>
        </div>
        <div style="text-align:right">
          <span class="status-badge ${statusClass}">${o.status}</span>
          <p class="order-total" style="margin-top:8px">$${o.total.toFixed(2)}</p>
        </div>
      </div>
      ${o.note ? `<p class="order-note">📝 ${o.note}</p>` : ''}
    </div>
  `;
}

/* ======================== REVIEWS PAGE ======================== */
async function renderReviews() {
  document.getElementById('app').innerHTML = tpl('tpl-reviews');
  try {
    const res = await fetch(API_BASE + '/api/reviews', { credentials: 'include' });
    const reviews = await res.json();
    const grid = document.getElementById('reviews-grid');
    grid.innerHTML = reviews.length
      ? reviews.map(reviewCardHTML).join('')
      : '<div class="empty-state" style="grid-column:1/-1"><span class="empty-icon">💬</span><h3 class="empty-title">No reviews yet</h3></div>';
  } catch {}
}

/* ======================== ADMIN ======================== */
function renderAdmin() {
  document.getElementById('app').innerHTML = tpl('tpl-admin');
  adminTab('orders');
}

function renderLab() {
  document.getElementById('app').innerHTML = tpl('tpl-lab');
}

async function adminTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('tab-active', (i === 0 && tab === 'orders') || (i === 1 && tab === 'users'));
  });
  const el = document.getElementById('admin-content');
  el.innerHTML = '<div class="skeleton-card"></div>';

  if (tab === 'orders') {
    try {
      const res = await fetch(API_BASE + '/admin/orders', { credentials: 'include', headers: { 'X-Admin-Token': 'lab-admin-bypass-token' } });
      const orders = await res.json();
      el.innerHTML = `<div class="table-wrap"><table class="admin-table">
        <thead><tr><th>ID</th><th>Customer</th><th>Total</th><th>Status</th><th>Date</th></tr></thead>
        <tbody>${orders.map(o => `<tr>
          <td>#${o.id}</td>
          <td>${o.username}</td>
          <td>$${o.total.toFixed(2)}</td>
          <td><span class="status-badge status-${o.status}">${o.status}</span></td>
          <td>${o.created_at ? o.created_at.substring(0, 10) : ''}</td>
        </tr>`).join('')}</tbody>
      </table></div>`;
    } catch { el.innerHTML = '<div class="empty-state">Failed to load</div>'; }
  } else {
    try {
      const res = await fetch(API_BASE + '/admin/users', { credentials: 'include', headers: { 'X-Admin-Token': 'lab-admin-bypass-token' } });
      const users = await res.json();
      el.innerHTML = `<div class="table-wrap"><table class="admin-table">
        <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Joined</th></tr></thead>
        <tbody>${users.map(u => `<tr>
          <td>#${u.id}</td>
          <td>${u.username}</td>
          <td>${u.email}</td>
          <td><span class="status-badge ${u.role === 'admin' ? 'status-completed' : 'status-pending'}">${u.role}</span></td>
          <td>${u.created_at ? u.created_at.substring(0, 10) : ''}</td>
        </tr>`).join('')}</tbody>
      </table></div>`;
    } catch { el.innerHTML = '<div class="empty-state">Failed to load</div>'; }
  }
}

/* ======================== AUTH ACTIONS ======================== */
function renderLogin() {
  document.getElementById('app').innerHTML = tpl('tpl-login');
}

function renderRegister() {
  document.getElementById('app').innerHTML = tpl('tpl-register');
}

async function doLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('login-btn');
  btn.textContent = 'Signing in…';
  btn.disabled = true;
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  try {
    const res = await fetch(API_BASE + '/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (res.ok) {
      currentUser = data;
      updateNavForAuth(data);
      showToast(`Welcome back, ${data.username}!`, 'success');
      navigate('home');
    } else {
      showToast(data.error || 'Login failed', 'error');
      btn.textContent = 'Sign In';
      btn.disabled = false;
    }
  } catch {
    showToast('Network error', 'error');
    btn.textContent = 'Sign In';
    btn.disabled = false;
  }
}

async function doRegister(e) {
  e.preventDefault();
  const btn = document.getElementById('register-btn');
  btn.textContent = 'Creating account…';
  btn.disabled = true;
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;
  try {
    const res = await fetch(API_BASE + '/register', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });
    const data = await res.json();
    if (res.ok) {
      showToast('Account created! Please sign in.', 'success');
      navigate('login');
    } else {
      showToast(data.error || 'Registration failed', 'error');
      btn.textContent = 'Create Account';
      btn.disabled = false;
    }
  } catch {
    showToast('Network error', 'error');
    btn.textContent = 'Create Account';
    btn.disabled = false;
  }
}

async function doLogout() {
  await fetch(API_BASE + '/logout', { method: 'POST', credentials: 'include' });
  currentUser = null;
  updateNavForGuest();
  showToast('Signed out successfully', 'info');
  navigate('home');
}

async function copyLabRequest(text, label = 'Request') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${label} copied`, 'success');
  } catch {
    showToast('Clipboard access failed', 'error');
  }
}

/* ======================== TOAST ======================== */
let toastTimer;
function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast toast-${type} show`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}
