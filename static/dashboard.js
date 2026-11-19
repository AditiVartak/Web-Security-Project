// WAFinity dashboard: polls /api/stats and /api/events every few seconds.
const REFRESH_MS = 3000;
const $ = (id) => document.getElementById(id);
const COLORS = ['#ff4d6d', '#ffb703', '#00FFD1', '#8ecae6', '#c77dff', '#adb5bd',
                '#f78c6b', '#06d6a0', '#118ab2', '#ef476f', '#e9c46a', '#9b5de5'];

let charts = {};
let lastEventId = 0;
const CSRF = document.querySelector('meta[name="csrf-token"]').content;

// Session expired or logged out in another tab -> go to the login page.
function authCheck(res) {
    if (res.status === 401) { window.location.href = '/login'; throw new Error('not authenticated'); }
}

function makeCharts() {
    Chart.defaults.color = 'rgba(255,255,255,0.7)';
    Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';
    charts.ratio = new Chart($('ch-ratio'), {
        type: 'doughnut',
        data: { labels: ['Allowed', 'Blocked'], datasets: [{ data: [0, 0], backgroundColor: ['#00FFD1', '#ff4d6d'], borderWidth: 0 }] },
        options: { maintainAspectRatio: false, cutout: '65%' }
    });
    charts.cat = new Chart($('ch-cat'), {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Blocked requests', data: [], backgroundColor: COLORS }] },
        options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
    charts.time = new Chart($('ch-time'), {
        type: 'line',
        data: { labels: [], datasets: [
            { label: 'Total', data: [], borderColor: '#00FFD1', backgroundColor: 'rgba(0,255,209,0.1)', fill: true, tension: 0.3 },
            { label: 'Blocked', data: [], borderColor: '#ff4d6d', tension: 0.3 }
        ] },
        options: { maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    });
}

function setLive(ok) {
    $('live-dot').classList.toggle('off', !ok);
    $('live-text').textContent = ok ? 'Live' : 'Disconnected';
}

async function loadStats() {
    const res = await fetch('/api/stats?range=' + encodeURIComponent($('range').value));
    authCheck(res);
    if (!res.ok) throw new Error('stats ' + res.status);
    const s = await res.json();

    $('c-total').textContent = s.total;
    $('c-blocked').textContent = s.blocked;
    $('c-allowed').textContent = s.allowed;
    $('c-ratio').textContent = s.block_ratio + '%';

    charts.ratio.data.datasets[0].data = [s.allowed, s.blocked];
    charts.ratio.update();

    charts.cat.data.labels = Object.keys(s.categories);
    charts.cat.data.datasets[0].data = Object.values(s.categories);
    charts.cat.update();

    charts.time.data.labels = s.timeline.map(t => t.bucket.replace('T', ' '));
    charts.time.data.datasets[0].data = s.timeline.map(t => t.total);
    charts.time.data.datasets[1].data = s.timeline.map(t => t.blocked);
    charts.time.update();

    const ips = $('ips');
    ips.replaceChildren();
    if (!s.top_ips.length) {
        const li = document.createElement('li'); li.textContent = 'No blocked requests yet'; ips.appendChild(li);
    }
    s.top_ips.forEach(r => {
        const li = document.createElement('li');
        const a = document.createElement('span'); a.textContent = r.ip || 'unknown';
        const b = document.createElement('span'); b.textContent = r.n;
        li.append(a, b); ips.appendChild(li);
    });
}

// Payloads are attacker-controlled text, so only ever insert them with textContent (never innerHTML).
function eventRow(e) {
    const tr = document.createElement('tr');
    const cell = (text, cls) => { const td = document.createElement('td'); td.textContent = text; if (cls) td.className = cls; return td; };
    tr.appendChild(cell(e.ts.replace('T', ' ')));
    tr.appendChild(cell(e.client_ip || 'unknown'));
    const actionTd = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = 'badge ' + (e.action === 'blocked' ? 'b-blocked' : 'b-allowed');
    badge.textContent = e.action;
    actionTd.appendChild(badge); tr.appendChild(actionTd);
    tr.appendChild(cell(e.category === 'None' ? '-' : e.category));
    tr.appendChild(cell(e.detected_by));
    tr.appendChild(cell(e.rule_id || '-'));
    tr.appendChild(cell(e.payload, 'payload'));
    return tr;
}

async function loadEvents() {
    const res = await fetch('/api/events?limit=50&after_id=' + lastEventId);
    authCheck(res);
    if (!res.ok) throw new Error('events ' + res.status);
    const events = await res.json();          // newest first
    if (!events.length) return;
    const feed = $('feed');
    // insert oldest->newest at the top so the newest ends up first
    events.slice().reverse().forEach(e => feed.insertBefore(eventRow(e), feed.firstChild));
    while (feed.children.length > 100) feed.removeChild(feed.lastChild);
    lastEventId = Math.max(lastEventId, events[0].id);
    $('feed-empty').style.display = 'none';
}

async function loadBans() {
    const res = await fetch('/api/bans');
    authCheck(res);
    if (!res.ok) throw new Error('bans ' + res.status);
    const bans = await res.json();
    const ul = $('bans');
    ul.replaceChildren();
    if (!bans.length) {
        const li = document.createElement('li'); li.textContent = 'No active bans'; ul.appendChild(li);
    }
    bans.forEach(b => {
        const li = document.createElement('li');
        const label = document.createElement('span');
        label.textContent = b.ip + '  (' + b.seconds_left + 's left)';
        const btn = document.createElement('button');
        btn.className = 'unban'; btn.textContent = 'Unban';
        btn.addEventListener('click', () => unban(b.ip));
        li.append(label, btn); ul.appendChild(li);
    });
}

async function unban(ip) {
    const res = await fetch('/api/unban', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
        body: JSON.stringify({ ip })
    });
    authCheck(res);
    refresh();
}

function updateExportLinks() {
    const r = encodeURIComponent($('range').value);
    $('export-csv').href = '/api/export?format=csv&range=' + r;
    $('export-json').href = '/api/export?format=json&range=' + r;
}

async function refresh() {
    try { await Promise.all([loadStats(), loadEvents(), loadBans()]); setLive(true); }
    catch (err) { console.error(err); setLive(false); }
}

makeCharts();
$('range').addEventListener('change', () => { updateExportLinks(); refresh(); });
refresh();
setInterval(refresh, REFRESH_MS);
