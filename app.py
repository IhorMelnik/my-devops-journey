#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from flask import Flask, render_template_string, send_file, abort, request, redirect, make_response, jsonify, session
import os, re, csv, io, shutil, psutil, functools
from datetime import datetime, timedelta

# ---------- НАЛАШТУВАННЯ ----------
ROOT = '/home/bcsftp'
WHITELIST_FILE = '/home/bcsftp/whitelist.txt'
USERS_FILE = '/home/bcsftp/users.txt'
BACKUP_FILE = '/home/bcsftp/whitelist.bak'
AUDIT_LOG = '/home/bcsftp/audit.log'
ROWS_PER_PAGE = 50
ALLOWED_SUBDIRS = {'enter', 'exit', 'pit'}

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)

@app.context_processor
def utility_processor():
    return dict(min=min, max=max, len=len, str=str, enumerate=enumerate)

def audit(action, detail=""):
    try:
        user = session.get('user', 'unknown')
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] {user} | {action} | {detail}\n")
    except: pass

def load_users():
    """Повертає dict: {username: {'password': ..., 'role': ...}}"""
    users = {}
    if os.path.isfile(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    parts = line.split('|')
                    u = parts[0]
                    p = parts[1] if len(parts) > 1 else ''
                    role = parts[2] if len(parts) > 2 else 'admin'
                    users[u] = {'password': p, 'role': role}
        except: pass
    return users if users else {"admin": {"password": "admin123", "role": "admin"}}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        for u, info in users.items():
            if isinstance(info, dict):
                f.write(f"{u}|{info['password']}|{info['role']}\n")
            else:
                f.write(f"{u}|{info}|admin\n")

def get_user_role(username):
    users = load_users()
    u = users.get(username, {})
    if isinstance(u, dict):
        return u.get('role', 'admin')
    return 'admin'

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session: return redirect('/login')
        # Охоронник може заходити тільки на сторінки перевірки
        if get_user_role(session['user']) == 'guard':
            allowed = ['/check_vehicles', '/check_results', '/check_history',
                       '/api/check_vehicle', '/api/reset_check', '/api/undo_check',
                       '/api/plate_info', '/api/add_trailer', '/api/remove_trailer',
                       '/api/save_trailer', '/logout']
            path = request.path
            if not any(path.startswith(a) for a in allowed):
                return redirect('/check_vehicles')
        return f(*args, **kwargs)
    return decorated_function

def guard_required(f):
    """Тільки охоронці і адміни."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session: return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def normalize_plate(p):
    if not p: return ""
    trans = str.maketrans("АВЕКМНОРСТХІ", "ABEKMHOPCTXI")
    return p.upper().translate(trans).replace(" ", "")

def is_standard_ua(p):
    n = normalize_plate(p)
    # Новий формат: AA1234BB
    if re.match(r'^[A-Z]{2}\d{4}[A-Z]{2}$', n): return True
    # Старий радянський формат: 1234AB, 12345AB, AB1234, AB12345
    if re.match(r'^\d{3,5}[A-Z]{2,3}$', n): return True
    if re.match(r'^[A-Z]{2,3}\d{3,5}$', n): return True
    # Тимчасові та спецномери: AA1234, 1234AA тощо
    if re.match(r'^[A-Z]{1,3}\d{2,6}$', n): return True
    if re.match(r'^\d{2,6}[A-Z]{1,3}$', n): return True
    return False

def format_duration(td):
    ts = int(td.total_seconds())
    if ts < 0: return "щойно"
    d, h, m = ts // 86400, (ts % 86400) // 3600, (ts % 3600) // 60
    res = []
    if d > 0: res.append(f"{d}д")
    if h > 0: res.append(f"{h}г")
    res.append(f"{m}хв")
    return " ".join(res)

def get_sys_info():
    try:
        total, used, free = shutil.disk_usage(ROOT)
        dp = round((used / total) * 100, 1)
        cp = psutil.cpu_percent(interval=0.1)
        rp = psutil.virtual_memory().percent
        def gc(p): return "#16a34a" if p < 75 else ("#d97706" if p < 90 else "#dc2626")
        return {"disk_p": dp, "disk_free": round(free/(2**30),1), "disk_color": gc(dp),
                "cpu_p": cp, "cpu_color": gc(cp), "ram_p": rp, "ram_color": gc(rp)}
    except: return None

def load_whitelist():
    base = {}
    if os.path.isfile(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if '|' in line:
                        p, n = line.strip().split('|', 1)
                        base[normalize_plate(p)] = n.strip()
        except: pass
    return base

def save_whitelist(base):
    if os.path.exists(WHITELIST_FILE): shutil.copy2(WHITELIST_FILE, BACKUP_FILE)
    with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
        for p, n in base.items(): f.write(f"{p}|{n}\n")

def find_similar_in_base(plate, base, max_dist=1):
    norm_p = normalize_plate(plate)
    if not norm_p or len(norm_p) < 6: return None
    for ref_p in base.keys():
        if len(norm_p) != len(ref_p): continue
        dist = sum(1 for a, b in zip(norm_p, ref_p) if a != b)
        if dist <= max_dist: return ref_p
    return None

def get_all_data():
    def scan(sub):
        path = os.path.join(ROOT, sub)
        res = []
        if not os.path.isdir(path): return res
        for f in os.listdir(path):
            if not f.lower().endswith('.jpg') or '.plate.' in f: continue
            m = re.match(r'(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d+)_+(.+)\.jpg$', f)
            if m:
                d_s, t_s, plate = m.groups()
                tc = f"{t_s[:2]}:{t_s[3:5]}"
                # Парсимо секунди/мілісекунди для точного сортування
                t_parts = t_s.split('-')
                secs_raw = t_parts[2] if len(t_parts) > 2 else '0'
                # Беремо перші 2 цифри як секунди (решта — мілісекунди)
                secs = int(secs_raw[:2]) if secs_raw[:2].isdigit() else 0
                try:
                    dt_base = datetime.strptime(f"{d_s} {tc}", "%Y-%m-%d %H:%M")
                    dt = dt_base.replace(second=min(secs, 59))
                    # Зберігаємо мілісекунди як мікросекунди для sub-секундного сортування
                    if len(secs_raw) > 2:
                        ms = int(secs_raw[2:8].ljust(6,'0')[:6])
                        dt = dt.replace(microsecond=ms)
                    res.append({'date': d_s, 'time': tc, 'dt': dt, 'plate': plate.upper(),
                                'norm_plate': normalize_plate(plate), 'file': f, 'subdir': sub})
                except: continue
        return res
    return scan('enter'), scan('exit'), scan('pit')

# ══════════════════════════════════════════════════════════════════
# СПІЛЬНІ CSS-ЗМІННІ (світла тема)
# ══════════════════════════════════════════════════════════════════
LIGHT_VARS = """
  --bg: #f0f4f8;
  --surface: #ffffff;
  --surface2: #f8fafc;
  --surface3: #f1f5f9;
  --border: #e2e8f0;
  --border2: #cbd5e1;
  --ua-blue: #0057b7;
  --ua-yellow: #ffd700;
  --accent: #0057b7;
  --accent-light: #dbeafe;
  --accent-hover: #004fa3;
  --green: #16a34a;
  --green-light: #dcfce7;
  --red: #dc2626;
  --red-light: #fee2e2;
  --orange: #d97706;
  --orange-light: #fef3c7;
  --purple: #7c3aed;
  --purple-light: #ede9fe;
  --text: #1e293b;
  --text-mid: #475569;
  --text-dim: #94a3b8;
  --shadow-sm: 0 1px 3px rgba(0,0,0,.06), 0 1px 2px rgba(0,0,0,.04);
  --shadow: 0 4px 6px rgba(0,0,0,.05), 0 2px 4px rgba(0,0,0,.04);
  --shadow-lg: 0 10px 25px rgba(0,0,0,.08), 0 4px 10px rgba(0,0,0,.05);
"""

# ══════════════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════════════
LOGIN_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · Вхід</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }
body{
  background: var(--bg);
  background-image:
    radial-gradient(circle at 20% 20%, rgba(0,87,183,.06) 0%, transparent 50%),
    radial-gradient(circle at 80% 80%, rgba(255,215,0,.08) 0%, transparent 50%);
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  font-family:'Nunito',sans-serif;
}
.wrap{width:420px}
.brand{text-align:center;margin-bottom:36px}
.brand-truck{font-size:3rem;display:block;margin-bottom:12px;filter:drop-shadow(0 4px 8px rgba(0,87,183,.2))}
.brand h1{font-size:1.6rem;font-weight:700;color:var(--ua-blue);letter-spacing:.05em}
.brand p{font-size:.8rem;color:var(--text-dim);margin-top:6px;font-family:'JetBrains Mono',monospace;letter-spacing:.05em}

.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:16px;
  padding:40px;
  box-shadow:var(--shadow-lg);
  position:relative;overflow:hidden;
}
.card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:4px;
  background:linear-gradient(90deg,var(--ua-blue) 0%,var(--ua-yellow) 100%);
  border-radius:16px 16px 0 0;
}
.field{margin-bottom:18px}
.field label{display:block;font-size:.78rem;font-weight:600;color:var(--text-mid);margin-bottom:7px;letter-spacing:.01em}
.field input{
  width:100%;padding:11px 14px;
  background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;
  color:var(--text);font-family:'Nunito',sans-serif;font-size:.95rem;outline:none;transition:.15s;
}
.field input:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
.btn{
  width:100%;padding:13px;
  background:var(--ua-blue);border:none;border-radius:8px;
  color:#fff;font-family:'Nunito',sans-serif;font-weight:700;font-size:1rem;
  cursor:pointer;transition:.15s;margin-top:4px;letter-spacing:.02em;
}
.btn:hover{background:var(--accent-hover);box-shadow:0 4px 12px rgba(0,87,183,.3)}
.btn:active{transform:translateY(1px)}
.error{
  background:var(--red-light);border:1px solid rgba(220,38,38,.2);border-radius:8px;
  color:var(--red);padding:10px 14px;font-size:.85rem;margin-bottom:18px;
  display:flex;align-items:center;gap:8px;
}
.footer{text-align:center;margin-top:20px;font-size:.75rem;color:var(--text-dim)}
</style></head>
<body>
<div class="wrap">
  <div class="brand">
    <span class="brand-truck">🚛</span>
    <h1>АГРОТЕП</h1>
    <p>СИСТЕМА КОНТРОЛЮ ДОСТУПУ</p>
  </div>
  <div class="card">
    {% if error %}<div class="error">⚠️ {{error}}</div>{% endif %}
    <form method="post">
      <div class="field"><label>Логін</label><input type="text" name="u" required autocomplete="username" placeholder="Введіть логін"></div>
      <div class="field"><label>Пароль</label><input type="password" name="p" required autocomplete="current-password" placeholder="Введіть пароль"></div>
      <button class="btn" type="submit">Увійти →</button>
    </form>
  </div>
  <div class="footer">АГРОТЕП · Система ANPR v2</div>
</div>
</body></html>'''


STATS_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · Звіти</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }

body{background:var(--bg);color:var(--text);font-family:"Nunito",sans-serif;min-height:100vh}
.topbar{background:var(--ua-blue);display:flex;align-items:center;padding:0 24px;height:56px;gap:14px;box-shadow:0 2px 8px rgba(0,87,183,.3);position:sticky;top:0;z-index:100}
.brand{font-size:1.05rem;font-weight:700;color:#fff}
a.back{padding:6px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;text-decoration:none;font-size:.82rem;font-weight:600;transition:.15s}
a.back:hover{background:rgba(255,255,255,.25)}
.tb-sep{flex:1}
.container{max-width:1280px;margin:0 auto;padding:28px 24px}
.tabs{display:flex;gap:4px;margin-bottom:24px;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:4px;width:fit-content}
.tab{padding:8px 20px;border-radius:7px;cursor:pointer;font-weight:600;font-size:.88rem;color:var(--text-mid);border:none;background:transparent;transition:.15s;font-family:"Nunito",sans-serif}
.tab:hover{background:var(--surface3);color:var(--text)}
.tab.active{background:var(--ua-blue);color:#fff}
.filter-bar{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin-bottom:20px;display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;box-shadow:var(--shadow-sm)}
.fg{display:flex;flex-direction:column;gap:4px}
.fg label{font-size:.72rem;font-weight:600;color:var(--text-mid)}
.fi,.fs{background:var(--surface2);border:1.5px solid var(--border);color:var(--text);padding:8px 11px;border-radius:7px;font-family:"Nunito",sans-serif;font-size:.88rem;outline:none;transition:.15s}
.fi:focus,.fs:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
.fs{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2394a3b8'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.fb{padding:8px 16px;border-radius:7px;font-family:"Nunito",sans-serif;font-weight:600;font-size:.88rem;cursor:pointer;border:none;transition:.15s;text-decoration:none;display:inline-flex;align-items:center;gap:5px}
.fb-primary{background:var(--ua-blue);color:#fff}
.fb-primary:hover{background:var(--accent-hover);box-shadow:0 3px 8px rgba(0,87,183,.25)}
.fb-ghost{background:transparent;border:1.5px solid var(--border2);color:var(--text-mid)}
.fb-ghost:hover{border-color:var(--red);color:var(--red)}
.fb-outline{background:transparent;border:1.5px solid var(--border2);color:var(--text-mid)}
.fb-outline:hover{border-color:var(--ua-blue);color:var(--ua-blue)}
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.kpi-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:22px;max-width:800px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 22px;box-shadow:var(--shadow-sm);position:relative;overflow:hidden}
.kpi::after{content:"";position:absolute;bottom:0;left:0;right:0;height:3px;background:var(--border)}
.kpi.c-blue::after{background:var(--ua-blue)} .kpi.c-green::after{background:var(--green)}
.kpi.c-red::after{background:var(--red)} .kpi.c-purple::after{background:var(--purple)} .kpi.c-orange::after{background:var(--orange)}
.kpi-lbl{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:8px}
.kpi-val{font-size:2.2rem;font-weight:700;font-family:"JetBrains Mono",monospace;line-height:1}
.kpi-sub{font-size:.78rem;color:var(--text-dim);margin-top:6px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px 24px;box-shadow:var(--shadow-sm);margin-bottom:20px}
.panel-hdr{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:16px;display:flex;align-items:center;gap:6px}
.panel-hdr::before{content:"";display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}
.chart-full{grid-column:1/-1}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:var(--shadow-sm);margin-bottom:20px}
.table-hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--border)}
.table-title{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;display:flex;align-items:center;gap:6px}
.table-title::before{content:"";display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.table-cnt{font-size:.72rem;color:var(--text-dim);font-family:"JetBrains Mono",monospace}
.table-cnt b{color:var(--ua-blue)}
table{width:100%;border-collapse:collapse}
thead th{padding:10px 14px;text-align:left;font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;background:var(--surface2);border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:.1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface3)}
tbody td{padding:10px 14px;vertical-align:middle;font-size:.88rem}
.plate{display:inline-flex;align-items:stretch;border:2px solid #1a1a2e;border-radius:5px;overflow:hidden;text-decoration:none;transition:.15s;box-shadow:0 1px 4px rgba(0,0,0,.12)}
.plate:hover{box-shadow:0 2px 8px rgba(0,87,183,.3);border-color:var(--ua-blue);transform:scale(1.02)}
.plate-flag{background:var(--ua-blue);width:14px;min-height:26px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px;flex-shrink:0}
.plate-flag span{font-size:.35rem;line-height:1}
.plate-body{background:#f5f5ee;padding:3px 10px;display:flex;align-items:center}
.plate-text{font-family:"JetBrains Mono",monospace;font-weight:700;color:#111;font-size:.88rem;letter-spacing:.04em}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:6px;font-size:.7rem;font-weight:700}
.badge-in{background:var(--green-light);color:var(--green)} .badge-out{background:var(--red-light);color:var(--red)} .badge-pit{background:var(--orange-light);color:var(--orange)}
.cat{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:6px;font-size:.7rem;font-weight:700}
.cat-T{background:var(--purple-light);color:var(--purple)} .cat-S{background:var(--accent-light);color:var(--ua-blue)}
.cat-L{background:var(--orange-light);color:var(--orange)} .cat-R{background:var(--surface3);color:var(--text-dim)}
.cat-CH{background:var(--red-light);color:var(--red)}
.cat-D{background:#e0f2fe;color:#0369a1} .cat-V{background:#f0fdf4;color:#0891b2} .cat-unk{background:#f1f5f9;color:#64748b}
.thumb-wrap{position:relative;width:64px;height:42px}
.thumb{width:100%;height:100%;object-fit:cover;border-radius:5px;border:1.5px solid var(--border);cursor:pointer;transition:.15s}
.thumb:hover{border-color:var(--ua-blue)}
.thumb-preview{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:9999;pointer-events:none;border-radius:8px;overflow:hidden;box-shadow:0 25px 60px rgba(0,0,0,.35)}
.thumb-wrap:hover .thumb-preview{display:block}
.thumb-preview img{max-width:75vw;max-height:75vh;display:block}
.dur-bar{height:6px;background:var(--border);border-radius:3px;overflow:hidden;width:120px;margin-top:4px}
.dur-fill{height:100%;border-radius:3px}
.top-bar{height:7px;background:var(--accent-light);border-radius:4px;overflow:hidden}
.top-bar-fill{height:100%;background:var(--ua-blue);border-radius:4px}
.tab-section{display:none} .tab-section.active{display:block}
.tr-black{background:linear-gradient(90deg,rgba(220,38,38,.06),transparent)!important}
.pagination{display:flex;gap:4px;justify-content:center;margin-top:18px}
.pg{background:var(--surface);border:1.5px solid var(--border);color:var(--text-mid);padding:6px 13px;border-radius:7px;font-size:.8rem;cursor:pointer;text-decoration:none;transition:.15s;font-family:"JetBrains Mono",monospace;font-weight:600}
.pg:hover,.pg.on{background:var(--ua-blue);border-color:var(--ua-blue);color:#fff}
.heatmap{display:grid;grid-template-columns:40px repeat(24,1fr);gap:2px;font-size:.6rem}
.hm-cell{height:22px;border-radius:3px;display:flex;align-items:center;justify-content:center;font-family:"JetBrains Mono",monospace;font-size:.58rem;font-weight:600}
.hm-label{display:flex;align-items:center;font-size:.68rem;color:var(--text-dim);font-weight:600;padding-right:4px}
.hm-head{display:flex;align-items:center;justify-content:center;color:var(--text-dim);font-size:.6rem;font-weight:600}
.insight-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px}
.insight{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 20px;box-shadow:var(--shadow-sm)}
.insight-icon{font-size:1.8rem;margin-bottom:8px}
.insight-title{font-size:.72rem;font-weight:700;letter-spacing:.05em;color:var(--text-dim);text-transform:uppercase;margin-bottom:6px}
.insight-val{font-size:1.3rem;font-weight:700;font-family:"JetBrains Mono",monospace;color:var(--text)}
.insight-sub{font-size:.78rem;color:var(--text-dim);margin-top:4px}
</style></head>
<body>
<div class="topbar">
  <div class="brand">🚛 АГРОТЕП</div>
  <div style="width:1px;height:24px;background:rgba(255,255,255,.2)"></div>
  <a href="/" class="back">← Термінал</a>
  <div class="tb-sep"></div>
  <span style="color:rgba(255,255,255,.7);font-size:.82rem;font-family:'JetBrains Mono',monospace">Звіти та аналітика</span>
</div>
<div class="container">

  <div class="tabs">
    <button class="tab active" onclick="switchTab('traffic',this)">📈 Трафік</button>
    <button class="tab" onclick="switchTab('journal',this)">📋 Журнал</button>
    <button class="tab" onclick="switchTab('duration',this)">⏱ Час перебування</button>
    <button class="tab" onclick="switchTab('unknown',this)">❓ Невідомі авто</button>
    <button class="tab" onclick="switchTab('analytics',this)">🔬 Аналітика</button>
  </div>

  <!-- ══ ТРАФІК ══ -->
  <div id="tab-traffic" class="tab-section active">
    <div class="kpi-grid">
      <div class="kpi c-blue"><div class="kpi-lbl">Всього подій</div><div class="kpi-val" style="color:var(--ua-blue)">{{total_events}}</div><div class="kpi-sub">за весь час</div></div>
      <div class="kpi c-green"><div class="kpi-lbl">Сьогодні</div><div class="kpi-val" style="color:var(--green)">{{today_events}}</div><div class="kpi-sub">подій за сьогодні</div></div>
      <div class="kpi c-purple"><div class="kpi-lbl">Унікальних авто</div><div class="kpi-val" style="color:var(--purple)">{{unique_plates}}</div><div class="kpi-sub">різних номерів</div></div>
      <div class="kpi c-orange"><div class="kpi-lbl">Невідомих авто</div><div class="kpi-val" style="color:var(--orange)">{{unknown_count}}</div><div class="kpi-sub">не в базі</div></div>
    </div>
    <div class="panel chart-full">
      <div class="panel-hdr">Трафік за 30 днів</div>
      <canvas id="daysChart" style="max-height:180px"></canvas>
    </div>
    <div class="charts-row">
      <div class="panel">
        <div class="panel-hdr">Погодинний трафік (середній)</div>
        <canvas id="hourChart" style="max-height:200px"></canvas>
      </div>
      <div class="panel">
        <div class="panel-hdr">Розподіл по категоріях</div>
        {% set cats = [("Тягачі","Т","var(--purple)"),("Співробітники","С","var(--ua-blue)"),("Водії","В","#0891b2"),("Доставка","Д","#0369a1"),("Службові","Л","var(--orange)"),("Інші","Р","var(--text-dim)"),("Чорний список","Ч","var(--red)"),("Невідомі","unknown","#94a3b8")] %}
        {% set total_cat = cat_stats.values()|sum %}
        {% for label,key,color in cats %}{% set cnt = cat_stats[key] %}{% if cnt > 0 %}
        <div style="display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:.88rem">{{label}}</span>
          <div style="display:flex;align-items:center;gap:10px">
            <div class="top-bar" style="width:100px"><div class="top-bar-fill" style="width:{{(cnt/total_cat*100)|int}}%;background:{{color}}"></div></div>
            <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.82rem;color:{{color}};min-width:32px;text-align:right">{{cnt}}</span>
          </div>
        </div>
        {% endif %}{% endfor %}
      </div>
    </div>
    <div class="panel">
      <div class="panel-hdr">Топ-10 найактивніших авто</div>
      <table>
        <thead><tr><th>Номер авто</th><th>Власник</th><th>Категорія</th><th>Кількість в'їздів</th></tr></thead>
        <tbody>
        {% for plate,cnt in top_plates %}
        {% set note=base.get(plate,"") %}{% set owner=note[4:] if note|length>3 else "—" %}
        <tr>
          <td><a href="/stats?tab=journal&search={{plate}}" class="plate"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text">{{plate}}</span></div></a></td>
          <td style="color:var(--text-mid)">{{owner}}</td>
          <td>{% if "[Т]" in note %}<span class="cat cat-T">🚛 Тягач</span>{% elif "[С]" in note %}<span class="cat cat-S">🚗 Співробітник</span>{% elif "[Л]" in note %}<span class="cat cat-L">🛠 Службове</span>{% elif "[Д]" in note %}<span class="cat cat-D">📦 Доставка</span>{% elif "[В]" in note %}<span class="cat cat-V">🚚 Водій</span>{% elif "[Ч]" in note %}<span class="cat cat-CH">🚫 Чорний список</span>{% elif "[П]" in note %}<span class="cat" style="background:#eff6ff;color:#1d4ed8">🔗 Причіп</span>{% elif note %}<span class="cat cat-R">👤 Інше</span>{% else %}<span class="cat cat-unk">❓ Невідомий</span>{% endif %}</td>
          <td><div style="display:flex;align-items:center;gap:10px"><div class="top-bar" style="width:150px"><div class="top-bar-fill" style="width:{{(cnt/top_plates[0][1]*100)|int}}%"></div></div><span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.88rem;color:var(--ua-blue)">{{cnt}}</span></div></td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ══ ЖУРНАЛ ══ -->
  <div id="tab-journal" class="tab-section">
    <form class="filter-bar" method="get" action="/stats">
      <input type="hidden" name="tab" value="journal">
      <div class="fg"><label>З дати</label><input type="date" name="start_date" class="fi" value="{{j_start}}"></div>
      <div class="fg"><label>По дату</label><input type="date" name="end_date" class="fi" value="{{j_end}}"></div>
      <div class="fg"><label>Напрямок</label>
        <select name="dir" class="fs" style="min-width:140px">
          <option value="">Всі напрямки</option>
          <option value="enter" {{"selected" if j_dir=="enter"}}>⬆️ В'їзд</option>
          <option value="exit" {{"selected" if j_dir=="exit"}}>⬇️ Виїзд</option>
          <option value="pit" {{"selected" if j_dir=="pit"}}>⚙️ Яма</option>
        </select>
      </div>
      <div class="fg"><label>Категорія</label>
        <select name="cat" class="fs" style="min-width:160px">
          <option value="">Всі категорії</option>
          <option value="Т" {{"selected" if j_cat=="Т"}}>🚛 Тягачі</option>
          <option value="С" {{"selected" if j_cat=="С"}}>🚗 Співробітники</option>
            <option value="П" {{"selected" if j_cat=="П"}}>🔗 Причепи</option>
          <option value="Л" {{"selected" if j_cat=="Л"}}>🛠 Службові</option>
          <option value="Р" {{"selected" if j_cat=="Р"}}>👤 Інші</option>
          <option value="Д" {{"selected" if j_cat=="Д"}}>📦 Доставка</option>
          <option value="unk" {{"selected" if j_cat=="unk"}}>❓ Невідомі</option>
        </select>
      </div>
      <div class="fg" style="flex:1"><label>Пошук за номером або прізвищем</label>
        <div style="display:flex;gap:6px">
          <input type="text" name="search" class="fi" style="flex:1" value="{{j_search}}" placeholder="AA1234BB або Іванов...">
          <button type="submit" class="fb fb-primary">🔍 Знайти</button>
          <a href="/stats?tab=journal" class="fb fb-ghost">✕ Скинути</a>
        </div>
      </div>
    </form>
    <div class="table-wrap">
      <div class="table-hdr">
        <div class="table-title">Журнал подій</div>
        <div class="table-cnt">Показано <b>{{j_rows|length}}</b> із {{j_total}}</div>
      </div>
      <table>
        <thead><tr><th>Дата та час</th><th>Напрямок</th><th>Номер авто</th><th>Власник</th><th>Категорія</th><th>Час перебування</th><th>Фото</th></tr></thead>
        <tbody>
        {% for r in j_rows %}
        {% set note=base.get(r.norm_plate,"") %}{% set owner=note[4:] if note|length>3 else "" %}
        <tr class="{{"tr-black" if "[Ч]" in note else ""}}">
          <td><div style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.88rem">{{r.time}}</div><div style="font-size:.72rem;color:var(--text-dim);margin-top:1px">{{r.date}}</div></td>
          <td>{% if r.subdir=="enter" %}<span class="badge badge-in">▲ В'їзд</span>{% elif r.subdir=="exit" %}<span class="badge badge-out">▼ Виїзд</span>{% else %}<span class="badge badge-pit">⚙ Яма</span>{% endif %}</td>
          <td><a href="/stats?tab=journal&search={{r.plate}}" class="plate"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text">{{r.plate}}</span></div></a></td>
          <td style="color:var(--text-mid)">{{owner or "—"}}</td>
          <td>{% if "[Т]" in note %}<span class="cat cat-T">🚛 Тягач</span>{% elif "[С]" in note %}<span class="cat cat-S">🚗 Співробітник</span>{% elif "[Л]" in note %}<span class="cat cat-L">🛠 Службове</span>{% elif "[Д]" in note %}<span class="cat cat-D">📦 Доставка</span>{% elif "[В]" in note %}<span class="cat cat-V">🚚 Водій</span>{% elif "[Ч]" in note %}<span class="cat cat-CH">🚫 Чорний список</span>{% elif "[П]" in note %}<span class="cat" style="background:#eff6ff;color:#1d4ed8">🔗 Причіп</span>{% elif note %}<span class="cat cat-R">👤 Інше</span>{% else %}<span class="cat cat-unk">❓ Невідомий</span>{% endif %}</td>
          <td>{% if r.file in j_durations %}<span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.78rem;color:var(--ua-blue)">⏱ {{j_durations[r.file]}}</span>{% else %}<span style="color:var(--text-dim)">—</span>{% endif %}</td>
          <td><div class="thumb-wrap"><img src="/img/{{r.subdir}}/{{r.file}}" class="thumb" alt=""><div class="thumb-preview"><img src="/img/{{r.subdir}}/{{r.file}}" alt=""></div></div></td>
        </tr>
        {% endfor %}
        {% if not j_rows %}<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-dim)">Записів не знайдено</td></tr>{% endif %}
        </tbody>
      </table>
    </div>
    {% if j_total_p > 1 %}
    <div class="pagination">
      <a href="/stats?tab=journal&start_date={{j_start}}&end_date={{j_end}}&dir={{j_dir}}&cat={{j_cat}}&search={{j_search}}&page={{[1,j_page-1]|max}}" class="pg">«</a>
      {% for i in range(1,j_total_p+1) %}
        {% if i==j_page %}<span class="pg on">{{i}}</span>
        {% elif i==1 or i==j_total_p or (i>=j_page-2 and i<=j_page+2) %}<a href="/stats?tab=journal&start_date={{j_start}}&end_date={{j_end}}&dir={{j_dir}}&cat={{j_cat}}&search={{j_search}}&page={{i}}" class="pg">{{i}}</a>
        {% elif i==j_page-3 or i==j_page+3 %}<span class="pg" style="cursor:default;border:none;background:transparent;color:var(--text-dim)">…</span>{% endif %}
      {% endfor %}
      <a href="/stats?tab=journal&start_date={{j_start}}&end_date={{j_end}}&dir={{j_dir}}&cat={{j_cat}}&search={{j_search}}&page={{[j_total_p,j_page+1]|min}}" class="pg">»</a>
    </div>
    {% endif %}
  </div>

  <!-- ══ ЧАС ПЕРЕБУВАННЯ ══ -->
  <div id="tab-duration" class="tab-section">
    <form class="filter-bar" method="get" action="/stats">
      <input type="hidden" name="tab" value="duration">
      <div class="fg"><label>З дати</label><input type="date" name="dur_start" class="fi" value="{{dur_start}}"></div>
      <div class="fg"><label>По дату</label><input type="date" name="dur_end" class="fi" value="{{dur_end}}"></div>
      <div class="fg"><label>Категорія</label>
        <select name="dur_cat" class="fs" style="min-width:160px">
          <option value="">Всі категорії</option>
          <option value="Т" {{"selected" if dur_cat=="Т"}}>🚛 Тягачі</option>
          <option value="С" {{"selected" if dur_cat=="С"}}>🚗 Співробітники</option>
          <option value="Л" {{"selected" if dur_cat=="Л"}}>🛠 Службові</option>
          <option value="Д" {{"selected" if dur_cat=="Д"}}>📦 Доставка</option>
          <option value="Р" {{"selected" if dur_cat=="Р"}}>👤 Інші</option>
        </select>
      </div>
      <div class="fg" style="flex:1"><label>Пошук за номером або прізвищем</label>
        <div style="display:flex;gap:6px">
          <input type="text" name="dur_search" class="fi" style="flex:1" value="{{dur_search}}" placeholder="AA1234BB або Іванов...">
          <button type="submit" class="fb fb-primary">🔍 Знайти</button>
          <a href="/stats?tab=duration" class="fb fb-ghost">✕ Скинути</a>
        </div>
      </div>
    </form>
    <div class="table-wrap">
      <div class="table-hdr">
        <div class="table-title">Час перебування на території</div>
        <div class="table-cnt">Знайдено <b>{{dur_rows|length}}</b> записів</div>
      </div>
      <table>
        <thead><tr><th>Номер авто</th><th>Власник</th><th>Категорія</th><th>В'їзд</th><th>Виїзд</th><th>Час перебування</th></tr></thead>
        <tbody>
        {% for r in dur_rows %}
        {% set note=base.get(r.norm_plate,"") %}{% set owner=note[4:] if note|length>3 else "—" %}
        {% set dsecs=r.duration_seconds %}
        {% set dpct=[((dsecs/86400)*100)|int,100]|min %}
        {% set dcol="var(--green)" if dsecs<3600 else ("var(--orange)" if dsecs<86400 else "var(--red)") %}
        <tr>
          <td><a href="/stats?tab=journal&search={{r.plate}}" class="plate"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text">{{r.plate}}</span></div></a></td>
          <td style="color:var(--text-mid)">{{owner}}</td>
          <td>{% if "[Т]" in note %}<span class="cat cat-T">🚛 Тягач</span>{% elif "[С]" in note %}<span class="cat cat-S">🚗 Співробітник</span>{% elif "[Л]" in note %}<span class="cat cat-L">🛠 Службове</span>{% elif "[Д]" in note %}<span class="cat cat-D">📦 Доставка</span>{% elif "[В]" in note %}<span class="cat cat-V">🚚 Водій</span>{% elif "[Ч]" in note %}<span class="cat cat-CH">🚫 Чорний список</span>{% elif "[П]" in note %}<span class="cat" style="background:#eff6ff;color:#1d4ed8">🔗 Причіп</span>{% elif note %}<span class="cat cat-R">👤 Інше</span>{% else %}<span class="cat cat-unk">❓ Невідомий</span>{% endif %}</td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{r.enter_dt}}</td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{r.exit_dt or "—"}}</td>
          <td><div style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.82rem;color:{{dcol}}">{{r.duration_str}}</div><div class="dur-bar"><div class="dur-fill" style="width:{{dpct}}%;background:{{dcol}}"></div></div></td>
        </tr>
        {% endfor %}
        {% if not dur_rows %}<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-dim)">Записів не знайдено</td></tr>{% endif %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- ══ НЕВІДОМІ АВТО ══ -->
  <div id="tab-unknown" class="tab-section">
    <form class="filter-bar" method="get" action="/stats">
      <input type="hidden" name="tab" value="unknown">
      <div class="fg"><label>З дати</label><input type="date" name="unk_start" class="fi" value="{{unk_start}}"></div>
      <div class="fg"><label>По дату</label><input type="date" name="unk_end" class="fi" value="{{unk_end}}"></div>
      <div class="fg" style="flex:1"><label>Пошук за номером</label>
        <div style="display:flex;gap:6px">
          <input type="text" name="unk_search" class="fi" style="flex:1" value="{{unk_search}}" placeholder="Частина номера...">
          <button type="submit" class="fb fb-primary">🔍 Знайти</button>
          <a href="/stats?tab=unknown" class="fb fb-ghost">✕ Скинути</a>
        </div>
      </div>
    </form>
    <div class="kpi-3">
      <div class="kpi c-orange"><div class="kpi-lbl">Невідомих авто</div><div class="kpi-val" style="color:var(--orange)">{{unk_unique}}</div><div class="kpi-sub">унікальних номерів</div></div>
      <div class="kpi c-red"><div class="kpi-lbl">Кількість подій</div><div class="kpi-val" style="color:var(--red)">{{unk_events}}</div><div class="kpi-sub">всього фіксацій</div></div>
      <div class="kpi c-blue"><div class="kpi-lbl">Діапазон</div><div class="kpi-val" style="color:var(--ua-blue)">{{unk_days}}</div><div class="kpi-sub">днів у фільтрі</div></div>
    </div>
    <div class="table-wrap">
      <div class="table-hdr">
        <div class="table-title">Невідомі авто — не знайдені в базі</div>
        <div class="table-cnt">Знайдено <b>{{unk_rows|length}}</b> номерів</div>
      </div>
      <table>
        <thead><tr><th>Номер авто</th><th>Перший візит</th><th>Останній візит</th><th>Кількість візитів</th><th>Фото</th><th>Дія</th></tr></thead>
        <tbody>
        {% for r in unk_rows %}
        <tr>
          <td><a href="/stats?tab=journal&search={{r.plate}}" class="plate"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text">{{r.plate}}</span></div></a></td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{r.first_seen}}</td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{r.last_seen}}</td>
          <td><div style="display:flex;align-items:center;gap:8px"><div class="top-bar" style="width:80px"><div class="top-bar-fill" style="width:{{([r.count/unk_max_count*100,100]|min)|int}}%"></div></div><span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.82rem;color:var(--ua-blue)">{{r.count}}</span></div></td>
          <td><div class="thumb-wrap"><img src="/img/{{r.last_subdir}}/{{r.last_file}}" class="thumb" alt=""><div class="thumb-preview"><img src="/img/{{r.last_subdir}}/{{r.last_file}}" alt=""></div></div></td>
          <td><a href="/base?prefill={{r.plate}}" class="fb fb-outline" style="font-size:.78rem;padding:5px 12px">+ Додати в базу</a></td>
        </tr>
        {% endfor %}
        {% if not unk_rows %}<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--text-dim)">Невідомих авто не знайдено</td></tr>{% endif %}
        </tbody>
      </table>
    </div>
  </div>


  <!-- ══ АНАЛІТИКА ══ -->
  <div id="tab-analytics" class="tab-section">

    {% set today_str = now_str %}
    <div class="insight-grid">
      <div class="insight" style="cursor:default">
        <div class="insight-icon">🕐</div>
        <div class="insight-title">Пік активності</div>
        <div class="insight-val">{{peak_hour}}:00 — {{peak_hour+1}}:00</div>
        <div class="insight-sub">найбільше в'їздів за всі дні</div>
      </div>
      <div class="insight" style="cursor:default">
        <div class="insight-icon">📅</div>
        <div class="insight-title">Найактивніший день тижня</div>
        <div class="insight-val">{{peak_weekday}}</div>
        <div class="insight-sub">в середньому більше всього в'їздів</div>
      </div>
      <div class="insight" style="cursor:default">
        <div class="insight-icon">⏱</div>
        <div class="insight-title">Середній час перебування</div>
        <div class="insight-val">{{avg_stay_all}}</div>
        <div class="insight-sub">по всіх завершених сесіях</div>
      </div>
      <a href="/stats?tab=analytics&modal=truck" class="insight" style="text-decoration:none;cursor:pointer" title="Натисни — детально">
        <div class="insight-icon">🚛</div>
        <div class="insight-title">Найчастіший тягач ↗</div>
        <div class="insight-val" style="font-size:1rem;color:var(--purple)">{{top_truck or "—"}}</div>
        <div class="insight-sub">{{top_truck_note or "немає тягачів в базі"}}</div>
      </a>
      <a href="/stats?tab=journal&cat=Д&start_date={{today_s}}&end_date={{today_s}}" class="insight" style="text-decoration:none;cursor:pointer" title="Натисни — журнал доставок сьогодні">
        <div class="insight-icon">📦</div>
        <div class="insight-title">Доставок сьогодні ↗</div>
        <div class="insight-val" style="color:var(--ua-blue)">{{today_delivery}}</div>
        <div class="insight-sub">натисни — журнал доставок</div>
      </a>
      <a href="/stats?tab=journal&start_date={{month_s}}&end_date={{today_s}}" class="insight" style="text-decoration:none;cursor:pointer" title="Натисни — журнал за місяць">
        <div class="insight-icon">🔄</div>
        <div class="insight-title">Постійних клієнтів ↗</div>
        <div class="insight-val" style="color:var(--green)">{{repeat_visitors}}</div>
        <div class="insight-sub">авто більше ніж 1 раз</div>
      </a>
    </div>

    <!-- Топ тягачів — розгортається при натисканні -->
    {% if active_tab == 'analytics' and request.args.get('modal') == 'truck' %}
    <div class="panel" style="border-color:var(--purple);margin-bottom:20px">
      <div class="panel-hdr" style="color:var(--purple)">🚛 Топ тягачів за кількістю відвідувань</div>
      <table>
        <thead><tr><th>Тягач</th><th>Власник</th><th>В'їздів</th><th>Частка</th></tr></thead>
        <tbody>
        {% for p, cnt in top_trucks_list %}
        {% set tnote = base.get(p,'') %}
        {% set towner = tnote[4:] if tnote|length > 3 else '—' %}
        {% set pct = (cnt / top_trucks_list[0][1] * 100)|int if top_trucks_list[0][1] > 0 else 0 %}
        <tr>
          <td><a href="/vehicle/{{p}}" class="plate" style="text-decoration:none"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text" style="font-size:.78rem">{{p}}</span></div></a></td>
          <td style="font-size:.85rem;color:var(--text-mid)">{{towner}}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--purple)">{{cnt}}</td>
          <td style="width:160px"><div style="background:var(--border);border-radius:4px;height:8px"><div style="background:var(--purple);border-radius:4px;height:8px;width:{{pct}}%"></div></div></td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      <div style="margin-top:12px"><a href="/stats?tab=analytics" class="fb fb-ghost" style="font-size:.8rem">✕ Закрити</a></div>
    </div>
    {% endif %}

    <div class="panel">
      <div class="panel-hdr">Теплова карта активності (день тижня × година)</div>
      <div style="overflow-x:auto;padding-bottom:8px">
        <div class="heatmap">
          <!-- Заголовки годин -->
          <div class="hm-cell"></div>
          {% for h in range(24) %}<div class="hm-head">{{h}}</div>{% endfor %}
          <!-- Рядки по днях тижня -->
          {% set days_uk = ["Пн","Вт","Ср","Чт","Пт","Сб","Нд"] %}
          {% set hm_max = heatmap_data|map('max')|max %}
          {% for di in range(7) %}
          <div class="hm-label">{{days_uk[di]}}</div>
          {% for h in range(24) %}
          {% set val = heatmap_data[di][h] %}
          {% set intensity = (val / hm_max * 100)|int if hm_max > 0 else 0 %}
          <div class="hm-cell" {% if val > 0 %}onclick="window.location.href='/stats?tab=journal&search={{h}}'" {% endif %}style="background:rgba(0,87,183,{{(intensity/100*0.85 + 0.05)|round(2)}});color:{{'#fff' if intensity > 40 else 'var(--text-dim)'}};cursor:{{'pointer' if val > 0 else 'default'}}" title="{{days_uk[di]}} {{h}}:00 — {{val}} подій">{{val if val > 0 else ''}}</div>
          {% endfor %}
          {% endfor %}
        </div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
      <div class="panel">
        <div class="panel-hdr">Топ за часом перебування</div>
        <table>
          <thead><tr><th>Номер авто</th><th>Власник</th><th>Максимум</th></tr></thead>
          <tbody>
          {% for r in top_by_duration %}
          {% set note = base.get(r.plate,'') %}
          {% set owner = note[4:] if note|length > 3 else '—' %}
          <tr>
            <td><a href="/vehicle/{{r.plate}}" class="plate" style="text-decoration:none"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text">{{r.plate}}</span></div></a></td>
            <td style="color:var(--text-mid);font-size:.82rem">{{owner}}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.82rem;color:var(--ua-blue)">{{r.max_dur}}</td>
          </tr>
          {% endfor %}
          {% if not top_by_duration %}<tr><td colspan="3" style="text-align:center;padding:20px;color:var(--text-dim)">Даних немає</td></tr>{% endif %}
          </tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-hdr">Нові авто по місяцях</div>
        <canvas id="newPlatesChart" style="max-height:220px"></canvas>
      </div>
    </div>

    <div class="panel">
      <div class="panel-hdr">Авто які давно не приїжджали (більше 30 днів)</div>
      <table>
        <thead><tr><th>Номер авто</th><th>Власник</th><th>Категорія</th><th>Останній візит</th><th>Днів тому</th></tr></thead>
        <tbody>
        {% for r in long_absent %}
        {% set note = base.get(r.plate,'') %}
        {% set owner = note[4:] if note|length > 3 else '—' %}
        <tr>
          <td><a href="/vehicle/{{r.plate}}" class="plate" style="text-decoration:none"><div class="plate-flag"><span>🇺🇦</span></div><div class="plate-body"><span class="plate-text" style="font-size:.78rem">{{r.plate}}</span></div></a></td>
          <td style="color:var(--text-mid);font-size:.82rem">{{owner}}</td>
          <td>{% if "[Т]" in note %}<span class="cat cat-T">🚛 Тягач</span>{% elif "[С]" in note %}<span class="cat cat-S">🚗 Співробітник</span>{% elif "[Л]" in note %}<span class="cat cat-L">🛠 Службове</span>{% elif "[Д]" in note %}<span class="cat cat-D">📦 Доставка</span>{% elif "[В]" in note %}<span class="cat cat-V">🚚 Водій</span>{% elif "[Ч]" in note %}<span class="cat cat-CH">🚫 Чорний список</span>{% elif "[П]" in note %}<span class="cat" style="background:#eff6ff;color:#1d4ed8">🔗 Причіп</span>{% elif note %}<span class="cat cat-R">👤 Інше</span>{% else %}<span class="cat cat-unk">❓ Невідомий</span>{% endif %}</td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{r.last_date}}</td>
          <td><span style="font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--orange)">{{r.days_ago}} днів</span></td>
        </tr>
        {% endfor %}
        {% if not long_absent %}<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-dim)">Всі авто приїжджали нещодавно</td></tr>{% endif %}
        </tbody>
      </table>
    </div>

  </div>

</div>
<script>
function switchTab(name, btn) {
  document.querySelectorAll(".tab-section").forEach(function(s){s.classList.remove("active");});
  document.querySelectorAll(".tab").forEach(function(t){t.classList.remove("active");});
  document.getElementById("tab-"+name).classList.add("active");
  if(btn) btn.classList.add("active");
  history.replaceState(null,"","/stats?tab="+name);
}
var initTab = "{{active_tab}}" || "traffic";
if(initTab !== "traffic"){
  var btn = document.querySelector(".tab[onclick*='"+initTab+"']");
  if(btn){btn.classList.add("active");document.querySelectorAll(".tab")[0].classList.remove("active");document.getElementById("tab-"+initTab).classList.add("active");document.getElementById("tab-traffic").classList.remove("active");}
}
new Chart(document.getElementById("daysChart"),{type:"bar",data:{labels:{{days_labels|tojson}},datasets:[{label:"В'їзд",data:{{days_in|tojson}},backgroundColor:"rgba(22,163,74,.7)",borderColor:"#16a34a",borderWidth:1},{label:"Виїзд",data:{{days_out|tojson}},backgroundColor:"rgba(220,38,38,.6)",borderColor:"#dc2626",borderWidth:1}]},options:{maintainAspectRatio:false,plugins:{legend:{labels:{color:"#475569",font:{family:"Nunito",size:11}}}},scales:{x:{ticks:{color:"#94a3b8",font:{size:9},maxRotation:45},grid:{color:"rgba(0,0,0,.04)"}},y:{ticks:{color:"#94a3b8",font:{size:9}},grid:{color:"rgba(0,0,0,.04)"}}}}});
new Chart(document.getElementById("hourChart"),{type:"line",data:{labels:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23],datasets:[{label:"В'їзд",data:{{hour_in|tojson}},borderColor:"#16a34a",backgroundColor:"rgba(22,163,74,.1)",tension:.3,fill:true,borderWidth:2},{label:"Виїзд",data:{{hour_out|tojson}},borderColor:"#dc2626",backgroundColor:"rgba(220,38,38,.08)",tension:.3,fill:true,borderWidth:2}]},options:{maintainAspectRatio:false,plugins:{legend:{labels:{color:"#475569",font:{family:"Nunito",size:11}}}},scales:{x:{ticks:{color:"#94a3b8",font:{size:9}},grid:{color:"rgba(0,0,0,.04)"}},y:{ticks:{color:"#94a3b8",font:{size:9}},grid:{color:"rgba(0,0,0,.04)"}}}}});

var npEl = document.getElementById("newPlatesChart");
if(npEl){
  var npChart = new Chart(npEl,{type:"bar",data:{labels:{{new_plates_labels|tojson}},datasets:[{label:"Нових авто",data:{{new_plates_data|tojson}},backgroundColor:"rgba(124,58,237,.7)",borderColor:"#7c3aed",borderWidth:1}]},options:{maintainAspectRatio:false,onClick:function(evt,el){if(!el.length)return;var idx=el[0].index;var lbl={{new_plates_labels|tojson}}[idx];var yr="{{today_s[:4]}}";var start=yr+"-"+lbl+"-01";var end=yr+"-"+lbl+"-28";window.location.href="/stats?tab=journal&start_date="+start+"&end_date="+end;},plugins:{tooltip:{callbacks:{title:function(items){return items[0].label+" — натисни щоб переглянути"}}},legend:{labels:{color:"#475569",font:{family:"Nunito",size:11}}}},scales:{x:{ticks:{color:"#94a3b8",font:{size:9}},grid:{color:"rgba(0,0,0,.04)"}},y:{ticks:{color:"#94a3b8",font:{size:9}},grid:{color:"rgba(0,0,0,.04)"}}}},cursor:"pointer"});
  npEl.style.cursor="pointer";
}
</script>
</body></html>'''

VEHICLE_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · {{plate}}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }
body{background:var(--bg);color:var(--text);font-family:"Nunito",sans-serif;min-height:100vh}
.topbar{background:var(--ua-blue);display:flex;align-items:center;padding:0 24px;height:56px;gap:14px;box-shadow:0 2px 8px rgba(0,87,183,.3)}
.brand{font-size:1.05rem;font-weight:700;color:#fff}
a.back{padding:6px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;text-decoration:none;font-size:.82rem;font-weight:600;transition:.15s}
a.back:hover{background:rgba(255,255,255,.25)}
.tb-sep{flex:1}
.container{max-width:1100px;margin:0 auto;padding:28px 24px}
.hero{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px 32px;margin-bottom:24px;box-shadow:var(--shadow-sm);display:flex;align-items:center;gap:32px;flex-wrap:wrap}
.hero-plate{display:inline-flex;align-items:stretch;border:3px solid #1a1a2e;border-radius:7px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.15)}
.hero-plate-flag{background:var(--ua-blue);width:22px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px}
.hero-plate-flag span{font-size:.5rem;line-height:1}
.hero-plate-body{background:#f5f5ee;padding:6px 18px;display:flex;align-items:center}
.hero-plate-text{font-family:"JetBrains Mono",monospace;font-weight:700;color:#111;font-size:1.6rem;letter-spacing:.06em}
.hero-info{flex:1}
.hero-owner{font-size:1.2rem;font-weight:700;color:var(--text);margin-bottom:6px}
.hero-note{font-size:.88rem;color:var(--text-mid);font-family:"JetBrains Mono",monospace}
.kpi-row{display:flex;gap:16px;flex-wrap:wrap;margin-top:16px}
.kpi-sm{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:12px 18px;min-width:120px}
.kpi-sm-lbl{font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px}
.kpi-sm-val{font-size:1.4rem;font-weight:700;font-family:"JetBrains Mono",monospace}
.section-title{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.section-title::before{content:"";display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px 24px;box-shadow:var(--shadow-sm);margin-bottom:20px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}
table{width:100%;border-collapse:collapse}
thead th{padding:10px 14px;text-align:left;font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;background:var(--surface2);border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);transition:.1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface3)}
tbody td{padding:10px 14px;vertical-align:middle;font-size:.88rem}
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:6px;font-size:.7rem;font-weight:700}
.badge-in{background:var(--green-light);color:var(--green)}
.badge-out{background:var(--red-light);color:var(--red)}
.badge-pit{background:var(--orange-light);color:var(--orange)}
.thumb-wrap{position:relative;width:64px;height:42px}
.thumb{width:100%;height:100%;object-fit:cover;border-radius:5px;border:1.5px solid var(--border);cursor:pointer;transition:.15s}
.thumb:hover{border-color:var(--ua-blue)}
.thumb-preview{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:9999;pointer-events:none;border-radius:8px;overflow:hidden;box-shadow:0 25px 60px rgba(0,0,0,.35)}
.thumb-wrap:hover .thumb-preview{display:block}
.thumb-preview img{max-width:75vw;max-height:75vh;display:block}
.timeline{position:relative;padding-left:28px}
.timeline::before{content:"";position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}
.tl-item{position:relative;margin-bottom:16px}
.tl-dot{position:absolute;left:-24px;top:4px;width:12px;height:12px;border-radius:50%;border:2px solid var(--surface);box-shadow:0 0 0 2px var(--border)}
.tl-dot.enter{background:var(--green);box-shadow:0 0 0 2px var(--green-light)}
.tl-dot.exit{background:var(--red);box-shadow:0 0 0 2px var(--red-light)}
.tl-dot.pit{background:var(--orange);box-shadow:0 0 0 2px var(--orange-light)}
.tl-content{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:10px 14px}
.tl-time{font-family:"JetBrains Mono",monospace;font-weight:700;font-size:.82rem;color:var(--text)}
.tl-date{font-size:.72rem;color:var(--text-dim);margin-top:1px}
.empty{text-align:center;padding:48px 20px;color:var(--text-dim);font-size:.88rem}
</style></head>
<body>
<div class="topbar">
  <div class="brand">🚛 АГРОТЕП</div>
  <div style="width:1px;height:24px;background:rgba(255,255,255,.2)"></div>
  <a href="javascript:history.back()" class="back">← Назад</a>
  <div class="tb-sep"></div>
  <span style="color:rgba(255,255,255,.7);font-size:.82rem;font-family:'JetBrains Mono',monospace">Картка автомобіля</span>
</div>
<div class="container">

  <!-- Шапка авто -->
  <div class="hero">
    <div class="hero-plate">
      <div class="hero-plate-flag"><span>🇺🇦</span></div>
      <div class="hero-plate-body"><span class="hero-plate-text">{{plate}}</span></div>
    </div>
    <div class="hero-info">
      <div class="hero-owner">{{owner or "Невідомий власник"}}</div>
      <div class="hero-note">{{note or "Не знайдено в базі"}}</div>
      <div class="kpi-row">
        <div class="kpi-sm">
          <div class="kpi-sm-lbl">Всього візитів</div>
          <div class="kpi-sm-val" style="color:var(--ua-blue)">{{total_visits}}</div>
        </div>
        <div class="kpi-sm">
          <div class="kpi-sm-lbl">Завершених сесій</div>
          <div class="kpi-sm-val" style="color:var(--green)">{{sessions|length}}</div>
        </div>
        {% if avg_duration %}
        <div class="kpi-sm">
          <div class="kpi-sm-lbl">Середній час</div>
          <div class="kpi-sm-val" style="color:var(--purple)">{{avg_duration}}</div>
        </div>
        {% endif %}
      </div>
    </div>
    <div>
      <a href="/base" style="padding:8px 18px;background:var(--ua-blue);color:#fff;border-radius:8px;text-decoration:none;font-weight:600;font-size:.88rem">🗄 Редагувати в базі</a>
    </div>
  </div>

  <div class="grid-2">
    <!-- Сесії -->
    <div class="panel">
      <div class="section-title">Сесії на території</div>
      {% if sessions %}
      <table>
        <thead><tr><th>В'їзд</th><th>Виїзд</th><th>Час перебування</th></tr></thead>
        <tbody>
        {% for s in sessions %}
        <tr>
          <td style="font-size:.82rem;color:var(--text-mid)">{{s.enter.date}} {{s.enter.time}}</td>
          <td style="font-size:.82rem;color:var(--text-mid)">{{s.exit.date}} {{s.exit.time}}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.82rem;color:var(--ua-blue)">{{s.duration}}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}<div class="empty">Завершених сесій не знайдено</div>{% endif %}
    </div>

    <!-- Хронологія -->
    <div class="panel">
      <div class="section-title">Хронологія подій</div>
      {% if events %}
      <div class="timeline">
        {% for e in events[:30] %}
        <div class="tl-item">
          <div class="tl-dot {{e.subdir if e.subdir in ['enter','exit','pit'] else ''}}"></div>
          <div class="tl-content">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
              <div>
                <div class="tl-time">{{e.time}}</div>
                <div class="tl-date">{{e.date}}</div>
              </div>
              {% if e.subdir=="enter" %}<span class="badge badge-in">▲ В'їзд</span>
              {% elif e.subdir=="exit" %}<span class="badge badge-out">▼ Виїзд</span>
              {% else %}<span class="badge" style="background:var(--orange-light);color:var(--orange)">⚙ Яма</span>{% endif %}
              <div class="thumb-wrap">
                <img src="/img/{{e.subdir}}/{{e.file}}" class="thumb" alt="">
                <div class="thumb-preview"><img src="/img/{{e.subdir}}/{{e.file}}" alt=""></div>
              </div>
            </div>
          </div>
        </div>
        {% endfor %}
        {% if events|length > 30 %}<div style="text-align:center;font-size:.82rem;color:var(--text-dim);padding:8px">...та ще {{events|length - 30}} подій</div>{% endif %}
      </div>
      {% else %}<div class="empty">Подій не знайдено</div>{% endif %}
    </div>
  </div>

</div>
</body></html>'''


# ══════════════════════════════════════════════════════════════════
# ГОЛОВНА СТОРІНКА
# ══════════════════════════════════════════════════════════════════

PRINT_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8">
<title>База пропусків — АГРОТЕП</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Arial',sans-serif;font-size:11pt;color:#000;background:#fff}
.no-print{margin:16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.btn-print{padding:10px 24px;background:#1d4ed8;color:#fff;border:none;border-radius:6px;font-size:1rem;font-weight:700;cursor:pointer}
.btn-print:hover{background:#1e40af}
.btn-back{padding:10px 18px;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:6px;color:#334155;text-decoration:none;font-size:.9rem}
.filter-hint{font-size:.85rem;color:#64748b}
.page{max-width:900px;margin:0 auto;padding:24px}
.header{text-align:center;margin-bottom:20px;border-bottom:2px solid #1d4ed8;padding-bottom:12px}
.header h1{font-size:16pt;font-weight:700;letter-spacing:.5px}
.header .meta{font-size:9pt;color:#64748b;margin-top:4px}
table{width:100%;border-collapse:collapse;margin-top:8px}
thead th{background:#1d4ed8;color:#fff;padding:8px 10px;text-align:left;font-size:9.5pt;font-weight:700;letter-spacing:.3px}
thead th:first-child{width:40px;text-align:center}
thead th:nth-child(2){width:130px}
tbody tr:nth-child(even){background:#f8fafc}
tbody tr:hover{background:#eff6ff}
tbody td{padding:7px 10px;border-bottom:1px solid #e2e8f0;font-size:10pt;vertical-align:middle}
td:first-child{text-align:center;color:#94a3b8;font-size:9pt}
.plate-cell{font-family:monospace;font-weight:700;font-size:11pt;letter-spacing:1px}
.cat-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:8.5pt;font-weight:700;background:#f1f5f9}
.footer{margin-top:20px;font-size:8pt;color:#94a3b8;text-align:right;border-top:1px solid #e2e8f0;padding-top:8px}
.summary{margin-bottom:12px;font-size:9.5pt;color:#475569;display:flex;gap:20px;flex-wrap:wrap}
.summary b{color:#1d4ed8}
@media print{
  .no-print{display:none!important}
  body{font-size:10pt}
  thead th{background:#1d4ed8!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  tbody tr:nth-child(even){background:#f8fafc!important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .page{padding:0}
}
</style></head>
<body>
<div class="no-print">
  <button class="btn-print" onclick="window.print()">🖨 Друкувати</button>
  <a href="/base" class="btn-back">← База</a>
  <span class="filter-hint">Тягачі не включені · {{total}} авто</span>
</div>
<div class="page">
  <div class="header">
    <h1>АГРОТЕП · Список допущених транспортних засобів</h1>
    <div class="meta">Згенеровано: {{generated}} &nbsp;·&nbsp; Всього записів: {{total}} (без тягачів)</div>
  </div>
  <div class="summary">
    {% set cnt = namespace(S=0,D=0,V=0,L=0,R=0,CH=0) %}
    {% for r in rows %}
      {% if 'Співробітник' in r.cat %}{% set cnt.S=cnt.S+1 %}
      {% elif 'Доставка' in r.cat %}{% set cnt.D=cnt.D+1 %}
      {% elif 'Водій' in r.cat %}{% set cnt.V=cnt.V+1 %}
      {% elif 'Службове' in r.cat %}{% set cnt.L=cnt.L+1 %}
      {% elif 'Чорний' in r.cat %}{% set cnt.CH=cnt.CH+1 %}
      {% else %}{% set cnt.R=cnt.R+1 %}{% endif %}
    {% endfor %}
    <span>🚗 Співробітники: <b>{{cnt.S}}</b></span>
    <span>📦 Доставка: <b>{{cnt.D}}</b></span>
    <span>🚚 Водії: <b>{{cnt.V}}</b></span>
    <span>🛠 Службові: <b>{{cnt.L}}</b></span>
    <span>👤 Гості: <b>{{cnt.R}}</b></span>
    {% if cnt.CH > 0 %}<span>🚫 Чорний список: <b>{{cnt.CH}}</b></span>{% endif %}
  </div>
  <table>
    <thead><tr>
      <th>№</th><th>Номер авто</th><th>Власник / Назва</th><th>Категорія</th>
    </tr></thead>
    <tbody>
    {% for r in rows %}
    <tr>
      <td>{{loop.index}}</td>
      <td class="plate-cell">{{r.plate}}</td>
      <td>{{r.owner}}</td>
      <td><span class="cat-badge" style="color:{{r.color}}">{{r.cat}}</span></td>
    </tr>
    {% endfor %}
    {% if not rows %}
    <tr><td colspan="4" style="text-align:center;padding:24px;color:#94a3b8">База порожня</td></tr>
    {% endif %}
    </tbody>
  </table>
  <div class="footer">АГРОТЕП · Термінал АНПР · {{generated}}</div>
</div>
</body></html>'''


MAIN_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · Термінал</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }

body{background:var(--bg);color:var(--text);font-family:'Nunito',sans-serif;font-size:14px;min-height:100vh}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── LAYOUT ──────────────────────────────── */
.shell{display:grid;grid-template-columns:240px 1fr;grid-template-rows:56px 1fr;min-height:100vh}
.topbar{grid-column:1/-1;background:var(--ua-blue);display:flex;align-items:center;padding:0 20px;gap:12px;position:sticky;top:0;z-index:200;box-shadow:0 2px 8px rgba(0,87,183,.3)}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:20px 0;position:sticky;top:56px;height:calc(100vh - 56px);overflow-y:auto;display:flex;flex-direction:column}
.main{padding:24px;background:var(--bg)}

/* ── TOPBAR ──────────────────────────────── */
.tb-brand{display:flex;align-items:center;gap:10px;color:#fff;font-weight:700;font-size:1.05rem;letter-spacing:-.01em}
.tb-brand-logo{background:rgba(255,255,255,.15);border-radius:8px;padding:5px 8px;font-size:1.1rem}
.tb-sep{flex:1}
.tb-sys{display:flex;gap:6px}
.tb-chip{display:flex;align-items:center;gap:5px;background:rgba(255,255,255,.12);border-radius:20px;padding:4px 10px;font-size:.72rem;color:rgba(255,255,255,.9);font-family:'JetBrains Mono',monospace;font-weight:500}
.tb-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.tb-actions{display:flex;gap:6px;margin-left:6px}
.tb-btn{padding:5px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;font-family:'Nunito',sans-serif;font-weight:600;font-size:.8rem;cursor:pointer;text-decoration:none;transition:.15s}
.tb-btn:hover{background:rgba(255,255,255,.25)}
.tb-btn-danger{background:rgba(220,38,38,.25);border-color:rgba(255,100,100,.4)}
.tb-btn-danger:hover{background:rgba(220,38,38,.45)}
.tb-clock{font-family:'JetBrains Mono',monospace;font-size:.72rem;color:rgba(255,255,255,.7);min-width:130px;text-align:right}

/* ── SIDEBAR ──────────────────────────────── */
.sb-section{padding:0 12px;margin-bottom:6px}
.sb-label{font-size:.68rem;font-weight:600;letter-spacing:.08em;color:var(--text-dim);padding:10px 8px 5px;text-transform:uppercase}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 12px;border-radius:8px;cursor:pointer;text-decoration:none;color:var(--text-mid);font-size:.88rem;font-weight:500;transition:.12s;margin-bottom:2px}
.sb-item:hover{background:var(--surface3);color:var(--text)}
.sb-item.active{background:var(--accent-light);color:var(--ua-blue);font-weight:600}
.sb-ico{width:20px;text-align:center;font-size:.95rem;flex-shrink:0}
.sb-badge{margin-left:auto;font-size:.68rem;font-weight:700;font-family:'JetBrains Mono',monospace;background:var(--surface3);border-radius:10px;padding:1px 7px;color:var(--text-dim)}
.sb-badge.green{background:var(--green-light);color:var(--green)}
.sb-badge.red{background:var(--red-light);color:var(--red)}
.sb-divider{height:1px;background:var(--border);margin:10px 16px}
.sb-sys-block{margin-top:auto;padding:16px}
.sb-sys-title{font-size:.68rem;font-weight:600;letter-spacing:.08em;color:var(--text-dim);text-transform:uppercase;margin-bottom:10px}
.meter-row{display:flex;align-items:center;gap:8px;margin-bottom:7px}
.meter-lbl{font-size:.68rem;font-family:'JetBrains Mono',monospace;color:var(--text-dim);width:32px;font-weight:600}
.meter-bar{flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden}
.meter-fill{height:100%;border-radius:3px;transition:width .4s ease}
.meter-val{font-size:.68rem;font-family:'JetBrains Mono',monospace;width:34px;text-align:right;font-weight:600}

/* ── STAT CARDS ──────────────────────────────── */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-bottom:16px}
.stat-card{
  background:var(--surface);border:1.5px solid var(--border);border-radius:10px;
  padding:10px 14px;cursor:pointer;transition:.15s;
  box-shadow:var(--shadow-sm);position:relative;overflow:hidden;
}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;right:0;height:3px;background:var(--border);transition:.2s}
.stat-card:hover{border-color:var(--border2);box-shadow:var(--shadow);transform:translateY(-1px)}
.stat-card:hover::after,.stat-card.active::after{background:var(--ua-blue)}
.stat-card.active{border-color:rgba(0,87,183,.3);background:linear-gradient(135deg,#fff,var(--accent-light))}
.stat-card.c-green::after{background:var(--green)}
.stat-card.c-green.active,.stat-card.c-green:hover{border-color:rgba(22,163,74,.25)}
.stat-card.c-red::after{background:var(--red)}
.stat-card.c-red.active,.stat-card.c-red:hover{border-color:rgba(220,38,38,.25)}
.stat-lbl{font-size:.65rem;font-weight:600;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:4px}
.stat-val{font-size:1.4rem;font-weight:700;line-height:1;font-family:'JetBrains Mono',monospace;color:var(--text)}
.stat-sub{font-size:.72rem;color:var(--text-dim);margin-top:5px;font-weight:500}

/* ── PANELS ROW ──────────────────────────────── */
.panels-row{display:grid;grid-template-columns:1fr 300px;gap:16px;margin-bottom:20px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px 20px;box-shadow:var(--shadow-sm)}
.panel-hdr{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.panel-hdr::before{content:'';display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}

/* ── FORM CONTROLS ──────────────────────────────── */
.filter-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
.fg{display:flex;flex-direction:column;gap:4px}
.fg label{font-size:.72rem;font-weight:600;color:var(--text-mid)}
.fi,.fs{
  background:var(--surface2);border:1.5px solid var(--border);color:var(--text);
  padding:8px 11px;border-radius:7px;font-family:'Nunito',sans-serif;font-size:.88rem;
  outline:none;transition:.15s;
}
.fi:focus,.fs:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
.fs{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2394a3b8'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.fb{
  padding:8px 16px;border-radius:7px;font-family:'Nunito',sans-serif;font-weight:600;
  font-size:.88rem;cursor:pointer;border:none;transition:.15s;text-decoration:none;
  display:inline-flex;align-items:center;gap:5px;
}
.fb-primary{background:var(--ua-blue);color:#fff}
.fb-primary:hover{background:var(--accent-hover);box-shadow:0 3px 8px rgba(0,87,183,.25)}
.fb-ghost{background:transparent;border:1.5px solid var(--border2);color:var(--text-mid)}
.fb-ghost:hover{border-color:var(--red);color:var(--red)}
.fb-outline{background:transparent;border:1.5px solid var(--border2);color:var(--text-mid)}
.fb-outline:hover{border-color:var(--ua-blue);color:var(--ua-blue)}

/* ── TABLE ──────────────────────────────── */
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:var(--shadow-sm)}
.table-hdr{display:flex;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid var(--border)}
.table-title{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;display:flex;align-items:center;gap:6px}
.table-title::before{content:'';display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.table-cnt{font-size:.72rem;color:var(--text-dim);font-family:'JetBrains Mono',monospace}
.table-cnt b{color:var(--ua-blue)}

table{width:100%;border-collapse:collapse}
thead th{
  padding:10px 14px;text-align:left;
  font-size:.68rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;
  background:var(--surface2);border-bottom:1px solid var(--border);white-space:nowrap;
}
tbody tr{border-bottom:1px solid var(--border);transition:.1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface3)}
tbody td{padding:11px 14px;vertical-align:middle}

.tr-inside{background:linear-gradient(90deg,rgba(22,163,74,.04),transparent)}
.tr-inside:hover{background:linear-gradient(90deg,rgba(22,163,74,.08),var(--surface3)) !important}
.tr-black{background:linear-gradient(90deg,rgba(220,38,38,.06),transparent) !important;animation:pulse-danger 3s ease-in-out infinite}
@keyframes pulse-danger{0%,100%{opacity:1}50%{opacity:.7}}

/* ── UA PLATE ──────────────────────────────── */
.plate{
  display:inline-flex;align-items:stretch;
  border:2px solid #1a1a2e;border-radius:5px;overflow:hidden;
  text-decoration:none;transition:.15s;
  box-shadow:0 1px 4px rgba(0,0,0,.12);
}
.plate:hover{box-shadow:0 2px 8px rgba(0,87,183,.3);border-color:var(--ua-blue);transform:scale(1.02)}
.plate-flag{
  background:var(--ua-blue);width:14px;min-height:28px;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px;flex-shrink:0;
}
.plate-flag span{font-size:.35rem;line-height:1}
.plate-body{background:#f5f5ee;padding:3px 10px;display:flex;align-items:center}
.plate-text{font-family:'JetBrains Mono',monospace;font-weight:700;color:#111;font-size:.92rem;letter-spacing:.04em}
.plate.invalid .plate-flag{background:var(--red)}
.plate.invalid .plate-body{background:#fff5f5}
.plate.invalid .plate-text{color:var(--red)}
.plate-hint{font-size:.65rem;color:var(--orange);margin-top:3px;font-family:'JetBrains Mono',monospace;font-weight:600}

/* ── BADGES ──────────────────────────────── */
.badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:6px;font-size:.7rem;font-weight:700;letter-spacing:.02em}
.badge-in{background:var(--green-light);color:var(--green)}
.badge-out{background:var(--red-light);color:var(--red)}
.badge-pit{background:var(--orange-light);color:var(--orange)}
.duration{font-size:.68rem;color:#be185d;font-family:'JetBrains Mono',monospace;font-weight:700;margin-top:3px}

.cat{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:6px;font-size:.7rem;font-weight:700}
.cat-T{background:var(--purple-light);color:var(--purple)}
.cat-S{background:var(--accent-light);color:var(--ua-blue)}
.cat-L{background:var(--orange-light);color:var(--orange)}
.cat-R{background:var(--surface3);color:var(--text-dim)}
.cat-CH{background:var(--red-light);color:var(--red)}
.cat-D{background:#e0f2fe;color:#0369a1}
.cat-V{background:#e0fffe;color:#0891b2}

/* ── THUMB ──────────────────────────────── */
.thumb-wrap{position:relative;width:72px;height:46px}
.thumb{width:100%;height:100%;object-fit:cover;border-radius:6px;border:1.5px solid var(--border);cursor:pointer;transition:.15s}
.thumb:hover{border-color:var(--ua-blue);box-shadow:0 2px 8px rgba(0,87,183,.2)}
.thumb-preview{display:none;position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:9999;pointer-events:none;border-radius:8px;overflow:hidden;box-shadow:0 25px 60px rgba(0,0,0,.35)}
.thumb-wrap:hover .thumb-preview{display:block}
.thumb-preview img{max-width:75vw;max-height:75vh;display:block}

/* ── ACTION BUTTONS ──────────────────────────────── */
.act-group{display:flex;gap:4px}
.act-btn{
  background:var(--surface2);border:1.5px solid var(--border);color:var(--text-mid);
  padding:5px 9px;border-radius:6px;cursor:pointer;font-size:.8rem;transition:.15s;
}
.act-btn:hover{background:var(--accent-light);border-color:var(--ua-blue);color:var(--ua-blue)}
.act-btn.del:hover{background:var(--red-light);border-color:var(--red);color:var(--red)}

/* ── NOTICE BAR ──────────────────────────────── */
.notice{
  background:var(--red-light);border:1px solid rgba(220,38,38,.2);border-left:4px solid var(--red);
  border-radius:8px;padding:11px 16px;margin-bottom:18px;
  display:flex;align-items:center;gap:10px;font-size:.88rem;color:var(--red);font-weight:500;
}
.notice a{color:var(--red);font-weight:700}

/* ── PAGINATION ──────────────────────────────── */
.pagination{display:flex;gap:4px;justify-content:center;margin-top:18px}
.pg{
  background:var(--surface);border:1.5px solid var(--border);color:var(--text-mid);
  padding:6px 13px;border-radius:7px;font-size:.8rem;cursor:pointer;
  text-decoration:none;transition:.15s;font-family:'JetBrains Mono',monospace;font-weight:600;
}
.pg:hover,.pg.on{background:var(--ua-blue);border-color:var(--ua-blue);color:#fff}
.pg.dots{cursor:default;border-color:transparent;background:transparent;color:var(--text-dim)}
</style></head>
<body>
<audio id="snd" src="https://actions.google.com/sounds/v1/alarms/beep_short.ogg" preload="auto"></audio>

<div class="shell">

<!-- ══ TOPBAR ══ -->
<header class="topbar">
  <a href="/" class="tb-brand" style="text-decoration:none">
    <div class="tb-brand-logo">🚛</div>
    АГРОТЕП <span style="font-weight:300;opacity:.7;margin-left:2px">· Термінал</span>
  </a>
  <div class="tb-sep"></div>
  {% if si %}
  <div class="tb-sys">
    <div class="tb-chip"><div class="tb-dot" style="background:{{si.cpu_color}}"></div>CPU {{si.cpu_p}}%</div>
    <div class="tb-chip"><div class="tb-dot" style="background:{{si.ram_color}}"></div>RAM {{si.ram_p}}%</div>
    <div class="tb-chip"><div class="tb-dot" style="background:{{si.disk_color}}"></div>{{si.disk_p}}% · {{si.disk_free}}GB</div>
  </div>
  {% endif %}
  <div class="tb-actions">
    {% if session['user']=='admin' %}<a href="/users" class="tb-btn">👥 Юзери</a>{% endif %}
    <a href="/check_vehicles" class="tb-btn" style="background:rgba(255,215,0,.2);border-color:rgba(255,215,0,.4)">📋 Перевірка</a>
    <a href="/base" class="tb-btn">🗄 База</a>
    <a href="/api/v1/vehicles" class="tb-btn" target="_blank">📡 API</a>
    <a href="/logout" class="tb-btn tb-btn-danger">Вихід</a>
  </div>
  <button id="themeBtn" class="tb-btn" style="font-size:.85rem" title="Перемкнути тему">🌙</button>
  <div class="tb-clock" id="clock"></div>
</header>

<!-- ══ SIDEBAR ══ -->
<aside class="sidebar">
  <div class="sb-section">
    <div class="sb-label">Стан</div>
    <a href="/?dir=inside" class="sb-item {{'active' if dir_f=='inside' and not cat_f}}">
      <span class="sb-ico">🟢</span>На території<span class="sb-badge green">{{len(inside_rows)}}</span>
    </a>
    <a href="/?dir=enter" class="sb-item {{'active' if dir_f=='enter'}}">
      <span class="sb-ico">⬆️</span>В'їзди
    </a>
    <a href="/?dir=exit" class="sb-item {{'active' if dir_f=='exit'}}">
      <span class="sb-ico">⬇️</span>Виїзди
    </a>
    <a href="/?dir=overstay" class="sb-item {{'active' if dir_f=='overstay'}}">
      <span class="sb-ico">⏰</span>Забуті (24г+)<span class="sb-badge red">{{len(overstay)}}</span>
    </a>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-section">
    <div class="sb-label">Категорії</div>
    <a href="/?dir=inside&cat=Т" class="sb-item {{'active' if cat_f=='Т'}}"><span class="sb-ico">🚛</span>Тягачі<span class="sb-badge">{{stats['Т']}}</span></a>
    <a href="/?dir=inside&cat=С" class="sb-item {{'active' if cat_f=='С'}}"><span class="sb-ico">🚗</span>Співробітники<span class="sb-badge">{{stats['С']}}</span></a>
    <a href="/?dir=inside&cat=Л" class="sb-item {{'active' if cat_f=='Л'}}"><span class="sb-ico">🛠</span>Службові<span class="sb-badge">{{stats['Л']}}</span></a>
    <a href="/?dir=inside&cat=Д" class="sb-item {{'active' if cat_f=='Д'}}"><span class="sb-ico">📦</span>Доставка<span class="sb-badge">{{stats['Д']}}</span></a>
    <a href="/?dir=inside&cat=В" class="sb-item {{'active' if cat_f=='В'}}"><span class="sb-ico">🚚</span>Водії<span class="sb-badge">{{stats['В']}}</span></a>
    <a href="/?dir=inside&cat=Р" class="sb-item {{'active' if cat_f=='Р'}}"><span class="sb-ico">👤</span>Інші<span class="sb-badge">{{stats['Р']}}</span></a>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-section">
    <div class="sb-label">Звіти</div>
    <a href="/stats" class="sb-item"><span class="sb-ico">📊</span>Статистика</a>
  </div>

  {% if si %}
  <div class="sb-sys-block">
    <div class="sb-sys-title">Система</div>
    <div class="meter-row">
      <span class="meter-lbl" style="color:{{si.cpu_color}}">CPU</span>
      <div class="meter-bar"><div class="meter-fill" style="width:{{si.cpu_p}}%;background:{{si.cpu_color}}"></div></div>
      <span class="meter-val" style="color:{{si.cpu_color}}">{{si.cpu_p}}%</span>
    </div>
    <div class="meter-row">
      <span class="meter-lbl" style="color:{{si.ram_color}}">RAM</span>
      <div class="meter-bar"><div class="meter-fill" style="width:{{si.ram_p}}%;background:{{si.ram_color}}"></div></div>
      <span class="meter-val" style="color:{{si.ram_color}}">{{si.ram_p}}%</span>
    </div>
    <div class="meter-row">
      <span class="meter-lbl" style="color:{{si.disk_color}}">DSK</span>
      <div class="meter-bar"><div class="meter-fill" style="width:{{si.disk_p}}%;background:{{si.disk_color}}"></div></div>
      <span class="meter-val" style="color:{{si.disk_color}}">{{si.disk_p}}%</span>
    </div>
  </div>
  {% endif %}
</aside>

<!-- ══ MAIN ══ -->
<main class="main">

  {% if overstay|length > 0 and dir_f != 'overstay' %}
  <div class="notice">
    ⏰ <strong>{{overstay|length}} авто</strong> на території понад 24 години —
    <a href="/?dir=overstay">переглянути</a>
  </div>
  {% endif %}

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card c-green {{'active' if dir_f=='inside' and not cat_f}}" onclick="location.href='/?dir=inside'">
      <div class="stat-lbl">На терит.</div>
      <div class="stat-val" style="color:var(--green)">{{len(inside_rows)}}</div>
      <div class="stat-sub">зараз</div>
    </div>
    <div class="stat-card c-red {{'active' if dir_f=='overstay'}}" onclick="location.href='/?dir=overstay'">
      <div class="stat-lbl">Забуті</div>
      <div class="stat-val" style="color:var(--red)">{{len(overstay)}}</div>
      <div class="stat-sub">&gt;24 год</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='Т'}}" onclick="location.href='/?dir=inside&cat=Т'">
      <div class="stat-lbl">Тягачі</div>
      <div class="stat-val" style="color:var(--purple)">{{stats['Т']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='С'}}" onclick="location.href='/?dir=inside&cat=С'">
      <div class="stat-lbl">Співроб.</div>
      <div class="stat-val" style="color:var(--ua-blue)">{{stats['С']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='Л'}}" onclick="location.href='/?dir=inside&cat=Л'">
      <div class="stat-lbl">Службові</div>
      <div class="stat-val" style="color:var(--orange)">{{stats['Л']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='Д'}}" onclick="location.href='/?dir=inside&cat=Д'">
      <div class="stat-lbl">Доставка</div>
      <div class="stat-val" style="color:#0891b2">{{stats['Д']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='В'}}" onclick="location.href='/?dir=inside&cat=В'">
      <div class="stat-lbl">Водії</div>
      <div class="stat-val" style="color:#0891b2">{{stats['В']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
    <div class="stat-card {{'active' if cat_f=='Р'}}" onclick="location.href='/?dir=inside&cat=Р'">
      <div class="stat-lbl">Інші</div>
      <div class="stat-val">{{stats['Р']}}</div>
      <div class="stat-sub">на терит.</div>
    </div>
  </div>

  <!-- Filter -->
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-hdr">Фільтр подій</div>
      <form class="filter-row">
        <div class="fg"><label>З дати</label><input type="date" name="start_date" class="fi" value="{{s_date}}"></div>
        <div class="fg"><label>По дату</label><input type="date" name="end_date" class="fi" value="{{e_date}}"></div>
        <div class="fg"><label>Напрямок</label>
          <select name="dir" class="fs" style="min-width:130px">
            <option value="">Всі події</option>
            <option value="enter" {{'selected' if dir_f=='enter'}}>⬆️ В'їзд</option>
            <option value="exit" {{'selected' if dir_f=='exit'}}>⬇️ Виїзд</option>
            <option value="inside" {{'selected' if dir_f=='inside'}}>🟢 На терит.</option>
            <option value="pit" {{'selected' if dir_f=='pit'}}>⚙️ Яма</option>
          </select>
        </div>
        <div class="fg"><label>Категорія</label>
          <select name="cat" class="fs" style="min-width:145px">
            <option value="">Всі категорії</option>
            <option value="Т" {{'selected' if cat_f=='Т'}}>🚛 Тягачі</option>
            <option value="С" {{'selected' if cat_f=='С'}}>🚗 Співробітники</option>
            <option value="Д" {{'selected' if cat_f=='Д'}}>📦 Доставка</option>
            <option value="В" {{'selected' if cat_f=='В'}}>🚚 Водії</option>
            <option value="Л" {{'selected' if cat_f=='Л'}}>🛠 Службові</option>
            <option value="Р" {{'selected' if cat_f=='Р'}}>👤 Інші</option>
          </select>
        </div>

        <div class="fg" style="flex:1"><label>Пошук</label>
          <div style="display:flex;gap:6px">
            <input type="text" name="search" class="fi" style="flex:1" value="{{search_raw}}" placeholder="Номер або прізвище...">
            <button type="submit" class="fb fb-primary">🔍 Знайти</button>
            <a href="/" class="fb fb-ghost">✕</a>
          </div>
        </div>
      </form>
  </div>

  <!-- Table -->
  <div class="table-wrap">
    <div class="table-hdr">
      <div class="table-title">Журнал подій</div>
      <div class="table-cnt">Показано <b>{{rows_slice|length}}</b> з {{total_rows}}</div>
    </div>
    <table>
      <thead><tr>
        <th>Час</th><th>Дія</th><th>Номер</th><th>Власник</th><th>Кат.</th><th>Фото</th><th style="width:100px">Дії</th>
      </tr></thead>
      <tbody>
      {% for r in rows_slice %}
      {% set n = base.get(r.norm_plate, "") %}
      {% set is_black = '[Ч]' in n.upper() %}
      {% set is_inside = r.subdir in ['enter','pit'] %}
      <tr class="{{ 'tr-black' if is_black else ('tr-inside' if is_inside else '') }}">
        <td>
          <div style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.88rem;color:var(--text)">{{r.time}}</div>
          <div style="font-size:.72rem;color:var(--text-dim);margin-top:1px">{{r.date}}</div>
        </td>
        <td>
          {% if r.subdir == 'enter' %}<span class="badge badge-in">▲ В'їзд</span>
          {% elif r.subdir == 'exit' %}<span class="badge badge-out">▼ Виїзд</span>
          {% else %}<span class="badge badge-pit">⚙ Яма</span>{% endif %}
          {% if r.file in durations %}<div class="duration">⏱ {{durations[r.file]}}</div>{% endif %}
        </td>
        <td>
          <a href="{{ make_url(search_p=r.plate) }}" class="plate {{ 'invalid' if not is_standard_ua(r.plate) }}">
            <div class="plate-flag">
              <span>🇺🇦</span>
            </div>
            <div class="plate-body"><span class="plate-text">{{r.plate}}</span></div>
          </a>
          {% if r.norm_plate in similar_hints %}
          <div class="plate-hint">≈ {{similar_hints[r.norm_plate]}}</div>
          {% endif %}
        </td>
        <td style="font-size:.88rem;color:var(--text);max-width:160px">
          {% set owner = base.get(r.norm_plate, base.get(similar_hints.get(r.norm_plate), '')) %}
          {% set owner_clean = owner.replace('[Т] ','').replace('[С] ','').replace('[Л] ','').replace('[Р] ','').replace('[Д] ','').replace('[В] ','').replace('[Ч] ','') %}
          {% if owner_clean %}{{ owner_clean }}{% else %}<span style="color:var(--text-dim)">—</span>{% endif %}
        </td>
        <td>
          {% set pk = r.norm_plate if r.norm_plate in base else similar_hints.get(r.norm_plate, r.norm_plate) %}
          {% set n2 = base.get(pk, "") %}
          {% if "[Т]" in n2 %}<span class="cat cat-T">🚛 Тягач</span>
          {% elif "[С]" in n2 %}<span class="cat cat-S">🚗 Співробітник</span>
          {% elif "[Л]" in n2 %}<span class="cat cat-L">🛠 Службове</span>
          {% elif "[Д]" in n2 %}<span class="cat cat-D">📦 Доставка</span>
          {% elif "[В]" in n2 %}<span class="cat cat-V">🚚 Водій</span>
          {% elif "[Ч]" in n2 %}<span class="cat cat-CH">🚫 Чорний список</span>
          {% else %}<span class="cat cat-R">👤 Гість</span>{% endif %}
        </td>
        <td>
          <div class="thumb-wrap">
            <img src="/img/{{r.subdir}}/{{r.file}}" class="thumb" alt=""
                 onclick="window.location.href='/vehicle/{{r.norm_plate}}'" style="cursor:pointer">
            <div class="thumb-preview"><img src="/img/{{r.subdir}}/{{r.file}}" alt=""></div>
          </div>
        </td>
        <td>
          <div class="act-group">
            {% if r.subdir in ['enter','pit'] %}
            <button class="act-btn btn-force-exit" data-plate="{{r.norm_plate}}" title="Позначити як виїхав" style="color:var(--red)">🚗↗</button>
            {% endif %}
            <button class="act-btn btn-swap" data-file="{{r.file}}" data-sub="{{r.subdir}}" title="Змінити напрямок">⇄</button>
            <button class="act-btn btn-edit" data-file="{{r.file}}" data-sub="{{r.subdir}}" data-plate="{{r.plate}}" title="Редагувати">✎</button>
            <button class="act-btn del btn-del" data-file="{{r.file}}" data-sub="{{r.subdir}}" title="Видалити">✕</button>
          </div>
        </td>
      </tr>
      {% endfor %}
      {% if not rows_slice %}
      <tr><td colspan="7" style="text-align:center;padding:48px 20px;color:var(--text-dim);font-size:.88rem">
        Записів не знайдено
      </td></tr>
      {% endif %}
      </tbody>
    </table>
  </div>

  {% if total_p > 1 %}
  <div class="pagination">
    <a href="{{ make_url(p=max(1,page-1)) }}" class="pg">«</a>
    {% for i in range(1, total_p+1) %}
      {% if i == page %}<span class="pg on">{{i}}</span>
      {% elif i==1 or i==total_p or (i>=page-2 and i<=page+2) %}<a href="{{ make_url(p=i) }}" class="pg">{{i}}</a>
      {% elif i==page-3 or i==page+3 %}<span class="pg dots">…</span>{% endif %}
    {% endfor %}
    <a href="{{ make_url(p=min(total_p,page+1)) }}" class="pg">»</a>
  </div>
  {% endif %}

</main>
</div>

<script>
// Clock
function tick(){
  var n = new Date();
  var d = n.toLocaleDateString("uk-UA",{day:"2-digit",month:"2-digit",year:"numeric"});
  var t = n.toLocaleTimeString("uk-UA",{hour:"2-digit",minute:"2-digit",second:"2-digit"});
  document.getElementById("clock").textContent = d + " · " + t;
}
tick(); setInterval(tick, 1000);

// Chart removed

// Actions via data-attributes — no Ukrainian text in JS strings
document.addEventListener("click", function(e) {
  var btn = e.target.closest("button");
  if (!btn) return;

  if (btn.classList.contains("btn-swap")) {
    var f = btn.dataset.file, s = btn.dataset.sub;
    if (confirm("Змінити напрямок?")) {
      fetch("/swap", {method: "POST", body: new URLSearchParams({f: f, s: s})})
        .then(function(resp) { if (resp.ok) location.reload(); });
    }
    return;
  }

  if (btn.classList.contains("btn-edit")) {
    var f2 = btn.dataset.file, s2 = btn.dataset.sub, p2 = btn.dataset.plate;
    var newPlate = prompt("Новий номер:", p2);
    if (newPlate && newPlate.trim()) {
      fetch("/edit", {method: "POST", body: new URLSearchParams({old_name: f2, subdir: s2, new_plate: newPlate.trim().toUpperCase()})})
        .then(function(resp) { if (resp.ok) location.reload(); });
    }
    return;
  }

  if (btn.classList.contains("btn-force-exit")) {
    var fpl = btn.dataset.plate;
    if (confirm("\u041f\u043e\u0437\u043d\u0430\u0447\u0438\u0442\u0438 \u0430\u0432\u0442\u043e \u044f\u043a \u0432\u0438\u0457\u0445\u0430\u043b\u043e?")) {
      fetch("/force_exit", {method: "POST", body: new URLSearchParams({plate: fpl})})
        .then(function(resp) { if (resp.ok) location.reload(); });
    }
    return;
  }

  if (btn.classList.contains("btn-del")) {
    var f3 = btn.dataset.file, s3 = btn.dataset.sub;
    if (confirm("Видалити цей запис?")) {
      fetch("/edit", {method: "POST", body: new URLSearchParams({old_name: f3, subdir: s3, new_plate: ""})})
        .then(function(resp) { if (resp.ok) location.reload(); });
    }
    return;
  }
});

// Auto-reload + Push notifications
var _lf = null;

function requestNotifyPermission() {
  if ("Notification" in window && Notification.permission === "default") {
    Notification.requestPermission();
  }
}
requestNotifyPermission();

function sendNotification(plate, direction) {
  if ("Notification" in window && Notification.permission === "granted") {
    new Notification("АГРОТЕП: " + direction, {
      body: "Номер: " + plate,
      icon: "/favicon.ico"
    });
  }
}

setInterval(function() {
  fetch("/api/latest_file")
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (_lf !== null && d.file !== _lf) {
        // Витягуємо номер з імені файлу
        var parts = d.file ? d.file.replace(".jpg","").split("_") : [];
        var plate = parts.length > 0 ? parts[parts.length-1] : "???";
        var dir = d.subdir === "exit" ? "Виїзд" : "Заїзд";
        sendNotification(plate, dir);
        location.reload();
      }
      _lf = d.file;
    })
    .catch(function(){});
}, 15000);

// Theme switcher
var DARK_VARS = "--bg:#0f172a;--surface:#1e293b;--surface2:#263244;--surface3:#2d3f55;--border:#2d3f55;--border2:#3d5068;--ua-blue:#3b82f6;--ua-yellow:#ffd700;--accent:#3b82f6;--accent-light:rgba(59,130,246,.18);--accent-hover:#2563eb;--green:#22c55e;--green-light:rgba(34,197,94,.18);--red:#ef4444;--red-light:rgba(239,68,68,.18);--orange:#f59e0b;--orange-light:rgba(245,158,11,.18);--purple:#a78bfa;--purple-light:rgba(167,139,250,.18);--text:#f1f5f9;--text-mid:#94a3b8;--text-dim:#64748b;--shadow-sm:0 1px 3px rgba(0,0,0,.4);--shadow:0 4px 6px rgba(0,0,0,.3);--shadow-lg:0 10px 25px rgba(0,0,0,.5)";

function applyTheme(dark) {
  var root = document.documentElement;
  if (dark) {
    DARK_VARS.split(";").forEach(function(v) {
      if (!v.trim()) return;
      var idx = v.indexOf(":");
      root.style.setProperty(v.slice(0,idx).trim(), v.slice(idx+1).trim());
    });
    document.getElementById("themeBtn").textContent = "☀️";
    document.querySelector(".topbar").style.background = "#1e3a5f";
  } else {
    // Reset all custom props
    DARK_VARS.split(";").forEach(function(v) {
      if (!v.trim()) return;
      var idx = v.indexOf(":");
      root.style.removeProperty(v.slice(0,idx).trim());
    });
    document.getElementById("themeBtn").textContent = "🌙";
    document.querySelector(".topbar").style.background = "";
  }
}

var isDark = localStorage.getItem("theme") === "dark";
applyTheme(isDark);

document.getElementById("themeBtn").addEventListener("click", function() {
  isDark = !isDark;
  localStorage.setItem("theme", isDark ? "dark" : "light");
  applyTheme(isDark);
});
</script>
</body></html>'''


# ══════════════════════════════════════════════════════════════════
# СТОРІНКА БАЗИ
# ══════════════════════════════════════════════════════════════════
BASE_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · База</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }
body{background:var(--bg);color:var(--text);font-family:'Nunito',sans-serif;min-height:100vh}
.topbar{background:var(--ua-blue);display:flex;align-items:center;padding:0 24px;height:56px;gap:14px;box-shadow:0 2px 8px rgba(0,87,183,.3)}
.brand{font-size:1.05rem;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}
a.back{padding:6px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;text-decoration:none;font-size:.82rem;font-weight:600;transition:.15s}
a.back:hover{background:rgba(255,255,255,.25)}
.container{max-width:1100px;margin:0 auto;padding:28px 24px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;margin-bottom:20px;box-shadow:var(--shadow-sm)}
.panel-hdr{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:18px;display:flex;align-items:center;gap:6px}
.panel-hdr::before{content:'';display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.add-form{display:grid;grid-template-columns:180px 1fr 180px auto;gap:12px;align-items:end}
.fg{display:flex;flex-direction:column;gap:4px}
.fg label{font-size:.75rem;font-weight:600;color:var(--text-mid)}
.fi,.fs{background:var(--surface2);border:1.5px solid var(--border);color:var(--text);padding:9px 13px;border-radius:8px;font-family:'Nunito',sans-serif;font-size:.9rem;outline:none;width:100%;transition:.15s}
.fi:focus,.fs:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
.fs{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%2394a3b8'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.fb-add{padding:9px 22px;background:var(--ua-blue);border:none;border-radius:8px;color:#fff;font-family:'Nunito',sans-serif;font-weight:700;font-size:.9rem;cursor:pointer;transition:.15s;align-self:end;white-space:nowrap}
.fb-add:hover{background:var(--accent-hover);box-shadow:0 3px 8px rgba(0,87,183,.25)}
.stats-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.stat-chip{display:flex;align-items:center;gap:6px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:6px 14px;font-size:.75rem;font-weight:600;color:var(--text-mid)}
.stat-chip b{font-family:'JetBrains Mono',monospace;font-size:.8rem}
.search-wrap{margin-bottom:16px}
.search-wrap input{background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;color:var(--text);padding:9px 14px;font-family:'Nunito',sans-serif;font-size:.9rem;outline:none;width:100%;max-width:380px;transition:.15s}
.search-wrap input:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
table{width:100%;border-collapse:collapse}
thead th{padding:10px 16px;text-align:left;font-size:.7rem;font-weight:700;letter-spacing:.05em;color:var(--text-dim);text-transform:uppercase;background:var(--surface2);border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);transition:.1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface3)}
tbody td{padding:11px 16px;vertical-align:middle;font-size:.9rem}
.plate-mono{font-family:'JetBrains Mono',monospace;font-weight:700;color:var(--text);font-size:.9rem}
.cat-pill{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:6px;font-size:.72rem;font-weight:700}
.del-btn{background:transparent;border:1.5px solid rgba(220,38,38,.3);border-radius:6px;color:rgba(220,38,38,.7);padding:4px 12px;cursor:pointer;font-size:.78rem;font-family:'Nunito',sans-serif;font-weight:600;transition:.15s}
.del-btn:hover{border-color:var(--red);color:var(--red);background:var(--red-light)}
</style></head>
<body>
<div class="topbar">
  <div class="brand">🚛 АГРОТЕП</div>
  <div style="width:1px;height:24px;background:rgba(255,255,255,.2)"></div>
  <a href="/" class="back">← Термінал</a>
  <a href="/print_base" target="_blank" class="back" style="background:rgba(255,255,255,.25)">🖨 Друк пропусків</a>
</div>
<div class="container">
  <div class="panel">
    <div class="panel-hdr">Додати транспорт</div>
    <form method="post" class="add-form">
      <div class="fg"><label>Номер</label><input type="text" name="plate" class="fi" placeholder="AA0000AA" required style="text-transform:uppercase"></div>
      <div class="fg"><label>Прізвище / Назва</label><input type="text" name="note" class="fi" placeholder="Іванов І.І. або назва компанії"></div>
      <div class="fg"><label>Категорія</label>
        <select name="category" class="fs">
          <option value="С">🚗 Співробітник</option>
            <option value="П">🔗 Причіп</option>
          <option value="Т">🚛 Тягач</option>
          <option value="Л">🛠 Службове</option>
          <option value="Р">👤 Інше</option>
          <option value="Д">📦 Доставка</option>
          <option value="В">🚚 Водій</option>
          <option value="Ч">🚫 Чорний список</option>
        </select>
      </div>
      <button type="submit" class="fb-add">+ Додати</button>
    </form>
  </div>
  <div class="panel">
    <div class="panel-hdr">База номерів · {{base|length}} записів</div>
    <div class="stats-row">
      {% set cnt = namespace(T=0,S=0,L=0,R=0,CH=0) %}
      {% for p,n in base.items() %}{% if '[Т]' in n %}{% set cnt.T=cnt.T+1 %}{% elif '[С]' in n %}{% set cnt.S=cnt.S+1 %}{% elif '[Л]' in n %}{% set cnt.L=cnt.L+1 %}{% elif '[Ч]' in n %}{% set cnt.CH=cnt.CH+1 %}{% else %}{% set cnt.R=cnt.R+1 %}{% endif %}{% endfor %}
      <div class="stat-chip">🚛 Тягачів: <b>{{cnt.T}}</b></div>
      <div class="stat-chip">🚗 Співроб: <b>{{cnt.S}}</b></div>
      <div class="stat-chip">🛠 Служб: <b>{{cnt.L}}</b></div>
      <div class="stat-chip">👤 Інших: <b>{{cnt.R}}</b></div>
      <div class="stat-chip" style="border-color:rgba(220,38,38,.3);color:var(--red)">🚫 Чорний: <b>{{cnt.CH}}</b></div>
    </div>
    <div class="search-wrap">
      <input type="text" id="bS" placeholder="🔍 Пошук за номером або прізвищем..." onkeyup="fB()">
    </div>
    <table id="bT">
      <thead><tr><th>Номер</th><th>Прізвище / Назва</th><th>Категорія</th><th style="width:100px">Дія</th></tr></thead>
      <tbody>
      {% for p, n in base.items() %}
      {% set cat = n[:3] %}{% set note = n[4:] if n|length > 3 else '' %}
      <tr>
        <td><span class="plate-mono">{{p}}</span></td>
        <td style="color:var(--text-mid)">{{note or '—'}}</td>
        <td>
          {% if '[Т]' in cat %}<span class="cat-pill" style="background:var(--purple-light);color:var(--purple)">🚛 Тягач</span>
          {% elif '[С]' in cat %}<span class="cat-pill" style="background:var(--accent-light);color:var(--ua-blue)">🚗 Співроб</span>
          {% elif '[Л]' in cat %}<span class="cat-pill" style="background:var(--orange-light);color:var(--orange)">🛠 Служб</span>
          {% elif '[Д]' in cat %}<span class="cat-pill" style="background:#e0f2fe;color:#0369a1">📦 Доставка</span>
          {% elif '[В]' in cat %}<span class="cat-pill" style="background:#e0fffe;color:#0891b2">🚚 Водій</span>
          {% elif '[Ч]' in cat %}<span class="cat-pill" style="background:var(--red-light);color:var(--red)">🚫 Чорний</span>
          {% else %}<span class="cat-pill" style="background:var(--surface3);color:var(--text-dim)">👤 Інше</span>{% endif %}
        </td>
        <td><button class="del-btn" onclick="if(confirm('Видалити {{p}}?'))location.href='/base?delete={{p}}'">Видалити</button></td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
</div>
<script>
function fB(){const q=document.getElementById('bS').value.toUpperCase();document.querySelectorAll('#bT tbody tr').forEach(r=>{r.style.display=r.innerText.toUpperCase().includes(q)?'':'none';});}
</script>
</body></html>'''


# ══════════════════════════════════════════════════════════════════
# СТОРІНКА ЮЗЕРІВ
# ══════════════════════════════════════════════════════════════════
USERS_TEMPLATE = '''<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>АГРОТЕП · Користувачі</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;500;600;700&family=JetBrains+Mono:wght@500;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{ ''' + LIGHT_VARS + ''' }
body{background:var(--bg);color:var(--text);font-family:'Nunito',sans-serif;min-height:100vh}
.topbar{background:var(--ua-blue);display:flex;align-items:center;padding:0 24px;height:56px;gap:14px;box-shadow:0 2px 8px rgba(0,87,183,.3)}
.brand{font-size:1.05rem;font-weight:700;color:#fff;display:flex;align-items:center;gap:8px}
a.back{padding:6px 14px;background:rgba(255,255,255,.15);border:1px solid rgba(255,255,255,.25);border-radius:6px;color:#fff;text-decoration:none;font-size:.82rem;font-weight:600;transition:.15s}
a.back:hover{background:rgba(255,255,255,.25)}
.container{max-width:600px;margin:40px auto;padding:0 20px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px;box-shadow:var(--shadow)}
.panel-hdr{font-size:.72rem;font-weight:700;letter-spacing:.06em;color:var(--text-dim);text-transform:uppercase;margin-bottom:20px;display:flex;align-items:center;gap:6px}
.panel-hdr::before{content:'';display:block;width:3px;height:14px;background:var(--ua-blue);border-radius:2px}
.f-row{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;margin-bottom:24px}
.fg{display:flex;flex-direction:column;gap:4px}
.fg label{font-size:.75rem;font-weight:600;color:var(--text-mid)}
.fi{background:var(--surface2);border:1.5px solid var(--border);border-radius:8px;color:var(--text);padding:9px 13px;font-family:'Nunito',sans-serif;font-size:.9rem;outline:none;width:100%;transition:.15s}
.fi:focus{border-color:var(--ua-blue);box-shadow:0 0 0 3px rgba(0,87,183,.1);background:#fff}
.fb-add{padding:9px 20px;background:var(--ua-blue);border:none;border-radius:8px;color:#fff;font-weight:700;font-size:.9rem;cursor:pointer;transition:.15s;align-self:end;white-space:nowrap;font-family:'Nunito',sans-serif}
.fb-add:hover{background:var(--accent-hover);box-shadow:0 3px 8px rgba(0,87,183,.25)}
table{width:100%;border-collapse:collapse}
thead th{padding:10px 16px;text-align:left;font-size:.7rem;font-weight:700;letter-spacing:.05em;color:var(--text-dim);text-transform:uppercase;background:var(--surface2);border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border)}tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface3)}
tbody td{padding:12px 16px;font-size:.9rem}
.del-btn{background:transparent;border:1.5px solid rgba(220,38,38,.3);border-radius:6px;color:rgba(220,38,38,.7);padding:4px 12px;cursor:pointer;font-size:.78rem;font-weight:600;transition:.15s;font-family:'Nunito',sans-serif}
.del-btn:hover{border-color:var(--red);color:var(--red);background:var(--red-light)}
</style></head>
<body>
<div class="topbar">
  <div class="brand">🚛 АГРОТЕП</div>
  <div style="width:1px;height:24px;background:rgba(255,255,255,.2)"></div>
  <a href="/" class="back">← Термінал</a>
</div>
<div class="container">
  <div class="panel">
    <div class="panel-hdr">Керування користувачами</div>
    <form method="post" style="margin-bottom:24px">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
        <div class="fg"><label>Логін</label><input type="text" name="new_u" class="fi" required placeholder="новий_логін"></div>
        <div class="fg"><label>Пароль</label><input type="password" name="new_p" class="fi" required placeholder="пароль"></div>
        <div class="fg"><label>Роль</label>
          <select name="role" class="fi">
            <option value="admin">👨‍💼 Адмін</option>
            <option value="guard">👮 Охоронець</option>
          </select>
        </div>
        <button type="submit" class="fb-add">+ Додати</button>
      </div>
    </form>
    <table>
      <thead><tr><th>Логін</th><th>Роль</th><th>Дія</th></tr></thead>
      <tbody>
      {% for u, info in users.items() %}
      {% set role = info.role if info is mapping else 'admin' %}
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-weight:700">{{u}}</td>
        <td>
          {% if role == 'guard' %}
            <span style="background:#dbeafe;color:#1d4ed8;padding:3px 10px;border-radius:5px;font-size:.78rem;font-weight:700">👮 Охоронець</span>
          {% else %}
            <span style="background:#f0fdf4;color:#16a34a;padding:3px 10px;border-radius:5px;font-size:.78rem;font-weight:700">👨‍💼 Адмін</span>
          {% endif %}
        </td>
        <td>{% if u == 'admin' %}
          <span style="font-size:.78rem;color:var(--text-dim);background:var(--surface3);padding:3px 10px;border-radius:5px">захищений</span>
        {% else %}
          <button class="del-btn" onclick="if(confirm('Видалити {{u}}?'))location.href='/users?delete={{u}}'">Видалити</button>
        {% endif %}</td>
      </tr>{% endfor %}
      </tbody>
    </table>
  </div>
</div>
</body></html>'''


# ══════════════════════════════════════════════════════════════════
# РОУТИ
# ══════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        u, p = request.form.get('u',''), request.form.get('p','')
        users = load_users()
        user_data = users.get(u)
        stored_pass = user_data['password'] if isinstance(user_data, dict) else user_data
        if user_data and stored_pass == p:
            session['user'] = u
            audit('LOGIN', f'user={u}')
            role = get_user_role(u)
            if role == 'guard':
                return redirect('/check_vehicles')
            return redirect('/')
        audit('LOGIN_FAIL', f'user={u}')
        error = "Невірний логін або пароль"
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/logout')
def logout():
    audit('LOGOUT')
    session.clear()
    return redirect('/login')

@app.route('/')
@login_required
def index():
    en, ex, pi = get_all_data()
    base = load_whitelist()
    sys_info = get_sys_info()
    now = datetime.now()

    t_date = request.args.get('date', now.strftime('%Y-%m-%d'))
    s_date_str = request.args.get('start_date', t_date)
    e_date_str = request.args.get('end_date', t_date)
    search_raw = request.args.get('search', '')
    search = normalize_plate(search_raw)
    dir_f = request.args.get('dir', '')
    cat_f = request.args.get('cat', '')
    page = max(1, int(request.args.get('page', 1)))

    all_events = sorted(en + ex + pi, key=lambda x: x['dt'])
    status_map, entry_tracker, durations = {}, {}, {}

    for e in all_events:
        p_n = e['norm_plate']
        status_map[p_n] = e
        if e['subdir'] in ['enter','pit']:
            entry_tracker[p_n] = e['dt']
        else:
            if p_n in entry_tracker:
                durations[e['file']] = format_duration(e['dt'] - entry_tracker[p_n])
                del entry_tracker[p_n]

    inside_rows_all = [e for p, e in status_map.items() if e['subdir'] in ['enter','pit']]
    overstay_rows = []
    stats = {'Т': 0, 'С': 0, 'Л': 0, 'Р': 0, 'Д': 0, 'В': 0}
    for r in inside_rows_all:
        diff = now - r['dt']
        durations[r['file']] = format_duration(diff)
        n_note = base.get(r['norm_plate'], "").upper()
        if diff.total_seconds() > 86400 and "[Т]" not in n_note and "[В]" not in n_note:
            overstay_rows.append(r)
        if "[Т]" in n_note: stats['Т'] += 1
        elif "[С]" in n_note: stats['С'] += 1
        elif "[Л]" in n_note: stats['Л'] += 1
        elif "[Д]" in n_note: stats['Д'] += 1
        elif "[В]" in n_note: stats['В'] += 1
        elif "[П]" in n_note: stats['П'] = stats.get('П', 0) + 1
        else: stats['Р'] += 1

    if dir_f == 'overstay':
        rows = list(overstay_rows)
    elif dir_f == 'inside' or cat_f:
        rows = list(inside_rows_all)
        if cat_f:
            if cat_f == 'Р':
                rows = [r for r in rows if not any(f'[{c}]' in base.get(r['norm_plate'],'').upper() for c in ['Т','С','Л','Д','В','Ч','П'])]
            else:
                rows = [r for r in rows if f'[{cat_f}]' in base.get(r['norm_plate'], '').upper()]
    elif search:
        rows = [e for e in all_events if search in e['norm_plate'] or
                (e['norm_plate'] in base and search in normalize_plate(base[e['norm_plate']]))]
    else:
        rows = [r for r in all_events if s_date_str <= r['date'] <= e_date_str]
        if dir_f in ['enter','exit','pit']:
            rows = [r for r in rows if r['subdir'] == dir_f]

    rows.sort(key=lambda x: x['dt'], reverse=True)
    total_rows = len(rows)
    total_p = max(1, (total_rows + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE)
    page = min(page, total_p)
    rows_slice = rows[(page-1)*ROWS_PER_PAGE : page*ROWS_PER_PAGE]

    labels, h_in, h_out = [], [], []
    if s_date_str == e_date_str:
        labels = [str(i) for i in range(24)]
        h_in, h_out = [0]*24, [0]*24
        for r in [e for e in all_events if e['date'] == s_date_str]:
            try:
                h = int(r['time'].split(':')[0])
                if r['subdir'] in ['enter','pit']: h_in[h] += 1
                else: h_out[h] += 1
            except: continue
    else:
        try:
            sd = datetime.strptime(s_date_str, '%Y-%m-%d')
            ed = datetime.strptime(e_date_str, '%Y-%m-%d')
            delta = min((ed - sd).days + 1, 31)
            for i in range(delta):
                curr = (sd + timedelta(days=i)).strftime('%Y-%m-%d')
                labels.append(curr[5:])
                h_in.append(sum(1 for r in all_events if r['date']==curr and r['subdir'] in ['enter','pit']))
                h_out.append(sum(1 for r in all_events if r['date']==curr and r['subdir']=='exit'))
        except: pass

    similar_hints = {}
    for r in rows_slice:
        if r['norm_plate'] not in base:
            sim = find_similar_in_base(r['norm_plate'], base)
            if sim: similar_hints[r['norm_plate']] = sim

    def make_url(p=None, search_p=None):
        a = request.args.copy()
        if p: a['page'] = p
        if search_p:
            a['search'] = search_p
            a.pop('dir', None); a.pop('cat', None); a.pop('start_date', None)
            a['page'] = 1
        return "/?" + "&".join(f"{k}={v}" for k, v in a.items())

    return render_template_string(MAIN_TEMPLATE,
        si=sys_info, rows_slice=rows_slice, base=base, t_date=t_date,
        stats=stats, inside_rows=inside_rows_all, durations=durations,
        page=page, total_p=total_p, total_rows=total_rows,
        make_url=make_url, overstay=overstay_rows,
        is_standard_ua=is_standard_ua, s_date=s_date_str, e_date=e_date_str,
        similar_hints=similar_hints, h_in=h_in, h_out=h_out, labels=labels,
        dir_f=dir_f, cat_f=cat_f, search_raw=search_raw)

@app.route('/api/latest_file')
@login_required
def api_latest_file():
    en, ex, pi = get_all_data()
    all_events = sorted(en + ex + pi, key=lambda x: x['dt'], reverse=True)
    if all_events:
        e = all_events[0]
        return jsonify({'file': e['file'], 'subdir': e['subdir'], 'plate': e['plate']})
    return jsonify({'file': None, 'subdir': None, 'plate': None})

@app.route('/api/v1/vehicles')
@login_required
def api_vehicles():
    en, ex, pi = get_all_data()
    base = load_whitelist()
    now = datetime.now()
    all_events = sorted(en + ex + pi, key=lambda x: x['dt'])
    status_map, entry_tracker = {}, {}
    for e in all_events:
        p_n = e['norm_plate']
        status_map[p_n] = e
        if e['subdir'] in ['enter','pit']: entry_tracker[p_n] = e['dt']
        elif p_n in entry_tracker: del entry_tracker[p_n]
    result = []
    for p_n, e in status_map.items():
        info = base.get(p_n, "")
        inside = e['subdir'] in ['enter','pit']
        result.append({
            'plate': p_n, 'note': info[4:] if len(info) > 3 else '',
            'category': info[:3], 'inside': inside,
            'last_event': e['subdir'], 'last_seen': e['dt'].isoformat(),
            'duration_seconds': int((now - e['dt']).total_seconds()) if inside else None,
        })
    return jsonify({'count': len(result), 'vehicles': result, 'generated': now.isoformat()})

@app.route('/swap', methods=['POST'])
@login_required
def swap_direction():
    f, s = request.form.get('f',''), request.form.get('s','')
    if s not in ALLOWED_SUBDIRS: return "Invalid", 400
    new_sub = 'exit' if s in ['enter','pit'] else 'enter'
    try:
        os.rename(os.path.join(ROOT, s, os.path.basename(f)),
                  os.path.join(ROOT, new_sub, os.path.basename(f)))
        audit('SWAP', f'{f}: {s}→{new_sub}')
        return "OK"
    except: return "Error", 500

@app.route('/edit', methods=['POST'])
@login_required
def edit_plate():
    old = request.form.get('old_name','')
    new = request.form.get('new_plate','').upper()
    sub = request.form.get('subdir','')
    if sub not in ALLOWED_SUBDIRS: return "Invalid", 400
    p_old = os.path.join(ROOT, sub, os.path.basename(old))
    if not new:
        if os.path.exists(p_old): os.remove(p_old)
        audit('DELETE', old)
    else:
        m = re.match(r'^(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d+)_', old)
        if m and os.path.exists(p_old):
            new_name = f"{m.group(1)}_{new}.jpg"
            os.rename(p_old, os.path.join(ROOT, sub, new_name))
            audit('EDIT_PLATE', f'{old} → {new_name}')
    return "OK"

@app.route('/img/<subdir>/<filename>')
@login_required
def img(subdir, filename):
    if subdir not in ALLOWED_SUBDIRS: abort(404)
    return send_file(os.path.join(ROOT, subdir, os.path.basename(filename)))

@app.route('/export_csv')
@login_required
def export_csv():
    en, ex, pi = get_all_data()
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Дата','Час','Напрямок','Номер'])
    for r in sorted(en + ex + pi, key=lambda x: x['dt'], reverse=True):
        cw.writerow([r['date'], r['time'], r['subdir'], r['plate']])
    audit('EXPORT_CSV')
    out = make_response(si.getvalue())
    out.headers["Content-Disposition"] = "attachment; filename=report.csv"
    out.headers["Content-type"] = "text/csv; charset=utf-8"
    return out

@app.route('/users', methods=['GET','POST'])
@login_required
def manage_users():
    if session.get('user') != 'admin': return "Доступ заборонено", 403
    users = load_users()
    if request.method == 'POST':
        nu = request.form.get('new_u','').strip()
        np_ = request.form.get('new_p','').strip()
        role = request.form.get('role','admin').strip()
        if nu and np_:
            users[nu] = {'password': np_, 'role': role}
            save_users(users)
            audit('ADD_USER', f'{nu} role={role}')
        return redirect('/users')
    if request.args.get('delete'):
        target = request.args.get('delete')
        if target != 'admin':
            users.pop(target, None); save_users(users)
            audit('DEL_USER', target)
        return redirect('/users')
    return render_template_string(USERS_TEMPLATE, users=users)

@app.route('/base', methods=['GET','POST'])
@login_required
def manage_base():
    base = load_whitelist()
    if request.method == 'POST':
        p = request.form.get('plate','').strip().upper()
        n = request.form.get('note','').strip()
        c = request.form.get('category','').strip()
        if p and c:
            base[normalize_plate(p)] = f"[{c}] {n}"
            save_whitelist(base)
            audit('BASE_ADD', f'{p} [{c}] {n}')
        return redirect('/base')
    if request.args.get('delete'):
        p = normalize_plate(request.args.get('delete'))
        if p in base:
            del base[p]; save_whitelist(base)
            audit('BASE_DEL', p)
        return redirect('/base')
    return render_template_string(BASE_TEMPLATE, base=base)


@app.route('/stats')
@login_required
def stats_page():
    from collections import Counter
    en, ex, pi = get_all_data()
    base = load_whitelist()
    now = datetime.now()
    all_events = sorted(en + ex + pi, key=lambda x: x['dt'])
    active_tab = request.args.get('tab', 'traffic')

    # ── ТРАФІК ──────────────────────────────────────────────────────
    days_labels, days_in, days_out = [], [], []
    for i in range(29, -1, -1):
        d = (now - timedelta(days=i)).strftime('%Y-%m-%d')
        days_labels.append(d[5:])
        days_in.append(sum(1 for e in all_events if e['date']==d and e['subdir'] in ['enter','pit']))
        days_out.append(sum(1 for e in all_events if e['date']==d and e['subdir']=='exit'))

    plate_counts = Counter(e['norm_plate'] for e in all_events)
    top_plates = plate_counts.most_common(10)

    cat_stats = {'Т':0,'С':0,'Л':0,'Д':0,'В':0,'Р':0,'Ч':0,'unknown':0}
    for e in all_events:
        n = base.get(e['norm_plate'],'')
        if '[Т]' in n: cat_stats['Т']+=1
        elif '[С]' in n: cat_stats['С']+=1
        elif '[Л]' in n: cat_stats['Л']+=1
        elif '[Д]' in n: cat_stats['Д']+=1
        elif '[В]' in n: cat_stats['В']+=1
        elif '[Ч]' in n: cat_stats['Ч']+=1
        elif '[Р]' in n: cat_stats['Р']+=1
        else: cat_stats['unknown']+=1

    hour_in=[0]*24; hour_out=[0]*24
    for e in all_events:
        try:
            h=int(e['time'].split(':')[0])
            if e['subdir'] in ['enter','pit']: hour_in[h]+=1
            else: hour_out[h]+=1
        except: pass

    total_events = len(all_events)
    today_events = sum(1 for e in all_events if e['date']==now.strftime('%Y-%m-%d'))
    unique_plates = len(set(e['norm_plate'] for e in all_events))
    unknown_count = sum(1 for p in set(e['norm_plate'] for e in all_events) if p not in base)

    # ── ЖУРНАЛ ──────────────────────────────────────────────────────
    today_str = now.strftime('%Y-%m-%d')
    j_start  = request.args.get('start_date', today_str)
    j_end    = request.args.get('end_date', today_str)
    j_dir    = request.args.get('dir', '')
    j_cat    = request.args.get('cat', '')
    j_search = request.args.get('search', '')
    j_page   = max(1, int(request.args.get('page', 1)))

    j_norm_search = normalize_plate(j_search)
    j_all = [e for e in all_events if j_start <= e['date'] <= j_end]
    if j_dir: j_all = [e for e in j_all if e['subdir']==j_dir]
    if j_cat == 'unk':
        j_all = [e for e in j_all if e['norm_plate'] not in base]
    elif j_cat == 'Р':
        j_all = [e for e in j_all if not any(f'[{c}]' in base.get(e['norm_plate'],'').upper() for c in ['Т','С','Л','Д','В','Ч']) and e['norm_plate'] in base]
    elif j_cat:
        j_all = [e for e in j_all if f'[{j_cat}]' in base.get(e['norm_plate'],'').upper()]
    if j_search:
        j_all = [e for e in j_all if j_norm_search in e['norm_plate'] or
                 (e['norm_plate'] in base and j_search.lower() in base[e['norm_plate']].lower())]
    j_all.sort(key=lambda x: x['dt'], reverse=True)

    # Тривалості для журналу
    j_durations = {}
    entry_map = {}
    for e in sorted(j_all, key=lambda x: x['dt']):
        if e['subdir'] in ['enter','pit']: entry_map[e['norm_plate']] = e['dt']
        elif e['norm_plate'] in entry_map:
            j_durations[e['file']] = format_duration(e['dt'] - entry_map[e['norm_plate']])
            del entry_map[e['norm_plate']]

    j_total = len(j_all)
    j_total_p = max(1, (j_total + ROWS_PER_PAGE - 1) // ROWS_PER_PAGE)
    j_page = min(j_page, j_total_p)
    j_rows = j_all[(j_page-1)*ROWS_PER_PAGE : j_page*ROWS_PER_PAGE]

    # ── ЧАС ПЕРЕБУВАННЯ ─────────────────────────────────────────────
    dur_start  = request.args.get('dur_start', today_str)
    dur_end    = request.args.get('dur_end', today_str)
    dur_cat    = request.args.get('dur_cat', '')
    dur_search = request.args.get('dur_search', '')

    dur_events = sorted([e for e in all_events if dur_start <= e['date'] <= dur_end], key=lambda x: x['dt'])
    dur_map, dur_rows = {}, []
    for e in dur_events:
        if e['subdir'] in ['enter','pit']:
            dur_map[e['norm_plate']] = {'enter': e, 'exit': None}
        elif e['norm_plate'] in dur_map and dur_map[e['norm_plate']]['enter']:
            dur_map[e['norm_plate']]['exit'] = e

    for norm, rec in dur_map.items():
        enter_e = rec['enter']
        exit_e  = rec['exit']
        if exit_e:
            secs = int((exit_e['dt'] - enter_e['dt']).total_seconds())
        else:
            secs = int((now - enter_e['dt']).total_seconds())

        note = base.get(norm, '')
        if dur_cat == 'Р':
            if any(f'[{c}]' in note.upper() for c in ['Т','С','Л','Д','В','Ч']): continue
            if norm not in base: continue
        elif dur_cat and f'[{dur_cat}]' not in note.upper(): continue
        dur_search_norm = normalize_plate(dur_search)
        if dur_search and dur_search_norm not in norm and dur_search.lower() not in note.lower(): continue

        class DurRow:
            pass
        row = DurRow()
        row.plate = enter_e['plate']
        row.norm_plate = norm
        row.enter_dt = enter_e['dt'].strftime('%d.%m.%Y %H:%M')
        row.exit_dt  = exit_e['dt'].strftime('%d.%m.%Y %H:%M') if exit_e else None
        row.duration_seconds = secs
        row.duration_str = format_duration(timedelta(seconds=secs))
        dur_rows.append(row)

    dur_rows.sort(key=lambda x: x.duration_seconds, reverse=True)

    # ── НЕВІДОМІ АВТО ────────────────────────────────────────────────
    unk_start  = request.args.get('unk_start', today_str)
    unk_end    = request.args.get('unk_end', today_str)
    unk_search = request.args.get('unk_search', '').upper()

    try:
        unk_days = (datetime.strptime(unk_end,'%Y-%m-%d') - datetime.strptime(unk_start,'%Y-%m-%d')).days + 1
    except: unk_days = 1

    unk_events_list = [e for e in all_events
                       if unk_start <= e['date'] <= unk_end and e['norm_plate'] not in base]
    if unk_search:
        unk_events_list = [e for e in unk_events_list if unk_search in e['norm_plate']]

    unk_by_plate = {}
    for e in unk_events_list:
        p = e['norm_plate']
        if p not in unk_by_plate:
            unk_by_plate[p] = {'plate':e['plate'],'first':e['dt'],'last':e['dt'],'count':0,'last_file':e['file'],'last_subdir':e['subdir']}
        else:
            if e['dt'] < unk_by_plate[p]['first']: unk_by_plate[p]['first'] = e['dt']
            if e['dt'] > unk_by_plate[p]['last']:
                unk_by_plate[p]['last'] = e['dt']
                unk_by_plate[p]['last_file'] = e['file']
                unk_by_plate[p]['last_subdir'] = e['subdir']
        unk_by_plate[p]['count'] += 1

    class UnkRow:
        pass
    unk_rows = []
    for norm, d in sorted(unk_by_plate.items(), key=lambda x: -x[1]['count']):
        row = UnkRow()
        row.plate = d['plate']
        row.first_seen = d['first'].strftime('%d.%m.%Y %H:%M')
        row.last_seen  = d['last'].strftime('%d.%m.%Y %H:%M')
        row.count = d['count']
        row.last_file = d['last_file']
        row.last_subdir = d['last_subdir']
        unk_rows.append(row)

    unk_max_count = unk_rows[0].count if unk_rows else 1

    # ── АНАЛІТИКА ────────────────────────────────────────────────
    from collections import Counter as _Counter

    # Теплова карта: день тижня (0=Пн) × година
    heatmap_data = [[0]*24 for _ in range(7)]
    for e in all_events:
        if e['subdir'] in ['enter','pit']:
            try:
                heatmap_data[e['dt'].weekday()][e['dt'].hour] += 1
            except: pass

    # Пік активності (година)
    hour_totals = [sum(heatmap_data[d][h] for d in range(7)) for h in range(24)]
    peak_hour = hour_totals.index(max(hour_totals)) if any(hour_totals) else 9

    # Найактивніший день тижня
    weekday_names = ['Понеділок','Вівторок','Середа','Четвер','Пятниця','Субота','Неділя']
    weekday_totals = [sum(heatmap_data[d]) for d in range(7)]
    peak_weekday = weekday_names[weekday_totals.index(max(weekday_totals))] if any(weekday_totals) else '—'

    # Середній час перебування
    all_sess_secs = []
    s_entry_map = {}
    for e in sorted(all_events, key=lambda x: x['dt']):
        if e['subdir'] in ['enter','pit']:
            s_entry_map[e['norm_plate']] = e['dt']
        elif e['norm_plate'] in s_entry_map:
            secs = int((e['dt'] - s_entry_map[e['norm_plate']]).total_seconds())
            if 0 < secs < 86400*3: all_sess_secs.append(secs)
            del s_entry_map[e['norm_plate']]
    avg_stay_all = format_duration(timedelta(seconds=int(sum(all_sess_secs)/len(all_sess_secs)))) if all_sess_secs else '—'

    # Топ тягач
    truck_cnts = _Counter(e['norm_plate'] for e in all_events if '[Т]' in base.get(e['norm_plate'],''))
    top_truck, top_truck_note = '', ''
    if truck_cnts:
        tp = truck_cnts.most_common(1)[0][0]
        top_truck = tp
        top_truck_note = base.get(tp,'')[4:] or tp

    today_str2 = now.strftime('%Y-%m-%d')
    today_delivery = sum(1 for e in all_events if e['date']==today_str2 and '[Д]' in base.get(e['norm_plate'],''))
    plate_visit_count = _Counter(e['norm_plate'] for e in all_events if e['subdir'] in ['enter','pit'])
    repeat_visitors = sum(1 for cnt in plate_visit_count.values() if cnt > 1)

    # Топ по максимальному часу перебування
    max_dur_map = {}
    ms_entry = {}
    for e in sorted(all_events, key=lambda x: x['dt']):
        if e['subdir'] in ['enter','pit']:
            ms_entry[e['norm_plate']] = e['dt']
        elif e['norm_plate'] in ms_entry:
            secs = int((e['dt'] - ms_entry[e['norm_plate']]).total_seconds())
            if secs > 0 and (e['norm_plate'] not in max_dur_map or secs > max_dur_map[e['norm_plate']]):
                max_dur_map[e['norm_plate']] = secs
            del ms_entry[e['norm_plate']]

    class _DRow:
        pass
    top_by_duration = []
    for norm, secs in sorted(max_dur_map.items(), key=lambda x: -x[1])[:8]:
        r = _DRow(); r.plate = norm
        r.max_dur = format_duration(timedelta(seconds=secs))
        top_by_duration.append(r)

    # Авто що давно не приїжджали (>30 днів, з бази)
    last_seen_map2 = {}
    for e in all_events:
        if e['norm_plate'] not in last_seen_map2 or e['dt'] > last_seen_map2[e['norm_plate']]['dt']:
            last_seen_map2[e['norm_plate']] = e

    class _ARow:
        pass
    long_absent = []
    for norm, e in last_seen_map2.items():
        if norm not in base: continue
        days_ago = (now - e['dt']).days
        if days_ago >= 30:
            r = _ARow(); r.plate = norm
            r.last_date = e['dt'].strftime('%d.%m.%Y'); r.days_ago = days_ago
            long_absent.append(r)
    long_absent.sort(key=lambda x: -x.days_ago)

    # Нові авто по місяцях
    first_seen_map2 = {}
    for e in all_events:
        if e['norm_plate'] not in first_seen_map2:
            first_seen_map2[e['norm_plate']] = e['dt']
    months_new = _Counter(dt.strftime('%Y-%m') for dt in first_seen_map2.values())
    sorted_months = sorted(months_new.keys())[-12:]
    new_plates_labels = [m[5:] for m in sorted_months]
    new_plates_data   = [months_new[m] for m in sorted_months]

    return render_template_string(STATS_TEMPLATE,
        active_tab=active_tab,
        days_labels=days_labels, days_in=days_in, days_out=days_out,
        top_plates=top_plates, cat_stats=cat_stats,
        hour_in=hour_in, hour_out=hour_out,
        total_events=total_events, today_events=today_events,
        unique_plates=unique_plates, unknown_count=unknown_count, base=base,
        j_rows=j_rows, j_total=j_total, j_total_p=j_total_p, j_page=j_page,
        j_start=j_start, j_end=j_end, j_dir=j_dir, j_cat=j_cat, j_search=j_search,
        j_durations=j_durations,
        dur_rows=dur_rows, dur_start=dur_start, dur_end=dur_end, dur_cat=dur_cat, dur_search=dur_search,
        unk_rows=unk_rows, unk_start=unk_start, unk_end=unk_end, unk_search=unk_search,
        unk_unique=len(unk_rows), unk_events=len(unk_events_list), unk_days=unk_days,
        unk_max_count=unk_max_count,
        heatmap_data=heatmap_data, peak_hour=peak_hour, peak_weekday=peak_weekday,
        avg_stay_all=avg_stay_all, top_truck=top_truck, top_truck_note=top_truck_note,
        today_delivery=today_delivery, repeat_visitors=repeat_visitors,
        top_by_duration=top_by_duration, long_absent=long_absent,
        new_plates_labels=new_plates_labels, new_plates_data=new_plates_data,
        today_s=now.strftime('%Y-%m-%d'),
        month_s=(now - timedelta(days=30)).strftime('%Y-%m-%d'),
        top_trucks_list=truck_cnts.most_common(10) if truck_cnts else [])


@app.route('/vehicle/<plate>')
@login_required
def vehicle_history(plate):
    en, ex, pi = get_all_data()
    base = load_whitelist()
    now = datetime.now()
    norm = normalize_plate(plate)

    all_events = sorted(en + ex + pi, key=lambda x: x['dt'])
    events = [e for e in all_events if e['norm_plate'] == norm]
    events.sort(key=lambda x: x['dt'], reverse=True)

    note = base.get(norm, '')
    owner = note[4:] if len(note) > 3 else ''

    # Підраховуємо сесії (в'їзд → виїзд)
    sessions = []
    entry = None
    for e in sorted(events, key=lambda x: x['dt']):
        if e['subdir'] in ['enter', 'pit']:
            entry = e
        elif e['subdir'] == 'exit' and entry:
            secs = int((e['dt'] - entry['dt']).total_seconds())
            sessions.append({
                'enter': entry,
                'exit': e,
                'duration': format_duration(timedelta(seconds=secs)),
                'duration_seconds': secs
            })
            entry = None

    total_visits = sum(1 for e in events if e['subdir'] in ['enter', 'pit'])
    avg_duration = ''
    if sessions:
        avg_secs = sum(s['duration_seconds'] for s in sessions) // len(sessions)
        avg_duration = format_duration(timedelta(seconds=avg_secs))

    return render_template_string(VEHICLE_TEMPLATE,
        plate=plate, norm=norm, note=note, owner=owner,
        events=events, sessions=sessions,
        total_visits=total_visits, avg_duration=avg_duration,
        is_standard_ua=is_standard_ua)


@app.route('/force_exit', methods=['POST'])
@login_required
def force_exit():
    norm = normalize_plate(request.form.get('plate',''))
    if not norm: return "Invalid", 400
    now = datetime.now()
    fname = f"{now.strftime('%Y-%m-%d')}_{now.strftime('%H-%M-%S%f')[:15]}_{norm}.jpg"
    # Копіюємо останнє фото в'їзду як фото виїзду
    en, ex, pi = get_all_data()
    all_ev = sorted(en + ex + pi, key=lambda x: x['dt'])
    last_enter = next((e for e in reversed(all_ev) if e['norm_plate']==norm and e['subdir'] in ['enter','pit']), None)
    exit_path = os.path.join(ROOT, 'exit', fname)
    if last_enter:
        src = os.path.join(ROOT, last_enter['subdir'], last_enter['file'])
        if os.path.exists(src):
            import shutil as _sh
            _sh.copy2(src, exit_path)
        else:
            open(exit_path, 'wb').close()
    else:
        open(exit_path, 'wb').close()
    audit('FORCE_EXIT', norm)
    return "OK"


@app.route('/print_base')
@login_required
def print_base():
    base = load_whitelist()
    # Виключаємо тягачі [Т], залишаємо всі інші категорії
    rows = []
    for norm, note in sorted(base.items()):
        if '[Т]' in note.upper(): continue
        cat_tag = note[:3] if len(note) >= 3 else '[Р]'
        owner = note[4:] if len(note) > 3 else '—'
        if '[С]' in cat_tag:   cat_name, cat_color = '🚗 Співробітник', '#1d4ed8'
        elif '[Д]' in cat_tag: cat_name, cat_color = '📦 Доставка',    '#0369a1'
        elif '[В]' in cat_tag: cat_name, cat_color = '🚚 Водій',       '#0891b2'
        elif '[Л]' in cat_tag: cat_name, cat_color = '🛠 Службове',    '#d97706'
        elif '[Ч]' in cat_tag: cat_name, cat_color = '🚫 Чорний сп.',  '#dc2626'
        else:                  cat_name, cat_color = '👤 Гість',       '#64748b'
        rows.append({'plate': norm, 'owner': owner, 'cat': cat_name, 'color': cat_color})

    from datetime import datetime as _dt
    generated = _dt.now().strftime('%d.%m.%Y %H:%M')
    return render_template_string(PRINT_TEMPLATE, rows=rows, generated=generated, total=len(rows))

# =====================================================================
# ІНВЕНТАРИЗАЦІЯ МАШИН НА ТЕРИТОРІЇ
# =====================================================================

CHECKS_DIR = '/home/bcsftp/checks'

UA_WEEKDAYS = {
    0: "понеділок", 1: "вівторок", 2: "середа",
    3: "четвер", 4: "п'ятниця", 5: "субота", 6: "неділя"
}

def get_check_filename():
    now = datetime.now()
    weekday = UA_WEEKDAYS[now.weekday()]
    fname = f"check_{now.strftime('%Y-%m-%d')}_{weekday}.txt"
    return os.path.join(CHECKS_DIR, fname)

def get_trailers_filename():
    now = datetime.now()
    weekday = UA_WEEKDAYS[now.weekday()]
    fname = f"trailers_{now.strftime('%Y-%m-%d')}_{weekday}.txt"
    return os.path.join(CHECKS_DIR, fname)

def load_trailers():
    result = []
    fpath = get_trailers_filename()
    if not os.path.isfile(fpath):
        return result
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                t = line.strip()
                if t: result.append(t)
    except: pass
    return result

def save_trailers(trailers):
    os.makedirs(CHECKS_DIR, exist_ok=True)
    fpath = get_trailers_filename()
    with open(fpath, 'w', encoding='utf-8') as f:
        for t in trailers:
            f.write(t + '\n')

def load_check_data():
    result = {}
    fpath = get_check_filename()
    if not os.path.isfile(fpath):
        return result
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('|')
                if len(parts) >= 3:
                    plate, status, time = parts[0], parts[1], parts[2]
                    trailer = parts[3] if len(parts) > 3 else ''
                    result[plate] = {'status': status, 'time': time, 'trailer': trailer}
    except:
        pass
    return result

def save_check_data(plate, status):
    try:
        os.makedirs(CHECKS_DIR, exist_ok=True)
        fpath = get_check_filename()
        data = load_check_data()
        data[plate] = {'status': status, 'time': datetime.now().strftime('%H:%M:%S')}
        with open(fpath, 'w', encoding='utf-8') as f:
            for p, info in data.items():
                trailer = info.get('trailer', '')
                f.write(f"{p}|{info['status']}|{info['time']}|{trailer}\n")
        return True
    except:
        return False

def get_vehicles_on_territory():
    """Повертає список машин які зараз на території (заїхали але не виїхали).
    Також повертає час заїзду і фото."""
    enter_data, exit_data, pit_data = get_all_data()
    base = load_whitelist()

    # Знаходимо останній заїзд для кожної машини
    last_enter = {}
    for r in enter_data:
        p = r['norm_plate']
        if p not in last_enter or r['dt'] > last_enter[p]['dt']:
            last_enter[p] = r

    # Знаходимо останній виїзд для кожної машини
    last_exit = {}
    for r in exit_data:
        p = r['norm_plate']
        if p not in last_exit or r['dt'] > last_exit[p]['dt']:
            last_exit[p] = r

    # Машина на території якщо: є заїзд І (немає виїзду АБО заїзд пізніше виїзду)
    on_territory = {}
    for plate, enter in last_enter.items():
        ex = last_exit.get(plate)
        if ex is None or enter['dt'] > ex['dt']:
            note = base.get(plate, '')
            owner = '—'
            m = re.match(r'\[[^\]]+\]\s*(.*)', note)
            if m and m.group(1).strip():
                owner = m.group(1).strip()
            # Час на території
            _now = datetime.now()
            _delta = _now - enter['dt']
            _total_mins = int(_delta.total_seconds() // 60)
            _days = _total_mins // 1440
            _hours = (_total_mins % 1440) // 60
            _mins = _total_mins % 60
            if _days > 0:
                dur_str = f"{_days}д {_hours}г {_mins}хв"
            elif _hours > 0:
                dur_str = f"{_hours}г {_mins}хв"
            else:
                dur_str = f"{_mins}хв" 

            is_truck = '[Т]' in note
            on_territory[plate] = {
                'plate': plate,
                'owner': owner,
                'note': note,
                'is_truck': is_truck,
                'enter_time': enter['dt'].strftime('%H:%M'),
                'enter_date': enter['dt'].strftime('%d.%m'),
                'duration': dur_str,
                'photo': f"/img/enter/{enter['file']}",
            }

    # Сортуємо за часом заїзду (спочатку найновіші)
    return sorted(on_territory.values(), key=lambda x: x['enter_time'], reverse=True)


CHECK_VEHICLES_TEMPLATE = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Перевірка машин</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
       background: #f0f4f8; color: #1e293b; }

.header { background: #0057b7; color: white; padding: 10px 12px; text-align: center;
          position: sticky; top: 0; z-index: 200; box-shadow: 0 2px 6px rgba(0,0,0,.3); }
.header h1 { font-size: .95rem; font-weight: 700; }
.header .date { font-size: .72rem; opacity: .82; }

.search-wrap { background: #0057b7; padding: 0 10px 10px; position: sticky; top: 48px; z-index: 199; }
.search-box { display: flex; gap: 6px; }
.search-input { flex: 1; padding: 10px 12px; border: none; border-radius: 9px;
                font-size: 1.05rem; font-family: 'Courier New', monospace; font-weight: 800;
                text-transform: uppercase; outline: none; letter-spacing: .06em; }
.search-clear { background: rgba(255,255,255,.2); border: none; border-radius: 9px;
                color: white; padding: 0 12px; font-size: 1.1rem; cursor: pointer; }

.progress-wrap { background: #004fa3; padding: 4px 12px 8px; }
.progress-bar-bg { background: rgba(255,255,255,.25); border-radius: 99px; height: 7px; overflow: hidden; }
.progress-bar-fill { background: #ffd700; height: 100%; border-radius: 99px; transition: width .4s; }
.progress-label { color: rgba(255,255,255,.75); font-size: .68rem; margin-top: 3px; text-align: right; }

.stats { display: grid; grid-template-columns: repeat(4,1fr);
         background: white; border-bottom: 1px solid #e2e8f0; }
.stat-item { text-align: center; padding: 7px 2px; }
.stat-num { font-size: 1.25rem; font-weight: 800; color: #0057b7; line-height: 1; }
.stat-num.green { color: #16a34a; }
.stat-num.red   { color: #dc2626; }
.stat-label { font-size: .55rem; color: #94a3b8; text-transform: uppercase; margin-top: 1px; }

.container { padding: 8px 8px; max-width: 700px; margin: 0 auto; }

.section-hdr { font-size: .7rem; font-weight: 700; text-transform: uppercase;
               letter-spacing: .07em; color: #64748b; margin: 10px 0 6px;
               display: flex; align-items: center; justify-content: space-between; }
.cnt-badge { background: #e2e8f0; color: #475569; border-radius: 99px;
             padding: 1px 7px; font-size: .65rem; }

/* СІТКА 3 КОЛОНКИ — МАЛЕНЬКІ КАРТКИ */
.vehicles-grid { display: grid; grid-template-columns: 1fr; gap: 6px; }
@media (max-width: 380px) { .vehicles-grid { grid-template-columns: repeat(2,1fr); } }

.vehicle-card { background: white; border-radius: 9px; overflow: hidden;
                border: 2px solid #e2e8f0; transition: border-color .2s;
                box-shadow: 0 1px 2px rgba(0,0,0,.05);
                display: flex; flex-direction: row; }
.vehicle-card.status-yes { border-color: #16a34a; }
.vehicle-card.status-no  { border-color: #dc2626; }
.vehicle-card.highlight  { border-color: #0057b7; box-shadow: 0 0 0 3px rgba(0,87,183,.2); order: -1; }

/* ФОТО З НОМЕРОМ */
.photo-wrap { position: relative; width: 100px; min-height: 80px; flex-shrink: 0; overflow: hidden;
              background: #f1f5f9; }
.photo-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
.photo-no { width: 100%; height: 100%; display: flex; align-items: center;
            justify-content: center; font-size: 1.8rem; color: #cbd5e1; }
/* plate now shown in card-right */
.status-icon { position: absolute; top: 4px; right: 4px; width: 22px; height: 22px;
               border-radius: 50%; display: none; align-items: center;
               justify-content: center; font-size: .7rem; font-weight: 900; }
.status-yes .status-icon { background: #16a34a; color: white; display: flex; }
.status-no  .status-icon { background: #dc2626; color: white; display: flex; }

.card-right { display: flex; flex-direction: column; flex: 1; min-width: 0; }
.card-meta { padding: 6px 8px 2px; }
.vehicle-owner { font-size: .68rem; color: #334155; font-weight: 600;
                 white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.meta-row { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 1px; }
.meta-chip { font-size: .6rem; color: #94a3b8; }

.btn-group { display: flex; gap: 4px; padding: 4px 8px 8px; margin-top: auto; }
.btn { flex: 1; padding: 8px 2px; border: none; border-radius: 6px; font-size: .78rem;
       font-weight: 700; cursor: pointer; min-height: 36px; transition: transform .1s; }
.btn:active { transform: scale(.94); }
.btn-yes { background: #16a34a; color: white; }
.btn-no  { background: #dc2626; color: white; }

/* ПЕРЕВІРЕНО */
.checked-grid { display: flex; flex-wrap: wrap; gap: 5px; }
.checked-pill { border-radius: 7px; padding: 4px 9px; font-size: .75rem; font-weight: 700;
                font-family: 'Courier New', monospace; cursor: pointer;
                display: flex; align-items: center; gap: 4px; }
.checked-pill.yes { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
.checked-pill.no  { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }

/* ВІДСУТНІ */
.missing-section { background: #fef2f2; border: 1px solid #fecaca; border-radius: 9px;
                   padding: 9px 11px; margin-top: 8px; }
.missing-title { color: #dc2626; font-weight: 700; font-size: .82rem; margin-bottom: 6px; }
.missing-list { display: flex; flex-wrap: wrap; gap: 4px; }
.missing-pill { background: #dc2626; color: white; border-radius: 5px;
                padding: 2px 8px; font-size: .75rem; font-weight: 700;
                font-family: 'Courier New', monospace; }

/* ДОДАТИ ВРУЧНУ */
.add-manual { background: white; border: 2px dashed #cbd5e1; border-radius: 9px;
              padding: 10px 11px; margin-top: 8px; }
.add-manual-title { font-size: .72rem; color: #64748b; font-weight: 700; margin-bottom: 7px; }
.add-manual-row { display: flex; gap: 6px; }
.add-input { flex: 1; padding: 9px 10px; border: 1px solid #e2e8f0; border-radius: 7px;
             font-size: .95rem; font-family: 'Courier New', monospace; font-weight: 800;
             text-transform: uppercase; letter-spacing: .06em; }
.add-btn { background: #16a34a; color: white; border: none; border-radius: 7px;
           padding: 9px 14px; font-size: .85rem; font-weight: 700; cursor: pointer; }
.add-info { font-size: .72rem; color: #64748b; margin-top: 5px; min-height: 1rem; }

/* ПРИЦЕПИ */
.trailers-section { background: white; border: 1px solid #e2e8f0; border-radius: 9px;
                    padding: 10px 11px; margin-top: 8px; }
.trailers-title { font-size: .72rem; font-weight: 700; color: #64748b;
                  text-transform: uppercase; letter-spacing: .06em; margin-bottom: 7px; }
.trailer-add-row { display: flex; gap: 6px; }
.trailer-input-main { flex: 1; padding: 9px 10px; border: 1px solid #e2e8f0; border-radius: 7px;
                      font-size: .95rem; font-family: 'Courier New', monospace; font-weight: 800;
                      text-transform: uppercase; letter-spacing: .06em; }
.trailer-add-btn { background: #0057b7; color: white; border: none; border-radius: 7px;
                   padding: 9px 14px; font-size: .85rem; font-weight: 700; cursor: pointer; }
.trailer-list { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
.trailer-pill { background: #eff6ff; border: 1px solid #bfdbfe; color: #1d4ed8;
                border-radius: 6px; padding: 3px 9px; font-size: .75rem;
                font-weight: 700; font-family: 'Courier New', monospace;
                cursor: pointer; display: flex; align-items: center; gap: 4px; }

.actions { display: flex; gap: 7px; margin-top: 12px; margin-bottom: 18px; }
.btn-finish { flex: 2; background: #0057b7; color: white; padding: 12px;
              border: none; border-radius: 9px; font-size: .9rem; font-weight: 700;
              cursor: pointer; min-height: 46px; }
.btn-reset  { flex: 1; background: white; color: #dc2626; padding: 12px;
              border: 2px solid #dc2626; border-radius: 9px; font-size: .9rem;
              font-weight: 700; cursor: pointer; min-height: 46px; }

.toast { position: fixed; bottom: 16px; left: 50%; transform: translateX(-50%);
         background: #1e293b; color: white; padding: 9px 18px; border-radius: 8px;
         font-size: .88rem; opacity: 0; transition: opacity .3s; pointer-events: none; z-index: 999; }
.toast.show { opacity: 1; }
.trailers-top { background: #1e3a5f; border-bottom: 1px solid #1e40af; }
.trailers-top-inner { max-width:700px; margin:0 auto; padding:7px 10px;
                      display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
.trailers-label { font-size:.72rem; font-weight:700; color:#93c5fd; white-space:nowrap; }
.trailer-list { display:flex; flex-wrap:wrap; gap:4px; flex:1; }
.trailer-pill { background:#1d4ed8; color:white; border-radius:5px;
                padding:2px 8px; font-size:.75rem; font-weight:700;
                font-family:'Courier New',monospace; cursor:pointer; }
.no-trailers { color:#4b7ab5; font-size:.75rem; }
.trailer-add-mini { display:flex; gap:4px; }
.trailer-input-mini { padding:4px 8px; border:1px solid #3b5fa0; border-radius:6px;
                      font-size:.82rem; font-family:'Courier New',monospace;
                      font-weight:700; text-transform:uppercase; background:#0f2d50;
                      color:white; width:120px; }
.trailer-input-mini::placeholder { color:#4b7ab5; font-weight:400; font-family:sans-serif; }
.trailer-add-mini-btn { background:#2563eb; color:white; border:none; border-radius:6px;
                        padding:4px 10px; font-size:1rem; font-weight:700; cursor:pointer; }
.nav-link { display: block; text-align: center; padding: 4px; color: #0057b7;
            font-size: .78rem; text-decoration: none; }
.hidden { display: none !important; }
</style>
</head>
<body>

<div class="header">
  <div style="display:flex;align-items:center;gap:8px">
    <h1 style="flex:1;font-size:.95rem">📋 Перевірка · {{ date_str }}</h1>
    <a href="/" style="background:rgba(255,255,255,.2);color:white;text-decoration:none;
       border-radius:7px;padding:5px 11px;font-size:.8rem;font-weight:700;
       border:1px solid rgba(255,255,255,.3);white-space:nowrap">← Вихід</a>
  </div>
</div>

<div class="search-wrap">
  <div class="search-box">
    <input class="search-input" id="searchInput" type="text" placeholder="🔍 Введіть номер..."
           maxlength="10" autocomplete="off" autocorrect="off" spellcheck="false"
           oninput="onSearch(this.value.toUpperCase()); this.value=this.value.toUpperCase()">
    <button class="search-clear" onclick="clearSearch()">✕</button>
  </div>
</div>

<div class="progress-wrap">
  <div class="progress-bar-bg">
    <div class="progress-bar-fill" id="progressFill" style="width:{{ progress_pct }}%"></div>
  </div>
  <div class="progress-label" id="progressLabel">
    Перевірено {{ checked_count }} з {{ total_count }} ({{ progress_pct }}%)
  </div>
</div>

<div class="stats">
  <div class="stat-item"><div class="stat-num" id="statTotal">{{ total_count }}</div><div class="stat-label">На терит.</div></div>
  <div class="stat-item"><div class="stat-num" id="statChecked">{{ checked_count }}</div><div class="stat-label">Перевірено</div></div>
  <div class="stat-item"><div class="stat-num green" id="statYes">{{ yes_count }}</div><div class="stat-label">Знайдено</div></div>
  <div class="stat-item"><div class="stat-num red" id="statNo">{{ no_count }}</div><div class="stat-label">Відсутні</div></div>
</div>

<!-- ПРИЦЕПИ НА ТЕРИТОРІЇ -->
<div class="trailers-top">
  <div class="trailers-top-inner">
    <span class="trailers-label">➕ Додати транспорт:</span>
    <div class="trailer-list" id="trailerList">
      {% for t in trailers %}
      <span class="trailer-pill" onclick="removeTrailer('{{ t }}')">{{ t }} ✕</span>
      {% endfor %}
      {% if not trailers %}<span class="no-trailers">—</span>{% endif %}
    </div>
    <div class="trailer-add-mini">
      <input class="trailer-input-mini" id="trailerInput" type="text"
             placeholder="Додати транспорт..." maxlength="10" spellcheck="false"
             oninput="this.value=this.value.toUpperCase()">
      <button class="trailer-add-mini-btn" onclick="addTrailer()">+</button>
    </div>
  </div>
</div>

<div class="container">

  <div class="section-hdr">
    🔍 Треба перевірити
    <span class="cnt-badge" id="pendingCount">{{ total_count - checked_count }}</span>
  </div>

  <div class="vehicles-grid" id="pendingGrid">
  {% for v in vehicles %}{% if v.plate not in check_data %}
  <div class="vehicle-card" id="card-{{ v.plate }}" data-plate="{{ v.plate }}">
    <div class="photo-wrap">
      <img src="{{ v.photo }}" alt="{{ v.plate }}" loading="lazy"
           onerror="this.style.display='none'">
      <div class="status-icon" id="icon-{{ v.plate }}"></div>
    </div>
    <div class="card-right">
      <div class="card-meta">
        <div class="plate-always">{{ v.plate }}</div>
        {% if v.owner != '—' %}<div class="vehicle-owner">{{ v.owner }}</div>{% endif %}
        <div class="meta-row">
          <span class="meta-chip">🕐{{ v.enter_time }}</span>
          <span class="meta-chip">⏱{{ v.duration }}</span>
        </div>
      </div>
      <div class="btn-group">
        <button class="btn btn-yes" onclick="markVehicle('{{ v.plate }}','yes',this)">✓ Є</button>
        <button class="btn btn-no"  onclick="markVehicle('{{ v.plate }}','no',this)">✗ Нема</button>
      </div>
    </div>
  </div>
  {% endif %}{% endfor %}
  </div>

  <!-- ПЕРЕВІРЕНІ -->
  <div class="section-hdr" id="checkedTitle" {% if not check_data %}style="display:none"{% endif %}>
    ✅ Перевірено <span class="cnt-badge" id="checkedCount">{{ checked_count }}</span>
  </div>
  <div class="checked-grid" id="checkedGrid">
  {% for v in vehicles %}{% set info = check_data.get(v.plate) %}{% if info %}
  <div class="checked-pill {{ info.status }}" id="pill-{{ v.plate }}" onclick="undoCheck('{{ v.plate }}')">
    <span>{% if info.status=='yes' %}✓{% else %}✗{% endif %}</span>{{ v.plate }}
  </div>
  {% endif %}{% endfor %}
  </div>

  <!-- ВІДСУТНІ -->
  <div class="missing-section" id="missingSection" {% if not no_plates %}style="display:none"{% endif %}>
    <div class="missing-title">❌ Відсутні на території</div>
    <div class="missing-list" id="missingList">
      {% for p in no_plates %}<span class="missing-pill">{{ p }}</span>{% endfor %}
    </div>
  </div>

  <!-- ДОДАТИ ВРУЧНУ -->
  <div class="add-manual" id="addManualBox">
    <div class="add-manual-title">➕ Знайшов машину без картки — додати вручну</div>
    <div class="add-manual-row">
      <input class="add-input" id="manualPlate" type="text" placeholder="AA1234BB"
             maxlength="10" spellcheck="false"
             oninput="this.value=this.value.toUpperCase(); checkManualInfo(this.value)">
      <button class="add-btn" onclick="addManual()">✓ Є</button>
    </div>
    <div class="add-info" id="manualInfo"></div>
  </div>

  <div class="actions">
    <button class="btn-finish" onclick="finishCheck()">💾 Завершити</button>
    <button class="btn-reset" onclick="resetCheck()">🔄 Скинути</button>
  </div>
  <a href="/check_results" class="nav-link">📊 Результати перевірки →</a>
</div>

<div class="toast" id="toast"></div>

<script>
const vehicles = {{ vehicles_json | safe }};
let checkData = {{ check_data_json | safe }};
let trailers = {{ trailers_json | safe }};
const vehicleMap = {};
vehicles.forEach(v => vehicleMap[v.plate] = v);

function showToast(msg, dur=2000) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), dur);
}

function updateStats() {
  const total = vehicles.length;
  let checked=0, yes=0, no=0;
  for (const v of vehicles) {
    const d = checkData[v.plate];
    if (d) { checked++; d.status==='yes' ? yes++ : no++; }
  }
  const pct = total>0 ? Math.round(checked/total*100) : 0;
  document.getElementById('progressFill').style.width = pct+'%';
  document.getElementById('progressLabel').textContent =
    `Перевірено ${checked} з ${total} (${pct}%)`;
  document.getElementById('statChecked').textContent = checked;
  document.getElementById('statYes').textContent = yes;
  document.getElementById('statNo').textContent = no;
  document.getElementById('pendingCount').textContent = total - checked;
  document.getElementById('checkedCount').textContent = checked;
  document.getElementById('checkedTitle').style.display = checked>0 ? '' : 'none';

  const noPl = vehicles.filter(v => checkData[v.plate]?.status==='no');
  const ms = document.getElementById('missingSection');
  if (noPl.length>0) {
    ms.style.display='';
    document.getElementById('missingList').innerHTML =
      noPl.map(v=>`<span class="missing-pill">${v.plate}</span>`).join('');
  } else ms.style.display='none';
}

function onSearch(val) {
  val = val.trim();
  const cards = document.querySelectorAll('#pendingGrid .vehicle-card');
  let found = null;
  cards.forEach(card => {
    const plate = card.dataset.plate;
    if (!val) {
      card.classList.remove('hidden','highlight');
    } else if (plate.includes(val)) {
      card.classList.remove('hidden');
      if (plate === val) { card.classList.add('highlight'); found = card; }
      else card.classList.remove('highlight');
      if (!found) found = card;
    } else {
      card.classList.add('hidden');
      card.classList.remove('highlight');
    }
  });
  // Показуємо блок додавання якщо немає точного збігу серед непровірених
  const exactPending = vehicles.find(v => v.plate===val && !checkData[v.plate]);
  const showAdd = val.length>=4 && !exactPending;
  document.getElementById('addManualBox').style.display = showAdd ? '' : 'none';
  if (showAdd) {
    document.getElementById('manualPlate').value = val;
    checkManualInfo(val);
  }
  if (found) found.scrollIntoView({behavior:'smooth', block:'center'});
}

function clearSearch() {
  const inp = document.getElementById('searchInput');
  inp.value=''; onSearch(''); inp.focus();
}

async function checkManualInfo(plate) {
  const el = document.getElementById('manualInfo');
  if (plate.length<4) { el.textContent=''; return; }
  try {
    const r = await fetch(`/api/plate_info?plate=${encodeURIComponent(plate)}`);
    const d = await r.json();
    if (d.found) el.innerHTML = `📋 В базі: <b>${d.note}</b>`;
    else if (d.last_seen) el.innerHTML = `🕐 Останній заїзд: <b>${d.last_seen}</b> (не в базі)`;
    else el.textContent = '❓ Не знайдено в базі та архіві';
  } catch(e) {}
}

async function markVehicle(plate, status, btn) {
  const card = document.getElementById('card-'+plate);
  if (!card) return;
  const btns = card.querySelectorAll('.btn');
  btns.forEach(b => b.disabled=true);
  try {
    const resp = await fetch('/api/check_vehicle', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({plate, status})
    });
    const data = await resp.json();
    if (data.ok) {
      checkData[plate] = {status, time: new Date().toTimeString().slice(0,8)};
      card.style.transition='opacity .22s,transform .22s';
      card.style.opacity='0'; card.style.transform='scale(.9)';
      setTimeout(()=>card.style.display='none', 220);

      const pill = document.createElement('div');
      pill.className=`checked-pill ${status}`;
      pill.id='pill-'+plate;
      pill.innerHTML=`<span>${status==='yes'?'✓':'✗'}</span>${plate}`;
      pill.onclick=()=>undoCheck(plate);
      document.getElementById('checkedGrid').appendChild(pill);

      const si = document.getElementById('searchInput');
      if (si.value) { si.value=''; onSearch(''); }
      updateStats();
      showToast(status==='yes' ? '✅ Є на території' : '❌ Відсутня');
    } else { showToast('⚠️ Помилка'); btns.forEach(b=>b.disabled=false); }
  } catch(e) { showToast('⚠️ Помилка мережі'); btns.forEach(b=>b.disabled=false); }
}

async function undoCheck(plate) {
  if (!confirm(`Скасувати відмітку ${plate}?`)) return;
  try {
    const r = await fetch('/api/undo_check', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({plate})
    });
    const d = await r.json();
    if (d.ok) {
      delete checkData[plate];
      document.getElementById('pill-'+plate)?.remove();
      const card = document.getElementById('card-'+plate);
      if (card) { card.style.display=''; requestAnimationFrame(()=>{card.style.opacity='1';card.style.transform='';}); }
      updateStats(); showToast('↩️ Скасовано');
    }
  } catch(e) { showToast('⚠️ Помилка'); }
}

async function addManual() {
  const inp = document.getElementById('manualPlate');
  const plate = inp.value.trim().toUpperCase();
  if (!plate || plate.length<4) { showToast('⚠️ Введіть номер'); return; }
  const r = await fetch('/api/check_vehicle', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({plate, status:'yes'})
  });
  const d = await r.json();
  if (d.ok) {
    checkData[plate]={status:'yes',time:new Date().toTimeString().slice(0,8)};
    if (!vehicleMap[plate]) {
      const v={plate,owner:'—',note:'',enter_time:'вручну',duration:'—',photo:''};
      vehicles.push(v); vehicleMap[plate]=v;
    }
    const pill=document.createElement('div');
    pill.className='checked-pill yes'; pill.id='pill-'+plate;
    pill.innerHTML=`<span>✓</span>${plate}<small style="opacity:.5;font-size:.6rem"> вручну</small>`;
    pill.onclick=()=>undoCheck(plate);
    document.getElementById('checkedGrid').appendChild(pill);
    inp.value=''; document.getElementById('manualInfo').textContent='';
    document.getElementById('searchInput').value=''; onSearch('');
    updateStats(); showToast(`✅ ${plate} додано`);
  }
}

async function addTrailer() {
  const inp = document.getElementById('trailerInput');
  const t = inp.value.trim().toUpperCase();
  if (!t || t.length<4) { showToast('⚠️ Введіть номер прицепа'); return; }
  const r = await fetch('/api/add_trailer', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({trailer:t})
  });
  const d = await r.json();
  if (d.ok) {
    trailers.push(t);
    const pill=document.createElement('span');
    pill.className='trailer-pill'; pill.textContent='🔗 '+t+' ✕';
    pill.onclick=()=>removeTrailer(t);
    document.getElementById('trailerList').appendChild(pill);
    inp.value=''; showToast(`🔗 Прицеп ${t} додано`);
  }
}

async function removeTrailer(t) {
  if (!confirm(`Видалити прицеп ${t}?`)) return;
  const r = await fetch('/api/remove_trailer', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({trailer:t})
  });
  const d = await r.json();
  if (d.ok) {
    trailers = trailers.filter(x=>x!==t);
    document.querySelectorAll('.trailer-pill').forEach(p=>{
      if (p.textContent.includes(t)) p.remove();
    });
    showToast(`🔗 ${t} видалено`);
  }
}

async function finishCheck() {
  const total=vehicles.length, checked=Object.keys(checkData).length;
  if (checked<total && !confirm(`Перевірено ${checked} з ${total}. Завершити?`)) return;
  try {
    const r = await fetch('/api/finish_check', {method:'POST'});
    const d = await r.json();
    if (d.ok) {
      showToast('💾 Перевірку завершено! Починаємо нову...', 2500);
      setTimeout(() => location.reload(), 2600);
    }
  } catch(e) { showToast('💾 Збережено!', 2000); }
}

async function resetCheck() {
  if (!confirm('Скинути всі результати за сьогодні?')) return;
  const r=await fetch('/api/reset_check',{method:'POST'});
  const d=await r.json();
  if (d.ok) {
    checkData={};
    document.querySelectorAll('.checked-pill').forEach(p=>p.remove());
    document.querySelectorAll('.vehicle-card').forEach(c=>{
      c.style.display=''; c.style.opacity='1'; c.style.transform='';
      c.className='vehicle-card';
    });
    updateStats(); showToast('🔄 Скинуто');
  }
}

// Початок — ховаємо блок додавання
document.getElementById('addManualBox').style.display='none';
</script>
</body>
</html>"""


CHECK_RESULTS_TEMPLATE = """<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Результати перевірки</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif;
       background: #f0f4f8; color: #1e293b; }
.header { background: #0057b7; color: white; padding: 14px 16px; }
.header h1 { font-size: 1.05rem; font-weight: 700; }
.header .sub { font-size: .78rem; opacity: .8; margin-top: 2px; }
.container { padding: 12px; max-width: 800px; margin: 0 auto; }

.report-card { background: white; border-radius: 10px; padding: 14px;
               border: 1px solid #e2e8f0; margin-bottom: 10px;
               box-shadow: 0 1px 3px rgba(0,0,0,.06); }
.report-title { font-size: .7rem; font-weight: 700; text-transform: uppercase;
                letter-spacing: .07em; color: #64748b; margin-bottom: 10px;
                display: flex; align-items: center; gap: 6px; }
.report-title::before { content:''; display:block; width:3px; height:12px;
                        background:#0057b7; border-radius:2px; }

.summary-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 8px; }
.sum-box { text-align: center; background: #f8fafc; border-radius: 8px; padding: 8px 4px; }
.sum-num { font-size: 1.4rem; font-weight: 800; line-height: 1; }
.sum-label { font-size: .6rem; color: #94a3b8; text-transform: uppercase; margin-top: 2px; }

.meta-info { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 8px; }
.meta-box { background: #f8fafc; border-radius: 7px; padding: 7px 10px; }
.meta-label { font-size: .62rem; color: #94a3b8; text-transform: uppercase; }
.meta-val { font-size: .85rem; font-weight: 700; color: #1e293b; margin-top: 1px; }

table { width: 100%; border-collapse: collapse; }
th { padding: 7px 10px; text-align: left; font-size: .65rem; font-weight: 700;
     letter-spacing: .05em; color: #64748b; text-transform: uppercase;
     background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
td { padding: 8px 10px; border-bottom: 1px solid #f1f5f9; font-size: .85rem; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #f8fafc; }

.badge { display: inline-flex; align-items: center; gap: 3px; padding: 2px 8px;
         border-radius: 99px; font-size: .75rem; font-weight: 700; }
.badge-yes { background: #dcfce7; color: #16a34a; }
.badge-no  { background: #fee2e2; color: #dc2626; }
.plate { font-family: 'Courier New', monospace; font-weight: 700; font-size: .92rem; }
.owner-cell { font-size: .78rem; color: #64748b; }

.trailers-list { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 4px; }
.t-pill { background: #eff6ff; border: 1px solid #bfdbfe; color: #1d4ed8;
          border-radius: 5px; padding: 2px 8px; font-size: .75rem;
          font-weight: 700; font-family: 'Courier New', monospace; }

.empty { text-align: center; padding: 30px; color: #94a3b8; font-size: .9rem; }
.print-btn { background: #0057b7; color: white; border: none; border-radius: 8px;
             padding: 10px 20px; font-size: .88rem; font-weight: 700; cursor: pointer;
             display: flex; align-items: center; gap: 6px; }
.actions-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
.back-link { color: #0057b7; text-decoration: none; font-size: .85rem; font-weight: 600; }

@media print {
  .actions-row { display: none; }
  body { background: white; }
  .report-card { box-shadow: none; border: 1px solid #ccc; }
}
</style>
</head>
<body>
<div class="header">
  <h1>📊 Звіт перевірки машин на території</h1>
  <div class="sub">{{ date_str }} | {{ weekday_str }}</div>
</div>
<div class="container">

  <!-- ЗВЕДЕННЯ -->
  <div class="report-card">
    <div class="report-title">Зведення</div>
    <div class="summary-grid">
      <div class="sum-box">
        <div class="sum-num">{{ total_on_territory }}</div>
        <div class="sum-label">На терит.</div>
      </div>
      <div class="sum-box">
        <div class="sum-num">{{ rows|length }}</div>
        <div class="sum-label">Перевірено</div>
      </div>
      <div class="sum-box">
        <div class="sum-num" style="color:#16a34a">{{ yes_count }}</div>
        <div class="sum-label">Знайдено</div>
      </div>
      <div class="sum-box">
        <div class="sum-num" style="color:#dc2626">{{ no_count }}</div>
        <div class="sum-label">Відсутні</div>
      </div>
    </div>
    <div class="meta-info">
      <div class="meta-box">
        <div class="meta-label">Перевірку проводив</div>
        <div class="meta-val">👤 {{ inspector }}</div>
      </div>
      <div class="meta-box">
        <div class="meta-label">Час перевірки</div>
        <div class="meta-val">
          {% if rows %}{{ rows[0].time }} — {{ rows[-1].time }}{% else %}—{% endif %}
        </div>
      </div>
      <div class="meta-box">
        <div class="meta-label">Дата</div>
        <div class="meta-val">{{ date_str }} ({{ weekday_str }})</div>
      </div>
      <div class="meta-box">
        <div class="meta-label">Прицепи на терит.</div>
        <div class="meta-val">{{ trailers|length }} шт.</div>
      </div>
    </div>
  </div>

  <!-- ВІДСУТНІ -->
  {% if no_rows %}
  <div class="report-card">
    <div class="report-title" style="color:#dc2626">❌ Відсутні на території ({{ no_rows|length }})</div>
    <table>
      <thead><tr><th>Номер</th><th>Власник</th><th>Час відмітки</th></tr></thead>
      <tbody>
      {% for r in no_rows %}
      <tr>
        <td><span class="plate">{{ r.plate }}</span></td>
        <td class="owner-cell">{{ r.owner }}</td>
        <td>{{ r.time }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- ЗНАЙДЕНІ -->
  <div class="report-card">
    <div class="report-title">✅ Знайдено на території ({{ yes_rows|length }})</div>
    {% if yes_rows %}
    <table>
      <thead><tr><th>Номер</th><th>Власник</th><th>Час відмітки</th></tr></thead>
      <tbody>
      {% for r in yes_rows %}
      <tr>
        <td><span class="plate">{{ r.plate }}</span></td>
        <td class="owner-cell">{{ r.owner }}</td>
        <td>{{ r.time }}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    {% else %}<div class="empty">Нічого не відмічено</div>{% endif %}
  </div>

  <!-- ПРИЦЕПИ -->
  {% if trailers %}
  <div class="report-card">
    <div class="report-title">🔗 Прицепи на території</div>
    <div class="trailers-list">
      {% for t in trailers %}<span class="t-pill">{{ t }}</span>{% endfor %}
    </div>
  </div>
  {% endif %}

  <div class="actions-row">
    <button class="print-btn" onclick="window.print()">🖨️ Друк / PDF</button>
    <a href="/check_vehicles" class="back-link">← До перевірки</a>
    <a href="/check_history" class="back-link">📅 Історія →</a>
  </div>
</div>
</body>
</html>"""




@app.route('/check_vehicles')
@login_required
def check_vehicles():
    import json
    vehicles = get_vehicles_on_territory()
    check_data = load_check_data()

    now = datetime.now()
    date_str = now.strftime('%d.%m.%Y')
    weekday_str = UA_WEEKDAYS[now.weekday()].capitalize()

    total_count = len(vehicles)
    checked_count = sum(1 for v in vehicles if v['plate'] in check_data)
    yes_count = sum(1 for v in vehicles if check_data.get(v['plate'], {}).get('status') == 'yes')
    no_count = sum(1 for v in vehicles if check_data.get(v['plate'], {}).get('status') == 'no')
    progress_pct = round((checked_count / total_count * 100)) if total_count > 0 else 0
    no_plates = [v['plate'] for v in vehicles if check_data.get(v['plate'], {}).get('status') == 'no']

    trailers = load_trailers()

    return render_template_string(
        CHECK_VEHICLES_TEMPLATE,
        vehicles=vehicles,
        check_data=check_data,
        trailers=trailers,
        date_str=date_str,
        weekday_str=weekday_str,
        total_count=total_count,
        checked_count=checked_count,
        yes_count=yes_count,
        no_count=no_count,
        progress_pct=progress_pct,
        no_plates=no_plates,
        vehicles_json=json.dumps(vehicles, ensure_ascii=True),
        check_data_json=json.dumps(check_data, ensure_ascii=True),
        trailers_json=json.dumps(trailers, ensure_ascii=True),
    )


@app.route('/api/check_vehicle', methods=['POST'])
@login_required
def api_check_vehicle():
    data = request.get_json(silent=True) or {}
    plate = normalize_plate(str(data.get('plate', '')))
    status = str(data.get('status', ''))
    if not plate or status not in ('yes', 'no'):
        return jsonify({'ok': False, 'error': 'Invalid data'}), 400
    ok = save_check_data(plate, status)
    if ok:
        audit('CHECK_VEHICLE', f'{plate}={status}')
        # Якщо охоронник відмітив "немає" — записуємо виїзд щоб головна сторінка оновилась
        if status == 'no':
            try:
                now = datetime.now()
                fname = f"{now.strftime('%Y-%m-%d')}_{now.strftime('%H-%M-%S%f')[:15]}_{plate}.jpg"
                os.makedirs(os.path.join(ROOT, 'exit'), exist_ok=True)
                exit_path = os.path.join(ROOT, 'exit', fname)
                en, ex, pi = get_all_data()
                all_ev = sorted(en + ex + pi, key=lambda x: x['dt'])
                last_enter = next((e for e in reversed(all_ev)
                                   if e['norm_plate'] == plate and e['subdir'] in ['enter','pit']), None)
                if last_enter:
                    src = os.path.join(ROOT, last_enter['subdir'], last_enter['file'])
                    if os.path.exists(src):
                        import shutil as _sh
                        _sh.copy2(src, exit_path)
                    else:
                        open(exit_path, 'wb').close()
                else:
                    open(exit_path, 'wb').close()
                audit('GUARD_EXIT', plate)
            except Exception as ex_err:
                pass  # Не критично — статус збережено
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Save error'}), 500


@app.route('/api/undo_check', methods=['POST'])
@login_required
def api_undo_check():
    data = request.get_json(silent=True) or {}
    plate = normalize_plate(str(data.get('plate', '')))
    if not plate:
        return jsonify({'ok': False}), 400
    try:
        fpath = get_check_filename()
        check_data = load_check_data()
        if plate in check_data:
            del check_data[plate]
            with open(fpath, 'w', encoding='utf-8') as f:
                for p, info in check_data.items():
                    f.write(f"{p}|{info['status']}|{info['time']}\n")
        audit('UNDO_CHECK', plate)
        return jsonify({'ok': True})
    except:
        return jsonify({'ok': False}), 500


@app.route('/api/reset_check', methods=['POST'])
@login_required
def api_reset_check():
    try:
        fpath = get_check_filename()
        if os.path.isfile(fpath):
            os.remove(fpath)
        # Очищаємо і прицепи
        tfpath = get_trailers_filename()
        if os.path.isfile(tfpath):
            os.remove(tfpath)
        audit('RESET_CHECK', 'All check data cleared')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/check_results')
@login_required
def check_results():
    check_data = load_check_data()
    trailers = load_trailers()
    now = datetime.now()
    base = load_whitelist()
    vehicles_on_territory = get_vehicles_on_territory()
    owner_map = {v['plate']: v['owner'] for v in vehicles_on_territory}

    rows = sorted(
        [{'plate': p, 'status': info['status'], 'time': info['time'],
          'owner': owner_map.get(p, base.get(p, '—'))}
         for p, info in check_data.items()],
        key=lambda x: x['time']
    )
    yes_rows = [r for r in rows if r['status'] == 'yes']
    no_rows  = [r for r in rows if r['status'] == 'no']

    return render_template_string(
        CHECK_RESULTS_TEMPLATE,
        rows=rows,
        yes_rows=yes_rows,
        no_rows=no_rows,
        trailers=trailers,
        date_str=now.strftime('%d.%m.%Y'),
        weekday_str=UA_WEEKDAYS[now.weekday()].capitalize(),
        yes_count=len(yes_rows),
        no_count=len(no_rows),
        total_on_territory=len(vehicles_on_territory),
        inspector=session.get('user', '—'),
    )


@app.route('/check_history')
@login_required
def check_history():
    files = []
    if os.path.isdir(CHECKS_DIR):
        for fname in sorted(os.listdir(CHECKS_DIR), reverse=True):
            if fname.startswith('check_') and fname.endswith('.txt'):
                fpath = os.path.join(CHECKS_DIR, fname)
                yes = no = 0
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        for line in f:
                            parts = line.strip().split('|')
                            if len(parts) >= 2:
                                if parts[1] == 'yes': yes += 1
                                else: no += 1
                except: pass
                label = fname.replace('check_', '').replace('.txt', '')
                files.append({'label': label, 'yes': yes, 'no': no, 'total': yes+no})

    HISTORY_TEMPLATE = (
        '<!DOCTYPE html><html lang="uk"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Istoriya</title>'
        '<style>'
        '*{box-sizing:border-box;margin:0;padding:0}'
        'body{font-family:-apple-system,sans-serif;background:#f0f4f8;color:#1e293b}'
        '.hdr{background:#0057b7;color:white;padding:12px 14px}'
        '.hdr h1{font-size:1rem;font-weight:700}'
        '.c{padding:12px;max-width:600px;margin:0 auto}'
        '.card{background:white;border-radius:9px;padding:11px 13px;margin-bottom:7px;'
        'border:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between}'
        '.lbl{font-size:.88rem;font-weight:700}'
        '.st{display:flex;gap:10px}'
        '.yes{color:#16a34a;font-weight:700;font-size:.8rem}'
        '.no{color:#dc2626;font-weight:700;font-size:.8rem}'
        '.tot{color:#64748b;font-size:.8rem}'
        '.empty{text-align:center;padding:40px;color:#94a3b8}'
        '.back{display:inline-block;margin-top:12px;color:#0057b7;text-decoration:none;font-size:.85rem}'
        '</style></head><body>'
        '<div class="hdr"><h1>📅 Історія перевірок</h1></div>'
        '<div class="c">'
        '{% if files %}{% for f in files %}'
        '<div class="card">'
        '<div class="lbl">{{ f.label }}</div>'
        '<div class="st">'
        '<span class="tot">{{ f.total }} перев.</span>'
        '<span class="yes">✓ {{ f.yes }}</span>'
        '<span class="no">✗ {{ f.no }}</span>'
        '</div></div>'
        '{% endfor %}{% else %}'
        '<div class="empty">Поки немає перевірок</div>'
        '{% endif %}'
        '<a href="/check_vehicles" class="back">← До перевірки</a>'
        '</div></body></html>'
    )
    return render_template_string(HISTORY_TEMPLATE, files=files)



@app.route('/api/plate_info')
@login_required
def api_plate_info():
    """Повертає інфо про номер — чи є в базі, коли останній раз бачили."""
    plate = normalize_plate(request.args.get('plate', ''))
    if not plate:
        return jsonify({'found': False})
    base = load_whitelist()
    if plate in base:
        return jsonify({'found': True, 'note': base[plate]})
    # Шукаємо в архіві
    enter_data, _, _ = get_all_data()
    matches = [r for r in enter_data if r['norm_plate'] == plate]
    if matches:
        last = max(matches, key=lambda x: x['dt'])
        return jsonify({'found': False, 'last_seen': last['dt'].strftime('%d.%m.%Y %H:%M')})
    return jsonify({'found': False})


@app.route('/api/save_trailer', methods=['POST'])
@login_required
def api_save_trailer():
    """Зберігає номер прицепа для машини."""
    data = request.get_json(silent=True) or {}
    plate = normalize_plate(str(data.get('plate', '')))
    trailer = normalize_plate(str(data.get('trailer', '')))
    if not plate or not trailer:
        return jsonify({'ok': False}), 400
    try:
        fpath = get_check_filename()
        check_data = load_check_data()
        if plate in check_data:
            check_data[plate]['trailer'] = trailer
            with open(fpath, 'w', encoding='utf-8') as f:
                for p, info in check_data.items():
                    f.write(f"{p}|{info['status']}|{info['time']}|{info.get('trailer','')}\n")
        audit('SAVE_TRAILER', f'{plate}+{trailer}')
        return jsonify({'ok': True})
    except:
        return jsonify({'ok': False}), 500



@app.route('/api/finish_check', methods=['POST'])
@login_required
def api_finish_check():
    """Завершує перевірку — архівує файл з міткою часу і очищає поточний."""
    try:
        fpath = get_check_filename()
        if os.path.isfile(fpath):
            # Перейменовуємо файл — додаємо час завершення
            now = datetime.now()
            time_suffix = now.strftime('%H-%M')
            archived = fpath.replace('.txt', f'_{time_suffix}.txt')
            # Якщо такий файл вже є — просто видаляємо поточний
            if not os.path.exists(archived):
                import shutil as _sh
                _sh.copy2(fpath, archived)
            os.remove(fpath)
        # Очищаємо прицепи
        tfpath = get_trailers_filename()
        if os.path.isfile(tfpath):
            os.remove(tfpath)
        audit('FINISH_CHECK', f'by {session.get("user","?")}')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/add_trailer', methods=['POST'])
@login_required
def api_add_trailer():
    data = request.get_json(silent=True) or {}
    trailer = normalize_plate(str(data.get('trailer', '')))
    if not trailer:
        return jsonify({'ok': False}), 400
    trailers = load_trailers()
    if trailer not in trailers:
        trailers.append(trailer)
        save_trailers(trailers)
        audit('ADD_TRAILER', trailer)
    return jsonify({'ok': True})


@app.route('/api/remove_trailer', methods=['POST'])
@login_required
def api_remove_trailer():
    data = request.get_json(silent=True) or {}
    trailer = normalize_plate(str(data.get('trailer', '')))
    trailers = load_trailers()
    trailers = [t for t in trailers if t != trailer]
    save_trailers(trailers)
    audit('REMOVE_TRAILER', trailer)
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
