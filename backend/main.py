"""SentinelAI backend: simulated events -> rules + scikit-learn IsolationForest -> correlation -> SQLite -> WebSocket.
Run:  uvicorn main:app --reload --port 8000   then open http://localhost:8000"""
import asyncio, json, random, sqlite3, time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from sklearn.ensemble import IsolationForest

app = FastAPI(title="SentinelAI")
R, now = random.randint, lambda: int(time.time() * 1000)
HOSTS = ["web-01", "web-02", "app-03", "db-02"]
W = {1: 10, 2: 35, 3: 55, 4: 75}
CFG = dict(brute=5, scan=8, mb=500, z=3, mlp=70, auto=False, off={})
PB = {"ML anomaly: transaction": ["Hold the transaction pending review", "Contact the account owner to confirm the activity", "Freeze the account if fraud is confirmed"],
      "Brute force": ["Block source IP at the firewall", "Force password reset for the targeted account", "Review auth logs for other targeted accounts"],
      "Login after brute force": ["Disable the compromised account", "Revoke active sessions and tokens", "Notify account owner and security lead"],
      "Port scan": ["Block scanning IP", "Review exposed services on target host", "Add IDS signature for the scan pattern"],
      "Impossible travel": ["Verify with user via secondary channel", "Require MFA re-authentication", "Disable account if unverified"],
      "Data exfiltration": ["Isolate the host from the network", "Identify and block the destination IP", "Snapshot host for forensics"],
      "Metric anomaly": ["Check recent deployments", "Restart or scale out the service", "Isolate host if security-related"]}

db = sqlite3.connect(Path(__file__).with_name("sentinel.db"), check_same_thread=False)
db.executescript("create table if not exists alerts(id int,t int,rule text,sev int,ip text,usr text,host text,msg text,ml int);"
                 "create table if not exists audit(t int,inc text,msg text);")

# ---- ML: scikit-learn Isolation Forest trained on a synthetic "normal" baseline (amount, velocity, new-payee)
MODEL = IsolationForest(n_estimators=100, random_state=7).fit(
    [[R(20, 450), random.choice([1, 1, 2, 2, 3, 3, 4, 5, 6]), int(random.random() < .08)] for _ in range(1000)])
ml_score = lambda x: float(-MODEL.score_samples([x])[0])  # 0..1, higher = more anomalous

def fresh():
    return dict(ev=[], al=[], inc=[], blocked=set(), disabled=set(), isolated=set(), audit=[], fails={}, ports={}, login={}, cool={},
                seen=set(), lab=set(), n=0, cnt=0, last=0, rate=[0]*60, cpu=[35]*60, lat=[110]*60, an=[0]*60, det=[], rt=[], rec=[],
                spike=0, t0=0, tx={}, paused=False)
S = fresh()
ext = lambda: f"{random.choice([185,45,91,103])}.{R(10,250)}.{R(1,250)}.{R(1,250)}"
lan = lambda: f"10.0.{R(0,3)}.{R(2,250)}"
def push(e): S["ev"].insert(0, e); del S["ev"][120:]

def msg(e):
    g = e.get
    return {"auth_fail": f"Failed login for {g('user')} from {g('ip')}", "auth_ok": f"Login OK {g('user')} from {g('ip')} ({g('country')})",
            "conn": f"{g('ip')} → {g('host')}:{g('port')}", "http": f"HTTP 200 {g('ip')} → {g('host')}",
            "egress": f"{g('host')} outbound {g('bytes',0)//10**6} MB → {g('ip')}",
            "txn": f"Txn ${g('amt')} by {g('user')}{' to NEW payee' if g('np') else ''} (velocity {g('vel')}/min)"}[e["type"]]

def emit(e):
    e["t"] = now()
    if e.get("ext") and (e["ip"] in S["blocked"] or e.get("host") in S["isolated"] or (e.get("user") in S["disabled"] and e["type"].startswith("auth"))):
        push({"t": e["t"], "type": "blocked", "msg": f"Dropped {e['type']} from {e['ip']} (response action active)"}); return
    if e.get("atk"): S["lab"].add(e["atk"])
    else: S["n"] += 1
    e["msg"] = msg(e); push(e); S["cnt"] += 1; detect(e)

def detect(e):
    n, k, ty = e["t"], e.get("ip"), e["type"]
    if ty == "txn":
        s = ml_score([e["amt"], e["vel"], e["np"]])
        if s * 100 >= CFG["mlp"]:
            raise_("ML anomaly: transaction", 4 if s >= .75 else 3, e, f"Isolation Forest score {s:.2f}: ${e['amt']} by {e['user']}{' to a new payee' if e['np'] else ''}, velocity {e['vel']}/min")
    if ty == "auth_fail":
        a = S["fails"][k] = [t for t in S["fails"].get(k, []) if n - t < 6e4] + [n]
        if len(a) >= CFG["brute"]: raise_("Brute force", 3, e, f"{len(a)} failed logins from {k} in 60s targeting {e['user']}")
    if ty == "auth_ok":
        if len([t for t in S["fails"].get(k, []) if n - t < 6e4]) >= CFG["brute"]:
            raise_("Login after brute force", 4, e, f"{e['user']} logged in from {k} right after a failed-login burst")
        l = S["login"].get(e["user"])
        if l and l[0] != e["country"] and n - l[1] < 6e5:
            raise_("Impossible travel", 3, e, f"{e['user']} logged in from {e['country']} only {(n-l[1])//1000}s after {l[0]}")
        S["login"][e["user"]] = (e["country"], n)
    if ty == "conn":
        a = S["ports"][k] = [x for x in S["ports"].get(k, []) if n - x[1] < 3e4] + [(e["port"], n)]
        d = len({x[0] for x in a})
        if d >= CFG["scan"]: raise_("Port scan", 2, e, f"{k} probed {d} ports on {e['host']} in 30s")
    if ty == "egress" and e["bytes"] >= CFG["mb"] * 10**6:
        raise_("Data exfiltration", 4, e, f"{e['host']} sent {e['bytes']//10**6} MB to external {k}")

def raise_(rule, sev, e, m):
    if CFG["off"].get(rule): return
    key, n = rule + str(e.get("ip") or e.get("host")), e.get("t") or now()
    if n - S["cool"].get(key, 0) < 6e4: return
    S["cool"][key] = n
    a = dict(id=len(S["al"]) + 1, t=n, rule=rule, sev=sev, ip=e.get("ip"), user=e.get("user"), host=e.get("host"), msg=m, atk=e.get("atk"), ml=rule.startswith("ML"))
    if e.get("atk") and e["atk"] not in S["seen"]: S["seen"].add(e["atk"]); S["det"].append((n - e["atk"]) / 1000)
    S["al"].append(a); push({"t": n, "type": "alert", "msg": f"ALERT [{rule}] {m}"})
    db.execute("insert into alerts values(?,?,?,?,?,?,?,?,?)", (a["id"], n, rule, sev, a["ip"], a["user"], a["host"], m, int(a["ml"]))); db.commit()
    i = correlate(a)
    if CFG["auto"] and i["risk"] >= 75:
        for x in list(i["ips"]):
            if not x.startswith("10.") and x not in S["blocked"]: request(i, "ip", x, "SentinelAI")

def correlate(a):
    i = next((x for x in S["inc"] if x["status"] != "Resolved" and a["t"] - x["upd"] < 3e5 and ((a["ip"] and a["ip"] in x["ips"]) or (a["user"] and a["user"] in x["users"]) or (a["host"] and a["host"] in x["hosts"]))), None)
    if not i:
        i = dict(id=f"INC-{1001+len(S['inc'])}", created=a["t"], upd=a["t"], status="New", st={"det": a["t"]}, alerts=[], ips=set(), users=set(), hosts=set(),
                 tl=[{"t": a["t"], "m": "Incident opened automatically"}], steps={}, pend=[])
        S["inc"].insert(0, i)
    i["alerts"].append(a); a["inc"] = i["id"]; i["upd"] = a["t"]
    for k, f in (("ips", "ip"), ("users", "user"), ("hosts", "host")):
        if a[f]: i[k].add(a[f])
    i["tl"].append({"t": a["t"], "m": f"Alert: {a['rule']} — {a['msg']}"})
    p0 = time.perf_counter(); score(i); S["rec"].append((time.perf_counter() - p0) * 1000)
    return i

def score(i):
    rules, top = {a["rule"] for a in i["alerts"]}, max(i["alerts"], key=lambda a: a["sev"])
    i["risk"] = min(100, W[top["sev"]] + (len(rules) - 1) * 12 + min(len(i["alerts"]) - 1, 4) * 3)
    i["sev"] = "Critical" if i["risk"] >= 80 else "High" if i["risk"] >= 60 else "Medium" if i["risk"] >= 35 else "Low"
    i["title"] = ("Multi-stage: " if len(rules) > 1 else "") + top["rule"] + " · " + (top["user"] or top["host"] or top["ip"])
    v = []
    if {"Port scan", "Brute force"} <= rules: v.append("Reconnaissance followed by a credential attack from one source.")
    if "Login after brute force" in rules: v.append("A successful login right after repeated failures suggests account takeover.")
    if "Data exfiltration" in rules: v.append("Large outbound transfer after intrusion indicators matches a full kill chain (recon → access → exfiltration)." if len(rules) > 1 else "Unusually large outbound transfer to an external address.")
    if "Impossible travel" in rules: v.append("Same account active from two countries faster than physically possible.")
    if "ML anomaly: transaction" in rules: v.append("scikit-learn Isolation Forest flagged a transaction as an outlier versus the learned baseline (amount, velocity, new payee).")
    if "Metric anomaly" in rules: v.append("Metrics deviated over 3 standard deviations from the rolling baseline.")
    i["why"] = f"{len(i['alerts'])} raw alert(s) from {len(rules)} detector(s) merged on shared entities. " + " ".join(v)

steps_of = lambda i: [s for r in dict.fromkeys(a["rule"] for a in i["alerts"]) for s in PB[r]]
def log(i, m):
    t = now(); i["tl"].append({"t": t, "m": m}); S["audit"].insert(0, {"t": t, "id": i["id"], "m": m})
    db.execute("insert into audit values(?,?,?)", (t, i["id"], m)); db.commit()

def set_status(i, st, auto=False):
    if i["status"] == st: return
    i["status"] = st; k = {"Investigating": "ana", "Contained": "con", "Resolved": "res"}.get(st)
    if k: i["st"].setdefault(k, now())
    if st == "Resolved" and not i.get("res"): i["res"] = now(); S["rt"].append((i["res"] - i["created"]) / 1000)
    log(i, f"Status → {st}" + (" (auto, after response action)" if auto else ""))

def request(i, k, v, by):  # human-in-the-loop: nothing executes until an Admin approves
    if any(p["k"] == k and p["v"] == v for p in i["pend"]): return
    i["pend"].append(dict(k=k, v=v, by=by)); log(i, f"Approval requested: {k} {v} (by {by})")

def do_act(i, k, v):  # simulated remediation
    if k == "ip": S["blocked"].add(v); log(i, f"Response: blocked IP {v} at firewall")
    if k == "user": S["disabled"].add(v); log(i, f"Response: disabled account {v}, sessions revoked")
    if k == "host": S["isolated"].add(v); S["spike"] = 0; log(i, f"Response: isolated host {v} from network")
    if i["status"] in ("New", "Investigating"): set_status(i, "Contained", True)

def txn(u, bad=0):
    t = now(); h = S["tx"][u] = [x for x in S["tx"].get(u, []) if t - x < 6e4] + [t]
    return dict(type="txn", user=u, ip=f"10.1.0.{len(u)+10}", amt=R(15000, 40000) if bad else R(20, 450), vel=len(h) + (4 if bad else 0), np=1 if bad else int(random.random() < .08), atk=bad)

def normal():
    r, u, ip, host = random.random(), random.choice(["alice", "bob", "carol", "dev.ops"]), lan(), random.choice(HOSTS)
    if r < .3: emit(dict(type="auth_ok", ip=ip, user=u, country="IN"))
    elif r < .38: emit(dict(type="auth_fail", ip=ip, user=u))
    elif r < .68: emit(dict(type="http", ip=ip, host=host))
    elif r < .85: emit(txn(u))
    else: emit(dict(type="egress", host=host, ip=ext(), bytes=R(1, 40) * 10**6))

def tick():
    sp, pc = S["spike"] > 0 and "app-03" not in S["isolated"], S["cpu"][-1]
    cpu = R(88, 99) if sp else max(15, min(60, pc + R(-5, 5)))
    if not sp and pc > 65: cpu = R(35, 45)
    lat = R(1400, 2200) if sp else R(90, 140)
    if S["spike"] > 0: S["spike"] -= 1
    w = S["cpu"][-30:]; m = sum(w) / 30; sd = max(2, (sum((x - m) ** 2 for x in w) / 30) ** .5); z = (cpu - m) / sd; an = int(abs(z) > CFG["z"])
    for k, v in (("cpu", cpu), ("lat", lat), ("an", an), ("rate", S["cnt"] - S["last"])): S[k].append(v); S[k].pop(0)
    S["last"] = S["cnt"]
    if an: raise_("Metric anomaly", 2, dict(t=now(), host="app-03", atk=S["t0"]), f"CPU {cpu}% (z-score {z:.1f}), latency {lat} ms on app-03")
    if not S["spike"]: S["t0"] = 0

async def burst(n, ms, f):
    for k in range(n):
        if not S["paused"]: emit(f(k))
        await asyncio.sleep(ms / 1000)
async def later(s, f): await asyncio.sleep(s); f()

def run(name, ip=None):
    atk, ip, T = now(), ip or ext(), asyncio.create_task
    if name == "brute": T(burst(9, 350, lambda k: dict(type="auth_fail" if k < 8 else "auth_ok", ip=ip, user="admin", country="RU", ext=1, atk=atk)))
    if name == "scan":
        ports = [22, 80, 443, 3306, 3389, 8080, 21, 25, 53, 110, 445, 5432, 6379, 9200]
        T(burst(14, 200, lambda k: dict(type="conn", ip=ip, host="web-01", port=ports[k], ext=1, atk=atk)))
    if name == "travel":
        emit(dict(type="auth_ok", ip=lan(), user="priya.n", country="IN"))
        T(later(1.5, lambda: emit(dict(type="auth_ok", ip=ip, user="priya.n", country="RU", ext=1, atk=atk))))
    if name == "exfil": T(burst(4, 500, lambda k: dict(type="egress", host="db-02", ip=ip, bytes=R(600, 900) * 10**6, ext=1, atk=atk)))
    if name == "txn": T(burst(3, 600, lambda k: txn("carol", atk)))
    if name == "anom": S["spike"], S["t0"] = 10, atk; S["lab"].add(atk)
    if name == "chain": run("scan", ip); T(later(3.5, lambda: run("brute", ip))); T(later(9.5, lambda: run("exfil", ip)))

def reset():
    global S; S = fresh()
def suite():
    reset()
    for k, n in enumerate(["brute", "scan", "travel", "exfil", "txn", "anom"]): asyncio.create_task(later(1.5 + 6 * k, lambda n=n: run(n)))

CLIENTS = set()
def snap():
    inc = [{**i, "ips": list(i["ips"]), "users": list(i["users"]), "hosts": list(i["hosts"])} for i in S["inc"]]
    return dict(ev=S["ev"], al=S["al"], inc=inc, rate=S["rate"], cpu=S["cpu"], lat=S["lat"], an=S["an"], det=S["det"], rt=S["rt"], rec=S["rec"][-200:], nCnt=S["n"],
                seen=len(S["seen"]), lab=len(S["lab"]), blocked=list(S["blocked"]), disabled=list(S["disabled"]), isolated=list(S["isolated"]),
                audit=S["audit"][:200], paused=S["paused"], cfg=CFG)
async def broadcast():
    data = json.dumps(snap())
    for ws in list(CLIENTS):
        try: await ws.send_text(data)
        except Exception: CLIENTS.discard(ws)
async def gen_loop():
    while True:
        await asyncio.sleep(.55)
        if not S["paused"]: normal()
async def tick_loop():
    while True:
        await asyncio.sleep(1)
        if not S["paused"]: tick()
        if CLIENTS: await broadcast()
@app.on_event("startup")
async def startup(): asyncio.create_task(gen_loop()); asyncio.create_task(tick_loop())

def inc_of(d):
    x = next((x for x in S["inc"] if x["id"] == d["id"]), None)
    if not x: raise HTTPException(404, "incident not found")
    return x
def admin(d):
    if d.get("role") != "Admin": raise HTTPException(403, "Admin role required (human approval)")

@app.get("/api/health")
async def health(): return dict(ok=True, model="scikit-learn IsolationForest", db="sqlite", clients=len(CLIENTS))
@app.get("/api/audit")
async def audit(): return [dict(t=r[0], incident=r[1], msg=r[2]) for r in db.execute("select t,inc,msg from audit order by t desc limit 500")]
@app.get("/api/alerts")
async def alerts(): return [dict(zip(("id", "t", "rule", "sev", "ip", "user", "host", "msg", "ml"), r)) for r in db.execute("select * from alerts order by t desc limit 500")]
@app.post("/api/simulate/{name}")
async def simulate(name: str):
    suite() if name == "suite" else run(name); return dict(ok=True)
@app.post("/api/request")
async def api_request(r: Request): d = await r.json(); request(inc_of(d), d["k"], d["v"], d.get("role", "Analyst")); return dict(ok=True)
@app.post("/api/approve")
async def approve(r: Request):
    d = await r.json(); admin(d); i = inc_of(d); p = i["pend"].pop(d["n"])
    if d["yes"]: log(i, f"Approved by Admin: {p['k']} {p['v']}"); do_act(i, p["k"], p["v"])
    else: log(i, f"Rejected by Admin: {p['k']} {p['v']}")
    return dict(ok=True)
@app.post("/api/status")
async def status(r: Request):
    d = await r.json()
    if d["st"] == "Resolved": admin(d)
    set_status(inc_of(d), d["st"]); return dict(ok=True)
@app.post("/api/step")
async def step(r: Request):
    d = await r.json(); i = inc_of(d); i["steps"][str(d["n"])] = d["c"]; i["st"].setdefault("ana", now())
    log(i, f"Playbook step {'done' if d['c'] else 'reopened'}: {steps_of(i)[d['n']]}"); return dict(ok=True)
@app.post("/api/config")
async def config(r: Request):
    d = await r.json()
    for k in ("brute", "scan", "mb", "z", "mlp", "auto", "off"):
        if k in d: CFG[k] = d[k]
    return CFG
@app.post("/api/pause")
async def pause(r: Request): S["paused"] = not S["paused"]; return dict(paused=S["paused"])
@app.post("/api/reset")
async def reset_api(r: Request): reset(); return dict(ok=True)

@app.get("/")
def index(): return FileResponse(Path(__file__).parent.parent / "frontend" / "index.html")
@app.websocket("/ws")
async def stream(sock: WebSocket):
    await sock.accept(); CLIENTS.add(sock)
    try:
        await sock.send_text(json.dumps(snap()))
        while True: await sock.receive_text()
    except WebSocketDisconnect: pass
    finally: CLIENTS.discard(sock)
