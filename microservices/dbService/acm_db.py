#!/usr/bin/env python3
"""
acm-db - user credential storage service.

Pure Python standard library (no pip install). Implements the acm-db OpenAPI
contract exactly and adds a few extras:

  POST /db/users             store {username, password_hash}      -> 201 / 400
  GET  /db/users/{username}  fetch a stored record                -> 200 / 404

  Added (does not alter the contract):
  GET  /events               live event stream (Server-Sent Events, JSON)
  GET  /dashboard            live event-log dashboard (HTML)
  GET  /health               status, user count, DNS registration state
  422 for malformed input, 413 for oversized bodies, 405 for wrong methods,
  500 as a clean JSON error.

Run:
  python acm_db.py --dns <host:port of acm-dns>
  (or set DNS_ADDR, or type it when prompted)

Every address is supplied at runtime: nothing is hardcoded.
"""
import argparse
import json
import os
import queue
import socket
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

SERVICE = "acm-db"
MAX_BODY = 64 * 1024
MAX_USERNAME = 128
MAX_HASH = 1024
START = time.time()

# --- acm-dns registration contract (ASSUMED: adjust to the real acm-dns spec) ---
DNS_REGISTER_PATH = os.environ.get("DNS_REGISTER_PATH", "/register")
DNS_NAME_FIELD = os.environ.get("DNS_NAME_FIELD", "domain")
DNS_ADDR_FIELD = os.environ.get("DNS_ADDR_FIELD", "ip")
DNS_REREGISTER_SECONDS = float(os.environ.get("DNS_REREGISTER_SECONDS", "30"))

STATE = {"dns_registered": False, "advertise": None, "dns": None}


# --------------------------------------------------------------------------
# Event bus: feeds /events (SSE), the dashboard and the console
# --------------------------------------------------------------------------
class EventBus:
    def __init__(self):
        self.lock = threading.Lock()
        self.subs = set()
        self.history = deque(maxlen=200)
        self.counter = 0

    def emit(self, message, source=SERVICE, target=None, level="info"):
        with self.lock:
            self.counter += 1
            ev = {
                "id": self.counter,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "source": source,
                "level": level,
                "message": message,
            }
            if target:
                ev["target"] = target
            self.history.append(ev)
            subs = list(self.subs)
        for q in subs:
            try:
                q.put_nowait(ev)
            except queue.Full:
                pass  # slow consumer: drop rather than block the service
        arrow = f" -> {target}" if target else ""
        print(f"[{ev['ts'][11:23]}] {level.upper():5} {source}{arrow}: {message}", flush=True)

    def subscribe(self, replay=0):
        q = queue.Queue(maxsize=500)
        with self.lock:
            backlog = list(self.history)[-replay:] if replay > 0 else []
            self.subs.add(q)
        return q, backlog

    def unsubscribe(self, q):
        with self.lock:
            self.subs.discard(q)


BUS = EventBus()


# --------------------------------------------------------------------------
# Storage (SQLite, unique index on username makes duplicate detection atomic)
# --------------------------------------------------------------------------
DB = None
DB_LOCK = threading.Lock()


def open_db(path):
    global DB
    DB = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5)
    DB.execute("PRAGMA journal_mode=WAL")
    DB.execute("PRAGMA synchronous=NORMAL")
    DB.execute(
        """CREATE TABLE IF NOT EXISTS users (
               user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
               username      TEXT NOT NULL UNIQUE,
               password_hash TEXT NOT NULL,
               created_at    TEXT NOT NULL
           )"""
    )


def insert_user(username, password_hash):
    """Returns user_id, or None if the username already exists."""
    with DB_LOCK:
        try:
            cur = DB.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None


def find_user(username):
    with DB_LOCK:
        return DB.execute(
            "SELECT user_id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def count_users():
    with DB_LOCK:
        return DB.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# --------------------------------------------------------------------------
# acm-dns registration with retry / backoff (never blocks or crashes the API)
# --------------------------------------------------------------------------
def with_scheme(addr):
    addr = addr.strip().rstrip("/")
    return addr if addr.lower().startswith(("http://", "https://")) else "http://" + addr


def detect_advertise_host(dns_addr):
    """Ask the OS which local address routes towards acm-dns (no packet is sent)."""
    try:
        hostport = with_scheme(dns_addr).split("://", 1)[1].split("/")[0]
        host, _, port = hostport.partition(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, int(port or 80)))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return socket.gethostname()


def try_register():
    url = with_scheme(STATE["dns"]) + DNS_REGISTER_PATH
    body = json.dumps({DNS_NAME_FIELD: SERVICE, DNS_ADDR_FIELD: STATE["advertise"]}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as r:
            return 200 <= r.status < 300, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        if e.code == 409:  # already registered: treat as success
            return True, "already registered"
        return False, f"HTTP {e.code}"
    except Exception as e:  # DNS down / unreachable / timeout
        return False, type(e).__name__


def registrar_loop(stop):
    attempt, backoff, was_registered = 0, 1.0, False
    while not stop.is_set():
        attempt += 1
        ok, info = try_register()
        if ok:
            if not was_registered:
                BUS.emit(
                    f"registered as {SERVICE} at {STATE['advertise']} ({info})",
                    target="acm-dns",
                )
            was_registered = True
            STATE["dns_registered"] = True
            attempt, backoff = 0, 1.0
            if DNS_REREGISTER_SECONDS <= 0:
                return
            stop.wait(DNS_REREGISTER_SECONDS)  # keep-alive: heals a restarted DNS
        else:
            STATE["dns_registered"] = False
            was_registered = False
            BUS.emit(
                f"DNS registration failed ({info}), attempt {attempt}, retrying in {backoff:.0f}s",
                target="acm-dns",
                level="error",
            )
            stop.wait(backoff)
            backoff = min(backoff * 2, 15.0)


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
def clean_str(value, limit):
    return isinstance(value, str) and value.strip() != "" and len(value) <= limit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive for fast service-to-service calls
    server_version = SERVICE

    def log_message(self, *args):  # we emit our own events
        pass

    # ---- helpers
    def _cors(self):
        origin = self.headers.get("Origin")
        if origin:  # credentials are allowed, so the origin must be echoed, never "*"
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                self.headers.get("Access-Control-Request-Headers") or "Content-Type",
            )
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send(self, status, body=b"", ctype="application/json", extra=None):
        self.status = status
        self.send_response(status)
        if status != 204:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self._cors()
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status, obj, extra=None):
        self._send(status, json.dumps(obj).encode(), extra=extra)

    def _error(self, status, message, note=None, extra=None):
        self.note = note or message
        self._json(status, {"error": message}, extra=extra)

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True  # body not consumed, connection unusable
            return None, 413
        return self.rfile.read(length) if length else b"", 0

    # ---- dispatch
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_HEAD(self): self._handle()
    def do_OPTIONS(self): self._handle()

    def _handle(self):
        t0 = time.perf_counter()
        method = self.command
        parts = urlsplit(self.path)
        path = parts.path
        self.status, self.note = 0, ""
        quiet = path in ("/", "/events", "/dashboard", "/health", "/favicon.ico") or method == "OPTIONS"
        if not quiet:
            BUS.emit(f"{method} {path} received", source="acm-server", target=SERVICE)
        try:
            if method == "OPTIONS":
                self._send(204)
            elif path == "/db/users":
                self._create_user(method)
            elif path.startswith("/db/users/"):
                self._get_user(method, unquote(path[len("/db/users/"):]))
            elif path == "/events" and method == "GET":
                self._events(parts.query)
                return
            elif path in ("/", "/dashboard") and method in ("GET", "HEAD"):
                self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
            elif path == "/health" and method in ("GET", "HEAD"):
                self._json(200, {
                    "status": "ok",
                    "service": SERVICE,
                    "users": count_users(),
                    "dns": {"registered": STATE["dns_registered"], "address": STATE["advertise"]},
                    "uptime_s": int(time.time() - START),
                })
            else:
                self._error(404, "Not found")
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return
        except Exception as e:  # never leak internals, never crash the service
            self.note = f"internal error: {type(e).__name__}"
            try:
                self._json(500, {"error": "Internal database error"})
            except Exception:
                self.close_connection = True
        if not quiet:
            ms = (time.perf_counter() - t0) * 1000
            level = "error" if self.status >= 500 else "warn" if self.status >= 400 else "info"
            tail = f" - {self.note}" if self.note else ""
            BUS.emit(f"{method} {path} -> {self.status} in {ms:.1f} ms{tail}",
                     target="acm-server", level=level)

    # ---- POST /db/users
    def _create_user(self, method):
        if method != "POST":
            return self._error(405, "Method not allowed", extra={"Allow": "POST"})
        raw, problem = self._read_body()
        if problem:
            return self._error(413, "Request body too large")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._error(422, "Body must be valid JSON", "invalid JSON body")
        if not isinstance(data, dict):
            return self._error(422, "Body must be a JSON object", "invalid body")
        username, pw_hash = data.get("username"), data.get("password_hash")
        if not clean_str(username, MAX_USERNAME):
            return self._error(422, "username is required (non-empty string)", "invalid username")
        if not clean_str(pw_hash, MAX_HASH):
            return self._error(422, "password_hash is required (non-empty string)", "invalid password_hash")
        user_id = insert_user(username, pw_hash)
        if user_id is None:
            return self._error(400, "Username already exists",
                               f'duplicate username "{username}" rejected')
        self.note = f'user row inserted (id {user_id})'
        self._json(201, {"status": "ok", "user_id": user_id})

    # ---- GET /db/users/{username}
    def _get_user(self, method, username):
        if method not in ("GET", "HEAD"):
            return self._error(405, "Method not allowed", extra={"Allow": "GET"})
        if not username:
            return self._error(404, "User not found", "0 rows")
        row = find_user(username)
        if row is None:
            return self._error(404, "User not found", f'0 rows for "{username}"')
        self.note = f'1 row for "{username}", hash returned'
        self._json(200, {"user_id": row[0], "username": row[1], "password_hash": row[2]})

    # ---- GET /events  (Server-Sent Events)
    def _events(self, query):
        try:
            replay = max(0, min(200, int(parse_qs(query).get("replay", ["0"])[0])))
        except ValueError:
            replay = 0
        q, backlog = BUS.subscribe(replay)
        self.status = 200
        self.close_connection = True
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self._cors()
            self.end_headers()
            self.wfile.write(b"retry: 3000\n\n")
            for ev in backlog:
                self.wfile.write(b"data: " + json.dumps(ev).encode() + b"\n\n")
            while True:
                try:
                    ev = q.get(timeout=15)
                    self.wfile.write(b"data: " + json.dumps(ev).encode() + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")  # keep proxies and browsers happy
        except OSError:
            pass  # client went away
        finally:
            BUS.unsubscribe(q)


# --------------------------------------------------------------------------
# Dashboard (served at /dashboard, consumes /events)
# --------------------------------------------------------------------------
DASHBOARD_HTML = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>acm-db monitor</title>
<style>
:root{--deep:#0b2220;--panel:#0f2b29;--line:#1d413d;--mint:#d9f2e6;--muted:#8fb3aa;--ok:#3cc088;--warn:#f2b632;--bad:#ff7a63}
*{box-sizing:border-box}
body{margin:0;background:var(--deep);color:var(--mint);font:15px/1.5 "Segoe UI",Helvetica,Arial,sans-serif;padding:24px;display:flex;justify-content:center}
main{width:min(980px,100%)}
h1{margin:0 0 4px;font-size:26px;letter-spacing:-.02em}
p.sub{margin:0 0 18px;color:var(--muted)}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.chip{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:8px 14px;min-width:140px}
.chip small{display:block;color:var(--muted);font-size:12px}
.chip strong{font-size:17px}
.chip.live strong,.chip.ok strong{color:var(--ok)}
.chip.bad strong{color:var(--bad)}
.log{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:6px 14px;max-height:62vh;overflow:auto;font:13px/1.5 Consolas,Menlo,monospace}
.log div{padding:4px 0;border-top:1px solid #173532;overflow-wrap:anywhere}
.log div:first-child{border-top:0}
.log time{color:#5f8a82;margin-right:8px}
.log .route{color:var(--muted);margin-right:8px}
.log .warn{color:var(--warn)}.log .error{color:var(--bad)}
.empty{color:#5f8a82;padding:12px 0}
</style></head><body><main>
<h1>acm-db monitor</h1>
<p class="sub">Live requests from acm-server, storage activity and DNS registration.</p>
<div class="chips">
  <div class="chip" id="cStream"><small>Event stream</small><strong>connecting</strong></div>
  <div class="chip" id="cDns"><small>acm-dns</small><strong>-</strong></div>
  <div class="chip"><small>Users stored</small><strong id="cUsers">-</strong></div>
  <div class="chip"><small>Requests seen</small><strong id="cReq">0</strong></div>
  <div class="chip"><small>Errors (5xx / DNS)</small><strong id="cErr">0</strong></div>
</div>
<div class="log" id="log"><div class="empty">Waiting for events...</div></div>
</main>
<script>
const $=id=>document.getElementById(id);
let req=0,errs=0,seen=new Set();
function chip(id,text,cls){const c=$(id);c.className='chip '+(cls||'');c.querySelector('strong').textContent=text;}
function add(ev){
  const key=ev.ts+'#'+ev.id; if(seen.has(key))return; seen.add(key);
  const log=$('log'); const e=log.querySelector('.empty'); if(e)e.remove();
  const row=document.createElement('div'); row.className=ev.level||'info';
  const t=document.createElement('time'); t.textContent=new Date(ev.ts).toLocaleTimeString([], {hour12:false});
  const r=document.createElement('span'); r.className='route';
  r.textContent=ev.source+(ev.target?' \\u2192 '+ev.target:'');
  row.append(t,r,document.createTextNode(ev.message));
  log.prepend(row); while(log.children.length>300)log.lastChild.remove();
  if(/-> \\d{3} in /.test(ev.message))req++;
  if(ev.level==='error')errs++;
  $('cReq').textContent=req; $('cErr').textContent=errs;
}
function connect(){
  const es=new EventSource('/events?replay=60');
  es.onopen=()=>chip('cStream','live','live');
  es.onmessage=m=>{try{add(JSON.parse(m.data));}catch(e){}};
  es.onerror=()=>chip('cStream','reconnecting','bad');
}
function health(){
  fetch('/health').then(r=>r.json()).then(h=>{
    $('cUsers').textContent=h.users;
    h.dns.registered?chip('cDns','registered','ok'):chip('cDns','not registered','bad');
  }).catch(()=>chip('cDns','unreachable','bad'));
}
connect(); health(); setInterval(health,4000);
</script></body></html>
"""


# --------------------------------------------------------------------------
# Startup
# --------------------------------------------------------------------------
class Server(ThreadingHTTPServer):
    daemon_threads = True      # in-flight and SSE threads never block shutdown
    request_queue_size = 256   # listen backlog: survive bursts of simultaneous connections


def parse_args():
    p = argparse.ArgumentParser(description="acm-db: user credential storage service")
    p.add_argument("--dns", default=os.environ.get("DNS_ADDR", ""),
                   help="host:port of acm-dns (or env DNS_ADDR; prompted if missing)")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")),
                   help="port to listen on (env PORT, default 8000)")
    p.add_argument("--bind", default=os.environ.get("BIND_HOST", ""),
                   help="interface to bind (env BIND_HOST, default: all)")
    p.add_argument("--advertise", default=os.environ.get("ADVERTISE_ADDR", ""),
                   help="host:port other services should use to reach acm-db "
                        "(env ADVERTISE_ADDR; auto-detected if missing)")
    p.add_argument("--db", default=os.environ.get("DB_PATH", "acm-db.sqlite3"),
                   help="SQLite file (env DB_PATH)")
    p.add_argument("--no-dns", action="store_true",
                   help="local testing only: skip DNS registration")
    return p.parse_args()


def main():
    args = parse_args()
    dns = args.dns.strip()
    if not dns and not args.no_dns:
        if sys.stdin.isatty():
            dns = input("acm-dns address (host:port): ").strip()
        if not dns:
            sys.exit("error: acm-dns address required (--dns host:port or env DNS_ADDR)")

    open_db(args.db)
    server = Server((args.bind, args.port), Handler)

    stop = threading.Event()
    if not args.no_dns:
        STATE["dns"] = dns
        STATE["advertise"] = args.advertise.strip() or f"{detect_advertise_host(dns)}:{args.port}"
        threading.Thread(target=registrar_loop, args=(stop,), daemon=True).start()

    BUS.emit(f"listening on port {args.port}, database {args.db} ({count_users()} users)")
    print(f"  dashboard: http://localhost:{args.port}/dashboard", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        BUS.emit("shutting down")


if __name__ == "__main__":
    main()
