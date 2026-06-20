"""
BotSignal — Visitor Intelligence for the AI Age.

A lightweight analytics service that scores web traffic as human or agent/bot.
Site owners embed a single <script> tag. BotSignal collects behavioral signals
(client-side mouse/scroll/timing + server-side IP/TLS/UA) and returns a score.

Dual-mode architecture:
  MODE=standalone   — everything in one process (default)
  MODE=proxy        — scrape async from Cloudflare/nginx logs
"""

import os
import json
import time
import sqlite3
import hashlib
import re
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, jsonify, send_from_directory,
    make_response, g, render_template_string
)

# ─── Config ─────────────────────────────────────────────────────────────────

DB_PATH = Path(os.environ.get("BOTSIGNAL_DB", Path.home() / "botsignal" / "botsignal.db"))
STATIC_DIR = Path(__file__).parent / "static"
HOST = os.environ.get("BOTSIGNAL_HOST", "0.0.0.0")
PORT = int(os.environ.get("BOTSIGNAL_PORT", 8080))
SECRET = os.environ.get("BOTSIGNAL_SECRET", "changeme-in-production")

# ─── App init ───────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")

# ─── DB helpers ──────────────────────────────────────────────────────────────

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at REAL NOT NULL,
            total_visits INTEGER DEFAULT 0,
            human_visits INTEGER DEFAULT 0,
            agent_visits INTEGER DEFAULT 0,
            unknown_visits INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS visits (
            id TEXT PRIMARY KEY,
            site_id TEXT NOT NULL,
            classification TEXT NOT NULL,
            confidence REAL NOT NULL,
            ip_hash TEXT,
            user_agent TEXT,
            page_url TEXT,
            page_title TEXT,
            time_to_first_action REAL,
            mouse_samples INTEGER,
            scroll_events INTEGER,
            viewport_changes INTEGER,
            total_time_ms INTEGER,
            canvas_hash TEXT,
            honeypot_filled INTEGER DEFAULT 0,
            score_breakdown TEXT,
            created_at REAL NOT NULL,
            FOREIGN KEY (site_id) REFERENCES sites(id)
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_visits_site_time
        ON visits(site_id, created_at)
    """)
    conn.commit()
    conn.close()

# ─── Scoring Engine ──────────────────────────────────────────────────────────

# Known AI/datacenter ASN patterns and cloud providers
CLOUD_IPS = re.compile(r"^(aws|gcp|azure|oracle|digitalocean|linode|vultr|hetzner|ovh|scaleway)", re.I)
KNOWN_AGENT_IPS = {}  # populated from /api/agent-ips endpoint or config

KNOWN_BOT_UA_PATTERNS = [
    r"bot", r"crawler", r"spider", r"scraper", r"googlebot",
    r"bingbot", r"slurp", r"duckduckbot", r"baiduspider",
    r"yandexbot", r"facebookexternalhit", r"twitterbot",
    r"linkedinbot", r"semrush", r"ahrefs", r"majestic",
    r"python-requests", r"python-httpx", r"aiohttp", r"curl",
    r"wget", r"go-http-client", r"okhttp", r"axios",
    r"claude-ai", r"anthropic", r"openai", r"gptbot",
    r"chatgpt-user", r"perplexitybot", r"cohere", r"bytespider",
]

def classify_user_agent(ua: str) -> tuple:
    """Returns (classification: str, confidence: float)."""
    if not ua:
        return ("unknown", 0.0)
    ua_lower = ua.lower()
    for pattern in KNOWN_BOT_UA_PATTERNS:
        if re.search(pattern, ua_lower):
            return ("agent", 0.85)
    # Headless browser detection via UA quirks
    if "headless" in ua_lower or "phantom" in ua_lower:
        return ("agent", 0.90)
    return ("unknown", 0.0)

def score_visit(behavior_data: dict, server_data: dict) -> dict:
    """
    Combined scoring: client behavioral signals + server-side signals.
    Returns {'classification': str, 'confidence': float, 'breakdown': dict}
    """
    breakdown = {}
    total_score = 0.0
    max_score = 0.0

    # 1. Server-side: user-agent check
    max_score += 25
    ua_class, ua_conf = classify_user_agent(server_data.get("user_agent", ""))
    if ua_class == "agent":
        breakdown["user_agent"] = {"score": 0, "max": 25, "detail": f"Known bot pattern: {ua_conf*100:.0f}% confidence"}
    elif ua_class == "unknown":
        breakdown["user_agent"] = {"score": 20, "max": 25, "detail": "Unknown UA — needs behavioral data"}
        total_score += 20
    else:
        breakdown["user_agent"] = {"score": 25, "max": 25, "detail": "Standard browser"}
        total_score += 25

    # 2. Server-side: time to first request (from server perspective)
    max_score += 10
    ttf = server_data.get("time_to_first_request_ms", 0)
    if 0 < ttf < 100:  # Sub-100ms suggests automation
        breakdown["time_to_request"] = {"score": 0, "max": 10, "detail": f"Immediate request ({ttf}ms)"}
    elif ttf >= 100:
        breakdown["time_to_request"] = {"score": 10, "max": 10, "detail": f"Natural timing ({ttf}ms)"}
        total_score += 10

    # 3. Client-side: time to first action
    max_score += 20
    ttfa = behavior_data.get("time_to_first_action_ms", -1)
    if ttfa < 0:
        breakdown["time_to_action"] = {"score": 5, "max": 20, "detail": "No interaction data"}
        total_score += 5
    elif ttfa < 500:
        breakdown["time_to_action"] = {"score": 0, "max": 20, "detail": f"Suspiciously fast ({ttfa}ms)"}
    elif ttfa < 2000:
        breakdown["time_to_action"] = {"score": 8, "max": 20, "detail": f"Quick but possible ({ttfa}ms)"}
        total_score += 8
    elif ttfa < 8000:
        breakdown["time_to_action"] = {"score": 15, "max": 20, "detail": f"Human-like ({ttfa}ms)"}
        total_score += 15
    else:
        breakdown["time_to_action"] = {"score": 20, "max": 20, "detail": f"Reading before acting ({ttfa}ms)"}
        total_score += 20

    # 4. Client-side: mouse movement
    max_score += 20
    mouse_samples = behavior_data.get("mouse_samples", 0)
    if mouse_samples == 0:
        breakdown["mouse"] = {"score": 0, "max": 20, "detail": "No mouse movement detected"}
    elif mouse_samples < 5:
        breakdown["mouse"] = {"score": 5, "max": 20, "detail": f"Minimal movement ({mouse_samples} samples)"}
        total_score += 5
    elif mouse_samples < 20:
        breakdown["mouse"] = {"score": 12, "max": 20, "detail": f"Some movement ({mouse_samples} samples)"}
        total_score += 12
    else:
        breakdown["mouse"] = {"score": 20, "max": 20, "detail": f"Natural mouse movement ({mouse_samples} samples)"}
        total_score += 20

    # 5. Client-side: scroll behavior
    max_score += 15
    scroll_events = behavior_data.get("scroll_events", 0)
    scroll_variance = behavior_data.get("scroll_variance", 0)
    if scroll_events == 0:
        breakdown["scroll"] = {"score": 5, "max": 15, "detail": "No scrolling"}
        total_score += 5
    elif scroll_variance > 50:
        breakdown["scroll"] = {"score": 15, "max": 15, "detail": f"Natural scroll patterns ({scroll_events} events)"}
        total_score += 15
    else:
        breakdown["scroll"] = {"score": 8, "max": 15, "detail": f"Linear scroll pattern ({scroll_events} events)"}
        total_score += 8

    # 6. Client-side: canvas fingerprint
    max_score += 15
    canvas_hash = behavior_data.get("canvas_hash", "")
    if not canvas_hash or canvas_hash == "no-canvas":
        breakdown["canvas"] = {"score": 0, "max": 15, "detail": "Canvas fingerprint not available (headless/blocked)"}
    elif canvas_hash == "error":
        breakdown["canvas"] = {"score": 5, "max": 15, "detail": "Canvas access error — possibly restricted"}
        total_score += 5
    else:
        breakdown["canvas"] = {"score": 15, "max": 15, "detail": f"Canvas fingerprint captured ({canvas_hash[:8]}...)"}
        total_score += 15

    # 7. Client-side: honeypot field
    max_score += 10
    honeypot_filled = behavior_data.get("honeypot_filled", False)
    if honeypot_filled:
        breakdown["honeypot"] = {"score": 0, "max": 10, "detail": "Honeypot field was filled — likely a bot/scraper"}
    else:
        breakdown["honeypot"] = {"score": 10, "max": 10, "detail": "Honeypot field untouched"}
        total_score += 10

    # 8. Client-side: total time on page
    max_score += 10
    total_time = behavior_data.get("total_time_ms", 0)
    if total_time < 2000:
        breakdown["dwell_time"] = {"score": 0, "max": 10, "detail": f"Very short visit ({total_time}ms)"}
    elif total_time < 10000:
        breakdown["dwell_time"] = {"score": 3, "max": 10, "detail": f"Short visit ({total_time}ms)"}
        total_score += 3
    elif total_time < 30000:
        breakdown["dwell_time"] = {"score": 7, "max": 10, "detail": f"Normal visit ({total_time}ms)"}
        total_score += 7
    else:
        breakdown["dwell_time"] = {"score": 10, "max": 10, "detail": f"Engaged visit ({total_time}ms)"}
        total_score += 10

    # Final classification
    confidence = round((total_score / max_score) * 100, 1) if max_score > 0 else 0
    if confidence >= 70:
        classification = "human"
    elif confidence >= 30:
        classification = "unknown"
    else:
        classification = "agent"

    return {
        "classification": classification,
        "confidence": confidence,
        "breakdown": breakdown,
        "raw_score": total_score,
        "max_score": max_score,
    }

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/tracker.js")
def serve_tracker():
    """Serve the embeddable tracker script."""
    tracker_path = STATIC_DIR / "tracker.js"
    if not tracker_path.exists():
        return "Tracker not found", 404
    resp = make_response(tracker_path.read_text())
    resp.headers["Content-Type"] = "application/javascript"
    resp.headers["Cache-Control"] = "public, max-age=3600"
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/api/visit", methods=["POST"])
def record_visit():
    """
    Initial visit ping from the tracker.
    Registers the site, logs the visit, returns a session_id.
    Server-side signals checked here (IP, UA, timing).
    """
    data = request.get_json(silent=True) or {}
    site_id = data.get("site_id", "default")
    page_url = data.get("url", "")
    page_title = data.get("title", "")
    
    user_agent = request.headers.get("User-Agent", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:12]
    visit_id = hashlib.sha256(f"{ip_hash}:{time.time()}:{os.urandom(4).hex()}".encode()).hexdigest()[:16]

    # Initial score based on server-side signals only
    server_data = {
        "user_agent": user_agent,
        "time_to_first_request_ms": 0,  # We don't have this in async mode
    }
    score_result = score_visit({}, server_data)

    db = get_db()
    
    # Upsert site
    db.execute("""
        INSERT INTO sites (id, name, created_at, total_visits)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(id) DO UPDATE SET
            total_visits = total_visits + 1
    """, (site_id, site_id, time.time()))
    
    # Update classification counters
    col = f"{score_result['classification']}_visits"
    db.execute(f"UPDATE sites SET {col} = {col} + 1 WHERE id = ?", (site_id,))

    # Insert visit record with partial data (behavior comes later)
    db.execute("""
        INSERT INTO visits (id, site_id, classification, confidence, ip_hash,
                           user_agent, page_url, page_title, created_at, score_breakdown)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        visit_id, site_id, score_result["classification"],
        score_result["confidence"], ip_hash,
        user_agent[:200], page_url[:500], page_title[:200],
        time.time(), json.dumps(score_result["breakdown"])
    ))
    db.commit()

    return jsonify({
        "visit_id": visit_id,
        "classification": score_result["classification"],
        "confidence": score_result["confidence"],
    })

@app.route("/api/behavior", methods=["POST"])
def record_behavior():
    """
    Behavioral data sent on page unload.
    Re-scores the visit with client-side signals.
    """
    data = request.get_json(silent=True) or {}
    visit_id = data.get("visit_id")
    if not visit_id:
        return jsonify({"error": "visit_id required"}), 400

    db = get_db()
    visit = db.execute("SELECT * FROM visits WHERE id = ?", (visit_id,)).fetchone()
    if not visit:
        return jsonify({"error": "visit not found"}), 404

    # Build behavior data from client payload
    behavior_data = {
        "time_to_first_action_ms": data.get("time_to_first_action_ms", -1),
        "mouse_samples": data.get("mouse_samples", 0),
        "scroll_events": data.get("scroll_events", 0),
        "scroll_variance": data.get("scroll_variance", 0),
        "viewport_changes": data.get("viewport_changes", 0),
        "total_time_ms": data.get("total_time_ms", 0),
        "canvas_hash": data.get("canvas_hash", ""),
        "honeypot_filled": data.get("honeypot_filled", False),
    }

    server_data = {
        "user_agent": visit["user_agent"] or "",
        "time_to_first_request_ms": 0,
    }

    score_result = score_visit(behavior_data, server_data)

    # Update visit with behavioral data and new score
    db.execute("""
        UPDATE visits SET
            classification = ?, confidence = ?,
            time_to_first_action = ?, mouse_samples = ?,
            scroll_events = ?, total_time_ms = ?,
            score_breakdown = ?
        WHERE id = ?
    """, (
        score_result["classification"], score_result["confidence"],
        behavior_data["time_to_first_action_ms"],
        behavior_data["mouse_samples"],
        behavior_data["scroll_events"],
        behavior_data["total_time_ms"],
        json.dumps(score_result["breakdown"]),
        visit_id,
    ))

    # Update site counters if classification changed
    if score_result["classification"] != visit["classification"]:
        old_col = f"{visit['classification']}_visits"
        new_col = f"{score_result['classification']}_visits"
        db.execute(f"UPDATE sites SET {old_col} = MAX(0, {old_col} - 1), {new_col} = {new_col} + 1 WHERE id = ?",
                   (visit["site_id"],))

    db.commit()

    return jsonify({
        "visit_id": visit_id,
        "classification": score_result["classification"],
        "confidence": score_result["confidence"],
    })

@app.route("/api/sites")
def list_sites():
    """Return all sites with aggregate stats."""
    db = get_db()
    sites = db.execute("""
        SELECT id, name, created_at, total_visits,
               human_visits, agent_visits, unknown_visits
        FROM sites ORDER BY total_visits DESC
    """).fetchall()
    result = []
    for s in sites:
        total = s["total_visits"] or 1
        result.append(dict(s) | {
            "human_pct": round((s["human_visits"] / total) * 100, 1),
            "agent_pct": round((s["agent_visits"] / total) * 100, 1),
        })
    return jsonify(result)

@app.route("/api/site/<site_id>")
def site_detail(site_id):
    """Return detailed stats + recent visits for a site."""
    db = get_db()
    site = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
    if not site:
        return jsonify({"error": "site not found"}), 404

    visits = db.execute(
        "SELECT * FROM visits WHERE site_id = ? ORDER BY created_at DESC LIMIT 100",
        (site_id,)
    ).fetchall()

    # Time-series breakdown (last 24h)
    cutoff = time.time() - 86400
    recent = db.execute("""
        SELECT classification, COUNT(*) as cnt
        FROM visits
        WHERE site_id = ? AND created_at > ?
        GROUP BY classification
    """, (site_id, cutoff)).fetchall()

    return jsonify({
        "site": dict(site),
        "recent_24h": {r["classification"]: r["cnt"] for r in recent},
        "recent_visits": [dict(v) for v in visits],
    })

@app.route("/api/check")
def check_me():
    """
    Check the current visitor. Useful for testing - the tracker calls this
    so the user can see their own classification.
    """
    ua = request.headers.get("User-Agent", "")
    score = score_visit({}, {"user_agent": ua, "time_to_first_request_ms": 0})
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    return jsonify({
        "your_ip_hash": hashlib.sha256(ip.encode()).hexdigest()[:12],
        "your_user_agent": ua[:100],
        "classification": score["classification"],
        "confidence": score["confidence"],
    })

@app.route("/")
@app.route("/dashboard")
def dashboard():
    """Serve the dashboard HTML."""
    dashboard_path = STATIC_DIR / "dashboard.html"
    if not dashboard_path.exists():
        return "Dashboard not found", 404
    return dashboard_path.read_text()

@app.route("/api/overview")
def api_overview():
    """Aggregate stats across all sites (for dashboard)."""
    db = get_db()
    total = db.execute("""
        SELECT COALESCE(SUM(total_visits), 0) as total,
               COALESCE(SUM(human_visits), 0) as humans,
               COALESCE(SUM(agent_visits), 0) as agents,
               COALESCE(SUM(unknown_visits), 0) as unknown,
               COUNT(*) as site_count
        FROM sites
    """).fetchone()

    # Recent activity (last hour)
    hour_ago = time.time() - 3600
    recent = db.execute("""
        SELECT classification, COUNT(*) as cnt
        FROM visits WHERE created_at > ?
        GROUP BY classification
    """, (hour_ago,)).fetchall()

    # Last 24h hourly breakdown
    day_ago = time.time() - 86400
    hourly_raw = db.execute("""
        SELECT
            CAST((created_at - ?) / 3600 AS INTEGER) as hour_offset,
            classification,
            COUNT(*) as cnt
        FROM visits
        WHERE created_at > ?
        GROUP BY hour_offset, classification
        ORDER BY hour_offset
    """, (day_ago, day_ago)).fetchall()

    hourly = {}
    for row in hourly_raw:
        h = int(row["hour_offset"])
        if h not in hourly:
            hourly[h] = {"hour": h, "human": 0, "agent": 0, "unknown": 0}
        hourly[h][row["classification"]] = row["cnt"]

    return jsonify({
        "totals": dict(total),
        "recent_hour": {r["classification"]: r["cnt"] for r in recent},
        "hourly_24h": sorted(hourly.values(), key=lambda x: x["hour"]),
    })

if __name__ == "__main__":
    init_db()
    print(f"🔍 BotSignal running on http://{HOST}:{PORT}")
    print(f"   Dashboard: http://localhost:{PORT}/dashboard")
    print(f"   Embed: <script src=\"http://localhost:{PORT}/tracker.js\" data-site-id=\"yoursite\"></script>")
    app.run(host=HOST, port=PORT, debug=True)