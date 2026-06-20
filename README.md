# BotSignal

**Visitor Intelligence for the AI Age**

A lightweight, open-source tool that tells you whether your web traffic comes from humans or AI agents — no enterprise pricing, no sales call, just one `<script>` tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://python.org)

> **30% of web traffic is now AI agents.** Most site owners don't know. BotSignal tells you.

## How It Works

1. **Embed** — Drop one `<script>` tag on any page
2. **Collect** — Gathers behavioral signals: mouse movement, scroll patterns, interaction timing, canvas fingerprint, honeypot detection
3. **Score** — Server-side engine combines client signals + server-side analysis (IP, UA, timing)
4. **Dashboard** — See a real-time breakdown: human vs agent traffic per site

## Signals Analyzed

| Signal | What it detects | Weight |
|---|---|---|
| **User-Agent** | Known bot/crawler patterns (GPTBot, Claude, python-requests, etc.) | 25 pts |
| **Time to first action** | <500ms = automation, 2-8s = human reading | 20 pts |
| **Mouse movement** | 0 samples = bot teleporting, 20+ = human navigating | 20 pts |
| **Canvas fingerprint** | Headless browsers render differently than real GPUs | 15 pts |
| **Scroll variance** | Bursty with direction changes = human, linear = bot | 15 pts |
| **Honeypot field** | Hidden input bots auto-fill, humans never see | 10 pts |
| **Dwell time** | <2s = bounce, 30s+ = engaged human | 10 pts |
| **Request timing** | Sub-100ms = automation pipeline | 10 pts |

## Scoring

```
 0-29%   → Agent
30-69%   → Unknown (needs more data)
70-100%  → Human
```

## Quick Start

```bash
pip install -r requirements.txt
python app.py
```

Open **http://localhost:8080/dashboard**

## Embed

```html
<script src="http://your-server:8080/tracker.js" data-site-id="mysite"></script>
```

## Deploy

```bash
docker build -t botsignal .
docker run -p 8080:8080 botsignal
```

## Roadmap

- [x] Behavioral tracking (mouse, scroll, timing, canvas, honeypot)
- [x] Server-side scoring engine
- [x] Dashboard with hourly breakdown
- [ ] Slack / email alerts
- [ ] Weekly digest reports
- [ ] Agent catalog (name known bots)
- [ ] WordPress plugin
- [ ] Cloudflare Worker deployment

## License

MIT