# BotSignal — Competitive Landscape

**Date:** June 2026
**Context:** BotSignal is an open-source visitor intelligence tool that tells site owners whether their traffic is human or AI agent. This document maps the existing market.

---

## Existing Tools

### Enterprise Tier ($3K–$10K+/mo)

| Tool | Focus | Price (approx) | Install |
|---|---|---|---|
| **Cloudflare Bot Management** | Bot blocking at edge | $5K+/mo | CDN config |
| **DataDome** | Fraud prevention, AI agent governance | $3K–10K+/mo | Reverse proxy / SDK |
| **HUMAN Security** (fka PerimeterX) | Bot mitigation, account protection | Contact (expensive) | JavaScript + API |
| **Akamai Bot Manager** | Enterprise bot blocking | $10K+/mo | CDN config |
| **Kasada** | Anti-scraping, credential stuffing | $2K+/mo | JavaScript SDK |

All are **security products** focused on **blocking** bad traffic. Enterprise sales, long contracts, complex setup.

### Mid-Market

| Tool | Focus | Notes |
|---|---|---|
| **Superline** | AI agent *experience* platform | Newer entrant (2024). Open-source agent detection library on GitHub. Focused on optimizing FOR agents, not just detecting them. |

### What's Missing

A simple, affordable, open-source analytics layer that tells site owners if their visitors are human or AI — without being a security product or requiring enterprise pricing.

---

## BotSignal Positioning

```
                     Price               Complexity         Focus
Cloudflare           $$$$$$              🔴🔴🔴🔴🔴        Blocking
DataDome             $$$$$$              🔴🔴🔴🔴🔴        Blocking
HUMAN Security       $$$$$$              🔴🔴🔴🔴🔴        Blocking
Akamai               $$$$$$              🔴🔴🔴🔴🔴        Blocking
Kasada               $$$$                🔴🔴🔴🔴          Blocking
Superline            $$$                 🟡🟡🟡            Agent Optimization
──────────────────────────────────────────────────────────────────────
BotSignal            $0 / $19-99/mo      🟢                  Intelligence

```

## Differentiation Matrix

| Feature | Enterprise Tools | Superline | **BotSignal** |
|---|---|---|---|
| Goal | Block bad traffic | Serve agents better | Tell you who's visiting |
| Install | CDN config, 3 engineers | SDK integration | One `<script>` tag |
| Pricing | $3K–10K+/mo | $$$ | Free tier / $19 Pro |
| Open source | ❌ | Library only | ✅ Full stack |
| Self-hostable | ❌ | ❌ | ✅ |
| Behavioral signals | ✅ | ✅ | ✅ |
| Canvas fingerprint | ✅ | ? | ✅ |
| Honeypot detection | ✅ | ? | ✅ |
| Know your bot intent | ❌ (block it) | ✅ (serve it) | ✅ (see it) |
| Simple dashboard | Enterprise UX | Agent optimization UX | Clean analytics view |
| No sales call to start | ❌ | ❌ | ✅ |

---

## The Gap

The market is bifurcated:

- **Top:** Expensive security products that block bots (Cloudflare, DataDome, HUMAN, etc.)
- **New:** Agent optimization platforms (Superline) — useful but complex, aimed at GEO/marketing teams
- **Bottom:** **Empty** — no simple "what is visiting my site?" tool for the other 99% of site owners

BotSignal fills the bottom. Single `<script>` tag, instant dashboard, open source, affordable.

## Target User

- Blogger who sees weird traffic in their logs but doesn't understand it
- SaaS founder who wants to know if the 200 visits from "Anthropic" are reading docs or scraping code
- Developer who runs a side project and wants to see what's hitting it
- Anyone who uses Google Analytics but doesn't trust it anymore

## Key Insight

Every site owner already knows bot traffic is growing. No one has a simple answer. BotSignal doesn't block — it reveals. In a world where 30%+ of web traffic is AI, knowing who's on your site is the first problem to solve.