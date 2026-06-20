/**
 * BotSignal Tracker — Visitor Intelligence for the AI Age
 *
 * Embed on any page:
 *   <script src="https://your-server.com/tracker.js" data-site-id="mysite"></script>
 *
 * Collects behavioral signals (mouse, scroll, timing, canvas fingerprint,
 * honeypot fields) and sends them to the BotSignal API for human vs agent
 * classification.
 *
 * This tool provides INTEL, not blocking — site owners see who's visiting.
 */
(function() {
  'use strict';

  var SCRIPT = document.currentScript || document.querySelector('script[src*="tracker.js"]');
  var SITE_ID = SCRIPT.getAttribute('data-site-id') || 'default';
  var API_BASE = SCRIPT.getAttribute('data-api') || '';

  if (!API_BASE) {
    var src = SCRIPT.src || '';
    API_BASE = src.substring(0, src.lastIndexOf('/'));
  }

  var VISIT_ID = null;
  var START_TIME = Date.now();
  var FIRST_ACTION_TIME = null;
  var MOUSE_SAMPLES = [];
  var SCROLL_EVENTS = [];
  var VIEWPORT_CHANGES = 0;
  var ORIENTATION_CHANGES = 0;
  var FORM_INTERACTIONS = 0;
  var HAS_SENT_BEHAVIOR = false;
  var CANVAS_HASH = null;
  var HONEYPOT_FILLED = false;

  // ─── Utilities ─────────────────────────────────────────────────────────

  function generateId() {
    return Math.random().toString(36).substring(2, 15) +
           Math.random().toString(36).substring(2, 15);
  }

  function sendToApi(endpoint, data) {
    try {
      var payload = JSON.stringify(data);
      if (navigator.sendBeacon) {
        navigator.sendBeacon(API_BASE + endpoint, payload);
      } else {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', API_BASE + endpoint, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(payload);
      }
    } catch(e) {
      // Fail silently
    }
  }

  // ─── Canvas Fingerprint ────────────────────────────────────────────────
  // Headless browsers render canvas text/shapes differently than real GPUs.
  // The resulting toDataURL hash is a strong signal.

  function captureCanvas() {
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 50;
      var ctx = c.getContext('2d');
      if (!ctx) { CANVAS_HASH = 'no-canvas'; return; }
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f60';
      ctx.fillRect(10, 10, 180, 30);
      ctx.fillStyle = '#069';
      ctx.font = '14px Arial';
      ctx.fillText('BotSignal', 15, 32);
      ctx.beginPath();
      ctx.arc(100, 25, 15, 0, Math.PI * 2);
      ctx.strokeStyle = '#000';
      ctx.lineWidth = 0.5;
      ctx.stroke();
      var url = c.toDataURL();
      var h = 0;
      for (var i = 0; i < url.length; i++) { h = ((h << 5) - h) + url.charCodeAt(i); h |= 0; }
      CANVAS_HASH = Math.abs(h).toString(16);
    } catch(e) { CANVAS_HASH = 'error'; }
  }

  // ─── Honeypot Fields ──────────────────────────────────────────────────
  // Invisible input that bots auto-fill but humans never touch.

  function setupHoneypot() {
    var hp = document.createElement('input');
    hp.type = 'text';
    hp.name = 'botsignal_hp_website';
    hp.autocomplete = 'off';
    hp.tabIndex = -1;
    hp.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;opacity:0;pointer-events:none;';
    var checkHp = function() { if (hp.value && hp.value.length > 0) HONEYPOT_FILLED = true; };
    document.addEventListener('click', checkHp, { passive: true, once: true });
    setTimeout(checkHp, 3000);
    setTimeout(function() { document.body.appendChild(hp); }, 500);
  }

  // ─── Signal Collection ─────────────────────────────────────────────────

  // Mouse movement (sampled)
  var MOUSE_THROTTLE = null;
  document.addEventListener('mousemove', function(e) {
    if (MOUSE_THROTTLE) return;
    MOUSE_THROTTLE = setTimeout(function() { MOUSE_THROTTLE = null; }, 100);
    MOUSE_SAMPLES.push({ x: e.clientX, y: e.clientY, t: Date.now() - START_TIME });
    if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
  }, { passive: true });

  document.addEventListener('click', function() {
    if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
  }, { passive: true });

  document.addEventListener('touchstart', function() {
    if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
  }, { passive: true });

  // Scroll
  var SCROLL_THROTTLE = null;
  var LAST_SCROLL_Y = window.scrollY;
  var SCROLL_DIRECTION_CHANGES = 0;
  var LAST_SCROLL_DIR = null;
  window.addEventListener('scroll', function() {
    if (SCROLL_THROTTLE) return;
    SCROLL_THROTTLE = setTimeout(function() { SCROLL_THROTTLE = null; }, 150);
    var currentY = window.scrollY;
    var dir = currentY > LAST_SCROLL_Y ? 'down' : 'up';
    if (LAST_SCROLL_DIR && dir !== LAST_SCROLL_DIR) SCROLL_DIRECTION_CHANGES++;
    LAST_SCROLL_DIR = dir;
    LAST_SCROLL_Y = currentY;
    SCROLL_EVENTS.push({ y: currentY, t: Date.now() - START_TIME, dir: dir });
    if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
  }, { passive: true });

  var RESIZE_TIMER = null;
  window.addEventListener('resize', function() {
    clearTimeout(RESIZE_TIMER);
    RESIZE_TIMER = setTimeout(function() { VIEWPORT_CHANGES++; }, 500);
  }, { passive: true });

  document.addEventListener('focusin', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
      FORM_INTERACTIONS++;
      if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
    }
  }, { passive: true });

  document.addEventListener('keydown', function() {
    if (!FIRST_ACTION_TIME) FIRST_ACTION_TIME = Date.now() - START_TIME;
  }, { passive: true });

  window.addEventListener('orientationchange', function() { ORIENTATION_CHANGES++; });

  // ─── Compute Signals ──────────────────────────────────────────────────

  function computeSignals() {
    var totalTime = Date.now() - START_TIME;
    var scrollVariance = 0;
    if (SCROLL_EVENTS.length > 1) {
      var meanY = SCROLL_EVENTS.reduce(function(s, e) { return s + e.y; }, 0) / SCROLL_EVENTS.length;
      scrollVariance = Math.sqrt(
        SCROLL_EVENTS.reduce(function(a, e) { return a + Math.pow(e.y - meanY, 2); }, 0) / SCROLL_EVENTS.length
      );
    }

    return {
      visit_id: VISIT_ID,
      site_id: SITE_ID,
      time_to_first_action_ms: FIRST_ACTION_TIME || -1,
      mouse_samples: MOUSE_SAMPLES.length,
      mouse_path_length: MOUSE_SAMPLES.length > 1
        ? MOUSE_SAMPLES.reduce(function(acc, s, i, arr) {
            if (i === 0) return 0;
            return acc + Math.sqrt(Math.pow(s.x - arr[i-1].x, 2) + Math.pow(s.y - arr[i-1].y, 2));
          }, 0)
        : 0,
      scroll_events: SCROLL_EVENTS.length,
      scroll_variance: Math.round(scrollVariance),
      scroll_direction_changes: SCROLL_DIRECTION_CHANGES,
      viewport_changes: VIEWPORT_CHANGES,
      orientation_changes: ORIENTATION_CHANGES,
      form_interactions: FORM_INTERACTIONS,
      canvas_hash: CANVAS_HASH,
      honeypot_filled: HONEYPOT_FILLED,
      total_time_ms: totalTime,
      page_visibility: document.visibilityState,
      screen: window.screen.width + 'x' + window.screen.height,
      viewport: window.innerWidth + 'x' + window.innerHeight,
      device_pixel_ratio: window.devicePixelRatio || 1,
      timezone_offset: new Date().getTimezoneOffset(),
      languages: (navigator.languages || [navigator.language]).join(','),
    };
  }

  // ─── Visit Lifecycle ──────────────────────────────────────────────────

  function initVisit() {
    VISIT_ID = generateId();
    var visitData = {
      site_id: SITE_ID,
      visit_id: VISIT_ID,
      url: window.location.href.substring(0, 500),
      title: document.title.substring(0, 200),
      referrer: document.referrer || '',
    };
    var xhr = new XMLHttpRequest();
    xhr.open('POST', API_BASE + '/api/visit', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onreadystatechange = function() {
      if (xhr.readyState === 4 && xhr.status === 200) {
        try { var resp = JSON.parse(xhr.responseText); if (resp.visit_id) VISIT_ID = resp.visit_id; } catch(e) {}
      }
    };
    xhr.send(JSON.stringify(visitData));
  }

  function sendBehavior() {
    if (HAS_SENT_BEHAVIOR) return;
    HAS_SENT_BEHAVIOR = true;
    var signals = computeSignals();
    sendToApi('/api/behavior', signals);
  }

  // ─── Boot ──────────────────────────────────────────────────────────────

  captureCanvas();
  setupHoneypot();
  initVisit();

  window.addEventListener('beforeunload', sendBehavior);
  window.addEventListener('pagehide', sendBehavior);
  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') sendBehavior();
  });

  setTimeout(function() {
    if (!HAS_SENT_BEHAVIOR) { sendBehavior(); }
  }, 300000);

  console.log('[BotSignal] Tracking initialized for site: ' + SITE_ID);
})();