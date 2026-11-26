# Changelog

All notable changes to **BAITSCOPE — Cyber Deception and Threat Intelligence Platform** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to Semantic Versioning.

## [5.0] - 2026-11-26

### Added
- **Real-Time SSE Telemetry Streaming**: Added `GET /admin/api/events/stream` powered by `RealtimeStreamBroker`, observing SQLite changes at `250ms` intervals with monotonic database ID cursors (`Last-Event-ID` / `since_id`), `reset` synchronization frames, `15s` keepalive heartbeats, and FastAPI `lifespan` graceful shutdown handling.
- **On-Demand Attack & Health Endpoints**: Added `GET /admin/api/attacks/{attack_id}` for un-truncated single-incident payload inspection and lightweight `GET /admin/api/health` (`Cache-Control: no-store, no-cache`) for connectivity monitoring.
- **Configurable Update Modes & Header Manual Refresh**: Added `Real-time`, timed polling (`10s`, `15s`, `30s`, `60s`), and `Manual` dashboard update modes persisted in `localStorage`, plus an icon-only manual refresh control (`#manual-refresh-btn`) between the theme toggle and Download Logs buttons.
- **Connectivity Watchdog & Alert Restoration**: Added independent `5s` backend health probing distinguishing SSE-only interruptions (`LIVE STREAM INTERRUPTED — POLLING FALLBACK (5S)`) from genuine backend outages (`SERVER CONNECTION LOST` / auto-clearing recovery banner).
- **Dashboard Operational Refinements**: Added event-driven 5-second radar blips (`SCANNER: IDLE` between attacks), collapsible `72px` desktop sidebar navigation rail, expanded Recent Adversarial Events feed (`16` rows), and single-icon theme toggle button.
- **IP Threat Intelligence, Provenance & Rate Limiting**: Added `source_attribution.py` (`SourceAttribution`, CIDR trusted proxy chain traversal, IPv4/IPv6 canonicalization), `threat_intel.py` (`IPThreatRegistry`, weighted deterministic risk scoring, IP Watchlist API/UI, atomic SQLite fixed-window rate limiting), and idempotent schema migrations (`database.run_migrations()`).
- **Fresh-Clone Bootstrap & Empty Directory Placeholders**: Added automatic missing-directory creation (`database/`, `logs/`, `uploads/quarantine/`) and automatic self-signed TLS certificate generation in `start.py` and `app_decoy.py`, alongside `.gitkeep` placeholders.
- **myTunes Decoy Profile Avatars & Conditional Overlays**: Added `User.avatar_filename` (`models.py`), idempotent column migration (`database.py`), safe magic-byte raster image detection (`detect_safe_image` for PNG, JPEG, GIF, and WEBP), isolated per-user storage (`AVATARS_DIR`), `GET /avatar`, and `POST /delete-avatar` (`app_decoy.py`), paired with a WhatsApp-style blank SVG silhouette placeholder, client-side `onerror` fallback, and neutral translucent hover/focus edit and delete overlays inside the circular avatar in `templates/decoy_home.html`.
- **Decoy Server Availability Watchdog**: Added public `GET /health` (`{"status": "ok"}`, `Cache-Control: no-store, no-cache`) in `app_decoy.py` and a `5s` availability watchdog (`1s` confirm retry, two-failure threshold) displaying a fixed top-centre **`SERVER CONNECTION LOST`** alert (`The server is not responding. Trying to reconnect...`) with automatic recovery dismissal in `templates/decoy_home.html`.
- **IP Watchlist Count Badge & Activity Pulse**: Added live `watchlisted_ips` tracking, `is_watchlisted` attack-log attribution, and watchlist delta updates (`routes/admin.py`), rendered as a compact numerical `#nav-watchlist-badge` on the `IP Watchlist` sidebar item (expanded and collapsed `72px` rail) with a subtle opacity-blink indicator on newly detected suspicious activity from watchlisted IPs (`templates/admin.html`).

### Changed
- **Official BAITSCOPE Branding & Application Version `5.0`**: Updated application metadata in `app_dashboard.py`, `app_decoy.py`, `decoy_side/app_decoy.py`, templates, API helpers, and documentation to BAITSCOPE Version `5.0` while preserving `SENTINEL_*` environment fallbacks.
- **Restored & Refined BAITSCOPE Frontend**: Reintegrated and stabilized the high-contrast brutalist UI (`Space Grotesk`, `JetBrains Mono`, `Inter`, `#DFE104` accent, `0px` geometry) in `templates/admin.html` and `templates/home.html` with `static/js/baitscope_api.js`.
- **Simplified Interface Copy & Vector Favicon Update**: Simplified user-facing wording across admin dashboard, overview, login, password reset, upload pages, and API messages (`templates/*.html`, `decoy_side/templates/*.html`, `static/js/baitscope_api.js`), and updated `static/favicon.svg` and `decoy_side/static/favicon.svg` (`?v=5`).
- **Clean Runtime Repository Structure**: Reorganized `.gitignore` and tracked release manifest so only runtime code, templates, static assets, configuration templates, and deployment scripts are published to GitHub.
- **Dependency Manifests**: Audited runtime imports and added explicit `cryptography` (root and `decoy_side/`) and `python-dotenv` (`decoy_side/`) declarations so fresh clones initialize TLS and environment config without manual extras.

### Removed
- **Machine Learning Stack**: Removed `ml_analysis/` (`model.pkl`, training, classifier, extractor, reports), `ml_dataset/` (`raw_logs.csv`), `run_ml_tests.py`, unused ML-only packages (`pandas`, `matplotlib`, `joblib`, `scikit-learn`), CSV dataset logging hooks in `logger.py` and `routes/admin.py`, and AI/ML copy from `templates/home.html`.
- **Retired Command Injection Vector**: Removed Command Injection from active payload signature matching, charts, and documentation while mapping historical rows safely to `"Legacy (Retired)"`.
- **Deprecated UI Chrome & Clutter**: Removed header `ROOT ADMIN` button, `Threat Intel` and `Attack Vectors` sidebar views (consolidated into IP Watchlist & Operational Deck), and `VERIFIED PEER` provenance tag badges.
- **Tracked Non-Runtime Artifacts**: Removed tracked `venv/` files, private TLS keys/certificates (`key.pem`, `cert.pem`), historical quarantine samples, stale `docker/Dockerfile` (`app:app`), `.vscode/` IDE files, and bogus nested `honeypot` gitlink from the Git release tree.

### Security
- **Hardened TLS Certificate Generation**: Upgraded [generate_ssl.py](generate_ssl.py) and [decoy_side/generate_ssl.py](decoy_side/generate_ssl.py) to use **RSA 3072-bit** keys (`PKCS8`), rotated active keys cleanly, reduced default TLS validity from 10 years to **365 days**, expanded X.509 v3 SAN handling (`localhost`, loopback/LAN IPs, hostnames, and custom SAN configuration), enforced server constraints/EKU, and restricted private-key file permissions (owner-only POSIX `0o600` and restricted Windows NTFS ACLs).
- **Enforced Strict Authentication & Secret Hygiene**: Consolidated admin authentication around `PBKDF2-HMAC-SHA256` + constant-time HMAC session tokens (`HttpOnly`, `SameSite=lax`), `BAITSCOPE_STRICT_SECRETS` enforcement, and sanitized `.env.example` placeholders.
- **Zero-Trust Source IP Attribution**: Prevented unauthenticated `X-Forwarded-For` / `X-Real-IP` spoofing when requests originate outside configured `BAITSCOPE_TRUSTED_PROXIES` ranges.
- **Bounded Upload Quarantine Containment**: Enforced 64 KB chunked upload bounds (`MAX_UPLOAD_SIZE_BYTES`), filename sanitization, and `os.path.realpath` + `os.path.commonpath` path traversal containment in `app_decoy.py`.
- **Safe Avatar Serving & Upload Validation**: Restricted non-malicious avatar uploads to verified PNG/JPEG/GIF/WEBP magic bytes stored under opaque per-user filenames with canonical containment checks, and served `/avatar` strictly to the owning authenticated decoy user with `X-Content-Type-Options: nosniff`, `Cache-Control: no-store, private`, and `Content-Security-Policy: default-src 'none'`.
- **SSE Query Secret Rejection**: Blocked secret or token credentials passed in SSE URL query parameters (`HTTP 400`) and enforced cookie-based authentication on `/admin/api/events/stream`.

### Fixed
- **ReDoS & Decode Bounds**: Bounded payload inspection (`MAX_PAYLOAD_LEN = 8192`) and capped URL decoding depth (`max_depth = 2`) in `detection.py`.
- **False Brute Force Distribution Inflation**: Fixed fallback classification mapping and excluded retired Command Injection rows from active KPI vector charts.
- **SSE Disconnect & Post-Purge Recovery**: Fixed backend connectivity false negatives after SSE integration, prevented duplicate attack log rows on SSE reconnect replay, and handled `clear-logs` across connected clients cleanly.
- **System Radar Light-Theme Visibility**: Added explicit `:root:not(.dark)` light-theme styles for the System Radar dial, concentric rings, sweep gradient, danger state, and blip markers in `templates/admin.html` and `decoy_side/templates/admin.html`.
- **Decoy Template Validation & Accessibility**: Moved inline Jinja user-state branching out of `<script>` to `body[data-authenticated]` and playlist `data-playlist-name` attributes, deduplicated conditional `#toast-banner` and `#user-avatar-blank` elements, and added image `alt` and control `aria-label` attributes in `templates/decoy_home.html`.

### Verification
- Corrected the local `SEC-AUTH-04` authentication verification configuration to run against isolated `BAITSCOPE_*` settings.
- Phase 1.1 security verification: 24/24 verified.
- Phase 1 regression suite: 38/38 passed.
- Phase 2A integration suite: 13/13 passed.
- Phase 2B threat management & IP intel suite: 21/21 passed.
- Decoy avatar silhouette, edit/delete overlay, and server availability E2E Chrome verification: passed (`0` console/page errors).
