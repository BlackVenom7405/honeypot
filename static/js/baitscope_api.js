/**
 * BAITSCOPE Centralized Admin API Client & Security Utilities
 * Integrates the restored original dashboard frontend with authoritative FastAPI endpoints.
 */
(function (global) {
    'use strict';

    class ApiError extends Error {
        constructor(message, status, detail = null) {
            super(message);
            this.name = 'ApiError';
            this.status = status;
            this.detail = detail;
        }
    }

    let authExpiredHandler = null;

    function setAuthExpiredHandler(fn) {
        authExpiredHandler = typeof fn === 'function' ? fn : null;
    }

    async function requestJson(url, options = {}) {
        const headers = Object.assign({ Accept: 'application/json' }, options.headers || {});
        if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
            headers['Content-Type'] = 'application/json';
        }
        const fetchOpts = Object.assign(
            {
                method: options.method || 'GET',
                credentials: 'same-origin',
                headers,
            },
            options.body
                ? {
                      body:
                          typeof options.body === 'string' || options.body instanceof FormData
                              ? options.body
                              : JSON.stringify(options.body),
                  }
                : {}
        );

        let response;
        try {
            response = await fetch(url, fetchOpts);
        } catch (networkErr) {
            throw new ApiError('Network connection lost. Unable to reach BAITSCOPE server.', 0);
        }

        if (response.status === 401) {
            if (authExpiredHandler) {
                authExpiredHandler();
            }
            throw new ApiError('Administrator session expired. Please sign in again.', 401);
        }

        const contentType = response.headers.get('content-type') || '';
        let payload = null;
        if (contentType.includes('application/json')) {
            try {
                payload = await response.json();
            } catch (_) {
                payload = null;
            }
        }

        if (!response.ok) {
            const msg =
                (payload && (payload.detail || payload.error || payload.message)) ||
                `HTTP ${response.status} error`;
            throw new ApiError(msg, response.status, payload);
        }

        return payload;
    }

    async function getStats() {
        return requestJson('/admin/api/stats');
    }

    async function getThreats({ classification = '', watchlisted = '', search = '', limit = 25, offset = 0 } = {}) {
        const params = new URLSearchParams();
        if (classification) params.set('classification', classification);
        if (watchlisted !== '' && watchlisted !== null && watchlisted !== undefined) {
            params.set('watchlisted', String(watchlisted));
        }
        if (search) params.set('search', search);
        params.set('limit', String(limit));
        params.set('offset', String(offset));
        return requestJson(`/admin/api/threats?${params.toString()}`);
    }

    async function getThreatDossier(ip) {
        return requestJson(`/admin/api/threats/${encodeURIComponent(ip)}`);
    }

    async function updateWatchlist(ip, action = 'toggle', notes = null) {
        const body = { action };
        if (notes !== null && notes !== undefined) {
            body.notes = notes;
        }
        return requestJson(`/admin/api/threats/${encodeURIComponent(ip)}/watchlist`, {
            method: 'POST',
            body,
        });
    }

    async function clearLogs() {
        return requestJson('/admin/api/clear-logs', { method: 'POST' });
    }

    async function downloadReport(url, fallbackFilename) {
        let response;
        try {
            response = await fetch(url, { credentials: 'same-origin' });
        } catch (_) {
            throw new ApiError('Download failed: server unreachable.', 0);
        }
        if (response.status === 401) {
            if (authExpiredHandler) authExpiredHandler();
            throw new ApiError('Session expired. Please sign in to export reports.', 401);
        }
        if (!response.ok) {
            let msg = `Export failed (HTTP ${response.status})`;
            try {
                const errJson = await response.json();
                msg = errJson.detail || errJson.error || msg;
            } catch (_) {}
            throw new ApiError(msg, response.status);
        }

        const blob = await response.blob();
        const disposition = response.headers.get('content-disposition') || '';
        const match = disposition.match(/filename\*?=(?:UTF-8'')?["']?([^"';\n]+)["']?/i);
        const filename = match ? decodeURIComponent(match[1]) : fallbackFilename;

        const objectUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = objectUrl;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
        return filename;
    }

    function escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatUtcToIst(utcStr) {
        if (!utcStr) return 'N/A';
        const raw = String(utcStr).trim();
        const normalized = /[zZ]|[+-]\d{2}:\d{2}$/.test(raw) ? raw : `${raw}Z`;
        const dt = new Date(normalized);
        if (Number.isNaN(dt.getTime())) return raw;
        return (
            dt.toLocaleString('en-IN', {
                timeZone: 'Asia/Kolkata',
                year: 'numeric',
                month: 'short',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true,
            }) + ' IST'
        );
    }

    function formatUtcTimeOnly(utcStr) {
        if (!utcStr) return 'N/A';
        const raw = String(utcStr).trim();
        const normalized = /[zZ]|[+-]\d{2}:\d{2}$/.test(raw) ? raw : `${raw}Z`;
        const dt = new Date(normalized);
        if (Number.isNaN(dt.getTime())) return raw;
        return (
            dt.toLocaleTimeString('en-IN', {
                timeZone: 'Asia/Kolkata',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true,
            }) + ' IST'
        );
    }

    function formatBytes(bytes) {
        const b = Number(bytes) || 0;
        if (b < 1024) return `${b} B`;
        if (b < 1024 * 1024) return `${(b / 1024).toFixed(2)} KB`;
        return `${(b / (1024 * 1024)).toFixed(2)} MB`;
    }

    function describeAttribution(item) {
        const status = (item && item.attribution_status) || 'unknown';
        const method = (item && item.attribution_method) || 'none';
        const peerIp = (item && item.peer_ip) || '';
        const synthetic = Boolean(item && item.is_synthetic);

        if (synthetic) {
            return {
                badge: 'SYNTHETIC',
                cls: 'border-warning text-warning bg-warning/10',
                title: `Synthetic telemetry (${method})`,
                peerIp,
                method,
                status,
            };
        }
        if (status === 'verified_peer') {
            return {
                badge: 'VERIFIED PEER',
                cls: 'border-success text-success bg-success/10',
                title: `Direct TCP peer (${method})`,
                peerIp,
                method,
                status,
            };
        }
        if (status === 'proxy_attributed') {
            return {
                badge: 'PROXY CHAIN',
                cls: 'border-accent text-accent bg-accent/10',
                title: `Trusted reverse proxy chain (${method}${peerIp ? ', peer ' + peerIp : ''})`,
                peerIp,
                method,
                status,
            };
        }
        if (status === 'remote_node_forwarded') {
            return {
                badge: 'REMOTE NODE',
                cls: 'border-blue-400 text-blue-400 bg-blue-500/10',
                title: `Remote honeypot node (${method}${peerIp ? ', peer ' + peerIp : ''})`,
                peerIp,
                method,
                status,
            };
        }
        return {
            badge: 'HISTORICAL',
            cls: 'border-border text-muted-foreground bg-muted/20',
            title: `Historical / unverified provenance (${method})`,
            peerIp,
            method,
            status,
        };
    }

    global.BaitscopeApi = {
        ApiError,
        setAuthExpiredHandler,
        requestJson,
        getStats,
        getThreats,
        getThreatDossier,
        updateWatchlist,
        clearLogs,
        downloadReport,
        escapeHtml,
        formatUtcToIst,
        formatUtcTimeOnly,
        formatBytes,
        describeAttribution,
    };
})(window);
