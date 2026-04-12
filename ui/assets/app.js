/**
 * UserSpice Security Scanner — UI JavaScript
 * Vanilla JS, no dependencies.
 */

const API = 'api.php';

// ---- Utility ----

function handleAuthError(resp) {
    if (resp.status === 401) {
        window.location.reload(); // PHP will show login form
        throw new Error('Session expired');
    }
    return resp;
}

async function api(action, params = {}) {
    const url = new URL(API, window.location.href);
    url.searchParams.set('action', action);
    for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    }
    const resp = handleAuthError(await fetch(url));
    return resp.json();
}

async function apiPost(action, body = {}) {
    const form = new FormData();
    form.set('action', action);
    for (const [k, v] of Object.entries(body)) {
        if (v !== undefined && v !== null && v !== '') form.set(k, v);
    }
    const resp = handleAuthError(await fetch(API, { method: 'POST', body: form }));
    return resp.json();
}

function el(tag, attrs = {}, children = []) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'className') e.className = v;
        else if (k === 'textContent') e.textContent = v;
        else if (k === 'innerHTML') e.innerHTML = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v);
    }
    for (const c of children) {
        if (typeof c === 'string') e.appendChild(document.createTextNode(c));
        else if (c) e.appendChild(c);
    }
    return e;
}

function severityBadge(sev, normalizedSev) {
    const norm = (normalizedSev || '').toLowerCase();
    const display = sev || normalizedSev || 'INFO';
    let cls = 'severity-info';
    if (['critical'].includes(norm)) cls = 'severity-critical';
    else if (['high'].includes(norm)) cls = 'severity-high';
    else if (['medium'].includes(norm)) cls = 'severity-medium';
    else if (['low'].includes(norm)) cls = 'severity-low';
    else {
        // Fallback for old data without normalized_severity
        const s = (sev || 'info').toLowerCase();
        if (['error','high','critical'].includes(s)) cls = 'severity-high';
        else if (['warning','medium'].includes(s)) cls = 'severity-medium';
        else if (['low'].includes(s)) cls = 'severity-low';
    }
    return el('span', { className: `badge ${cls}`, textContent: display });
}

function ownerBadge(owner) {
    const label = {
        'userspice-core': 'Core',
        'userspice-customizable': 'US Custom',
        'project': 'Your Code',
        'dependency': 'Dependency',
    }[owner] || owner;
    let cls = 'owner-project';
    if (owner === 'userspice-core' || owner === 'userspice-customizable') cls = 'owner-core';
    if (owner === 'dependency') cls = 'owner-dep';
    return el('span', { className: `badge ${cls}`, textContent: label });
}

// ---- Router ----

function navigate(hash) {
    window.location.hash = hash;
}

function getRoute() {
    const hash = window.location.hash.slice(1) || 'dashboard';
    const parts = hash.split('/');
    return { page: parts[0], project: parts[1], report: parts[2] };
}

window.addEventListener('hashchange', () => render());

// ---- Pages ----

async function render() {
    const route = getRoute();
    const main = document.getElementById('main');
    main.innerHTML = '';

    switch (route.page) {
        case 'project':
            if (route.report) await renderReport(main, route.project, route.report);
            else await renderProject(main, route.project);
            break;
        case 'suppressions':
            await renderSuppressionsPage(main, route.project);
            break;
        case 'trends':
            await renderTrends(main, route.project);
            break;
        case 'docs':
            await renderDocs(main);
            break;
        case 'dashboard':
        default:
            await renderDashboard(main);
    }
}

// Dashboard
async function renderDashboard(container) {
    const data = await api('projects');
    const projects = data.projects || [];

    // Show setup screen if scanner.conf doesn't exist
    if (!data.setup_complete) {
        container.appendChild(renderSetupRequired());
        return;
    }

    // Check environment readiness (cached in localStorage for 24h)
    const cacheKey = 'scanner_preflight';
    const cacheExpiry = 'scanner_preflight_ts';
    const now = Date.now();
    let preflight = null;

    try {
        const cached = localStorage.getItem(cacheKey);
        const ts = parseInt(localStorage.getItem(cacheExpiry) || '0');
        if (cached && (now - ts) < 86400000) {
            preflight = JSON.parse(cached);
        }
    } catch {}

    if (!preflight) {
        preflight = await api('preflight');
        try {
            localStorage.setItem(cacheKey, JSON.stringify(preflight));
            localStorage.setItem(cacheExpiry, String(now));
        } catch {}
    }

    if (!preflight.ready) {
        container.appendChild(renderSetupBanner(preflight));
    }

    // Header row with title + filter
    const headerRow = el('div', { style: 'display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;' }, [
        el('h2', { textContent: 'Projects', style: 'margin: 0' }),
        el('span', { id: 'project-count', style: 'color: var(--text-muted); font-size: 0.85rem;', textContent: `${projects.length} found` }),
    ]);
    container.appendChild(headerRow);

    // Filter input
    const filterInput = el('input', {
        type: 'text',
        id: 'project-filter',
        placeholder: 'Filter projects...',
        style: 'width: 100%; max-width: 400px; padding: 0.5rem 0.75rem; font-size: 0.9rem; background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; color: var(--text); margin-bottom: 1rem; outline: none;',
    });
    container.appendChild(filterInput);

    // Build all cards
    const grid = el('div', { className: 'project-grid', id: 'project-grid' });
    for (const p of projects) {
        const latest = p.latest_scan?.summary;
        const total = latest?.totals?.all_findings ?? '-';

        const card = el('div', {
            className: 'card project-card',
            'data-name': p.name.toLowerCase(),
            onClick: () => navigate(`project/${p.name}`),
        }, [
            el('div', { className: 'name' }, [
                document.createTextNode(p.name),
                p.userspice ? el('span', { className: 'badge-us', textContent: 'UserSpice' }) : null,
                p.is_scanning ? el('span', { className: 'badge severity-medium', textContent: 'Scanning...', style: 'margin-left: 0.5rem' }) : null,
            ].filter(Boolean)),
            el('div', { className: 'meta' }, [
                `${p.scan_count} scan(s)`,
                latest ? ` \u00B7 Last: ${total} finding(s)` : ' \u00B7 Never scanned',
            ].join('')),
        ]);
        grid.appendChild(card);
    }
    container.appendChild(grid);

    // Wire up live filter
    filterInput.addEventListener('input', () => {
        const query = filterInput.value.toLowerCase().trim();
        const cards = grid.querySelectorAll('.project-card');
        let visible = 0;
        cards.forEach(card => {
            const name = card.dataset.name;
            const match = !query || name.includes(query);
            card.style.display = match ? '' : 'none';
            if (match) visible++;
        });
        document.getElementById('project-count').textContent = query
            ? `${visible} of ${projects.length} shown`
            : `${projects.length} found`;
    });
    filterInput.focus();
}

// Project page
async function renderProject(container, project) {
    container.appendChild(el('a', { href: '#dashboard', textContent: '\u2190 All Projects', style: 'font-size: 0.85rem; display: inline-block; margin-bottom: 1rem;' }));

    // Check if scanning first — show minimal header during scan
    const status = await api('status', { project });
    if (status.scanning) {
        container.appendChild(el('h2', { textContent: project, style: 'margin-bottom: 1rem;' }));
        container.appendChild(renderScanProgress(project, status.log));
        return;
    }

    // Load reports so we can get previous scan options
    const data = await api('reports', { project });
    const reports = data.reports || [];

    let prevOpts = null;
    if (reports.length > 0) {
        const latestReport = await api('report', { project, id: reports[0].id });
        prevOpts = latestReport?.summary?.meta?.options || null;
    }

    const heading = el('div', { style: 'display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap;' }, [
        el('h2', { textContent: project }),
        el('button', { className: 'btn btn-primary', textContent: 'New Scan', onClick: () => openScanModal(project, prevOpts) }),
        el('a', { href: `#suppressions/${project}`, className: 'btn btn-sm', textContent: 'Suppressions' }),
        el('a', { href: `#trends/${project}`, className: 'btn btn-sm', textContent: 'Trends' }),
    ]);
    container.appendChild(heading);

    if (reports.length === 0) {
        container.appendChild(el('div', { className: 'card', innerHTML: '<p style="color: var(--text-muted);">No scans yet. Click <strong>New Scan</strong> to start.</p>' }));
        return;
    }

    const table = el('table');
    table.appendChild(el('thead', {}, [
        el('tr', {}, [
            el('th', { textContent: 'Date' }),
            el('th', { textContent: 'Findings' }),
            el('th', { textContent: 'Semgrep' }),
            el('th', { textContent: 'Psalm' }),
            el('th', { textContent: 'Trivy' }),
            el('th', { textContent: 'Gitleaks' }),
            el('th', { textContent: 'PHPStan' }),
            el('th', { textContent: 'ZAP' }),
            el('th', { textContent: 'Type' }),
            el('th', { textContent: 'Duration' }),
            el('th', { textContent: '' }),
        ])
    ]));
    const tbody = el('tbody');
    for (const r of reports) {
        const t = r.totals || {};
        const opts = r.options || {};
        const scanType = getScanTypeLabel(opts, t);
        const row = el('tr', { style: 'cursor: pointer', onClick: () => navigate(`project/${project}/${r.id}`) }, [
            el('td', { textContent: r.date }),
            el('td', {}, [el('strong', { textContent: String(t.all_findings ?? 0) })]),
            el('td', { textContent: String(t.semgrep ?? 0) }),
            el('td', { textContent: String(t.psalm ?? 0) }),
            el('td', { textContent: String((t.trivy_vulnerabilities ?? 0) + (t.trivy_secrets ?? 0)) }),
            el('td', { textContent: String(t.gitleaks ?? 0) }),
            el('td', { textContent: t.phpstan !== undefined ? String(t.phpstan) : '-' }),
            el('td', { textContent: t.zap !== undefined ? String(t.zap) : '-' }),
            el('td', {}, [el('span', { className: `badge ${scanType.cls}`, textContent: scanType.label })]),
            el('td', { textContent: r.duration ? `${r.duration}s` : '-' }),
            el('td', {}, [
                r.has_delta ? el('span', { textContent: '\u0394', title: 'Has delta analysis', style: 'color: var(--accent)' }) : null,
            ].filter(Boolean)),
        ]);
        tbody.appendChild(row);
    }
    table.appendChild(tbody);

    const card = el('div', { className: 'card' }, [
        el('div', { className: 'card-title' }, ['Scan History']),
        table,
    ]);
    container.appendChild(card);
}

// Report detail page
async function renderReport(container, project, reportId) {
    container.appendChild(el('a', { href: `#project/${project}`, textContent: `\u2190 ${project}`, style: 'font-size: 0.85rem; display: inline-block; margin-bottom: 1rem;' }));

    const data = await api('report', { project, id: reportId });
    if (data.error) {
        container.appendChild(el('div', { className: 'card', textContent: data.error }));
        return;
    }

    const s = data.summary;
    const t = s.totals || {};
    const d = data.delta;

    const opts = s.meta?.options || {};
    const scanType = getScanTypeLabel(opts, t);
    container.appendChild(el('div', { style: 'display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap;' }, [
        el('h2', { textContent: `${project} \u2014 ${data.id}`, style: 'margin: 0;' }),
        el('span', { className: `badge ${scanType.cls}`, textContent: scanType.label }),
        opts.url ? el('span', { style: 'font-size: 0.8rem; color: var(--text-muted);', textContent: opts.url }) : null,
        el('button', { className: 'btn btn-sm', textContent: 'View Log', onClick: () => showScanLog(project, reportId) }),
        el('button', { className: 'btn btn-sm', textContent: 'Export Report', onClick: async () => {
            const resp = await api('export', { project, id: reportId });
            if (resp.url) window.open(resp.url, '_blank');
            else alert(resp.error || 'Failed to generate report');
        }}),
        el('button', { className: 'btn btn-sm btn-primary', textContent: 'Re-run Scan', onClick: () => rerunScan(project, opts) }),
    ].filter(Boolean)));

    // Stats row
    const ts = s.meta?.tool_status || {};
    const stats = el('div', { className: 'stats' }, [
        statBox(t.all_findings, 'Total', t.all_findings > 0 ? 'red' : 'green'),
        statBox(t.semgrep, 'Semgrep', t.semgrep > 0 ? 'yellow' : 'green', ts.semgrep, 'semgrep'),
        statBox(t.psalm, 'Psalm', t.psalm > 0 ? 'yellow' : 'green', ts.psalm, 'psalm'),
        statBox((t.trivy_vulnerabilities ?? 0) + (t.trivy_secrets ?? 0), 'Trivy', ((t.trivy_vulnerabilities ?? 0) + (t.trivy_secrets ?? 0)) > 0 ? 'red' : 'green', ts.trivy, 'trivy_vulnerabilities'),
        statBox(t.gitleaks, 'Gitleaks', t.gitleaks > 0 ? 'red' : 'green', ts.gitleaks, 'gitleaks'),
        ts.phpstan !== 'skipped' ? statBox(t.phpstan ?? 0, 'PHPStan', (t.phpstan ?? 0) > 0 ? 'yellow' : 'green', ts.phpstan, 'phpstan') : null,
        ts.zap !== 'skipped' ? statBox(t.zap ?? 0, 'ZAP', (t.zap ?? 0) > 0 ? 'yellow' : 'green', ts.zap, 'zap') : null,
    ].filter(Boolean));
    container.appendChild(stats);

    // Delta summary
    if (d) {
        const delta = el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: `Delta vs ${d.previous_scan}` }),
        ]);
        const parts = [];
        for (const tool of ['semgrep', 'psalm', 'trivy', 'gitleaks']) {
            const td = d[tool];
            if (!td) continue;
            if (td.new > 0) parts.push(el('span', { className: 'delta-new', textContent: `+${td.new} new ${tool}  ` }));
            if (td.resolved > 0) parts.push(el('span', { className: 'delta-resolved', textContent: `-${td.resolved} resolved ${tool}  ` }));
        }
        if (parts.length === 0) parts.push(el('span', { className: 'delta-unchanged', textContent: 'No changes in findings' }));
        const deltaBody = el('div', { style: 'font-size: 0.85rem;' });
        parts.forEach(p => deltaBody.appendChild(p));
        delta.appendChild(deltaBody);
        container.appendChild(delta);
    }

    // Owner summary
    if (s.owner_summary) {
        const os = s.owner_summary;
        const proj = Object.values(os).reduce((sum, o) => sum + (o.project || 0), 0);
        const core = Object.values(os).reduce((sum, o) => sum + (o.userspice_core || 0), 0);
        const cust = Object.values(os).reduce((sum, o) => sum + (o.userspice_customizable || 0), 0);
        if (proj + core + cust > 0) {
            container.appendChild(el('div', { className: 'card' }, [
                el('div', { className: 'card-title', textContent: 'Ownership' }),
                el('div', { className: 'stats' }, [
                    proj > 0 ? statBox(proj, 'Your Code', 'blue') : null,
                    core > 0 ? statBox(core, 'US Core', 'yellow') : null,
                    cust > 0 ? statBox(cust, 'US Custom', 'yellow') : null,
                ].filter(Boolean)),
            ]));
        }
    }

    // Headers
    if (data.headers) {
        const h = data.headers;
        const hCard = el('div', { className: 'card' }, [
            el('div', { className: 'card-title' }, [
                'HTTP Headers ',
                h.passed
                    ? el('span', { className: 'badge severity-low', textContent: 'PASS' })
                    : el('span', { className: 'badge severity-high', textContent: `${h.counts.fail} missing` }),
            ]),
        ]);
        const hTable = el('table');
        hTable.appendChild(el('thead', {}, [el('tr', {}, [
            el('th', { textContent: 'Header' }),
            el('th', { textContent: 'Status' }),
            el('th', { textContent: 'Level' }),
        ])]));
        const hBody = el('tbody');
        for (const hdr of h.headers || []) {
            const statusText = hdr.status === 'present' ? 'Present' :
                               hdr.status === 'absent' ? 'Not exposed' :
                               hdr.status === 'exposed' ? 'EXPOSED' : 'MISSING';
            const cls = (hdr.status === 'present' || hdr.status === 'absent') ? 'severity-low' :
                        hdr.level === 'required' ? 'severity-high' : 'severity-medium';
            hBody.appendChild(el('tr', {}, [
                el('td', { textContent: hdr.header, style: 'font-family: var(--mono)' }),
                el('td', {}, [el('span', { className: `badge ${cls}`, textContent: statusText })]),
                el('td', { textContent: hdr.level, style: 'color: var(--text-muted)' }),
            ]));
        }
        hTable.appendChild(hBody);
        hCard.appendChild(hTable);
        container.appendChild(hCard);
    }

    // Findings tabs
    const findings = s.findings || {};
    const toolOrder = ['semgrep', 'psalm', 'phpstan', 'trivy_vulnerabilities', 'trivy_secrets', 'trivy_misconfigurations', 'gitleaks', 'zap'];
    const toolLabels = {
        semgrep: 'Semgrep', psalm: 'Psalm', phpstan: 'PHPStan',
        trivy_vulnerabilities: 'Trivy CVEs', trivy_secrets: 'Trivy Secrets',
        trivy_misconfigurations: 'Trivy Misconfig',
        gitleaks: 'Gitleaks', zap: 'ZAP'
    };

    // Filter bar
    const filterBar = el('div', { style: 'display: flex; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; align-items: center;' }, [
        el('input', {
            type: 'text', id: 'findings-search', placeholder: 'Search findings (file, rule, message)...',
            style: 'flex: 1; min-width: 200px; padding: 0.4rem 0.75rem; font-size: 0.85rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text);',
        }),
        el('select', { id: 'findings-owner-filter', style: 'padding: 0.4rem; font-size: 0.8rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text);' }, [
            el('option', { value: '', textContent: 'All owners' }),
            el('option', { value: 'project', textContent: 'Your Code' }),
            el('option', { value: 'userspice-core', textContent: 'US Core' }),
            el('option', { value: 'userspice-customizable', textContent: 'US Customizable' }),
        ]),
        el('select', { id: 'findings-severity-filter', style: 'padding: 0.4rem; font-size: 0.8rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text);' }, [
            el('option', { value: '', textContent: 'All severities' }),
            el('option', { value: 'critical', textContent: 'Critical' }),
            el('option', { value: 'high', textContent: 'High' }),
            el('option', { value: 'medium', textContent: 'Medium' }),
            el('option', { value: 'low', textContent: 'Low' }),
            el('option', { value: 'info', textContent: 'Info' }),
        ]),
        el('select', { id: 'findings-group-by', style: 'padding: 0.4rem; font-size: 0.8rem; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; color: var(--text);' }, [
            el('option', { value: '', textContent: 'Group: None' }),
            el('option', { value: 'rule', textContent: 'Group: By Rule' }),
            el('option', { value: 'file', textContent: 'Group: By File' }),
        ]),
        el('button', { className: 'btn btn-sm', textContent: 'Suppress all visible', onClick: () => bulkSuppressVisible(project) }),
        el('span', { id: 'findings-filter-count', style: 'font-size: 0.8rem; color: var(--text-muted);' }),
    ]);

    // Collect all findings with tool tag for grouping
    const allFindings = [];
    for (const tool of toolOrder) {
        for (const f of (findings[tool] || [])) {
            allFindings.push({ ...f, _tool: tool, _toolLabel: toolLabels[tool] || tool });
        }
    }

    const tabsDiv = el('div', { className: 'tabs' });
    const contentDiv = el('div');

    function buildToolTabs() {
        tabsDiv.innerHTML = '';
        contentDiv.innerHTML = '';
        let first = true;

        for (const tool of toolOrder) {
            const items = findings[tool] || [];
            if (items.length === 0 && tool !== 'semgrep') continue;

            const tabId = `tab-${tool}`;

            const tab = el('div', {
                className: `tab ${first ? 'active' : ''}`,
                'data-tab': tabId,
                onClick: () => switchTab(tabId),
            }, [
                toolLabels[tool] || tool,
                items.length > 0 ? el('span', { className: 'tab-count', textContent: String(items.length) }) : null,
            ].filter(Boolean));
            tabsDiv.appendChild(tab);

            const panel = el('div', {
                className: 'tab-panel',
                style: first ? '' : 'display: none',
                'data-tab': tabId,
            });

            if (items.length === 0) {
                panel.appendChild(el('p', { textContent: 'No findings.', style: 'color: var(--text-muted); padding: 1rem 0;' }));
            } else if (tool === 'zap') {
                renderZapFindings(panel, items, data.has_zap_html, project, reportId);
            } else {
                renderFindings(panel, items, project);
            }

            contentDiv.appendChild(panel);
            first = false;
        }
    }

    function buildGroupedByRule() {
        tabsDiv.innerHTML = '';
        contentDiv.innerHTML = '';

        // Group all non-ZAP findings by rule within each tool tab
        let first = true;
        for (const tool of toolOrder) {
            const items = findings[tool] || [];
            if (items.length === 0) continue;

            const tabId = `tab-${tool}`;
            const tab = el('div', {
                className: `tab ${first ? 'active' : ''}`,
                'data-tab': tabId,
                onClick: () => switchTab(tabId),
            }, [
                toolLabels[tool] || tool,
                el('span', { className: 'tab-count', textContent: String(items.length) }),
            ]);
            tabsDiv.appendChild(tab);

            const panel = el('div', {
                className: 'tab-panel',
                style: first ? '' : 'display: none',
                'data-tab': tabId,
            });

            if (tool === 'zap') {
                renderZapFindings(panel, items, data.has_zap_html, project, reportId);
            } else {
                // Group by rule
                const groups = {};
                for (const f of items) {
                    const key = f.rule || 'unknown';
                    if (!groups[key]) groups[key] = [];
                    groups[key].push(f);
                }
                for (const [rule, groupItems] of Object.entries(groups).sort((a, b) => b[1].length - a[1].length)) {
                    const details = el('details', { className: 'finding-group' });
                    const summary = el('summary', { style: 'cursor: pointer; padding: 0.5rem 0; font-size: 0.85rem; display: flex; align-items: center; gap: 0.5rem;' }, [
                        severityBadge(groupItems[0].severity, groupItems[0].normalized_severity),
                        el('span', { style: 'font-family: var(--mono); font-size: 0.8rem;', textContent: rule }),
                        el('span', { className: 'tab-count', textContent: String(groupItems.length) }),
                    ]);
                    details.appendChild(summary);
                    renderFindings(details, groupItems, project);
                    panel.appendChild(details);
                }
            }

            contentDiv.appendChild(panel);
            first = false;
        }
    }

    function buildGroupedByFile() {
        tabsDiv.innerHTML = '';
        contentDiv.innerHTML = '';

        // Group ALL findings across all tools by file
        const fileGroups = {};
        for (const f of allFindings) {
            const file = (f.file || '').replace(/^\/src\//, '').replace(/^\.\.\/src\//, '') || '(no file)';
            if (!fileGroups[file]) fileGroups[file] = [];
            fileGroups[file].push(f);
        }

        // Single "By File" tab
        tabsDiv.appendChild(el('div', { className: 'tab active' }, ['All Files']));

        const panel = el('div', { className: 'tab-panel' });
        const sortedFiles = Object.entries(fileGroups).sort((a, b) => b[1].length - a[1].length);
        for (const [file, groupItems] of sortedFiles) {
            const details = el('details', { className: 'finding-group' });
            const summary = el('summary', { style: 'cursor: pointer; padding: 0.5rem 0; font-size: 0.85rem; display: flex; align-items: center; gap: 0.5rem;' }, [
                el('span', { style: 'font-family: var(--mono);', textContent: file }),
                el('span', { className: 'tab-count', textContent: String(groupItems.length) }),
                // Show tool badges
                ...([...new Set(groupItems.map(f => f._toolLabel))].map(t =>
                    el('span', { className: 'badge severity-info', textContent: t, style: 'font-size: 0.65rem;' })
                )),
            ]);
            details.appendChild(summary);
            renderFindings(details, groupItems, project);
            panel.appendChild(details);
        }
        contentDiv.appendChild(panel);
    }

    // Initial render
    buildToolTabs();

    const findingsCard = el('div', { className: 'card' }, [filterBar, tabsDiv, contentDiv]);
    container.appendChild(findingsCard);

    // Update filters after DOM is ready
    updateFilterOptions();

    // Wire up group-by
    document.getElementById('findings-group-by')?.addEventListener('change', (e) => {
        const mode = e.target.value;
        if (mode === 'rule') buildGroupedByRule();
        else if (mode === 'file') buildGroupedByFile();
        else buildToolTabs();
        updateFilterOptions();
    });

    // Wire up findings filter
    const applyFilter = () => {
        const query = (document.getElementById('findings-search')?.value || '').toLowerCase();
        const ownerFilter = document.getElementById('findings-owner-filter')?.value || '';
        const sevFilter = document.getElementById('findings-severity-filter')?.value || '';
        let shown = 0, total = 0;

        findingsCard.querySelectorAll('.finding').forEach(f => {
            total++;
            const text = (f.dataset.file || '') + ' ' + (f.dataset.rule || '') + ' ' + (f.dataset.message || '');
            const owner = f.dataset.owner || '';
            const normSev = (f.dataset.normalizedSeverity || '').toLowerCase();

            let match = true;
            if (query && !text.toLowerCase().includes(query)) match = false;
            if (ownerFilter && owner !== ownerFilter) match = false;
            if (sevFilter && normSev !== sevFilter) match = false;

            f.style.display = match ? '' : 'none';
            if (match) shown++;
        });

        const countEl = document.getElementById('findings-filter-count');
        if (countEl) {
            countEl.textContent = (query || ownerFilter || sevFilter) ? `${shown} of ${total}` : '';
        }
    };

    document.getElementById('findings-search')?.addEventListener('input', applyFilter);
    document.getElementById('findings-owner-filter')?.addEventListener('change', applyFilter);
    document.getElementById('findings-severity-filter')?.addEventListener('change', applyFilter);
}

function renderFindings(panel, items, project) {
    for (const f of items) {
        const file = (f.file || '').replace(/^\/src\//, '').replace(/^\.\.\/src\//, '');
        const finding = el('div', {
            className: 'finding',
            'data-file': file,
            'data-rule': f.rule || '',
            'data-message': f.message || '',
            'data-owner': f.owner || '',
            'data-severity': (f.severity || '').toLowerCase(),
            'data-normalized-severity': f.normalized_severity || '',
        });
        let loaded = false;

        const body = el('div', { className: 'finding-body' }, [
            el('div', { textContent: f.message || '' }),
            el('div', { className: 'snippet-container', style: 'margin-top: 0.5rem;' }),
            el('div', { style: 'margin-top: 0.75rem; padding-top: 0.5rem; border-top: 1px solid var(--border); display: flex; gap: 0.5rem; flex-wrap: wrap;' }, [
                el('button', { className: 'btn btn-sm', textContent: 'Suppress', onClick: (e) => {
                    e.stopPropagation();
                    openSuppressModal(f, file, project);
                }}),
                el('button', { className: 'btn btn-sm', textContent: 'Suppress all this rule in file', onClick: (e) => {
                    e.stopPropagation();
                    openSuppressModal(f, file, project, 'file');
                }}),
                el('button', { className: 'btn btn-sm', textContent: 'Suppress this rule everywhere', onClick: (e) => {
                    e.stopPropagation();
                    openSuppressModal(f, file, project, 'rule');
                }}),
            ]),
        ]);

        const header = el('div', { className: 'finding-header', onClick: async () => {
            body.classList.toggle('open');
            // Lazy-load the real source snippet on first expand
            if (!loaded && body.classList.contains('open') && f.line && project) {
                loaded = true;
                const container = body.querySelector('.snippet-container');
                container.innerHTML = '<span style="color: var(--text-muted)">Loading source...</span>';
                try {
                    const data = await api('snippet', { project, file: f.file, line: f.line, context: 5 });
                    if (data.snippet) {
                        const pre = document.createElement('pre');
                        pre.style.margin = '0';
                        for (const ln of data.snippet) {
                            const lineEl = document.createElement('span');
                            lineEl.style.display = 'block';
                            if (ln.highlight) {
                                lineEl.style.background = 'rgba(248,81,73,0.15)';
                                lineEl.style.borderLeft = '3px solid var(--red)';
                                lineEl.style.paddingLeft = '0.5rem';
                                lineEl.style.marginLeft = '-0.5rem';
                            }
                            lineEl.textContent = `${String(ln.num).padStart(4)} │ ${ln.text}`;
                            pre.appendChild(lineEl);
                        }
                        container.innerHTML = '';
                        container.appendChild(pre);
                    } else {
                        container.textContent = data.error || 'Could not load snippet';
                    }
                } catch (e) {
                    container.textContent = 'Could not load snippet';
                }
            }
        }}, [
            severityBadge(f.severity, f.normalized_severity),
            f.owner ? ownerBadge(f.owner) : null,
            el('span', { className: 'finding-file', textContent: `${file}:${f.line || ''}` }),
            el('span', { className: 'finding-rule', textContent: f.rule || '' }),
        ].filter(Boolean));

        finding.appendChild(header);
        finding.appendChild(body);
        panel.appendChild(finding);
    }
}

function renderZapFindings(panel, items, hasHtml, project, reportId) {
    if (hasHtml) {
        const reportPath = `../reports/${encodeURIComponent(project)}/${encodeURIComponent(reportId)}/zap.html`;
        panel.appendChild(el('div', { style: 'margin-bottom: 0.75rem;' }, [
            el('a', { href: reportPath, target: '_blank', className: 'btn btn-sm', textContent: 'Open full ZAP HTML report' }),
        ]));
    }
    for (const f of items) {
        const finding = el('div', {
            className: 'finding',
            'data-rule': f.rule || '',
            'data-file': f.name || '',
            'data-message': f.name || '',
            'data-owner': '',
            'data-severity': (f.severity || '').toLowerCase(),
            'data-normalized-severity': f.normalized_severity || '',
        });
        const header = el('div', { className: 'finding-header', onClick: () => {
            finding.querySelector('.finding-body').classList.toggle('open');
        }}, [
            severityBadge(f.severity, f.normalized_severity),
            el('span', { className: 'finding-file', textContent: f.name || '' }),
            el('span', { className: 'finding-rule', textContent: `${f.count || 0} instance(s)` }),
        ]);

        const instances = (f.instances || []).slice(0, 5).map(i =>
            `${i.method || 'GET'} ${i.uri || ''}${i.param ? ` (param: ${i.param})` : ''}`
        ).join('\n');

        const body = el('div', { className: 'finding-body' }, [
            f.risk ? el('div', { textContent: `Risk: ${f.risk}` }) : null,
            f.solution ? el('div', { innerHTML: `<strong>Solution:</strong> ${f.solution}`, style: 'margin-top: 0.5rem;' }) : null,
            instances ? el('pre', { textContent: instances }) : null,
            el('div', { style: 'margin-top: 0.75rem; padding-top: 0.5rem; border-top: 1px solid var(--border);' }, [
                el('button', { className: 'btn btn-sm', textContent: 'Suppress this alert', onClick: (e) => {
                    e.stopPropagation();
                    openSuppressModal({ tool: 'zap', rule: f.rule || f.name, file: '', line: 0, severity: f.severity }, '', project, 'rule');
                }}),
            ]),
        ].filter(Boolean));

        finding.appendChild(header);
        finding.appendChild(body);
        panel.appendChild(finding);
    }
}

function statBox(num, label, color = '', status = '', tabTarget = '') {
    const children = [
        el('div', { className: 'number', textContent: status === 'failed' ? '!' : String(num ?? 0) }),
        el('div', { className: 'label', textContent: label }),
    ];
    if (status === 'failed') {
        children.push(el('div', { className: 'badge severity-high', textContent: 'FAILED', style: 'font-size: 0.6rem; margin-top: 0.25rem;' }));
        color = 'red';
    } else if (status === 'skipped') {
        children[0] = el('div', { className: 'number', textContent: '-', style: 'color: var(--text-muted)' });
    }
    const clickable = tabTarget && (num ?? 0) > 0;
    const box = el('div', {
        className: `stat ${color}`,
        style: clickable ? 'cursor: pointer;' : '',
        onClick: clickable ? () => {
            // Reset group-by to default (tool tabs) so the tab is visible
            const groupBy = document.getElementById('findings-group-by');
            if (groupBy && groupBy.value !== '') {
                groupBy.value = '';
                groupBy.dispatchEvent(new Event('change'));
            }
            switchTab(`tab-${tabTarget}`);
            // Scroll the findings card into view
            const panel = document.querySelector(`.tab-panel[data-tab="tab-${tabTarget}"]`);
            if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } : undefined,
    }, children);
    return box;
}

function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    document.querySelectorAll('.tab-panel').forEach(p => p.style.display = p.dataset.tab === tabId ? '' : 'none');
    updateFilterOptions();
}

function updateFilterOptions() {
    const sevFilter = document.getElementById('findings-severity-filter');
    const ownerFilter = document.getElementById('findings-owner-filter');
    if (!sevFilter || !ownerFilter) return;

    // Find the active panel and collect unique values from its findings
    const activePanel = document.querySelector('.tab-panel[style=""], .tab-panel:not([style*="none"])');
    const findings = activePanel ? activePanel.querySelectorAll('.finding') : document.querySelectorAll('.finding');

    const severities = new Set();
    const owners = new Set();
    findings.forEach(f => {
        const sev = (f.dataset.normalizedSeverity || '').toLowerCase();
        const owner = f.dataset.owner || '';
        if (sev) severities.add(sev);
        if (owner) owners.add(owner);
    });

    // Show/hide severity options
    for (const opt of sevFilter.options) {
        if (opt.value === '') { continue; } // "All" always visible
        opt.style.display = severities.has(opt.value) ? '' : 'none';
    }
    // Hide the whole severity dropdown if only one severity exists
    sevFilter.style.display = severities.size > 1 ? '' : 'none';

    // Show/hide owner options
    for (const opt of ownerFilter.options) {
        if (opt.value === '') { continue; }
        opt.style.display = owners.has(opt.value) ? '' : 'none';
    }
    // Hide the whole owner dropdown if only one owner or none
    ownerFilter.style.display = owners.size > 1 ? '' : 'none';

    // Reset filters if current selection is no longer valid
    if (sevFilter.value && !severities.has(sevFilter.value)) sevFilter.value = '';
    if (ownerFilter.value && !owners.has(ownerFilter.value)) ownerFilter.value = '';
}

// ---- Scan Modal ----

function openScanModal(project, prevOpts) {
    const existing = document.getElementById('scan-modal');
    if (existing) existing.remove();
    const o = prevOpts || {};

    const overlay = el('div', { className: 'modal-overlay open', id: 'scan-modal', onClick: (e) => {
        if (e.target === overlay) overlay.remove();
    }}, [
        el('div', { className: 'modal' }, [
            el('h2', { textContent: `Scan ${project}` }),

            // Tool selection
            el('div', { className: 'form-group' }, [
                el('div', { style: 'display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;' }, [
                    el('label', { textContent: 'Tools' }),
                    el('a', { href: '#', style: 'font-size: 0.75rem;', textContent: 'toggle all', onClick: (e) => {
                        e.preventDefault();
                        const boxes = document.querySelectorAll('#scan-tools input[type="checkbox"]');
                        const allChecked = [...boxes].every(cb => cb.checked);
                        boxes.forEach(cb => { cb.checked = !allChecked; cb.dispatchEvent(new Event('change')); });
                    }}),
                ]),
                el('div', { style: 'display: flex; gap: 1rem; flex-wrap: wrap;', id: 'scan-tools' }, [
                    toolCheckbox('semgrep', 'Semgrep', !(o.skip || '').includes('semgrep')),
                    toolCheckbox('psalm', 'Psalm', !(o.skip || '').includes('psalm')),
                    toolCheckbox('trivy', 'Trivy', !(o.skip || '').includes('trivy')),
                    toolCheckbox('gitleaks', 'Gitleaks', !(o.skip || '').includes('gitleaks')),
                    toolCheckbox('phpstan', 'PHPStan', (o.include || '').includes('phpstan')),
                    toolCheckbox('zap', 'ZAP', !(o.skip || '').includes('zap')),
                ]),
            ]),

            // ZAP settings — disabled when ZAP is unchecked
            el('div', { id: 'zap-settings' }, [
                el('div', { className: 'form-group' }, [
                    el('label', { textContent: 'Target URL (enables ZAP + header checks)' }),
                    el('input', { type: 'text', id: 'scan-url', value: o.url || `http://localhost/${project}/` }),
                ]),
                el('div', { style: 'border-top: 1px solid var(--border); margin: 0.75rem 0; padding-top: 0.75rem;' }, [
                    el('label', { style: 'font-size: 0.8rem; color: var(--text-muted); display: block; margin-bottom: 0.5rem;', textContent: 'ZAP Authentication (optional — lets ZAP crawl behind login)' }),
                ]),
                el('div', { style: 'display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;' }, [
                    el('div', { className: 'form-group' }, [
                        el('label', { textContent: 'Username' }),
                        el('input', { type: 'text', id: 'scan-zap-user', value: o.zap_user || '', placeholder: 'test_user', autocomplete: 'off' }),
                    ]),
                    el('div', { className: 'form-group' }, [
                        el('label', { textContent: 'Password' }),
                        el('input', { type: 'text', id: 'scan-zap-pass', value: o.zap_pass || '', placeholder: 'password', autocomplete: 'off' }),
                    ]),
                ]),
                el('div', { className: 'form-group' }, [
                    el('label', { textContent: 'Login URL Path' }),
                    el('input', { type: 'text', id: 'scan-zap-login', value: o.zap_login_path || 'users/login.php', autocomplete: 'off' }),
                    el('small', { style: 'color: var(--text-muted); font-size: 0.75rem;', textContent: 'Relative to project URL. Default: users/login.php' }),
                ]),
                el('div', { className: 'form-group', style: 'margin-top: 0.5rem;' }, [
                    el('label', { textContent: 'Scan Depth' }),
                    el('select', { id: 'scan-zap-profile' }, [
                        el('option', { value: 'quick', textContent: 'Quick (~3 min) — passive only · SAFE for any env, including production', selected: (o.zap_profile || 'standard') === 'quick' }),
                        el('option', { value: 'standard', textContent: 'Standard (~15 min) — active scan · LOCAL or STAGING only', selected: (o.zap_profile || 'standard') === 'standard' }),
                        el('option', { value: 'deep', textContent: 'Deep (~60 min) — full active scan + Ajax · LOCAL ONLY', selected: (o.zap_profile || 'standard') === 'deep' }),
                    ]),
                ]),
                el('p', {
                    style: 'font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.5rem;',
                    innerHTML: '<strong>Quick</strong> just observes responses — safe to point at production to check real TLS/CDN/header config. ' +
                        '<strong>Standard / Deep</strong> actively attack the target (SQLi, RCE, path traversal probes) and can pollute databases, trip WAFs, and create test accounts via join.php. Never run them against production.',
                }),
                el('p', {
                    style: 'font-size: 0.75rem; color: var(--text-muted); margin-bottom: 1rem;',
                    innerHTML: 'We recommend creating a <strong>dedicated non-admin test user</strong> for ZAP scanning (e.g. "scanner" / "scanner123"). ' +
                        'Credentials are stored in scan options for re-runs. ' +
                        'If force-SSL is enabled in UserSpice, disable it for local scans.',
                }),
            ]),
            el('div', { className: 'form-actions' }, [
                el('button', { className: 'btn', textContent: 'Cancel', onClick: () => overlay.remove() }),
                el('button', { className: 'btn btn-primary', textContent: 'Start Scan', onClick: async () => {
                    const zapChecked = document.getElementById('scan-tool-zap')?.checked;
                    const url = zapChecked ? document.getElementById('scan-url').value.trim() : '';
                    const zapUser = zapChecked ? document.getElementById('scan-zap-user').value.trim() : '';
                    const zapPass = zapChecked ? document.getElementById('scan-zap-pass').value : '';
                    const zapLogin = zapChecked ? document.getElementById('scan-zap-login').value.trim() : '';
                    const zapProfile = zapChecked ? document.getElementById('scan-zap-profile').value : 'standard';
                    const skip = getSkippedTools();
                    const include = getIncludedTools();
                    if (zapChecked && !confirmActiveScanTarget(url, zapProfile)) return;
                    overlay.remove();
                    await startScan(project, url, zapProfile, zapUser, zapPass, skip, zapLogin, include);
                }}),
            ]),
        ]),
    ]);
    document.body.appendChild(overlay);

    // Toggle ZAP settings visibility based on ZAP checkbox
    const zapCb = document.getElementById('scan-tool-zap');
    const zapSettings = document.getElementById('zap-settings');
    function updateZapVisibility() {
        const enabled = zapCb?.checked;
        if (zapSettings) {
            zapSettings.style.opacity = enabled ? '1' : '0.4';
            zapSettings.style.pointerEvents = enabled ? '' : 'none';
        }
    }
    zapCb?.addEventListener('change', updateZapVisibility);
    updateZapVisibility();
}

function toolCheckbox(id, label, checked) {
    const cb = el('label', { style: 'display: flex; align-items: center; gap: 0.3rem; font-size: 0.85rem; cursor: pointer;' }, [
        el('input', { type: 'checkbox', id: `scan-tool-${id}`, checked: checked ? 'checked' : undefined, style: 'cursor: pointer;' }),
        label,
    ]);
    return cb;
}

// Tools that are off by default — checking them sends --include, not --skip
const OPT_IN_TOOLS = ['phpstan'];

function getSkippedTools() {
    const tools = ['semgrep', 'psalm', 'trivy', 'gitleaks', 'zap'];
    return tools.filter(t => {
        const cb = document.getElementById(`scan-tool-${t}`);
        return cb && !cb.checked;
    }).join(',');
}

function getIncludedTools() {
    return OPT_IN_TOOLS.filter(t => {
        const cb = document.getElementById(`scan-tool-${t}`);
        return cb && cb.checked;
    }).join(',');
}

async function startScan(project, url, zapProfile, zapUser, zapPass, skip, zapLogin, include) {
    const result = await apiPost('scan', { project, url, zap_profile: zapProfile, zap_user: zapUser, zap_pass: zapPass, zap_login: zapLogin || '', skip: skip || '', include: include || '' });
    if (result.error) {
        alert(result.error);
        return;
    }
    // Switch to project view and show progress
    navigate(`project/${project}`);
    render();
    pollScanStatus(project);
}

async function rerunScan(project, opts) {
    if (!confirm(`Re-run scan for ${project} with same settings?`)) return;
    const url = opts.url || '';
    const zapUser = opts.zap_user || '';
    const zapPass = opts.zap_pass || '';
    const zapLogin = opts.zap_login_path || '';
    const zapProfile = opts.zap_profile || 'standard';
    const skip = opts.skip || '';
    const include = opts.include || '';
    const zapEnabled = !(skip.split(',').map(s => s.trim()).includes('zap'));
    if (zapEnabled && !confirmActiveScanTarget(url, zapProfile)) return;
    await startScan(project, url, zapProfile, zapUser, zapPass, skip, zapLogin, include);
}

// Returns true if the host portion of url looks like localhost / a private
// network. Everything else is treated as "possibly production".
function isLocalTarget(url) {
    if (!url) return true;  // empty URL -> scanner uses localhost default
    let host;
    try {
        host = new URL(url).hostname.toLowerCase();
    } catch (e) {
        return true;  // unparseable -> err on the side of letting them through
    }
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;
    if (host === 'host.docker.internal') return true;
    if (host.endsWith('.local') || host.endsWith('.localhost') || host.endsWith('.test')) return true;
    // RFC1918 private ranges
    if (/^10\./.test(host)) return true;
    if (/^192\.168\./.test(host)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)) return true;
    return false;
}

// Block active-scan profiles against non-local URLs unless the user explicitly
// confirms. Returns false if the user cancels.
function confirmActiveScanTarget(url, profile) {
    if (profile === 'quick') return true;
    if (isLocalTarget(url)) return true;
    const msg =
        `⚠️  You are about to run an ACTIVE ZAP scan (${profile}) against:\n\n` +
        `    ${url}\n\n` +
        `This host does NOT look like localhost or a private network.\n\n` +
        `Active scans send tens of thousands of attack probes (SQL injection, ` +
        `RCE, path traversal, XSS). Against a real environment this can:\n` +
        `  • pollute your database with garbage rows\n` +
        `  • create test users via join.php\n` +
        `  • trip WAFs / fail2ban / Cloudflare rules\n` +
        `  • spam logs and trigger alerts\n` +
        `  • get you banned from your own host\n\n` +
        `If this is production, cancel now and use the "Quick" profile instead ` +
        `(passive-only, safe for any environment).\n\n` +
        `Type "I UNDERSTAND" to proceed anyway.`;
    const response = prompt(msg);
    return response === 'I UNDERSTAND';
}

function renderScanProgress(project, log) {
    const card = el('div', { className: 'card' }, [
        el('div', { className: 'card-title' }, [
            el('span', { className: 'badge severity-medium', textContent: 'Scanning...' }),
            ` ${project}`,
        ]),
        el('div', { className: 'console', id: 'scan-log', textContent: log || 'Starting scan...' }),
    ]);
    pollScanStatus(project);
    return card;
}

let pollTimer = null;
function pollScanStatus(project) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
        const status = await api('status', { project });
        const logEl = document.getElementById('scan-log');
        if (logEl && status.log) {
            logEl.textContent = status.log;
            logEl.scrollTop = logEl.scrollHeight;
        }
        if (!status.scanning) {
            clearInterval(pollTimer);
            pollTimer = null;
            render(); // Refresh to show the new report
        }
    }, 2000);
}

// ---- Bulk Suppress ----

function bulkSuppressVisible(project) {
    const visible = document.querySelectorAll('.finding:not([style*="display: none"])');
    if (visible.length === 0) { alert('No visible findings to suppress.'); return; }

    const existing = document.getElementById('suppress-modal');
    if (existing) existing.remove();

    const overlay = el('div', { className: 'modal-overlay open', id: 'suppress-modal', onClick: (e) => {
        if (e.target === overlay) overlay.remove();
    }}, [
        el('div', { className: 'modal' }, [
            el('h2', { textContent: `Bulk Suppress ${visible.length} Finding(s)` }),
            el('p', { style: 'font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;',
                textContent: 'This will suppress all currently visible findings. Use the filters to narrow down first.' }),
            el('div', { className: 'form-group' }, [
                el('label', { textContent: 'Disposition' }),
                el('select', { id: 'suppress-disposition' }, [
                    el('option', { value: 'not_vulnerable', textContent: 'Not vulnerable' }),
                    el('option', { value: 'false_positive', textContent: 'False positive' }),
                    el('option', { value: 'not_reachable', textContent: 'Code not reachable' }),
                    el('option', { value: 'wont_fix', textContent: 'Won\'t fix (accepted risk)' }),
                ]),
            ]),
            el('div', { className: 'form-group' }, [
                el('label', { textContent: 'Reason' }),
                el('input', { type: 'text', id: 'suppress-reason', placeholder: 'e.g. All legacy migration code, reviewed and safe' }),
            ]),
            el('div', { className: 'form-actions' }, [
                el('button', { className: 'btn', textContent: 'Cancel', onClick: () => overlay.remove() }),
                el('button', { className: 'btn btn-primary', textContent: `Suppress ${visible.length}`, onClick: async () => {
                    const disposition = document.getElementById('suppress-disposition').value;
                    const reason = document.getElementById('suppress-reason').value.trim();

                    // Collect finding data from visible elements
                    const items = [];
                    visible.forEach(f => {
                        // Determine tool from the active tab
                        const panel = f.closest('.tab-panel');
                        const tabId = panel?.dataset.tab || '';
                        const toolMap = { 'tab-semgrep': 'semgrep', 'tab-psalm': 'psalm', 'tab-trivy_secrets': 'trivy', 'tab-gitleaks': 'gitleaks', 'tab-zap': 'zap', 'tab-trivy_vulnerabilities': 'trivy', 'tab-trivy_misconfigurations': 'trivy' };
                        const tool = toolMap[tabId] || 'semgrep';

                        items.push({
                            tool,
                            rule: f.dataset.rule,
                            file: f.dataset.file,
                            line: parseInt(f.dataset.file?.match(/:(\d+)/)?.[1] || '0') || 0,
                            scope: 'exact',
                            disposition,
                            reason,
                        });
                    });

                    const resp = await fetch('api.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'suppress', project, items }),
                    }).then(r => r.json());

                    overlay.remove();
                    alert(`${resp.added ?? 0} suppression(s) added. Re-scan to apply.`);
                }}),
            ]),
        ]),
    ]);
    document.body.appendChild(overlay);
}

// ---- Suppress Modal ----

function openSuppressModal(finding, file, project, scope = 'exact') {
    const existing = document.getElementById('suppress-modal');
    if (existing) existing.remove();

    const tool = finding.tool || 'semgrep';
    const rule = finding.rule || '';
    const scopeLabels = {
        exact: `This specific finding (${file}:${finding.line})`,
        file: `All "${rule}" findings in ${file}`,
        rule: `All "${rule}" findings everywhere`,
    };

    const overlay = el('div', { className: 'modal-overlay open', id: 'suppress-modal', onClick: (e) => {
        if (e.target === overlay) overlay.remove();
    }}, [
        el('div', { className: 'modal' }, [
            el('h2', { textContent: 'Suppress Finding', style: 'margin-bottom: 0.5rem;' }),
            el('p', { style: 'font-size: 0.8rem; color: var(--text-muted); margin-bottom: 1rem;',
                textContent: scopeLabels[scope] || scopeLabels.exact }),
            el('div', { className: 'form-group' }, [
                el('label', { textContent: 'Disposition' }),
                el('select', { id: 'suppress-disposition' }, [
                    el('option', { value: 'not_vulnerable', textContent: 'Not vulnerable' }),
                    el('option', { value: 'false_positive', textContent: 'False positive' }),
                    el('option', { value: 'not_reachable', textContent: 'Code not reachable' }),
                    el('option', { value: 'wont_fix', textContent: 'Won\'t fix (accepted risk)' }),
                ]),
            ]),
            el('div', { className: 'form-group' }, [
                el('label', { textContent: 'Reason (optional)' }),
                el('input', { type: 'text', id: 'suppress-reason', placeholder: 'e.g. SQL fragments are hardcoded, no user input' }),
            ]),
            el('div', { className: 'form-actions' }, [
                el('button', { className: 'btn', textContent: 'Cancel', onClick: () => overlay.remove() }),
                el('button', { className: 'btn btn-primary', textContent: 'Suppress', onClick: async () => {
                    const disposition = document.getElementById('suppress-disposition').value;
                    const reason = document.getElementById('suppress-reason').value.trim();

                    const body = {
                        tool, rule, file, line: finding.line || 0,
                        scope, disposition, reason,
                    };

                    const resp = await fetch('api.php', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ ...body, action: 'suppress', project }),
                    }).then(r => r.json());

                    overlay.remove();

                    if (resp.added !== undefined) {
                        // Visual feedback — grey out the finding
                        const msg = scope === 'exact'
                            ? 'Finding suppressed. Re-scan to apply.'
                            : `${resp.added} suppression(s) added. Re-scan to apply.`;
                        alert(msg);
                    } else {
                        alert(resp.error || 'Failed to suppress');
                    }
                }}),
            ]),
        ]),
    ]);
    document.body.appendChild(overlay);
}

// ---- Suppressions Page ----

async function renderSuppressionsPage(container, project) {
    container.appendChild(el('a', { href: `#project/${project}`, textContent: `\u2190 ${project}`, style: 'font-size: 0.85rem; display: inline-block; margin-bottom: 1rem;' }));
    container.appendChild(el('h2', { textContent: `${project} — Suppressions`, style: 'margin-bottom: 1rem;' }));

    const data = await api('suppressions', { project });

    // Counts summary
    const c = data.counts || {};
    container.appendChild(el('div', { className: 'stats' }, [
        statBox(c.project || 0, 'Project Suppressions', 'blue'),
        statBox(c.shared || 0, 'Shared Suppressions', 'blue'),
        statBox(c.zap_ignored || 0, 'ZAP Ignored', 'yellow'),
        statBox(c.paths_ignored || 0, 'Paths Excluded', 'yellow'),
    ]));

    // Project suppressions
    const projSupps = data.project_suppressions || [];
    if (projSupps.length > 0) {
        const card = el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: `Project Suppressions (${projSupps.length})` }),
        ]);
        const table = el('table');
        table.appendChild(el('thead', {}, [el('tr', {}, [
            el('th', { textContent: 'Tool' }),
            el('th', { textContent: 'Rule' }),
            el('th', { textContent: 'File' }),
            el('th', { textContent: 'Scope' }),
            el('th', { textContent: 'Disposition' }),
            el('th', { textContent: 'Reason' }),
            el('th', { textContent: 'Date' }),
            el('th', { textContent: '' }),
        ])]));
        const tbody = el('tbody');
        for (const s of projSupps) {
            tbody.appendChild(el('tr', {}, [
                el('td', { textContent: s.tool }),
                el('td', { textContent: s.rule, style: 'font-family: var(--mono); font-size: 0.75rem;' }),
                el('td', { textContent: s.scope === 'rule' ? '(all files)' : (s.file || '-'), style: 'font-family: var(--mono); font-size: 0.75rem;' }),
                el('td', {}, [el('span', { className: 'badge severity-info', textContent: s.scope || 'exact' })]),
                el('td', {}, [el('span', { className: `badge ${dispositionClass(s.disposition)}`, textContent: dispositionLabel(s.disposition) })]),
                el('td', { textContent: s.reason || '-', style: 'color: var(--text-muted); font-size: 0.8rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis;' }),
                el('td', { textContent: s.date || '-', style: 'font-size: 0.8rem;' }),
                el('td', {}, [
                    el('button', { className: 'btn btn-sm btn-danger', textContent: 'Remove', onClick: async () => {
                        const resp = await fetch('api.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'unsuppress', project, tool: s.tool, rule: s.rule, file: s.file, line: s.line }),
                        }).then(r => r.json());
                        render(); // Refresh
                    }}),
                ]),
            ]));
        }
        table.appendChild(tbody);
        card.appendChild(table);
        container.appendChild(card);
    }

    // Shared suppressions
    const sharedSupps = data.shared_suppressions || [];
    if (sharedSupps.length > 0) {
        const card = el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: `Shared Suppressions — Framework (${sharedSupps.length})` }),
            el('p', { style: 'font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;', textContent: 'Reviewed framework-level findings in shared/suppressions.json. These ship with the scanner.' }),
        ]);
        const table = el('table');
        table.appendChild(el('thead', {}, [el('tr', {}, [
            el('th', { textContent: 'Tool' }),
            el('th', { textContent: 'Rule' }),
            el('th', { textContent: 'File' }),
            el('th', { textContent: 'Scope' }),
            el('th', { textContent: 'Reason' }),
        ])]));
        const tbody = el('tbody');
        for (const s of sharedSupps) {
            tbody.appendChild(el('tr', {}, [
                el('td', { textContent: s.tool }),
                el('td', { textContent: s.rule, style: 'font-family: var(--mono); font-size: 0.75rem;' }),
                el('td', { textContent: s.scope === 'rule' ? '(all files)' : (s.file || '-'), style: 'font-family: var(--mono); font-size: 0.75rem;' }),
                el('td', {}, [el('span', { className: 'badge severity-info', textContent: s.scope || 'exact' })]),
                el('td', { textContent: s.reason || '-', style: 'color: var(--text-muted); font-size: 0.8rem; max-width: 300px; overflow: hidden; text-overflow: ellipsis;' }),
            ]));
        }
        table.appendChild(tbody);
        card.appendChild(table);
        container.appendChild(card);
    }

    // ZAP ignored
    const zapIgnored = data.zap_ignored || [];
    if (zapIgnored.length > 0) {
        const card = el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: `ZAP Ignored Alerts (${zapIgnored.length})` }),
        ]);
        for (const z of zapIgnored) {
            card.appendChild(el('div', { style: 'font-size: 0.85rem; padding: 0.25rem 0;' }, [
                el('span', { className: 'badge severity-info', textContent: z.id, style: 'margin-right: 0.5rem;' }),
                z.description,
            ]));
        }
        container.appendChild(card);
    }

    // Ignored paths
    const paths = data.semgrep_ignored_paths || [];
    if (paths.length > 0) {
        const card = el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: `Semgrep Excluded Paths (${paths.length})` }),
        ]);
        const list = el('div', { style: 'font-family: var(--mono); font-size: 0.8rem; line-height: 1.8;' });
        for (const p of paths) {
            list.appendChild(el('div', { textContent: p }));
        }
        card.appendChild(list);
        container.appendChild(card);
    }

    if (projSupps.length === 0 && sharedSupps.length === 0 && zapIgnored.length === 0) {
        container.appendChild(el('div', { className: 'card', innerHTML: '<p style="color: var(--text-muted);">No suppressions yet. Open a report and click "Suppress" on any finding.</p>' }));
    }
}

function dispositionLabel(d) {
    return { not_vulnerable: 'Not Vulnerable', false_positive: 'False Positive', not_reachable: 'Not Reachable', wont_fix: "Won't Fix" }[d] || d;
}
function dispositionClass(d) {
    return { not_vulnerable: 'severity-low', false_positive: 'severity-info', not_reachable: 'severity-info', wont_fix: 'severity-medium' }[d] || 'severity-info';
}

// ---- Scan Log Modal ----

async function showScanLog(project, reportId) {
    const existing = document.getElementById('log-modal');
    if (existing) existing.remove();

    const data = await api('scanlog', { project, id: reportId });
    const log = data.log || 'No scan log available for this report.';

    const overlay = el('div', { className: 'modal-overlay open', id: 'log-modal', onClick: (e) => {
        if (e.target === overlay) overlay.remove();
    }}, [
        el('div', { className: 'modal', style: 'width: 800px; max-width: 95vw; max-height: 90vh; display: flex; flex-direction: column;' }, [
            el('div', { style: 'display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;' }, [
                el('h2', { textContent: 'Scan Log', style: 'margin: 0;' }),
                el('button', { className: 'btn btn-sm', textContent: 'Close', onClick: () => overlay.remove() }),
            ]),
            el('div', { className: 'console', style: 'flex: 1; overflow-y: auto; max-height: 70vh;', textContent: log }),
        ]),
    ]);
    document.body.appendChild(overlay);
}

// ---- Trends Page ----

async function renderTrends(container, project) {
    container.appendChild(el('a', { href: `#project/${project}`, textContent: `\u2190 ${project}`, style: 'font-size: 0.85rem; display: inline-block; margin-bottom: 1rem;' }));
    container.appendChild(el('h2', { textContent: `${project} \u2014 Trends`, style: 'margin-bottom: 1rem;' }));

    const data = await api('trends', { project });
    const series = data.series || [];

    if (series.length < 2) {
        container.appendChild(el('div', { className: 'card', innerHTML: '<p style="color: var(--text-muted);">Need at least 2 scans to show trends. Run more scans to see data here.</p>' }));
        return;
    }

    // SVG chart
    const W = 800, H = 300, PAD = 50, RPAD = 20;
    const chartW = W - PAD - RPAD;
    const chartH = H - PAD - 20;
    const maxVal = Math.max(...series.map(s => s.total), 1);
    const xStep = chartW / Math.max(series.length - 1, 1);

    function toX(i) { return PAD + i * xStep; }
    function toY(v) { return H - PAD - (v / maxVal) * chartH; }

    const lines = {
        total: { color: '#e6edf3', label: 'Total' },
        semgrep: { color: '#f97583', label: 'Semgrep' },
        psalm: { color: '#d2a8ff', label: 'Psalm' },
        phpstan: { color: '#79c0ff', label: 'PHPStan' },
        trivy: { color: '#ffa657', label: 'Trivy' },
        gitleaks: { color: '#56d364', label: 'Gitleaks' },
    };

    let svgContent = '';
    // Grid lines
    for (let i = 0; i <= 4; i++) {
        const y = toY((maxVal / 4) * i);
        const val = Math.round((maxVal / 4) * i);
        svgContent += `<line x1="${PAD}" y1="${y}" x2="${W - RPAD}" y2="${y}" stroke="#21262d" stroke-width="1"/>`;
        svgContent += `<text x="${PAD - 8}" y="${y + 4}" fill="#8b949e" font-size="11" text-anchor="end">${val}</text>`;
    }

    // X-axis labels (show a few)
    const labelInterval = Math.max(1, Math.floor(series.length / 6));
    for (let i = 0; i < series.length; i += labelInterval) {
        const label = series[i].date.replace(/^\d{4}-/, '').slice(0, 5);
        svgContent += `<text x="${toX(i)}" y="${H - 8}" fill="#8b949e" font-size="10" text-anchor="middle">${label}</text>`;
    }

    // Data lines
    for (const [key, cfg] of Object.entries(lines)) {
        const points = series.map((s, i) => `${toX(i)},${toY(s[key] || 0)}`).join(' ');
        const sw = key === 'total' ? 2 : 1.5;
        const opacity = key === 'total' ? 1 : 0.7;
        svgContent += `<polyline points="${points}" fill="none" stroke="${cfg.color}" stroke-width="${sw}" opacity="${opacity}"/>`;
    }

    // Interactive dots for total line
    for (let i = 0; i < series.length; i++) {
        const s = series[i];
        svgContent += `<circle cx="${toX(i)}" cy="${toY(s.total)}" r="3" fill="#e6edf3" style="cursor:pointer" onclick="window.location.hash='project/${project}/${s.id}'">
            <title>${s.date}: ${s.total} findings</title></circle>`;
    }

    const svg = `<svg viewBox="0 0 ${W} ${H}" style="width: 100%; height: auto; max-height: 350px;">${svgContent}</svg>`;

    // Legend
    const legend = el('div', { style: 'display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; font-size: 0.8rem;' });
    for (const [key, cfg] of Object.entries(lines)) {
        legend.appendChild(el('span', { style: `display: flex; align-items: center; gap: 0.3rem;` }, [
            el('span', { style: `width: 12px; height: 3px; background: ${cfg.color}; display: inline-block; border-radius: 1px;` }),
            cfg.label,
        ]));
    }

    const card = el('div', { className: 'card' }, [
        el('div', { className: 'card-title', textContent: 'Findings Over Time' }),
        el('div', { innerHTML: svg }),
        legend,
    ]);
    container.appendChild(card);

    // Severity trend if available
    const sevSeries = series.filter(s => s.severity);
    if (sevSeries.length >= 2) {
        const maxSev = Math.max(...sevSeries.map(s => (s.severity.critical || 0) + (s.severity.high || 0) + (s.severity.medium || 0)), 1);
        const sevXStep = chartW / Math.max(sevSeries.length - 1, 1);
        function toSX(i) { return PAD + i * sevXStep; }
        function toSY(v) { return H - PAD - (v / maxSev) * chartH; }

        let sevSvg = '';
        for (let i = 0; i <= 4; i++) {
            const y = toSY((maxSev / 4) * i);
            const val = Math.round((maxSev / 4) * i);
            sevSvg += `<line x1="${PAD}" y1="${y}" x2="${W - RPAD}" y2="${y}" stroke="#21262d" stroke-width="1"/>`;
            sevSvg += `<text x="${PAD - 8}" y="${y + 4}" fill="#8b949e" font-size="11" text-anchor="end">${val}</text>`;
        }

        const sevLines = { critical: '#ff6b6b', high: '#f97583', medium: '#ffa657' };
        for (const [sev, color] of Object.entries(sevLines)) {
            const points = sevSeries.map((s, i) => `${toSX(i)},${toSY(s.severity[sev] || 0)}`).join(' ');
            sevSvg += `<polyline points="${points}" fill="none" stroke="${color}" stroke-width="1.5"/>`;
        }

        const sevLegend = el('div', { style: 'display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 0.5rem; font-size: 0.8rem;' });
        for (const [sev, color] of Object.entries(sevLines)) {
            sevLegend.appendChild(el('span', { style: 'display: flex; align-items: center; gap: 0.3rem;' }, [
                el('span', { style: `width: 12px; height: 3px; background: ${color}; display: inline-block;` }),
                sev.charAt(0).toUpperCase() + sev.slice(1),
            ]));
        }

        container.appendChild(el('div', { className: 'card' }, [
            el('div', { className: 'card-title', textContent: 'Severity Trend (Critical + High + Medium)' }),
            el('div', { innerHTML: `<svg viewBox="0 0 ${W} ${H}" style="width: 100%; height: auto; max-height: 350px;">${sevSvg}</svg>` }),
            sevLegend,
        ]));
    }
}

// ---- Docs Page ----

async function renderDocs(container) {
    const data = await api('docs');
    if (data.error) {
        container.appendChild(el('div', { className: 'card', textContent: data.error }));
        return;
    }

    const card = el('div', { className: 'card markdown-body' });
    card.innerHTML = renderMarkdown(data.content);
    container.appendChild(card);
}

function renderMarkdown(md) {
    // Lightweight markdown to HTML — handles the patterns in HOW-IT-WORKS.md
    let html = md
        // Escape HTML entities first
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    // Fenced code blocks (``` ... ```)
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) =>
        `<pre><code class="lang-${lang}">${code.trim()}</code></pre>`);

    // Tables
    html = html.replace(/^(\|.+\|)\n(\|[\s\-:|]+\|)\n((?:\|.+\|\n?)*)/gm, (_, header, sep, body) => {
        const ths = header.split('|').filter(c => c.trim()).map(c => `<th>${c.trim()}</th>`).join('');
        const rows = body.trim().split('\n').map(row => {
            const tds = row.split('|').filter(c => c.trim()).map(c => `<td>${c.trim()}</td>`).join('');
            return `<tr>${tds}</tr>`;
        }).join('');
        return `<table><thead><tr>${ths}</tr></thead><tbody>${rows}</tbody></table>`;
    });

    // Headers
    html = html.replace(/^#### (.+)$/gm, '<h4>$1</h4>');
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

    // Bold and italic
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');

    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Links: [text](url) — external links stay clickable, local files show as path
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, href) => {
        if (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('#')) {
            return `<a href="${href}">${text}</a>`;
        }
        // Local file — show as inline code path
        return `<code title="${href}">${href}</code>`;
    });

    // Unordered lists
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>\n?)+/g, match => `<ul>${match}</ul>`);

    // Numbered lists
    html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

    // Paragraphs — wrap remaining bare lines
    html = html.replace(/^(?!<[huptl]|$)(.+)$/gm, '<p>$1</p>');

    // Clean up double-wrapped
    html = html.replace(/<p><(h[1-4]|ul|ol|li|table|pre|blockquote)/g, '<$1');
    html = html.replace(/<\/(h[1-4]|ul|ol|li|table|pre|blockquote)><\/p>/g, '</$1>');

    return html;
}

// ---- Scan Type Label ----

function getScanTypeLabel(opts, totals) {
    const hasZap = totals && totals.zap !== undefined && totals.zap !== null;
    const skip = (opts?.skip || '').toLowerCase();
    const zapSkipped = skip.includes('zap');

    if (!hasZap && zapSkipped) {
        if (opts && opts.only) return { label: opts.only, cls: 'severity-info' };
        return { label: 'Static', cls: 'severity-info' };
    }
    const auth = opts?.zap_user ? ' + Auth' : '';
    if (hasZap || opts?.url) return { label: `Full${auth}`, cls: auth ? 'severity-high' : 'severity-medium' };
    return { label: 'Static', cls: 'severity-info' };
}

// ---- Setup Required Screen ----

function renderSetupRequired() {
    return el('div', { style: 'max-width: 600px; margin: 3rem auto; text-align: center;' }, [
        el('h2', { textContent: 'Welcome to UserSpice Security Scanner', style: 'margin-bottom: 1rem;' }),
        el('p', { style: 'color: var(--text-muted); margin-bottom: 2rem;', textContent: 'Run the setup script to configure your environment before using the scanner.' }),
        el('div', { className: 'card', style: 'text-align: left;' }, [
            el('div', { className: 'card-title', textContent: 'Getting Started' }),
            el('p', { style: 'font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;',
                textContent: 'The setup script checks prerequisites (Docker, jq, PHP), asks where your projects live, and optionally pulls the scanner Docker images.' }),
            el('div', {
                style: 'background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; font-family: var(--mono); font-size: 0.9rem; margin-bottom: 1rem; cursor: pointer;',
                title: 'Click to copy',
                onClick: (e) => {
                    navigator.clipboard.writeText('./setup.sh');
                    e.currentTarget.style.borderColor = 'var(--green)';
                    setTimeout(() => e.currentTarget.style.borderColor = '', 1000);
                },
            }, ['./setup.sh']),
            el('p', { style: 'font-size: 0.8rem; color: var(--text-muted);',
                innerHTML: 'Run this from the scanner directory. It will create <code>scanner.conf</code> with your local settings. Refresh this page when done.' }),
        ]),
        el('div', { className: 'card', style: 'text-align: left; margin-top: 1rem;' }, [
            el('div', { className: 'card-title', textContent: 'Requirements' }),
            el('div', { style: 'font-size: 0.85rem; line-height: 2;' }, [
                el('div', {}, ['Docker — runs all scanners in containers']),
                el('div', {}, ['jq — processes scan results']),
                el('div', {}, ['PHP 8.0+ — powers this web UI']),
                el('div', {}, ['bash 4+ — runs the scan scripts']),
                el('div', { style: 'color: var(--text-muted);' }, ['~4GB disk for Docker images (downloaded on first scan)']),
            ]),
        ]),
    ]);
}

// ---- Setup Banner ----

function renderSetupBanner(preflight) {
    const steps = [];

    if (!preflight.docker_installed) {
        steps.push({
            title: 'Install Docker',
            detail: 'Docker is required to run the security scanners.',
            cmd: 'curl -fsSL https://get.docker.com | sh',
            status: 'missing',
        });
    } else if (!preflight.docker_accessible) {
        steps.push({
            title: 'Add web server user to docker group',
            detail: `The web server runs as <code>${preflight.web_user}</code> which doesn\'t have permission to use Docker. ` +
                    `After running this command, restart Apache for it to take effect.`,
            cmd: `sudo usermod -aG docker ${preflight.web_user}\nsudo systemctl restart apache2`,
            status: 'action',
        });
    }

    if (!preflight.jq_installed) {
        steps.push({
            title: 'Install jq',
            detail: 'jq is used to generate detailed scan summaries.',
            cmd: 'sudo apt-get install -y jq',
            status: 'missing',
        });
    }

    if (!preflight.scanner_executable) {
        steps.push({
            title: 'Make scan.sh executable',
            detail: 'The scanner script needs execute permission.',
            cmd: 'chmod +x ' + (preflight.scanner_exists ? 'scan.sh' : '/path/to/codetest/scan.sh'),
            status: 'action',
        });
    }

    const banner = el('div', {
        className: 'card',
        style: 'border-color: var(--yellow); margin-bottom: 1.5rem;',
    }, [
        el('div', { className: 'card-title', style: 'color: var(--yellow);' }, [
            'Setup Required',
        ]),
        el('p', {
            style: 'font-size: 0.85rem; color: var(--text-muted); margin-bottom: 1rem;',
            textContent: 'The scanner needs a few things configured before it can run scans from the UI. You can still browse existing reports.',
        }),
    ]);

    for (const step of steps) {
        const stepEl = el('div', {
            style: 'background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.75rem;',
        }, [
            el('div', { style: 'font-weight: 600; font-size: 0.9rem; margin-bottom: 0.25rem;' }, [
                el('span', {
                    className: `badge ${step.status === 'missing' ? 'severity-high' : 'severity-medium'}`,
                    textContent: step.status === 'missing' ? 'Missing' : 'Action needed',
                    style: 'margin-right: 0.5rem;',
                }),
                step.title,
            ]),
            el('p', { innerHTML: step.detail, style: 'font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.5rem;' }),
            el('div', {
                style: 'background: #010409; border: 1px solid var(--border); border-radius: 4px; padding: 0.5rem 0.75rem; font-family: var(--mono); font-size: 0.8rem; cursor: pointer; position: relative;',
                title: 'Click to copy',
                onClick: (e) => {
                    navigator.clipboard.writeText(step.cmd).then(() => {
                        const el = e.currentTarget;
                        const orig = el.style.borderColor;
                        el.style.borderColor = 'var(--green)';
                        setTimeout(() => el.style.borderColor = orig, 1000);
                    });
                },
            }, [step.cmd]),
        ]);
        banner.appendChild(stepEl);
    }

    banner.appendChild(el('div', { style: 'margin-top: 0.75rem; display: flex; align-items: center; gap: 1rem;' }, [
        el('button', { className: 'btn btn-sm', textContent: 'Re-check Environment', onClick: () => {
            try {
                localStorage.removeItem('scanner_preflight');
                localStorage.removeItem('scanner_preflight_ts');
            } catch {}
            render();
        }}),
        el('span', {
            style: 'font-size: 0.75rem; color: var(--text-muted);',
            textContent: 'You can also run scans from the terminal: ./scan.sh <project>',
        }),
    ]));

    return banner;
}

// ---- Boot ----
document.addEventListener('DOMContentLoaded', () => render());
