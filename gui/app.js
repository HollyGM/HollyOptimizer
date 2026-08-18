// App State and DOM Elements
const panels = document.querySelectorAll('.panel');
const navButtons = document.querySelectorAll('.nav-btn');
const currentPanelTitle = document.getElementById('current-panel-title');
const loaderOverlay = document.getElementById('loader-overlay');
const loaderMessage = document.getElementById('loader-message');
const loaderProgress = document.getElementById('loader-progress');
const cancelOperationBtn = document.getElementById('btn-cancel-operation');
let activeOperation = null;
let operationProgressTimer = null;
let trackedOperationButton = null;

// Navigation click handler
navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-target');
        
        // Update navigation active state
        navButtons.forEach(b => {
            b.classList.remove('active');
            b.removeAttribute('aria-current');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-current', 'page');
        
        // Switch active panel
        panels.forEach(p => p.classList.remove('active'));
        const activePanel = document.getElementById(targetId);
        activePanel.classList.add('active');
        
        // Update header title
        currentPanelTitle.textContent = btn.querySelector('span').textContent;
        
        // Trigger auto-loads on specific tab open
        if (targetId === 'dependencies-panel') {
            stopMemoryMonitor();
            loadDependencies();
        } else if (targetId === 'network-panel') {
            stopMemoryMonitor();
            loadNetworkPing();
        } else if (targetId === 'uninstaller-panel') {
            stopMemoryMonitor();
            loadInstalledApps();
        } else if (targetId === 'memory-panel') {
            startMemoryMonitor();
        } else if (targetId === 'silicon-panel') {
            stopMemoryMonitor();
            loadHardwareProfile();
        } else {
            stopMemoryMonitor();
        }
    });
});

// Stat cards navigation shortcut
document.querySelectorAll('.stat-card').forEach(card => {
    card.addEventListener('click', () => {
        const targetNav = card.getAttribute('data-nav');
        const matchingBtn = document.querySelector(`.nav-btn[data-target="${targetNav}"]`);
        if (matchingBtn) matchingBtn.click();
    });
    card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            card.click();
        }
    });
});

// Loader helper
function showLoader(message) {
    loaderMessage.textContent = message || "Carregando dados...";
    loaderProgress.hidden = true;
    loaderProgress.textContent = '';
    cancelOperationBtn.hidden = true;
    cancelOperationBtn.disabled = false;
    loaderOverlay.style.display = 'flex';
    loaderOverlay.setAttribute('aria-hidden', 'false');
}

function startOperationTracking(operation) {
    stopOperationTracking();
    activeOperation = operation;
    const buttonByOperation = {
        large_files: 'btn-scan-large',
        duplicates: 'btn-scan-duplicates',
    };
    trackedOperationButton = document.getElementById(buttonByOperation[operation]);
    if (trackedOperationButton) trackedOperationButton.disabled = true;
    loaderProgress.hidden = false;
    cancelOperationBtn.hidden = false;
    const refresh = async () => {
        if (activeOperation !== operation) return;
        try {
            const state = await window.pywebview.api.get_operation_progress(operation);
            if (activeOperation !== operation) return;
            loaderProgress.textContent = state.processed > 0
                ? `${state.message} · ${state.processed}`
                : state.message;
            if (!state.active && state.message) stopOperationTracking();
        } catch (_) {
            // The main operation remains authoritative if progress polling fails.
        }
    };
    refresh();
    operationProgressTimer = setInterval(refresh, 350);
}

function stopOperationTracking() {
    if (operationProgressTimer) clearInterval(operationProgressTimer);
    if (trackedOperationButton) trackedOperationButton.disabled = false;
    operationProgressTimer = null;
    trackedOperationButton = null;
    activeOperation = null;
    loaderProgress.hidden = true;
    cancelOperationBtn.hidden = true;
    cancelOperationBtn.disabled = false;
}

async function reportScanIssues(feature) {
    try {
        const report = await window.pywebview.api.get_scan_issues(feature);
        if (feature === 'junk') {
            const accessWarning = document.getElementById('junk-access-warning');
            if (accessWarning) accessWarning.hidden = !(report.counts && report.counts.tcc_denied);
        }
        if (report.total > 0) {
            const accessDenied = report.counts && report.counts.tcc_denied;
            showToast(
                accessDenied
                    ? 'Análise parcial: o macOS bloqueou pastas do seu usuário. Use “Abrir Acesso Total ao Disco” nesta tela.'
                    : `Varredura concluída com acesso limitado a alguns locais. ${report.messages[0] || ''}`,
                'warning',
                8000
            );
        }
        return report;
    } catch (_) {
        return { total: 0, counts: {}, messages: [] };
    }
}

function hideLoader() {
    loaderOverlay.style.display = 'none';
    loaderOverlay.setAttribute('aria-hidden', 'true');
}

// ==================== DIALOG & HTML SAFETY ====================
function escapeHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function showDialog({ title = 'Confirmação', message = '', confirmText = 'Confirmar', cancelText = 'Cancelar', showCancel = true, confirmClass = 'primary' }) {
    return new Promise((resolve) => {
        const overlay = document.getElementById('dialog-overlay');
        const titleEl = document.getElementById('dialog-title');
        const messageEl = document.getElementById('dialog-message');
        const confirmBtn = document.getElementById('dialog-confirm');
        const cancelBtn = document.getElementById('dialog-cancel');
        const previousFocus = document.activeElement;

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = confirmText;
        cancelBtn.textContent = cancelText;
        cancelBtn.style.display = showCancel ? 'inline-flex' : 'none';
        confirmBtn.className = `btn ${confirmClass}`;

        overlay.style.display = 'flex';
        overlay.setAttribute('aria-hidden', 'false');

        const cleanup = (result) => {
            overlay.style.display = 'none';
            overlay.setAttribute('aria-hidden', 'true');
            confirmBtn.removeEventListener('click', onConfirm);
            cancelBtn.removeEventListener('click', onCancel);
            document.removeEventListener('keydown', onKeydown);
            if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus();
            resolve(result);
        };

        const onConfirm = () => cleanup(true);
        const onCancel = () => cleanup(false);
        const onKeydown = (event) => {
            if (event.key === 'Escape') cleanup(false);
            if (event.key === 'Tab') {
                const focusable = [cancelBtn, confirmBtn].filter(button => button.style.display !== 'none');
                const currentIndex = focusable.indexOf(document.activeElement);
                const direction = event.shiftKey ? -1 : 1;
                const nextIndex = (currentIndex + direction + focusable.length) % focusable.length;
                event.preventDefault();
                focusable[nextIndex].focus();
            }
        };

        confirmBtn.addEventListener('click', onConfirm);
        cancelBtn.addEventListener('click', onCancel);
        document.addEventListener('keydown', onKeydown);
        confirmBtn.focus();
    });
}

function showConfirm(message, options = {}) {
    return showDialog({ title: options.title || 'Confirmar ação', message, confirmText: options.confirmText || 'Confirmar', cancelText: options.cancelText || 'Cancelar', showCancel: true, confirmClass: options.danger ? 'danger' : 'primary' });
}

function showAlert(message, options = {}) {
    return showDialog({ title: options.title || 'HollyOptimizer', message, confirmText: options.confirmText || 'OK', showCancel: false, confirmClass: 'primary' });
}

function animateCountUp(element, targetBytes, duration = 800) {
    if (!element || targetBytes <= 0) {
        if (element) element.textContent = formatBytes(targetBytes || 0);
        return;
    }
    const start = performance.now();
    element.classList.add('count-up');
    const tick = (now) => {
        const progress = Math.min((now - start) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        element.textContent = formatBytes(Math.floor(targetBytes * eased));
        if (progress < 1) requestAnimationFrame(tick);
        else element.textContent = formatBytes(targetBytes);
    };
    requestAnimationFrame(tick);
}

// Global variables for scanner results
let scannedJunk = {};
let scannedLeftovers = [];
let dashboardState = 'idle'; // 'idle', 'scanning', 'scanned', 'fixing'
let buttonsInitialized = false;
let scannedStartup = [];
let scannedLargeFiles = [];
let scannedDuplicates = [];
let installedApps = [];
let selectedAppIdx = -1;
let relatedFiles = [];
let appIconObserver = null;
let installedAppsRequestId = 0;
let appSelectionRequestId = 0;
const appIconCache = new Map();
let scannedBrowserCaches = {};
let scannedDependencies = { brew: null, npm: null, pip: null };
let dependenciesRequestId = 0;

// Wait for PyWebView interface initialization
window.addEventListener('pywebviewready', () => {
    console.log("PyWebView API is ready!");
    
    // Run initial system stats ping for the header
    loadNetworkPingHeader();
    loadDashboardRam();
    refreshDiskUsage();

    // Proactively check required macOS permissions on launch so the user is
    // pointed at the right Settings pane before a feature fails deep in a
    // scan. Backgrounded: no loader, never blocks the rest of the UI.
    runPermissionsAudit(false);

    // Bind Scan and Action Buttons
    bindButtons();
});

setInterval(refreshDiskUsage, 60000);

function bindButtons() {
    const btnEmptyTrash = document.getElementById('btn-empty-trash');
    if(btnEmptyTrash) btnEmptyTrash.addEventListener('click', handleEmptyTrash);
    if (buttonsInitialized) return;
    buttonsInitialized = true;
    
    // 1. Dashboard: Main Complete Scan
    document.getElementById('btn-main-scan').addEventListener('click', handleMainScanClick);
    
    // 2. Junk Cleaner Panel
    document.getElementById('btn-scan-junk').addEventListener('click', scanJunk);
    document.getElementById('btn-clean-junk').addEventListener('click', cleanSelectedJunk);
    document.getElementById('btn-open-full-disk-access').addEventListener('click', () => {
        openSecuritySetting('full_disk_access');
    });
    document.getElementById('junk-select-all').addEventListener('change', (e) => {
        document.querySelectorAll('.junk-checkbox:not(:disabled)').forEach(cb => {
            cb.checked = e.target.checked;
        });
        updateJunkCleanButton();
    });
    document.querySelector('#junk-table tbody').addEventListener('change', (event) => {
        if (event.target.classList.contains('junk-checkbox')) updateJunkCleanButton();
    });
    
    // 3. App Leftovers Panel
    document.getElementById('btn-scan-leftovers').addEventListener('click', scanLeftovers);
    document.getElementById('btn-clean-leftovers').addEventListener('click', cleanSelectedLeftovers);
    document.getElementById('leftovers-select-all').addEventListener('change', (e) => {
        document.querySelectorAll('.leftover-checkbox').forEach(cb => cb.checked = e.target.checked);
    });
    
    // 4. Dependencies actions
    document.getElementById('btn-refresh-dependencies').addEventListener('click', loadDependencies);
    document.getElementById('btn-remove-dependencies').addEventListener('click', removeSelectedDependencies);
    document.querySelector('.dependencies-container').addEventListener('change', (event) => {
        if (event.target.classList.contains('dependency-checkbox')) updateDependencyRemoveButton();
    });
    document.getElementById('btn-brew-autoremove').addEventListener('click', () => runBrewAction('autoremove'));
    document.getElementById('btn-brew-cleanup').addEventListener('click', () => runBrewAction('cleanup'));
    
    // 5. Startup Agents Panel
    document.getElementById('btn-scan-startup').addEventListener('click', scanStartup);
    
    // 6. Large Files Panel
    document.getElementById('btn-scan-large').addEventListener('click', scanLargeFiles);
    document.getElementById('btn-clean-large').addEventListener('click', cleanSelectedLargeFiles);
    document.getElementById('large-select-all').addEventListener('change', (e) => {
        document.querySelectorAll('.large-checkbox').forEach(cb => cb.checked = e.target.checked);
    });
    
    // 7. Duplicate Files Panel
    document.getElementById('btn-scan-duplicates').addEventListener('click', scanDuplicates);
    document.getElementById('btn-clean-duplicates').addEventListener('click', cleanSelectedDuplicates);
    document.getElementById('dup-select-all').addEventListener('change', (e) => {
        document.querySelectorAll('.dup-checkbox:not([data-keeper="true"])').forEach(cb => {
            cb.checked = e.target.checked;
        });
    });

    // 8. Browser cache cleaner
    document.getElementById('btn-scan-browser-caches').addEventListener('click', scanBrowserCaches);
    document.getElementById('btn-clean-browser-caches').addEventListener('click', cleanSelectedBrowserCaches);
    document.querySelector('#browser-cache-table tbody').addEventListener('change', (event) => {
        if (event.target.classList.contains('browser-cache-checkbox')) updateBrowserCleanButton();
    });

    // 9. Read-only security audit
    document.getElementById('btn-run-security-audit').addEventListener('click', runSecurityAudit);

    // 9c. Permissions panel (Full Disk Access + Automation)
    document.getElementById('btn-run-permissions-audit').addEventListener('click', () => runPermissionsAudit(true));
    document.getElementById('btn-goto-permissions').addEventListener('click', () => {
        document.querySelector('.nav-btn[data-target="permissions-panel"]').click();
    });

    // 9b. Read-only Apple Silicon architecture audit
    document.getElementById('btn-scan-silicon').addEventListener('click', runSiliconAudit);
    document.getElementById('silicon-search').addEventListener('input', filterSiliconApps);
    
    // 10. Network Panel
    document.getElementById('btn-net-flush').addEventListener('click', runNetworkFlush);
    document.getElementById('btn-net-ping').addEventListener('click', loadNetworkPing);
    
    // 11. Uninstaller Panel
    document.getElementById('btn-refresh-uninstaller').addEventListener('click', loadInstalledApps);
    document.getElementById('btn-run-uninstall').addEventListener('click', runUninstall);
    document.getElementById('unit-select-all').addEventListener('change', (e) => {
        document.querySelectorAll('.unit-file-checkbox').forEach(cb => cb.checked = e.target.checked);
    });
    document.getElementById('uninstaller-search').addEventListener('input', filterInstalledApps);
    cancelOperationBtn.addEventListener('click', async () => {
        if (!activeOperation) return;
        cancelOperationBtn.disabled = true;
        loaderProgress.hidden = false;
        loaderProgress.textContent = 'Solicitando cancelamento seguro…';
        await window.pywebview.api.cancel_operation(activeOperation);
    });
}

// ==================== DASHBOARD SCAN ====================
async function runCompleteScan() {
    showLoader("Iniciando Varredura Completa...");
    
    try {
        // 1. Scan Junk
        loaderMessage.textContent = "Buscando lixo do sistema (caches, logs, Xcode)...";
        scannedJunk = await window.pywebview.api.scan_junk();
        await reportScanIssues('junk');
        let totalJunkBytes = 0;
        let manualReviewBytes = 0;
        for (let key in scannedJunk) {
            if (scannedJunk[key].cleanable) {
                totalJunkBytes += scannedJunk[key].size_bytes;
            } else {
                manualReviewBytes += scannedJunk[key].size_bytes;
            }
        }

        // 2. Scan cache-only browser locations
        loaderMessage.textContent = "Analisando caches temporários dos navegadores...";
        scannedBrowserCaches = await window.pywebview.api.scan_browser_caches();
        await reportScanIssues('browser_caches');
        const totalBrowserCacheBytes = Object.values(scannedBrowserCaches).reduce(
            (sum, browser) => sum + (
                browser.accessible && !browser.running ? Number(browser.size_bytes || 0) : 0
            ),
            0
        );
        
        // 3. Scan App Leftovers
        loaderMessage.textContent = "Procurando sobras de aplicativos desinstalados...";
        scannedLeftovers = await window.pywebview.api.scan_leftovers();
        await reportScanIssues('leftovers');
        
        // 4. Scan Startup items
        loaderMessage.textContent = "Auditando itens de inicialização do launchd...";
        scannedStartup = await window.pywebview.api.scan_startup();
        await reportScanIssues('startup');
        
        // 5. Scan Network Latency
        loaderMessage.textContent = "Medindo resposta de rede...";
        const netStats = await window.pywebview.api.run_network_diagnostic();
        
        // 6. Analyze RAM memory (read-only; no forced purge)
        loaderMessage.textContent = "Analisando consumo de memória RAM...";
        const ramStats = await window.pywebview.api.get_memory_stats();
        
        // Update Dashboard GUI
        animateCountUp(document.getElementById('dash-junk-size'), totalJunkBytes);
        document.getElementById('dash-leftovers-count').textContent = `${scannedLeftovers.length} itens`;
        document.getElementById('dash-startup-count').textContent = `${scannedStartup.length} serviços`;
        document.getElementById('dash-network-status').textContent = `${netStats.status} (${netStats.latency_human})`;
        document.getElementById('dash-ram-use').textContent = `${ramStats.used_human} (${ramStats.percent}%)`;
        
        // Update Header Latency
        document.getElementById('diagnostic-stat-latency').textContent = `Ping: ${netStats.latency_human}`;
        
        // Update Main Status text
        const totalSavings = totalJunkBytes + totalBrowserCacheBytes;
        const manualNote = manualReviewBytes > 0
            ? ` ${formatBytes(manualReviewBytes)} em categorias de revisão manual (Docker/Xcode) não entram na limpeza automática.`
            : '';
        document.getElementById('system-status-msg').textContent = "Varredura Concluída!";
        document.getElementById('system-status-sub').textContent = `${formatBytes(totalSavings)} de lixo e caches podem ser movidos para a Lixeira. ${scannedLeftovers.length} sobra(s) aguardam revisão manual.${manualNote}`;

        // Fire-and-forget: never blocks the scan result on an optional,
        // on-device-only rewrite of the sentence above.
        maybeShowAiSummary(
            `Uma varredura do HollyOptimizer encontrou ${formatBytes(totalSavings)} ` +
            `reaproveitáveis em lixo do sistema e caches de navegador. ` +
            `${scannedLeftovers.length} sobra(s) de aplicativos desinstalados aguardam revisão manual. ` +
            `${scannedStartup.length} item(ns) de inicialização estão cadastrados.${manualNote}`
        );
        return totalSavings;
        
    } catch (err) {
        console.error("Complete scan error:", err);
        dashboardState = 'idle';
        showToast("Ocorreu um erro durante a varredura completa.", "error");
        return 0;
    } finally {
        hideLoader();
    }
}

async function handleMainScanClick() {
    const btn = document.getElementById('btn-main-scan');
    const container = btn.closest('.scanner-circle-container');
    
    if (dashboardState === 'idle') {
        dashboardState = 'scanning';
        btn.innerHTML = `<span class="scan-circle-text">ANÁLISE</span><span class="scan-circle-sub">EM CURSO...</span>`;
        btn.disabled = true;
        
        const totalSavings = await runCompleteScan();
        btn.disabled = false;
        
        if (totalSavings > 0) {
            dashboardState = 'scanned';
            btn.innerHTML = `<span class="scan-circle-text" style="font-size:16px;">EXECUTAR</span><span class="scan-circle-sub" style="font-size:9px;">CORREÇÕES</span>`;
            btn.classList.add('ready-to-execute');
            if (container) container.classList.add('ready');
        } else {
            dashboardState = 'idle';
            btn.innerHTML = `<span class="scan-circle-text">VARREDURA</span><span class="scan-circle-sub">COMPLETA</span>`;
            btn.classList.remove('ready-to-execute');
            if (container) container.classList.remove('ready');
        }
    } else if (dashboardState === 'scanned') {
        const junkKeys = Object.keys(scannedJunk).filter(k => scannedJunk[k].cleanable && scannedJunk[k].size_bytes > 0);
        const browserKeys = Object.keys(scannedBrowserCaches).filter(key => {
            const browser = scannedBrowserCaches[key];
            return browser.accessible && !browser.running && browser.size_bytes > 0;
        });
        const confirmFix = await showConfirm(
            `Serão limpas ${junkKeys.length} categorias reversíveis de lixo e ${browserKeys.length} cache(s) de navegador elegível(is).\n\nSobras de apps exigem revisão manual. A RAM será reavaliada, mas caches de memória não serão forçados porque o macOS os libera automaticamente.`,
            { title: 'Executar correções', confirmText: 'Executar', danger: false }
        );
        if (!confirmFix) return;

        dashboardState = 'fixing';
        btn.innerHTML = `<span class="scan-circle-text">LIMPANDO</span><span class="scan-circle-sub">CORREÇÕES...</span>`;
        btn.disabled = true;
        btn.classList.remove('ready-to-execute');
        if (container) container.classList.remove('ready');
        
        await runCompleteFixes();
        btn.disabled = false;
        
        dashboardState = 'idle';
        btn.innerHTML = `<span class="scan-circle-text">VARREDURA</span><span class="scan-circle-sub">COMPLETA</span>`;
    }
}

async function runCompleteFixes() {
    await window.pywebview.api.reset_auth_state();
    showLoader("Executando todas as correções e limpezas...");
    
    let totalFreed = 0;
    let errors = [];
    
    // 1. Clean Junk — inventory-only categories (Docker, Xcode Archives,
    // DeviceSupport) are never part of the automatic batch.
    try {
        for (let key in scannedJunk) {
            if (scannedJunk[key].cleanable && scannedJunk[key].size_bytes > 0) {
                loaderMessage.textContent = `Limpando ${scannedJunk[key].name}...`;
                const result = await window.pywebview.api.clean_junk(key);
                totalFreed += result.bytes_moved || 0;
                if (result.failed) errors.push(...(result.errors || []));
            }
        }
    } catch (err) {
        errors.push(`Erro ao limpar lixo: ${err}`);
    }

    // 2. Browser caches — only closed and accessible browsers from this scan
    try {
        for (const [key, browser] of Object.entries(scannedBrowserCaches)) {
            if (!browser.accessible || browser.running || browser.size_bytes <= 0) continue;
            loaderMessage.textContent = `Revalidando cache do ${browser.name}...`;
            const result = await window.pywebview.api.clean_browser_cache(key);
            totalFreed += result.bytes_moved || 0;
            if (result.failed) errors.push(...(result.errors || []));
        }
    } catch (err) {
        errors.push(`Erro ao limpar caches de navegador: ${err}`);
    }
    
    // 3. Leftovers — never removed automatically (manual review required)

    // Refresh the junk snapshot so partial failures stay visible and the next
    // action never relies on the older dashboard analysis.
    try {
        scannedJunk = await window.pywebview.api.scan_junk();
        await reportScanIssues('junk');
    } catch (err) {
        errors.push(`Não foi possível atualizar o lixo restante: ${err.message || err}`);
        scannedJunk = {};
    }
    const remainingJunk = Object.values(scannedJunk).reduce(
        (sum, item) => sum + Number(item.size_bytes || 0),
        0
    );
    animateCountUp(document.getElementById('dash-junk-size'), remainingJunk, 400);
    document.getElementById('dash-leftovers-count').textContent = `${scannedLeftovers.length} itens`;
    
    // Refresh RAM badge on dashboard
    await loadDashboardRam();
    
    // Browser caches require a new explicit analysis after this operation.
    scannedBrowserCaches = {};

    document.getElementById('system-status-msg').textContent = errors.length
        ? "Correções concluídas parcialmente"
        : "Correções concluídas!";
    document.getElementById('system-status-sub').textContent = errors.length
        ? `Movidos: ${formatBytes(totalFreed)}. Permanecem ${formatBytes(remainingJunk)} para revisão.`
        : `Movidos para a Lixeira: ${formatBytes(totalFreed)}.`;
    
    hideLoader();
    
    if (errors.length > 0) {
        showToast(
            `Correções parciais. ${formatBytes(totalFreed)} movidos. ${summarizeFailures(errors)}`,
            "warning",
            9000
        );
        console.warn("Avisos da otimização:", errors);
    } else {
        showToast(`Correções concluídas. Movidos para a Lixeira: ${formatBytes(totalFreed)}`, "success", 5000);
    }
}

// ==================== JUNK CLEANER PANEL ====================
async function scanJunk() {
    showLoader("Procurando arquivos de lixo...");
    const tbody = document.querySelector('#junk-table tbody');
    tbody.innerHTML = '';
    
    try {
        scannedJunk = await window.pywebview.api.scan_junk();
        await reportScanIssues('junk');
        let html = '';
        for (let key in scannedJunk) {
            const data = scannedJunk[key];

            const checkboxState = (data.cleanable && data.size_bytes > 0) ? '' : 'disabled';
            const reviewBadge = data.cleanable ? '' : ' <span class="color-warning">(Revisão manual)</span>';

            // Items the safety gate refused used to disappear without a trace,
            // so the reported total quietly understated the disk.
            const skippedNote = data.skipped
                ? `<div class="color-muted" style="font-size:0.85em;margin-top:4px;">
                       ${data.skipped} item(ns) preservado(s) pela política de segurança
                       (${escapeHtml(data.skipped_human)}).
                   </div>`
                : '';
            const deferredNote = data.deferred_hint
                ? `<div class="color-warning" style="font-size:0.85em;margin-top:4px;">
                       ${escapeHtml(data.deferred_hint)}
                   </div>`
                : '';

            html += `
                <tr>
                    <td><input type="checkbox" class="junk-checkbox" value="${escapeHtml(key)}" aria-label="Selecionar ${escapeHtml(data.name)}" ${checkboxState}></td>
                    <td><strong>${escapeHtml(data.name)}</strong>${reviewBadge}</td>
                    <td class="${data.size_bytes > 0 ? 'color-warning' : ''}">${escapeHtml(data.size_human)}</td>
                    <td>${data.count}</td>
                    <td>${escapeHtml(data.description)}${skippedNote}${deferredNote}</td>
                </tr>
            `;
        }
        
        tbody.innerHTML = html;
        document.getElementById('junk-select-all').checked = false;
        updateJunkCleanButton();
        
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Erro ao escanear lixo: ${escapeHtml(err.message || err)}</td></tr>`;
    } finally {
        hideLoader();
    }
}

function updateJunkCleanButton() {
    const selected = document.querySelectorAll('.junk-checkbox:checked:not(:disabled)').length;
    const cleanBtn = document.getElementById('btn-clean-junk');
    cleanBtn.disabled = selected === 0;
    cleanBtn.classList.toggle('disabled', selected === 0);
}

async function cleanSelectedJunk() {
    // Inventory-only rows (including Time Machine snapshots) are disabled and
    // must never enter the cleaning request, even if script-driven selection
    // left a stale checked state on one of them.
    const checkboxes = document.querySelectorAll('.junk-checkbox:checked:not(:disabled)');
    const keysToClean = Array.from(checkboxes).map(cb => cb.value);
    
    if (keysToClean.length === 0) return;
    
    if (!await showConfirm('Deseja limpar os itens selecionados? Os arquivos serão movidos para a Lixeira.')) return;
    
    await window.pywebview.api.reset_auth_state();
    showLoader("Limpando arquivos selecionados...");
    let totalFreed = 0;
    const failures = [];
    
    try {
        for (let key of keysToClean) {
            loaderMessage.textContent = `Limpando ${scannedJunk[key].name}...`;
            const result = await window.pywebview.api.clean_junk(key);
            totalFreed += result.bytes_moved || 0;
            if (result.failed) failures.push(...(result.errors || []));
        }
        showToast(
            failures.length
                ? `${formatBytes(totalFreed)} movidos; ${failures.length} bloqueado(s). ${summarizeFailures(failures)}`
                : `Limpeza concluída! ${formatBytes(totalFreed)} movidos para a Lixeira.`,
            failures.length ? "warning" : "success",
            failures.length ? 9000 : 4000
        );
        await scanJunk();
    } catch (err) {
        showToast(`Erro durante a limpeza: ${err.message || err}`, "error");
    } finally {
        hideLoader();
    }
}

// ==================== APP LEFTOVERS PANEL ====================
async function scanLeftovers() {
    showLoader("Escaneando Library por sobras de aplicativos desinstalados...");
    const tbody = document.querySelector('#leftovers-table tbody');
    tbody.innerHTML = '';
    
    try {
        scannedLeftovers = await window.pywebview.api.scan_leftovers();
        await reportScanIssues('leftovers');
        
        if (scannedLeftovers.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Nenhuma sobra com evidência suficiente foi encontrada nos caches e estados salvos.</td></tr>`;
            document.getElementById('btn-clean-leftovers').classList.add('disabled');
            document.getElementById('btn-clean-leftovers').setAttribute('disabled', 'true');
            return;
        }
        
        let html = '';
        scannedLeftovers.forEach((item, idx) => {
            html += `
                <tr>
                    <td><input type="checkbox" class="leftover-checkbox" value="${idx}" aria-label="Selecionar sobra ${escapeHtml(item.name)}"></td>
                    <td><strong>${escapeHtml(item.name)}</strong></td>
                    <td class="color-warning">${escapeHtml(item.size_human)}</td>
                    <td>${escapeHtml(item.type)}</td>
                    <td><span class="badge ${item.confidence === 'Alta' ? 'active' : 'disabled'}" title="${escapeHtml(item.evidence)}">${escapeHtml(item.confidence)}</span></td>
                    <td class="color-muted">${escapeHtml(item.path)}</td>
                </tr>
            `;
        });
        
        tbody.innerHTML = html;
        
        const cleanBtn = document.getElementById('btn-clean-leftovers');
        cleanBtn.classList.remove('disabled');
        cleanBtn.removeAttribute('disabled');
        
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Erro ao pesquisar sobras: ${escapeHtml(err.message || err)}</td></tr>`;
    } finally {
        hideLoader();
    }
}

async function cleanSelectedLeftovers() {
    const checkboxes = document.querySelectorAll('.leftover-checkbox:checked');
    const indices = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    if (indices.length === 0) return;
    
    const confirmDelete = await showConfirm(
        `Você escolheu mover ${indices.length} sobras para a Lixeira. Deseja prosseguir?`,
        { title: 'Remover sobras', confirmText: 'Mover para Lixeira', danger: true }
    );
    if (!confirmDelete) return;
    
    await window.pywebview.api.reset_auth_state();
    showLoader("Removendo sobras de apps...");
    let freedBytes = 0;
    const failures = [];
    
    try {
        for (let idx of indices) {
            const item = scannedLeftovers[idx];
            loaderMessage.textContent = `Movendo ${item.name} para a Lixeira...`;
            const [success, msg] = await window.pywebview.api.delete_leftover(item.path);
            if (success) {
                freedBytes += item.size_bytes;
            } else {
                failures.push(msg);
            }
        }
        showToast(
            failures.length
                ? `${formatBytes(freedBytes)} movidos; ${failures.length} bloqueado(s). ${summarizeFailures(failures)}`
                : `Otimização finalizada. ${formatBytes(freedBytes)} movidos para a Lixeira.`,
            failures.length ? 'warning' : 'success',
            failures.length ? 9000 : 4000
        );
        await scanLeftovers();
    } catch (err) {
        showToast(`Erro na remoção: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== DEPENDENCIES PANEL ====================
function renderDependencyList(manager, packages, icon, emptyMessage) {
    const listEl = document.getElementById(`dep-${manager}-list`);
    if (!packages?.length) {
        listEl.innerHTML = `<li>${escapeHtml(emptyMessage)}</li>`;
        return;
    }
    listEl.innerHTML = packages.map(pkg => `
        <li class="dependency-item ${pkg.removable ? '' : 'protected'}">
            <label>
                <input type="checkbox" class="dependency-checkbox" data-manager="${escapeHtml(manager)}" data-package="${escapeHtml(pkg.name)}" ${pkg.removable ? '' : 'disabled'}>
                <span class="dependency-icon" aria-hidden="true">${icon}</span>
                <span class="dependency-copy">
                    <strong>${escapeHtml(pkg.name)}</strong>
                    <small>${escapeHtml(pkg.version)} · ${escapeHtml(pkg.removal_note || '')}</small>
                </span>
            </label>
        </li>
    `).join('');
}

function updateDependencyRemoveButton() {
    const button = document.getElementById('btn-remove-dependencies');
    const hasSelection = Boolean(document.querySelector('.dependency-checkbox:checked'));
    button.disabled = !hasSelection;
    button.classList.toggle('disabled', !hasSelection);
}

async function loadDependencies() {
    const requestId = ++dependenciesRequestId;
    const refreshButton = document.getElementById('btn-refresh-dependencies');
    refreshButton.disabled = true;
    document.getElementById('dependencies-updated-at').textContent = 'Atualizando inventário dos três gerenciadores…';
    document.getElementById('dep-brew-status').textContent = 'Escaneando Homebrew…';
    document.getElementById('dep-npm-status').textContent = 'Escaneando NPM…';
    document.getElementById('dep-pip-status').textContent = 'Escaneando Pip do usuário…';

    try {
        const results = await Promise.allSettled([
            window.pywebview.api.check_brew(),
            window.pywebview.api.check_npm(),
            window.pywebview.api.check_pip(),
        ]);
        if (requestId !== dependenciesRequestId) return;

        const valueOrError = (result, manager) => result.status === 'fulfilled'
            ? result.value
            : { installed: false, packages: [], error: `${manager}: ${result.reason}` };
        const brew = valueOrError(results[0], 'Homebrew');
        const npm = valueOrError(results[1], 'NPM');
        const pip = valueOrError(results[2], 'Pip');
        scannedDependencies = { brew, npm, pip };

        const autoremoveBtn = document.getElementById('btn-brew-autoremove');
        const cleanupBtn = document.getElementById('btn-brew-cleanup');
        if (brew.installed) {
            document.getElementById('dep-brew-status').textContent = `Instalado em ${brew.path}`;
            document.getElementById('dep-brew-leaves').textContent = brew.leaves.length;
            document.getElementById('dep-brew-orphans').textContent = brew.orphans.length;
            document.getElementById('dep-brew-cache').textContent = brew.cleanup_size;
            autoremoveBtn.disabled = brew.orphans.length === 0;
            autoremoveBtn.classList.toggle('disabled', autoremoveBtn.disabled);
            cleanupBtn.disabled = ['0 B', '0B'].includes(brew.cleanup_size);
            cleanupBtn.classList.toggle('disabled', cleanupBtn.disabled);
            renderDependencyList('brew', brew.packages, '🍺', 'Nenhuma fórmula instalada.');
        } else {
            document.getElementById('dep-brew-status').textContent = brew.error || 'Não instalado';
            document.getElementById('dep-brew-leaves').textContent = 'N/A';
            document.getElementById('dep-brew-orphans').textContent = 'N/A';
            document.getElementById('dep-brew-cache').textContent = 'N/A';
            autoremoveBtn.disabled = true;
            cleanupBtn.disabled = true;
            renderDependencyList('brew', [], '🍺', 'Homebrew não localizado.');
        }

        document.getElementById('dep-npm-status').textContent = npm.installed ? `Instalado em ${npm.path}` : (npm.error || 'Não instalado');
        document.getElementById('dep-npm-count').textContent = npm.installed ? npm.packages.length : 'N/A';
        renderDependencyList('npm', npm.packages, '📦', npm.installed ? 'Nenhum módulo global instalado.' : 'NPM não localizado.');

        document.getElementById('dep-pip-status').textContent = pip.installed ? (pip.scope || `Instalado em ${pip.path}`) : (pip.error || 'Não instalado');
        document.getElementById('dep-pip-count').textContent = pip.installed ? pip.packages.length : 'N/A';
        renderDependencyList('pip', pip.packages, '🐍', pip.installed ? 'Nenhum pacote do usuário encontrado.' : 'Pip não localizado.');

        document.getElementById('dependencies-updated-at').textContent = `Inventário atualizado às ${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}.`;
        updateDependencyRemoveButton();
    } finally {
        if (requestId === dependenciesRequestId) refreshButton.disabled = false;
    }
}

async function removeSelectedDependencies() {
    const selected = Array.from(document.querySelectorAll('.dependency-checkbox:checked')).map(input => ({
        manager: input.dataset.manager,
        package: input.dataset.package,
    }));
    if (!selected.length) return;

    const confirmed = await showConfirm(
        `Desinstalar ${selected.length} pacote(s) selecionado(s) pelos respectivos gerenciadores? Dependências exigidas por outras fórmulas e ferramentas-base estão bloqueadas. Esta operação não usa a Lixeira.`,
        { title: 'Desinstalar dependências', confirmText: 'Desinstalar', danger: true }
    );
    if (!confirmed) return;

    showLoader('Desinstalando dependências selecionadas…');
    const failures = [];
    let removed = 0;
    try {
        for (const item of selected) {
            loaderMessage.textContent = `Removendo ${item.package} via ${item.manager}…`;
            const result = await window.pywebview.api.remove_dependency(item.manager, item.package);
            if (result.success) removed += 1;
            else failures.push(result.message);
        }
        showToast(
            `${removed} pacote(s) removido(s)${failures.length ? `; ${failures.length} falha(s).` : '.'}`,
            failures.length ? 'warning' : 'success',
            6000
        );
    } catch (err) {
        showToast(`Erro ao remover dependências: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
        await loadDependencies();
    }
}

async function runBrewAction(action) {
    const actionLabel = action === 'autoremove'
        ? 'remover dependências consideradas órfãs pelo Homebrew'
        : 'limpar downloads e versões antigas mantidas pelo Homebrew';
    const confirmed = await showConfirm(
        `Deseja ${actionLabel}? Essa operação será executada pelo próprio Homebrew e não usa a Lixeira do macOS.`,
        { title: 'Confirmar operação do Homebrew', confirmText: 'Executar', danger: true }
    );
    if (!confirmed) return;

    showLoader(`Executando tarefas do Homebrew (${action})...`);
    
    try {
        const autoremove = action === 'autoremove';
        const cleanup = action === 'cleanup';
        
        const logs = await window.pywebview.api.clean_homebrew(autoremove, cleanup);
        await showAlert(logs.join("\n"), { title: 'Homebrew' });
        loadDependencies();
    } catch (err) {
        showToast(`Erro: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== STARTUP AGENTS PANEL ====================
async function scanStartup() {
    showLoader("Procurando LaunchAgents/LaunchDaemons...");
    const tbody = document.querySelector('#startup-table tbody');
    tbody.innerHTML = '';
    
    try {
        scannedStartup = await window.pywebview.api.scan_startup();
        await reportScanIssues('startup');
        
        if (scannedStartup.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Nenhum serviço de inicialização detectado.</td></tr>`;
            return;
        }
        
        let html = '';
        scannedStartup.forEach((item, idx) => {
            let statusBadge = '';
            let actionText = '';
            let btnClass = '';

            if (item.is_disabled) {
                statusBadge = '<span class="badge disabled">Desativado</span>';
                actionText = 'Ativar';
                btnClass = 'success';
            } else if (item.is_broken) {
                statusBadge = '<span class="badge broken">Quebrado</span>';
                actionText = item.kind === 'login_item' ? 'Remover' : 'Desativar';
                btnClass = 'danger';
            } else {
                statusBadge = '<span class="badge active">Ativo</span>';
                actionText = item.kind === 'login_item' ? 'Remover' : 'Desativar';
                btnClass = 'danger';
            }

            // A launchd job that is loaded right now keeps running until it is
            // booted out, so the distinction is worth showing.
            const loadedBadge = (item.kind !== 'login_item' && item.is_loaded)
                ? ' <span class="badge active" title="Carregado no launchd agora">em execução</span>'
                : '';

            html += `
                <tr>
                    <td>${statusBadge}${loadedBadge}</td>
                    <td>${escapeHtml(item.category_name)}</td>
                    <td><strong>${escapeHtml(item.label)}</strong></td>
                    <td class="color-muted">${escapeHtml(item.exec_path || 'Comando dinâmico')}</td>
                    <td>
                        <button onclick="toggleStartup(${idx})" class="btn ${btnClass} btn-sm">
                            ${actionText}
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tbody.innerHTML = html;
        
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Erro ao mapear startup: ${escapeHtml(err.message || err)}</td></tr>`;
    } finally {
        hideLoader();
    }
}

async function toggleStartup(idx) {
    const item = scannedStartup[idx];

    if (item.kind === 'login_item') {
        const confirmed = await showConfirm(
            `Remover “${item.label}” dos itens de início de sessão?\n\n` +
            'Ele deixa de abrir automaticamente ao ligar o Mac. O aplicativo não é ' +
            'desinstalado, e você pode readicioná-lo em Ajustes do Sistema > Geral > ' +
            'Itens de Início.',
            { title: 'Remover item de início', confirmText: 'remover', danger: true }
        );
        if (!confirmed) return;

        showLoader(`Removendo ${item.label} dos itens de início...`);
        try {
            const [success, msg] = await window.pywebview.api.remove_login_item(item.label);
            showToast(msg, success ? 'success' : 'error', success ? 6000 : 9000);
            await scanStartup();
        } catch (err) {
            showToast(`Erro ao remover item de início: ${err.message || err}`, 'error');
        } finally {
            hideLoader();
        }
        return;
    }

    const enable = item.is_disabled;
    const actionDesc = enable ? "ativar" : "desativar";

    const privilegeNote = item.sudo_required
        ? '\n\nO macOS solicitará autenticação administrativa para este item.'
        : '';
    const confirmed = await showConfirm(
        `Deseja ${actionDesc} “${item.label}”?${privilegeNote}`,
        { title: 'Alterar item de inicialização', confirmText: actionDesc, danger: !enable }
    );
    if (!confirmed) return;

    showLoader(`Tentando ${actionDesc} o serviço ${item.label}...`);

    try {
        const [success, msg] = await window.pywebview.api.toggle_startup(item.filepath, !enable);
        showToast(msg, success ? 'success' : 'error', success ? 7000 : 9000);
        await scanStartup();
    } catch (err) {
        showToast(`Erro ao alterar serviço: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== LARGE FILES PANEL ====================
async function scanLargeFiles() {
    const minSize = parseFloat(document.getElementById('large-file-size-filter').value);
    showLoader(`Buscando arquivos maiores que ${minSize} MB...`);
    
    const tbody = document.querySelector('#large-files-table tbody');
    tbody.innerHTML = '';
    startOperationTracking('large_files');
    
    try {
        scannedLargeFiles = await window.pywebview.api.scan_large_files(minSize);
        const operationState = await window.pywebview.api.get_operation_progress('large_files');

        if (operationState.cancelled) {
            scannedLargeFiles = [];
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Varredura cancelada com segurança. Nenhum arquivo foi alterado.</td></tr>';
            document.getElementById('btn-clean-large').classList.add('disabled');
            document.getElementById('btn-clean-large').setAttribute('disabled', 'true');
            showToast('Varredura de arquivos grandes cancelada.', 'warning');
            return;
        }
        
        if (scannedLargeFiles.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Nenhum arquivo maior que ${minSize} MB localizado nas pastas padrão.</td></tr>`;
            document.getElementById('btn-clean-large').classList.add('disabled');
            document.getElementById('btn-clean-large').setAttribute('disabled', 'true');
            return;
        }
        
        let html = '';
        scannedLargeFiles.forEach((item, idx) => {
            html += `
                <tr>
                    <td><input type="checkbox" class="large-checkbox" value="${idx}" aria-label="Selecionar arquivo ${escapeHtml(item.name)}"></td>
                    <td><strong>${escapeHtml(item.name)}</strong></td>
                    <td class="color-warning">${escapeHtml(item.size_human)}</td>
                    <td>${escapeHtml(item.modified)}</td>
                    <td>${item.days_inactive} dias</td>
                    <td class="color-muted">${escapeHtml(item.path)}</td>
                </tr>
            `;
        });
        
        tbody.innerHTML = html;
        
        const cleanBtn = document.getElementById('btn-clean-large');
        cleanBtn.classList.remove('disabled');
        cleanBtn.removeAttribute('disabled');
        
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Erro na pesquisa de arquivos: ${escapeHtml(err.message || err)}</td></tr>`;
    } finally {
        stopOperationTracking();
        await reportScanIssues('large_files');
        hideLoader();
    }
}

async function cleanSelectedLargeFiles() {
    const checkboxes = document.querySelectorAll('.large-checkbox:checked');
    const indices = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    if (indices.length === 0) return;
    
    const confirmDelete = await showConfirm(
        `Você selecionou ${indices.length} arquivos grandes para mover à Lixeira. Deseja prosseguir?`,
        { title: 'Remover arquivos grandes', confirmText: 'Mover para Lixeira', danger: true }
    );
    if (!confirmDelete) return;
    
    showLoader("Movendo arquivos grandes para a Lixeira...");
    let freedBytes = 0;
    const failures = [];
    
    try {
        for (let idx of indices) {
            const item = scannedLargeFiles[idx];
            loaderMessage.textContent = `Movendo ${item.name} para a Lixeira...`;
            const [success, msg] = await window.pywebview.api.delete_large_file(item.path);
            if (success) {
                freedBytes += item.size_bytes;
            } else {
                failures.push(msg);
            }
        }
        showToast(
            failures.length
                ? `${formatBytes(freedBytes)} movidos; ${failures.length} item(ns) bloqueado(s).`
                : `${formatBytes(freedBytes)} movidos para a Lixeira.`,
            failures.length ? 'warning' : 'success'
        );
        await scanLargeFiles();
    } catch (err) {
        showToast(`Erro ao mover arquivos: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== DUPLICATE FINDER PANEL ====================
async function scanDuplicates() {
    showLoader("Buscando duplicados (tamanho + hash parcial + SHA-256)...");
    const tbody = document.getElementById('duplicates-tbody');
    tbody.innerHTML = '';
    startOperationTracking('duplicates');
    
    try {
        scannedDuplicates = await window.pywebview.api.scan_duplicates();
        const operationState = await window.pywebview.api.get_operation_progress('duplicates');

        if (operationState.cancelled) {
            scannedDuplicates = [];
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Varredura cancelada com segurança. Nenhum arquivo foi alterado.</td></tr>';
            document.getElementById('btn-clean-duplicates').classList.add('disabled');
            document.getElementById('btn-clean-duplicates').setAttribute('disabled', 'true');
            showToast('Varredura de duplicados cancelada.', 'warning');
            return;
        }
        
        if (scannedDuplicates.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Nenhum arquivo duplicado encontrado no seu Mac!</td></tr>`;
            document.getElementById('btn-clean-duplicates').classList.add('disabled');
            document.getElementById('btn-clean-duplicates').setAttribute('disabled', 'true');
            return;
        }
        
        let html = '';
        scannedDuplicates.forEach((group, groupIdx) => {
            // Header for this group
            html += `
                <tr class="dup-header-row">
                    <td colspan="2">📁 Conjunto Duplicado (${escapeHtml(group.size_human)})</td>
                    <td colspan="3" class="color-muted">SHA-256: ${escapeHtml(group.hash.substring(0, 16))}…</td>
                </tr>
            `;
            
            // Files inside the group
            group.files.forEach((file, fileIdx) => {
                const keeperAttrs = fileIdx === 0
                    ? 'data-keeper="true" disabled title="Cópia preservada obrigatoriamente"'
                    : '';

                html += `
                    <tr>
                        <td><input type="checkbox" class="dup-checkbox" value="${groupIdx}:${fileIdx}" aria-label="Selecionar cópia ${escapeHtml(file.name)}" ${keeperAttrs}></td>
                        <td><strong>${escapeHtml(file.name)}</strong></td>
                        <td>${escapeHtml(group.size_human)}</td>
                        <td>${escapeHtml(file.modified)}</td>
                        <td class="color-muted">${escapeHtml(file.path)}</td>
                    </tr>
                `;
            });
        });
        
        tbody.innerHTML = html;
        
        const cleanBtn = document.getElementById('btn-clean-duplicates');
        cleanBtn.classList.remove('disabled');
        cleanBtn.removeAttribute('disabled');
        
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Erro ao buscar duplicados: ${escapeHtml(err.message || err)}</td></tr>`;
    } finally {
        stopOperationTracking();
        await reportScanIssues('duplicates');
        hideLoader();
    }
}

async function cleanSelectedDuplicates() {
    const checkboxes = document.querySelectorAll('.dup-checkbox:checked');
    const targets = Array.from(checkboxes).map(cb => {
        const [gIdx, fIdx] = cb.value.split(':').map(Number);
        return {
            hash: scannedDuplicates[gIdx].hash,
            path: scannedDuplicates[gIdx].files[fIdx].path,
        };
    });
    
    if (targets.length === 0) return;
    
    const confirmDelete = await showConfirm(
        `Você marcou ${targets.length} cópias duplicadas para a Lixeira. O primeiro arquivo de cada grupo será preservado.`,
        { title: 'Remover duplicados', confirmText: 'Mover para Lixeira', danger: true }
    );
    if (!confirmDelete) return;
    
    showLoader("Removendo arquivos duplicados...");
    try {
        const result = await window.pywebview.api.delete_duplicate_files(targets);
        if (result.errors && result.errors.length > 0) {
            console.warn('Itens bloqueados durante a remoção:', result.errors);
            showToast(
                `${result.deleted} cópia(s) movida(s). ${result.errors.length} item(ns) bloqueado(s) por segurança.`,
                'warning',
                6000
            );
        } else {
            // Nothing is freed until the Trash is emptied; every other panel
            // already says "movidos".
            showToast(
                `${formatBytes(result.bytes_freed)} movidos para a Lixeira.`,
                'success'
            );
        }
        await scanDuplicates();
    } catch (err) {
        showToast(`Erro ao mover duplicados: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}



// ==================== BROWSER CACHE PANEL ====================
function updateBrowserCleanButton() {
    const button = document.getElementById('btn-clean-browser-caches');
    const hasSelection = Boolean(document.querySelector('.browser-cache-checkbox:checked'));
    button.disabled = !hasSelection;
    button.classList.toggle('disabled', !hasSelection);
}

async function scanBrowserCaches() {
    showLoader('Analisando caches temporários do Safari e Firefox...');
    const tbody = document.querySelector('#browser-cache-table tbody');
    tbody.innerHTML = '';
    updateBrowserCleanButton();

    try {
        scannedBrowserCaches = await window.pywebview.api.scan_browser_caches();
        await reportScanIssues('browser_caches');
        let html = '';

        for (const [key, data] of Object.entries(scannedBrowserCaches)) {
            let state = 'Fechado';
            let stateClass = 'ok';
            let explanation = data.scope;

            if (!data.installed) {
                state = 'Não instalado';
                stateClass = 'unknown';
            } else if (!data.accessible) {
                state = 'Acesso bloqueado';
                stateClass = 'attention';
                explanation = 'O macOS bloqueou a leitura. Conceda Acesso Total ao Disco ao HollyOptimizer e analise novamente.';
            } else if (data.running) {
                state = 'Aberto';
                stateClass = 'attention';
                explanation = 'Feche completamente o navegador e faça uma nova análise antes de limpar.';
            }

            const selectable = data.installed && data.accessible && !data.running && data.size_bytes > 0;
            html += `
                <tr>
                    <td><input type="checkbox" class="browser-cache-checkbox" value="${escapeHtml(key)}" aria-label="Selecionar cache do ${escapeHtml(data.name)}" ${selectable ? '' : 'disabled'}></td>
                    <td><strong>${escapeHtml(data.name)}</strong></td>
                    <td><span class="browser-state ${stateClass}">${escapeHtml(state)}</span></td>
                    <td class="${data.size_bytes > 0 ? 'color-warning' : ''}">${escapeHtml(data.size_human)}</td>
                    <td>${Number(data.count) || 0}</td>
                    <td class="color-muted">${escapeHtml(explanation)}</td>
                </tr>
            `;
        }

        tbody.innerHTML = html || '<tr><td colspan="6" class="empty-state">Nenhum navegador compatível foi localizado.</td></tr>';
        updateBrowserCleanButton();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Erro ao analisar navegadores: ${escapeHtml(err.message || err)}</td></tr>`;
        showToast('Não foi possível concluir a análise dos navegadores.', 'error');
    } finally {
        hideLoader();
    }
}

async function cleanSelectedBrowserCaches() {
    const selected = Array.from(document.querySelectorAll('.browser-cache-checkbox:checked'))
        .map(checkbox => checkbox.value);
    if (selected.length === 0) return;

    const browserNames = selected.map(key => scannedBrowserCaches[key]?.name || key).join(' e ');
    const confirmed = await showConfirm(
        `Mover somente os caches temporários de ${browserNames} para a Lixeira? Histórico, cookies, senhas, sessões, favoritos, extensões e perfis serão preservados.`,
        { title: 'Limpar caches dos navegadores', confirmText: 'Mover para Lixeira' }
    );
    if (!confirmed) return;

    showLoader('Movendo caches temporários para a Lixeira...');
    let bytesMoved = 0;
    const errors = [];
    try {
        for (const key of selected) {
            loaderMessage.textContent = `Revalidando cache do ${scannedBrowserCaches[key]?.name || key}...`;
            const result = await window.pywebview.api.clean_browser_cache(key);
            bytesMoved += result.bytes_moved || 0;
            if (result.errors?.length) errors.push(...result.errors);
        }
        showToast(
            errors.length
                ? `${formatBytes(bytesMoved)} movidos; ${errors.length} item(ns) bloqueado(s) por segurança.`
                : `${formatBytes(bytesMoved)} de caches movidos para a Lixeira.`,
            errors.length ? 'warning' : 'success',
            6000
        );
    } catch (err) {
        showToast(`Erro durante a limpeza dos navegadores: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
        await scanBrowserCaches();
    }
}

// ==================== SECURITY AUDIT PANEL ====================
async function runSecurityAudit() {
    showLoader('Verificando as proteções do macOS...');
    const summary = document.getElementById('security-summary');
    const checksContainer = document.getElementById('security-checks');

    try {
        const report = await window.pywebview.api.run_security_audit();
        const statusMeta = {
            ok: { mark: '✓', title: 'Proteções essenciais ativas', css: 'ok' },
            attention: { mark: '!', title: 'Alguns ajustes requerem atenção', css: 'attention' },
            unknown: { mark: '?', title: 'Diagnóstico parcialmente concluído', css: 'unknown' },
        };
        const meta = statusMeta[report.status] || statusMeta.unknown;
        summary.className = `security-summary glass mt-20 ${meta.css}`;
        summary.innerHTML = `
            <div class="security-summary-mark">${meta.mark}</div>
            <div>
                <strong>${escapeHtml(meta.title)}</strong>
                <p>${report.summary.ok} ativas · ${report.summary.attention} requerem atenção · ${report.summary.unknown} não verificadas</p>
            </div>
            <span class="read-only-badge">Somente leitura</span>
        `;

        checksContainer.innerHTML = report.checks.map(check => {
            const icon = check.status === 'ok' ? '✓' : (check.status === 'attention' ? '!' : '?');
            const guidance = check.recommendation
                ? `<div class="security-guidance"><strong>Recomendação</strong><span>${escapeHtml(check.recommendation)}</span><small>${escapeHtml(check.settings_hint)}</small></div>`
                : '<div class="security-guidance protected"><span>Configuração recomendada detectada.</span></div>';
            const action = check.status === 'attention' && check.action_available
                ? `<button class="btn primary btn-sm security-settings-btn" data-check-id="${escapeHtml(check.id)}">${escapeHtml(check.action_label)}</button>`
                : '';
            return `
                <article class="security-check-card glass ${escapeHtml(check.status)}">
                    <div class="security-check-header">
                        <span class="security-check-icon">${icon}</span>
                        <div>
                            <h4>${escapeHtml(check.name)}</h4>
                            <span class="security-check-label">${escapeHtml(check.label)}</span>
                        </div>
                    </div>
                    <p class="security-check-detail">${escapeHtml(check.detail)}</p>
                    ${guidance}
                    ${action}
                </article>
            `;
        }).join('');
        checksContainer.querySelectorAll('.security-settings-btn').forEach(button => {
            button.addEventListener('click', () => openSecuritySetting(button.dataset.checkId));
        });
    } catch (err) {
        summary.className = 'security-summary glass mt-20 unknown';
        summary.innerHTML = '<div class="security-summary-mark">?</div><div><strong>Diagnóstico indisponível</strong><p>Não foi possível consultar as proteções do macOS.</p></div>';
        checksContainer.innerHTML = `<div class="security-placeholder glass">${escapeHtml(err.message || err)}</div>`;
        showToast('Não foi possível concluir o diagnóstico de segurança.', 'error');
    } finally {
        hideLoader();
    }
}

async function openSecuritySetting(checkId) {
    try {
        const [success, message] = await window.pywebview.api.open_security_setting(checkId);
        showToast(message, success ? 'info' : 'warning', 5000);
    } catch (err) {
        showToast(`Não foi possível abrir os Ajustes do Sistema: ${err.message || err}`, 'error');
    }
}

// ==================== PERMISSIONS PANEL ====================
async function runPermissionsAudit(showSpinner) {
    const summary = document.getElementById('permissions-summary');
    const checksContainer = document.getElementById('permissions-checks');
    if (showSpinner) showLoader('Verificando permissões do macOS...');
    try {
        const report = await window.pywebview.api.run_permissions_audit();
        renderPermissionsReport(report);
        updatePermissionsBanner(report);
        return report;
    } catch (err) {
        if (checksContainer) {
            checksContainer.innerHTML = `<div class="security-placeholder glass">${escapeHtml(err.message || err)}</div>`;
        }
        return null;
    } finally {
        if (showSpinner) hideLoader();
    }
}

function renderPermissionsReport(report) {
    const summary = document.getElementById('permissions-summary');
    const checksContainer = document.getElementById('permissions-checks');
    if (!summary || !checksContainer) return;

    const statusMeta = {
        ok: { mark: '✓', title: 'Todas as permissões concedidas', css: 'ok' },
        attention: { mark: '!', title: 'Algumas permissões precisam de atenção', css: 'attention' },
        unknown: { mark: '?', title: 'Verificação parcialmente concluída', css: 'unknown' },
    };
    const meta = statusMeta[report.status] || statusMeta.unknown;
    summary.className = `security-summary glass mt-20 ${meta.css}`;
    summary.innerHTML = `
        <div class="security-summary-mark">${meta.mark}</div>
        <div>
            <strong>${escapeHtml(meta.title)}</strong>
            <p>${report.summary.ok} concedida(s) · ${report.summary.attention} pendente(s) · ${report.summary.unknown} não verificada(s)</p>
        </div>
        <span class="read-only-badge">Somente leitura</span>
    `;

    checksContainer.innerHTML = report.checks.map(check => {
        const icon = check.status === 'ok' ? '✓' : (check.status === 'attention' ? '!' : '?');
        const action = check.status !== 'ok' && check.settings_url
            ? `<button class="btn primary btn-sm permission-settings-btn" data-check-id="${escapeHtml(check.id)}">Abrir nos Ajustes do Sistema</button>`
            : '';
        return `
            <article class="security-check-card glass ${escapeHtml(check.status)}">
                <div class="security-check-header">
                    <span class="security-check-icon">${icon}</span>
                    <div>
                        <h4>${escapeHtml(check.name)}</h4>
                        <span class="security-check-label">${escapeHtml(check.label)}</span>
                    </div>
                </div>
                <p class="security-check-detail">${escapeHtml(check.reason)}</p>
                ${action}
            </article>
        `;
    }).join('');
    checksContainer.querySelectorAll('.permission-settings-btn').forEach(button => {
        button.addEventListener('click', () => openPermissionSetting(button.dataset.checkId));
    });
}

function updatePermissionsBanner(report) {
    const banner = document.getElementById('permissions-banner');
    if (!banner || !report) return;
    const pending = report.checks.filter(check => check.status === 'attention');
    if (pending.length === 0) {
        banner.hidden = true;
        return;
    }
    document.getElementById('permissions-banner-title').textContent = pending.length === 1
        ? '1 permissão precisa de atenção'
        : `${pending.length} permissões precisam de atenção`;
    document.getElementById('permissions-banner-detail').textContent =
        `${pending.map(check => check.name).join(' · ')} — sem elas, algumas funções ficam parciais.`;
    banner.hidden = false;
}

async function openPermissionSetting(checkId) {
    try {
        const [success, message] = await window.pywebview.api.open_permission_setting(checkId);
        showToast(message, success ? 'info' : 'warning', 5000);
    } catch (err) {
        showToast(`Não foi possível abrir os Ajustes do Sistema: ${err.message || err}`, 'error');
    }
}

// ==================== ON-DEVICE AI SUMMARY (optional) ====================
async function maybeShowAiSummary(facts) {
    const card = document.getElementById('ai-summary-card');
    const textEl = document.getElementById('ai-summary-text');
    if (!card || !textEl) return;
    try {
        const available = await window.pywebview.api.ai_summary_available();
        if (!available) {
            card.hidden = true;
            return;
        }
        const result = await window.pywebview.api.get_ai_summary(facts);
        if (result && result.available && result.summary) {
            textEl.textContent = result.summary;
            card.hidden = false;
        } else {
            card.hidden = true;
        }
    } catch (_) {
        card.hidden = true;
    }
}

// ==================== APPLE SILICON PANEL (read-only) ====================
const SILICON_CATEGORY_META = {
    intel:     { badge: 'Intel',      css: 'attention', order: 'Somente Intel — traduzido pelo Rosetta 2' },
    unknown:   { badge: 'Indefinida', css: 'unknown',   order: 'Arquitetura não identificada' },
    script:    { badge: 'Script',     css: 'unknown',   order: 'Lançador em script' },
    universal: { badge: 'Universal',  css: 'ok',        order: 'Universal — usa a fatia arm64' },
    native:    { badge: 'Nativo',     css: 'ok',        order: 'Nativo Apple Silicon' },
    webapp:    { badge: 'Web app',    css: 'unknown',   order: 'Atalho de web app' },
};

async function loadHardwareProfile() {
    const container = document.getElementById('silicon-profile');
    if (!container) return;
    try {
        const profile = await window.pywebview.api.get_hardware_profile();
        const rosettaCss = profile.rosetta_installed ? 'unknown' : 'ok';
        container.innerHTML = `
            <div class="silicon-profile-grid">
                <div><span class="stat-label">Chip</span><strong>${escapeHtml(profile.chip)}</strong></div>
                <div><span class="stat-label">Núcleos</span><strong>${escapeHtml(profile.core_summary)}</strong></div>
                <div><span class="stat-label">Memória unificada</span><strong>${escapeHtml(profile.memory_human)}</strong></div>
                <div><span class="stat-label">Modelo</span><strong>${escapeHtml(profile.model_identifier)}</strong></div>
                <div><span class="stat-label">macOS</span><strong>${escapeHtml(profile.macos_version)} (${escapeHtml(profile.architecture)})</strong></div>
                <div><span class="stat-label">Rosetta 2</span><strong class="silicon-badge ${rosettaCss}">${escapeHtml(profile.rosetta_label)}</strong></div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<p class="empty-state">Não foi possível ler o perfil do hardware: ${escapeHtml(err.message || err)}</p>`;
    }
}

async function runSiliconAudit() {
    showLoader('Lendo a arquitetura dos aplicativos instalados...');
    const tbody = document.getElementById('silicon-tbody');
    const totalsBox = document.getElementById('silicon-totals');

    try {
        const report = await window.pywebview.api.scan_app_architectures();
        await loadHardwareProfile();

        const totals = report.totals || {};
        const cards = [
            ['intel', 'Somente Intel', totals.intel || 0],
            ['universal', 'Universal', totals.universal || 0],
            ['native', 'Nativo arm64', totals.native || 0],
            ['webapp', 'Web apps', totals.webapp || 0],
            ['script', 'Scripts', totals.script || 0],
            ['unknown', 'Indefinidos', totals.unknown || 0],
        ];
        totalsBox.innerHTML = `
            <p class="silicon-summary-line">${escapeHtml(report.summary)}</p>
            <div class="silicon-totals-grid">
                ${cards.map(([key, label, value]) => `
                    <div class="silicon-total-card ${escapeHtml(SILICON_CATEGORY_META[key].css)}">
                        <strong>${value}</strong>
                        <span>${escapeHtml(label)}</span>
                    </div>
                `).join('')}
            </div>
        `;

        if (!report.apps.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Nenhum aplicativo encontrado em /Applications ou ~/Applications.</td></tr>';
            return;
        }

        tbody.innerHTML = report.apps.map(app => {
            const meta = SILICON_CATEGORY_META[app.category] || SILICON_CATEGORY_META.unknown;
            const hint = app.category === 'intel'
                ? '<small class="color-muted">Procure a versão Apple Silicon no site do fabricante.</small>'
                : '';
            return `
                <tr class="silicon-row" data-name="${escapeHtml(app.name.toLowerCase())}" data-category="${escapeHtml(app.category)}">
                    <td>
                        <strong class="color-primary">${escapeHtml(app.name)}</strong>
                        <span class="color-muted" style="font-size:10px; display:block; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(app.path)}">${escapeHtml(app.path)}</span>
                    </td>
                    <td><span class="silicon-badge ${escapeHtml(meta.css)}">${escapeHtml(meta.badge)}</span>
                        <small class="color-muted" style="display:block;">${escapeHtml(app.architectures_human)}</small></td>
                    <td>${escapeHtml(app.category_label)}${hint}</td>
                </tr>
            `;
        }).join('');
        filterSiliconApps();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="3" class="empty-state">Erro na auditoria: ${escapeHtml(err.message || err)}</td></tr>`;
        showToast('Não foi possível auditar a arquitetura dos aplicativos.', 'error');
    } finally {
        hideLoader();
    }
}

function filterSiliconApps() {
    const term = (document.getElementById('silicon-search').value || '').trim().toLowerCase();
    document.querySelectorAll('#silicon-tbody .silicon-row').forEach(row => {
        row.style.display = !term || row.dataset.name.includes(term) ? '' : 'none';
    });
}

// ==================== NETWORK & DNS PANEL ====================
async function runNetworkFlush() {
    showLoader("Limpando cache DNS...");
    try {
        const [success, msg] = await window.pywebview.api.flush_dns();
        showToast(msg, success ? 'success' : 'warning');
    } catch (err) {
        showToast(`Erro ao limpar DNS: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

async function loadNetworkPing() {
    const valEl = document.getElementById('net-latency-val');
    valEl.textContent = "Medindo...";
    
    try {
        const netStats = await window.pywebview.api.run_network_diagnostic();
        valEl.textContent = netStats.latency_human;
        document.getElementById('diagnostic-stat-latency').textContent = `Ping: ${netStats.latency_human}`;
    } catch (err) {
        valEl.textContent = "Erro";
    }
}

async function loadNetworkPingHeader() {
    try {
        const netStats = await window.pywebview.api.run_network_diagnostic();
        document.getElementById('diagnostic-stat-latency').textContent = `Ping: ${netStats.latency_human}`;
    } catch (err) {
        document.getElementById('diagnostic-stat-latency').textContent = `Ping: N/A`;
    }
}

// ==================== APP UNINSTALLER PANEL ====================
function filterInstalledApps() {
    const query = document.getElementById('uninstaller-search').value.toLowerCase().trim();
    document.querySelectorAll('#uninstaller-app-list .app-item').forEach(item => {
        const name = item.dataset.name || '';
        item.style.display = !query || name.includes(query) ? '' : 'none';
    });
}

async function loadInstalledApps() {
    const requestId = ++installedAppsRequestId;
    appSelectionRequestId++;
    selectedAppIdx = -1;
    relatedFiles = [];
    const listEl = document.getElementById('uninstaller-app-list');
    listEl.innerHTML = '<li class="empty-state">Buscando aplicativos instalados...</li>';

    document.getElementById('uninstaller-active-details').style.display = 'none';
    document.getElementById('uninstaller-empty-details').style.display = 'block';
    document.getElementById('uninstaller-search').value = '';

    try {
        const apps = await window.pywebview.api.list_installed_apps();
        if (requestId !== installedAppsRequestId) return;
        installedApps = apps;
        await reportScanIssues('uninstaller');

        if (installedApps.length === 0) {
            listEl.innerHTML = '<li class="empty-state">Nenhum aplicativo de terceiros localizado.</li>';
            return;
        }

        let html = '';
        installedApps.forEach((app, idx) => {
            html += `
                <li class="app-item" id="app-item-${idx}" data-index="${idx}" data-name="${escapeHtml(app.name.toLowerCase())}" role="button" tabindex="0">
                    <span class="app-item-icon" id="app-icon-${idx}">📦</span>
                    <div class="app-item-info">
                        <span class="app-item-name">${escapeHtml(app.name)}</span>
                        <span class="app-item-meta">v${escapeHtml(app.version)} - ${escapeHtml(app.size_human)}</span>
                    </div>
                </li>
            `;
        });

        listEl.innerHTML = html;

        listEl.querySelectorAll('.app-item[data-index]').forEach(item => {
            const activate = () => selectApp(parseInt(item.dataset.index));
            item.addEventListener('click', activate);
            item.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    activate();
                }
            });
        });

        if (appIconObserver) appIconObserver.disconnect();
        const loadIcon = idx => {
            const app = installedApps[idx];
            if (!app) return;
            const cacheKey = `${app.path}\u0000${app.bundle_id}`;
            if (appIconCache.has(cacheKey)) {
                const el = document.getElementById(`app-icon-${idx}`);
                if (el) el.outerHTML = `<img src="${appIconCache.get(cacheKey)}" class="app-item-icon-img" alt="">`;
                return;
            }
            window.pywebview.api.get_app_icon_base64(app.path, app.bundle_id).then(b64 => {
                if (b64 && requestId === installedAppsRequestId) {
                    appIconCache.set(cacheKey, b64);
                    const el = document.getElementById(`app-icon-${idx}`);
                    if (el) el.outerHTML = `<img src="${b64}" class="app-item-icon-img" alt="">`;
                }
            }).catch(() => {});
        };

        if ('IntersectionObserver' in window) {
            appIconObserver = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    if (!entry.isIntersecting) return;
                    const idx = parseInt(entry.target.dataset.index);
                    appIconObserver.unobserve(entry.target);
                    loadIcon(idx);
                });
            }, { root: document.querySelector('.app-list-scroll'), rootMargin: '100px' });
            listEl.querySelectorAll('.app-item[data-index]').forEach(item => appIconObserver.observe(item));
        } else {
            installedApps.slice(0, 20).forEach((_, idx) => loadIcon(idx));
        }
    } catch (err) {
        listEl.innerHTML = `<li class="empty-state">Erro: ${escapeHtml(err)}</li>`;
    }
}

async function selectApp(idx) {
    const selectionRequestId = ++appSelectionRequestId;
    selectedAppIdx = idx;
    const app = installedApps[idx];
    
    // Highlight selected item in list
    document.querySelectorAll('.app-item').forEach(item => item.classList.remove('selected'));
    const selectedItem = document.getElementById(`app-item-${idx}`);
    if (selectedItem) selectedItem.classList.add('selected');
    
    // Switch details view
    document.getElementById('uninstaller-empty-details').style.display = 'none';
    const activeDetails = document.getElementById('uninstaller-active-details');
    activeDetails.style.display = 'flex';
    
    // Populate header info
    document.getElementById('unit-app-name').textContent = app.name;
    document.getElementById('unit-app-version').textContent = `v${app.version}`;
    document.getElementById('unit-app-size').textContent = app.size_human;

    const iconContainer = document.getElementById('unit-app-icon-container');
    if (iconContainer) {
        iconContainer.innerHTML = `<span class="details-app-icon-placeholder">📦</span>`;
        const cacheKey = `${app.path}\u0000${app.bundle_id}`;
        const iconPromise = appIconCache.has(cacheKey)
            ? Promise.resolve(appIconCache.get(cacheKey))
            : window.pywebview.api.get_app_icon_base64(app.path, app.bundle_id);
        iconPromise.then(b64 => {
            if (b64 && iconContainer && selectionRequestId === appSelectionRequestId) {
                appIconCache.set(cacheKey, b64);
                iconContainer.innerHTML = `<img src="${b64}" class="details-app-icon-img" alt="">`;
            }
        }).catch(() => {});
    }
    
    // Populate related files list
    const tbody = document.querySelector('#uninstaller-files-table tbody');
    tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Buscando caches e arquivos de suporte...</td></tr>';
    
    try {
        const files = await window.pywebview.api.get_app_related_files(app.path, app.bundle_id, app.name);
        if (selectionRequestId !== appSelectionRequestId || selectedAppIdx !== idx) return;
        relatedFiles = files;
        
        if (relatedFiles.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Nenhum arquivo de suporte extra localizado no Library.</td></tr>';
            return;
        }
        
        let html = '';
        relatedFiles.forEach((file, fIdx) => {
            html += `
                <tr>
                    <td><input type="checkbox" class="unit-file-checkbox" value="${fIdx}" aria-label="Selecionar ${escapeHtml(file.name)}"></td>
                    <td><strong>${escapeHtml(file.name)}</strong></td>
                    <td class="color-warning">${escapeHtml(file.size_human)}</td>
                    <td>${escapeHtml(file.type)}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
        
        // Reset main checkbox
        document.getElementById('unit-select-all').checked = false;
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Erro: ${escapeHtml(err.message || err)}</td></tr>`;
    }
}

async function runUninstall() {
    if (selectedAppIdx < 0) return;
    
    const app = installedApps[selectedAppIdx];
    
    // Gather selected support files
    const checkboxes = document.querySelectorAll('.unit-file-checkbox:checked');
    const fileIndices = Array.from(checkboxes).map(cb => parseInt(cb.value));
    
    const selectedPaths = fileIndices.map(fIdx => relatedFiles[fIdx].path);
    
    const privilegeNote = app.path.startsWith('/Applications/')
        ? '\n\nO macOS poderá solicitar a senha de administrador para remover o aplicativo de /Applications.'
        : '';
    const confirmUninstall = await showConfirm(
        `Remover "${app.name}" e ${fileIndices.length} arquivo(s) de suporte selecionados? Os itens serão movidos para a Lixeira.${privilegeNote}`,
        { title: 'Desinstalar aplicativo', confirmText: 'Desinstalar', danger: true }
    );
    if (!confirmUninstall) return;
    
    await window.pywebview.api.reset_auth_state();
    showLoader(`Desinstalando ${app.name}...`);
    
    try {
        const [success, logs] = await window.pywebview.api.uninstall_app(app.path, selectedPaths);
        await showAlert(logs.join("\n"), { title: success ? 'Desinstalação concluída' : 'Desinstalação com avisos' });
        loadInstalledApps();
    } catch (err) {
        showToast(`Erro na desinstalação: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== GENERAL FORMATTERS ====================
function formatBytes(bytes) {
    if (bytes === 0 || bytes < 0 || isNaN(bytes)) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==================== MEMORY RAM & PROCESSES PANEL ====================
let memoryMonitorInterval = null;
let lastProcessRefreshAt = 0;

function startMemoryMonitor() {
    if (document.hidden) return;
    // Immediate initial load
    updateMemoryPanel(true);
    
    // Set up click handlers once if not done
    const btnOptimize = document.getElementById('btn-optimize-ram');
    if (btnOptimize && !btnOptimize.dataset.listener) {
        btnOptimize.addEventListener('click', optimizeRam);
        btnOptimize.dataset.listener = 'true';
    }
    
    const btnRefresh = document.getElementById('btn-refresh-ram-processes');
    if (btnRefresh && !btnRefresh.dataset.listener) {
        btnRefresh.addEventListener('click', loadRamProcesses);
        btnRefresh.dataset.listener = 'true';
    }
    
    // Poll every 5 seconds
    if (!memoryMonitorInterval) {
        memoryMonitorInterval = setInterval(updateMemoryPanel, 5000);
    }
}

function stopMemoryMonitor() {
    if (memoryMonitorInterval) {
        clearInterval(memoryMonitorInterval);
        memoryMonitorInterval = null;
    }
}

let isMemoryUpdating = false;
async function updateMemoryPanel(forceProcesses = false) {
    if (isMemoryUpdating) return;
    isMemoryUpdating = true;
    try {
        const now = Date.now();
        const tasks = [loadMemoryStats()];
        if (forceProcesses || now - lastProcessRefreshAt >= 12000) {
            tasks.push(loadRamProcesses());
            lastProcessRefreshAt = now;
        }
        await Promise.all(tasks);
    } finally {
        isMemoryUpdating = false;
    }
}

document.addEventListener('visibilitychange', () => {
    const memoryPanelActive = document.getElementById('memory-panel').classList.contains('active');
    if (document.hidden) {
        stopMemoryMonitor();
    } else if (memoryPanelActive) {
        startMemoryMonitor();
    }
});

window.addEventListener('beforeunload', stopMemoryMonitor);

async function loadMemoryStats() {
    try {
        const stats = await window.pywebview.api.get_memory_stats();
        
        // Update text labels
        document.getElementById('ram-used-val').textContent = stats.used_human;
        document.getElementById('ram-free-val').textContent = stats.free_human;
        document.getElementById('ram-cache-val').textContent = stats.inactive_human;
        document.getElementById('ram-total-val').textContent = stats.total_human;
        document.getElementById('ram-use-pct').textContent = `${stats.percent}%`;
        
        // Update radial progress circle
        // The circumference of r=40 is 2 * pi * 40 = 251.2
        const circle = document.getElementById('ram-progress-circle');
        if (circle) {
            const circumference = 2 * Math.PI * 40;
            const safePercent = Math.max(0, Math.min(100, Number(stats.percent) || 0));
            const offset = circumference - (safePercent / 100) * circumference;
            circle.style.strokeDashoffset = offset;
            
            // Pressure is reported by macOS; occupancy remains a separate estimate.
            if (stats.pressure_level === 'critical') {
                circle.style.stroke = '#e74c3c'; // red
            } else if (stats.pressure_level === 'warning') {
                circle.style.stroke = '#e67e22'; // orange
            } else {
                circle.style.stroke = 'var(--accent-gold-light)'; // golden
            }
        }
        const pressureBadge = document.getElementById('ram-pressure-status');
        if (pressureBadge) {
            const level = stats.pressure_level || 'unknown';
            pressureBadge.className = `ram-pressure-badge pressure-${level}`;
            pressureBadge.textContent = `Pressão: ${stats.pressure_label || 'Indisponível'}`;
        }

        const swapBadge = document.getElementById('ram-swap-status');
        if (swapBadge) {
            const swapLevel = stats.swap_level || 'unknown';
            swapBadge.className = `ram-pressure-badge pressure-${swapLevel} mt-15`;
            swapBadge.textContent = swapLevel === 'unknown'
                ? 'Swap: indisponível'
                : `Swap: ${stats.swap_used_human} em uso — ${stats.swap_label}`;
        }
    } catch (err) {
        console.error("Error loading RAM stats:", err);
    }
}

async function loadDashboardRam() {
    try {
        const stats = await window.pywebview.api.get_memory_stats();
        document.getElementById('dash-ram-use').textContent = `${stats.used_human} (${stats.percent}%)`;
    } catch (err) {
        document.getElementById('dash-ram-use').textContent = 'Erro';
    }
}

async function loadRamProcesses() {
    const tbody = document.getElementById('ram-processes-tbody');
    try {
        const processes = await window.pywebview.api.get_top_ram_processes();
        if (processes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Nenhum processo pesado listado.</td></tr>';
            return;
        }
        
        let html = '';
        processes.forEach(proc => {
            const safeName = escapeHtml(proc.name);
            const safePath = escapeHtml(proc.path);
            html += `
                <tr>
                    <td><code>${proc.pid}</code></td>
                    <td>
                        <strong class="color-primary">${safeName}</strong>
                        <span class="color-muted" style="font-size:10px; display:block; max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${safePath}">
                            ${safePath}
                        </span>
                    </td>
                    <td class="color-warning">${proc.rss_human} <small class="color-muted">(${proc.pmem}%)</small></td>
                    <td>
                        <button class="btn-kill" data-pid="${proc.pid}" data-name="${safeName}">Encerrar</button>
                    </td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
        
        // Event delegation for kill buttons
        tbody.querySelectorAll('.btn-kill[data-pid]').forEach(btn => {
            btn.addEventListener('click', () => {
                killRamProcess(parseInt(btn.dataset.pid), btn.dataset.name);
            });
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Erro ao buscar processos: ${escapeHtml(err.message || err)}</td></tr>`;
    }
}

async function killRamProcess(pid, name) {
    const confirmKill = await showConfirm(
        `Encerrar o processo "${name}" (PID: ${pid})? Dados não salvos podem ser perdidos.`,
        { title: 'Encerrar processo', confirmText: 'Encerrar', danger: true }
    );
    if (!confirmKill) return;
    
    showLoader(`Encerrando processo ${name}...`);
    try {
        const [success, msg] = await window.pywebview.api.kill_ram_process(pid);
        showToast(msg, success ? 'success' : 'error');
        // Refresh list
        loadRamProcesses();
        loadMemoryStats();
        loadDashboardRam();
    } catch (err) {
        showToast(`Erro ao encerrar processo: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

async function optimizeRam() {
    showLoader("Reavaliando pressão de memória e processos...");
    try {
        await updateMemoryPanel(true);
        await loadDashboardRam();
        showToast(
            'Memória reavaliada. Caches úteis foram preservados; encerre apenas aplicativos identificados na lista se precisar liberar RAM.',
            'info',
            6500
        );
    } catch (err) {
        showToast(`Erro ao reavaliar memória: ${err.message || err}`, 'error');
    } finally {
        hideLoader();
    }
}

// ==================== UTILITY: TOAST ====================
function showToast(message, type = 'info', duration = 4000) {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
    toast.textContent = message;
    document.body.appendChild(toast);
    // Trigger animation
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, duration);
}


async function handleEmptyTrash() {
    const confirmed = await showConfirm(
        "Tem certeza que deseja esvaziar a Lixeira? Esta ação é permanente e não pode ser desfeita.",
        { title: 'Esvaziar Lixeira', confirmText: 'Esvaziar', danger: true }
    );
    if (!confirmed) return;

    showLoader("Esvaziando Lixeira via Finder...");
    let finderUnavailable = false;
    try {
        const result = await window.pywebview.api.empty_trash();
        finderUnavailable = Boolean(result[2]);
        showToast(result[1], result[0] ? 'success' : 'error', result[0] ? 5000 : 10000);
        await refreshDiskUsage();
    } catch (e) {
        showToast(`Não foi possível esvaziar a Lixeira: ${e.message || e}`, "error", 10000);
    } finally {
        hideLoader();
    }

    if (!finderUnavailable) return;

    // Finder automation was denied. The only remaining option is the local
    // permanent deletion, which requires its own dedicated confirmation.
    const localConfirmed = await showConfirm(
        "Exclusão permanente local: apagar definitivamente o conteúdo de ~/.Trash " +
        "SEM usar a semântica do Finder. Lixeiras de outros volumes (discos externos) " +
        "não serão esvaziadas e os itens NÃO poderão ser recuperados.\n\n" +
        "Alternativa recomendada: autorize o HollyOptimizer em Ajustes do Sistema > " +
        "Privacidade e Segurança > Automação > Finder e tente novamente.",
        { title: 'Exclusão permanente local', confirmText: 'Apagar definitivamente', danger: true }
    );
    if (!localConfirmed) return;

    showLoader("Executando exclusão permanente local (~/.Trash)...");
    try {
        const result = await window.pywebview.api.empty_trash_local_permanent();
        showToast(result[1], result[0] ? 'success' : 'error', result[0] ? 6000 : 10000);
        await refreshDiskUsage();
    } catch (e) {
        showToast(`Falha na exclusão permanente local: ${e.message || e}`, "error", 10000);
    } finally {
        hideLoader();
    }
}


function summarizeFailures(failures, limit = 2) {
    const unique = [...new Set((failures || []).filter(Boolean).map(String))];
    if (!unique.length) return '';
    const visible = unique.slice(0, limit).join(' ');
    const remaining = unique.length - limit;
    return remaining > 0 ? `${visible} (+${remaining} motivo(s))` : visible;
}


async function refreshDiskUsage() {
    try {
        const usage = await pywebview.api.get_disk_usage();
        if(usage && usage.total_bytes) {
            document.getElementById('dash-disk-text').textContent = usage.free_human + " livres de " + usage.total_human;
            document.getElementById('dash-disk-bar').style.width = usage.percentage + "%";
        }
    } catch(e) {}
}

// ==================== GENERIC TABLE FILTERING & SORTING ====================
function setupTableInteractions() {
    document.querySelectorAll('.search-input').forEach(input => {
        input.addEventListener('input', (e) => {
            const term = e.target.value.toLowerCase();
            const section = e.target.closest('.panel') || e.target.closest('.uninstaller-grid');
            if(!section) return;
            // Handle uninstaller list specifically
            if(e.target.id === 'uninstaller-search') {
                const lis = section.querySelectorAll('#uninstaller-app-list li:not(.empty-state)');
                lis.forEach(li => {
                    li.style.display = li.textContent.toLowerCase().includes(term) ? '' : 'none';
                });
                return;
            }
            const tbody = section.querySelector('tbody');
            if(!tbody) return;
            const rows = tbody.querySelectorAll('tr:not(.empty-state)');
            rows.forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(term) ? '' : 'none';
            });
        });
    });

    document.querySelectorAll('th[data-sort]').forEach(th => {
        th.addEventListener('click', () => {
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr:not(.empty-state)'));
            if(rows.length === 0) return;

            const index = Array.from(th.parentNode.children).indexOf(th);
            const type = th.dataset.sort;

            const isAsc = th.dataset.dir === 'asc';
            th.dataset.dir = isAsc ? 'desc' : 'asc';

            th.parentNode.querySelectorAll('.sort-icon').forEach(icon => icon.textContent = '▼');
            const icon = th.querySelector('.sort-icon');
            if(icon) icon.textContent = isAsc ? '▲' : '▼';

            rows.sort((a, b) => {
                const aCol = a.children[index];
                const bCol = b.children[index];
                if(!aCol || !bCol) return 0;

                let aVal = aCol.textContent.trim();
                let bVal = bCol.textContent.trim();

                if(type === 'size') {
                    const parseSize = (str) => {
                        const match = str.match(/([\d\.]+)\s*([KMGT]?B)/i);
                        if(!match) return 0;
                        const val = parseFloat(match[1]);
                        const unit = match[2].toUpperCase();
                        const m = {'B':1, 'KB':1024, 'MB':1024**2, 'GB':1024**3, 'TB':1024**4};
                        return val * (m[unit] || 1);
                    };
                    aVal = parseSize(aVal);
                    bVal = parseSize(bVal);
                    return isAsc ? aVal - bVal : bVal - aVal;
                } else if (type === 'number') {
                    aVal = parseFloat(aVal) || 0;
                    bVal = parseFloat(bVal) || 0;
                    return isAsc ? aVal - bVal : bVal - aVal;
                } else {
                    return isAsc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
                }
            });

            rows.forEach(row => tbody.appendChild(row));
        });
    });
}
document.addEventListener('DOMContentLoaded', setupTableInteractions);
