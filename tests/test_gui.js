const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '..', 'gui', 'app.js'), 'utf8');

function sourceBetween(start, end) {
    const from = source.indexOf(start);
    const to = source.indexOf(end, from);
    assert.ok(from >= 0 && to > from, `GUI functions must exist: ${start}`);
    return source.slice(from, to);
}

const functionsUnderTest = [
    sourceBetween('function startOperationTracking(', 'async function reportScanIssues('),
    sourceBetween('async function scanLargeFiles(', 'async function cleanSelectedLargeFiles('),
    sourceBetween('async function scanDuplicates(', 'async function cleanSelectedDuplicates('),
].join('\n');

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
    return { promise, resolve, reject };
}

function makeHarness(operation, apiScan) {
    const elements = new Map();
    const intervals = new Map();
    let nextInterval = 0;
    let progress = { active: false, cancelled: false, processed: 17, message: 'Concluído' };
    const element = id => {
        if (!elements.has(id)) {
            elements.set(id, {
                disabled: false,
                hidden: true,
                value: '100',
                innerHTML: '',
                textContent: '',
                classList: { add() {}, remove() {} },
                setAttribute(name, value) { this[name] = value; },
            });
        }
        return elements.get(id);
    };
    const buttonId = operation === 'large_files' ? 'btn-scan-large' : 'btn-scan-duplicates';
    const context = vm.createContext({
        document: {
            getElementById: element,
            querySelector: element,
        },
        loaderProgress: element('loader-progress'),
        cancelOperationBtn: element('btn-cancel-operation'),
        window: { pywebview: { api: {
            get_operation_progress: async () => ({ ...progress }),
            scan_large_files: apiScan,
            scan_duplicates: apiScan,
        } } },
        setInterval(callback) {
            intervals.set(++nextInterval, callback);
            return nextInterval;
        },
        clearInterval(id) { intervals.delete(id); },
        showLoader() {},
        hideLoader() {},
        reportScanIssues: async () => {},
        showToast() {},
        escapeHtml: value => String(value),
    });
    vm.runInContext(`
        let activeOperation = null;
        let operationProgressTimer = null;
        let trackedOperationButton = null;
        let scannedLargeFiles = [];
        let scannedDuplicates = [];
        ${functionsUnderTest}
    `, context);
    return {
        element,
        buttonId,
        intervals,
        active: () => vm.runInContext('activeOperation', context),
        run: () => vm.runInContext(
            operation === 'large_files' ? 'scanLargeFiles()' : 'scanDuplicates()', context
        ),
        setProgress(next) { progress = next; },
        async poll() { await Promise.all([...intervals.values()].map(callback => callback())); },
    };
}

// Allow the initial progress request to settle while the scan remains pending.
const settle = () => new Promise(resolve => setImmediate(resolve));

for (const operation of ['large_files', 'duplicates']) {
    test(`${operation}: previous completion cannot finish the new scan`, async () => {
        const scan = deferred();
        const harness = makeHarness(operation, () => scan.promise);
        const running = harness.run();
        await settle();

        assert.equal(harness.active(), operation);
        assert.equal(harness.element(harness.buttonId).disabled, true);
        assert.equal(harness.element('loader-progress').hidden, false);
        assert.equal(harness.element('loader-progress').textContent, 'Iniciando varredura…');
        assert.equal(harness.element('btn-cancel-operation').hidden, false);
        assert.equal(harness.intervals.size, 1);

        harness.setProgress({ active: true, cancelled: false, processed: 42, message: 'Examinando arquivos' });
        await harness.poll();
        assert.equal(harness.element('loader-progress').textContent, 'Examinando arquivos · 42');

        // Polling completion can arrive before the main API promise resolves.
        harness.setProgress({ active: false, cancelled: false, processed: 42, message: 'Concluído' });
        await harness.poll();
        assert.equal(harness.active(), operation);
        assert.equal(harness.element(harness.buttonId).disabled, true);
        assert.equal(harness.element('btn-cancel-operation').hidden, false);

        scan.resolve([]);
        await running;
        assert.equal(harness.active(), null);
        assert.equal(harness.element(harness.buttonId).disabled, false);
        assert.equal(harness.element('loader-progress').hidden, true);
        assert.equal(harness.element('btn-cancel-operation').hidden, true);
        assert.equal(harness.intervals.size, 0);
    });

    test(`${operation}: a fast scan releases tracking without observing active progress`, async () => {
        const harness = makeHarness(operation, async () => []);
        await harness.run();
        assert.equal(harness.active(), null);
        assert.equal(harness.element(harness.buttonId).disabled, false);
        assert.equal(harness.element('btn-cancel-operation').hidden, true);
        assert.equal(harness.intervals.size, 0);
    });

    test(`${operation}: a rejected scan releases tracking`, async () => {
        const scan = deferred();
        const harness = makeHarness(operation, () => scan.promise);
        const running = harness.run();
        await settle();
        scan.reject(new Error('Simulated scan failure'));
        await running;
        assert.equal(harness.active(), null);
        assert.equal(harness.element(harness.buttonId).disabled, false);
        assert.equal(harness.element('btn-cancel-operation').hidden, true);
        assert.equal(harness.intervals.size, 0);
    });
}

function makeDuplicateTable() {
    const groups = [
        { id: 'large', name: 'Bravo.txt', size: 2 * 1024 * 1024 },
        { id: 'tiny', name: 'Zulu.txt', size: 100 },
        { id: 'medium', name: 'Alpha.txt', size: 10 * 1024 },
    ];
    const rows = [];
    for (const group of groups) {
        rows.push({
            id: `${group.id}:header`,
            dataset: { groupName: group.name, groupSize: String(group.size) },
            classList: { contains: name => name === 'dup-header-row' },
            // Hash headers have only two cells because their cells span columns.
            children: [{ textContent: 'Conjunto Duplicado' }, { textContent: `SHA-256: ${group.id}` }],
        });
        for (const [index, name] of [group.name, `Copy-${group.name}`].entries()) {
            rows.push({
                id: `${group.id}:copy${index}`,
                dataset: {},
                classList: { contains: () => false },
                keeper: index === 0,
                checkboxValue: `${group.id}:${index}`,
                children: [
                    { textContent: '' },
                    { textContent: name },
                    { textContent: `${group.size} B` },
                ],
            });
        }
    }
    const tbody = {
        children: rows,
        querySelectorAll: () => rows,
        appendChild(row) {
            const index = rows.indexOf(row);
            if (index >= 0) rows.splice(index, 1);
            rows.push(row);
        },
    };
    const table = { id: 'duplicates-table', querySelector: () => tbody };
    const headers = ['name', 'size'].map(type => {
        const listeners = new Map();
        return {
            dataset: { sort: type },
            icon: { textContent: '▼' },
            closest: () => table,
            querySelector() { return this.icon; },
            addEventListener(name, listener) { listeners.set(name, listener); },
            click() { listeners.get('click')(); },
        };
    });
    const parentNode = {
        children: headers,
        querySelectorAll: () => headers.map(header => header.icon),
    };
    headers.forEach(header => { header.parentNode = parentNode; });
    const context = vm.createContext({ document: {
        querySelectorAll: selector => selector === 'th[data-sort]' ? headers : [],
    } });
    vm.runInContext(sourceBetween('function sortDuplicateGroups(', "document.addEventListener('DOMContentLoaded', setupTableInteractions);"), context);
    vm.runInContext('setupTableInteractions()', context);
    return { rows, headers, groups };
}

for (const [type, ascending] of [
    ['name', ['medium', 'large', 'tiny']],
    ['size', ['tiny', 'medium', 'large']],
]) {
    test(`duplicates: ${type} sorting keeps each hash and preserved copy together`, () => {
        const { rows, headers } = makeDuplicateTable();
        const header = headers.find(item => item.dataset.sort === type);
        const initialCopies = new Map(rows.filter(row => row.checkboxValue).map(row => [row.id, {
            value: row.checkboxValue,
            keeper: row.keeper,
        }]));
        const assertGroups = order => {
            assert.deepEqual(rows.map(row => row.id), order.flatMap(id => [
                `${id}:header`, `${id}:copy0`, `${id}:copy1`,
            ]));
            rows.filter(row => row.checkboxValue).forEach(row => {
                assert.equal(row.checkboxValue, initialCopies.get(row.id).value);
                assert.equal(row.keeper, initialCopies.get(row.id).keeper);
            });
        };

        header.click();
        assertGroups(ascending);
        assert.equal(header.dataset.dir, 'asc');
        assert.equal(header.icon.textContent, '▲');
        header.click();
        assertGroups([...ascending].reverse());
        assert.equal(header.dataset.dir, 'desc');
        assert.equal(header.icon.textContent, '▼');
    });
}
