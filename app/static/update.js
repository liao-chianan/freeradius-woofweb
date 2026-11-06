(function () {
    'use strict';
    var BASE = document.body.dataset.base || '';
    var $ = function (id) { return document.getElementById(id); };
    var latest = '';

    function post(path, data) {
        return fetch(BASE + path, { method: 'POST', body: data || new FormData(), credentials: 'same-origin' })
            .then(function (res) {
                var type = res.headers.get('Content-Type') || '';
                if (type.indexOf('application/json') === -1) { throw new Error('連線逾時或已登出，請重新整理（HTTP ' + res.status + '）'); }
                return res.json();
            });
    }
    function show(el, text, kind) {
        el.hidden = false;
        el.className = 'notice ' + (kind || 'success');
        el.textContent = text;
    }
    function notesBlock(item) {
        var box = document.createElement('div');
        box.className = 'release-note';
        var h = document.createElement('h4');
        h.textContent = item.title;
        var body = document.createElement('div');
        body.className = 'release-notes';
        body.textContent = item.notes;
        box.appendChild(h);
        box.appendChild(body);
        return box;
    }

    // ---- 確認密碼 ----
    var pwResolve = null;
    function askPassword(lead) {
        $('password-lead').textContent = lead;
        $('password-error').hidden = true;
        $('password-form').reset();
        $('password-dialog').showModal();
        return new Promise(function (resolve) { pwResolve = resolve; });
    }
    $('password-form').addEventListener('submit', function (event) {
        event.preventDefault();
        var value = $('password-form').password.value;
        $('password-dialog').close();
        if (pwResolve) { pwResolve(value); pwResolve = null; }
    });
    $('password-cancel').addEventListener('click', function () {
        $('password-dialog').close();
        if (pwResolve) { pwResolve(null); pwResolve = null; }
    });

    // ---- 檢查版本 ----
    function check() {
        post('/update/check').then(function (data) {
            if (data.public_key) { $('public-key').hidden = false; $('public-key').textContent = data.public_key; $('key-button').hidden = true; }
            if (!data.ok) {
                $('latest-version').textContent = '無法取得';
                show($('check-message'), data.error || '檢查失敗', 'error');
                $('key-box').hidden = false;
                return;
            }
            latest = data.latest;
            $('latest-version').textContent = data.latest || '（沒有版本標籤）';
            if (data.current_notes) { $('current-notes-box').hidden = false; $('current-notes').textContent = data.current_notes.notes; }
            if (data.public_key) { $('key-box').hidden = false; }
            if (data.newer.length) {
                show($('check-message'), '有新版本 ' + data.latest + '（目前 ' + data.current + '）', 'warning');
                var list = $('newer-notes');
                list.textContent = '';
                data.newer.forEach(function (item) { list.appendChild(notesBlock(item)); });
                $('update-button').textContent = '更新到 ' + data.latest;
                $('newer').hidden = false;
            } else {
                show($('check-message'), '目前已是最新版本', 'success');
            }
            if (data.running) { watch(); }
        }).catch(function (err) {
            $('latest-version').textContent = '無法取得';
            show($('check-message'), err.message, 'error');
        });
    }

    $('key-button').addEventListener('click', function () {
        post('/update/key').then(function (data) {
            if (!data.ok) { show($('check-message'), data.error, 'error'); return; }
            $('public-key').hidden = false;
            $('public-key').textContent = data.public_key;
            $('key-button').hidden = true;
        });
    });

    // ---- 更新與回溯 ----
    function start(kind, target, lead) {
        askPassword(lead).then(function (password) {
            if (password === null) { return; }
            var data = new FormData();
            data.append('password', password);
            data.append('kind', kind);
            data.append(kind === 'update' ? 'version' : 'backup', target);
            post('/update/start', data).then(function (result) {
                if (!result.ok) { show($('check-message'), result.error || '無法開始', 'error'); $('check-message').scrollIntoView({ block: 'center' }); return; }
                watch();
            }).catch(function (err) { show($('check-message'), err.message, 'error'); });
        });
    }
    $('update-button').addEventListener('click', function () {
        start('update', latest, '要更新到 ' + latest + ' 嗎？更新前會自動備份，FreeRADIUS 與網頁服務會重新啟動。');
    });

    var watching = false;
    function watch() {
        if (watching) { return; }
        watching = true;
        $('progress-card').hidden = false;
        $('progress-card').scrollIntoView({ block: 'start' });
        var started = Date.now();
        (function poll() {
            fetch(BASE + '/update/status', { credentials: 'same-origin' }).then(function (res) {
                if ((res.headers.get('Content-Type') || '').indexOf('application/json') === -1) { throw new Error('restart'); }
                return res.json();
            }).then(function (st) {
                $('progress-title').textContent = (st.kind === 'rollback' ? '回溯' : '更新到 ' + st.target) +
                    (st.state === 'running' ? ' 進行中…' : st.state === 'done' ? ' 完成' : ' 失敗');
                var steps = $('progress-steps');
                steps.textContent = '';
                (st.steps || []).forEach(function (item) {
                    var li = document.createElement('li');
                    li.className = item.ok ? 'ok' : 'fail';
                    li.textContent = item.name;
                    if (item.detail) { var small = document.createElement('small'); small.textContent = item.detail; li.appendChild(small); }
                    steps.appendChild(li);
                });
                if (st.log) { $('progress-log-box').hidden = false; $('progress-log').textContent = st.log; }
                if (st.state === 'done' || st.state === 'failed') {
                    show($('progress-message'), st.state === 'done' ? '完成，目前版本 ' + st.version + '。請重新整理頁面。' : '沒有完成，系統維持（或已切回）原本的版本。', st.state === 'done' ? 'success' : 'error');
                    $('progress-done').hidden = false;
                    watching = false;
                    return;
                }
                $('progress-message').hidden = true;
                setTimeout(poll, 2000);
            }).catch(function () {
                show($('progress-message'), '網頁服務重新啟動中…', 'warning');
                if (Date.now() - started > 20 * 60 * 1000) { show($('progress-message'), '超過 20 分鐘沒有結果，請重新整理或查看主機的 journalctl -u radius-manager-update', 'error'); watching = false; return; }
                setTimeout(poll, 3000);
            });
        }());
    }

    function loadBackups() {
        post('/update/backups').then(function (data) {
            var body = $('backup-rows');
            body.textContent = '';
            if (!data.ok || !data.backups.length) {
                var tr = document.createElement('tr');
                var td = document.createElement('td');
                td.colSpan = 5; td.className = 'muted';
                td.textContent = data.ok ? '還沒有備份，第一次更新時會自動建立' : (data.error || '無法讀取');
                tr.appendChild(td); body.appendChild(tr);
                return;
            }
            data.backups.forEach(function (b) {
                var tr = document.createElement('tr');
                [b.time, b.version, b.reason, (b.size / 1048576).toFixed(1) + ' MB'].forEach(function (text) {
                    var td = document.createElement('td'); td.textContent = text; tr.appendChild(td);
                });
                var td = document.createElement('td');
                var button = document.createElement('button');
                button.type = 'button'; button.className = 'btn small'; button.textContent = '回溯到 ' + b.version;
                button.addEventListener('click', function () {
                    start('rollback', b.id, '要回溯到 ' + b.version + '（' + b.time + ' 的備份）嗎？回溯前會先備份目前版本，FreeRADIUS 與網頁服務會重新啟動。');
                });
                td.appendChild(button); tr.appendChild(td);
                body.appendChild(tr);
            });
        });
    }

    // ---- 校驗 ----
    $('verify-button').addEventListener('click', function () {
        var button = $('verify-button');
        button.disabled = true;
        show($('verify-message'), '下載並比對中…', 'warning');
        $('verify-table-wrap').hidden = true;
        post('/update/verify').then(function (data) {
            if (!data.ok) { show($('verify-message'), data.error, 'error'); return; }
            var problems = data.differences.concat(data.links);
            if (!problems.length) {
                show($('verify-message'), '全部相同：' + data.compared + ' 個程式檔與 GitHub 上的 v' + data.version + ' 一致', 'success');
                return;
            }
            show($('verify-message'), '有 ' + problems.length + ' 處與 GitHub 上的 v' + data.version + ' 不同（相同 ' + data.same + ' 個）', 'error');
            var labels = { modified: '內容不同', missing: '這台主機缺少', extra: 'GitHub 上沒有（多出來的）' };
            var body = $('verify-rows');
            body.textContent = '';
            problems.forEach(function (row) {
                var tr = document.createElement('tr');
                var a = document.createElement('td'); a.className = 'mono'; a.textContent = row.path;
                var b = document.createElement('td'); b.className = 'status-off'; b.textContent = labels[row.state] || row.state;
                tr.appendChild(a); tr.appendChild(b); body.appendChild(tr);
            });
            $('verify-table-wrap').hidden = false;
        }).catch(function (err) { show($('verify-message'), err.message, 'error'); })
            .then(function () { button.disabled = false; });
    });

    // ---- 匯出設定 ----
    $('export-button').addEventListener('click', function () {
        askPassword('匯出的檔案含有密碼雜湊、RADIUS 共用金鑰與私鑰，請妥善保存。').then(function (password) {
            if (password === null) { return; }
            var data = new FormData();
            data.append('password', password);
            fetch(BASE + '/update/export', { method: 'POST', body: data, credentials: 'same-origin' }).then(function (res) {
                if ((res.headers.get('Content-Type') || '').indexOf('application/gzip') === -1) {
                    return res.json().then(function (body) { throw new Error(body.error || '匯出失敗'); });
                }
                var match = /filename=([^;]+)/.exec(res.headers.get('Content-Disposition') || '');
                return res.blob().then(function (blob) {
                    var link = document.createElement('a');
                    link.href = URL.createObjectURL(blob);
                    link.download = match ? match[1] : 'freeradius-woofweb-config.tar.gz';
                    document.body.appendChild(link);
                    link.click();
                    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1000);
                    show($('export-message'), '已下載 ' + link.download + '（' + (blob.size / 1024).toFixed(0) + ' KB）', 'success');
                });
            }).catch(function (err) { show($('export-message'), err.message, 'error'); });
        });
    });

    fetch(BASE + '/update/status', { credentials: 'same-origin' }).then(function (r) { return r.json(); })
        .then(function (st) { if (st.state === 'running') { watch(); } }).catch(function () {});
    check();
    loadBackups();
}());
