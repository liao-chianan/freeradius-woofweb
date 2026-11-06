(function () {
    'use strict';
    // 管理介面掛在 /woofradius 之類的前綴底下，由 base.html 的 body data-base 提供
    var BASE = document.body.dataset.base || '';
    var dialog = document.getElementById('entry-dialog');
    var form = document.getElementById('entry-form');
    var errorsBox = document.getElementById('entry-errors');
    var confirmBox = document.getElementById('entry-confirm');
    var goButton = document.getElementById('confirm-go');
    var preview = null;

    function post(url, data) {
        return fetch(url, { method: 'POST', body: data, credentials: 'same-origin' }).then(function (res) {
            var type = res.headers.get('content-type') || '';
            if (res.redirected || type.indexOf('application/json') === -1) {
                location.href = BASE + '/login';
                throw new Error('login required');
            }
            return res.json();
        });
    }

    function showErrors(errors) {
        errorsBox.textContent = '';
        errors.forEach(function (text) {
            var line = document.createElement('div');
            line.textContent = text;
            errorsBox.appendChild(line);
        });
        errorsBox.hidden = errors.length === 0;
    }

    function setField(name, value) {
        form.elements[name].value = value || '';
    }

    function showForm() {
        form.hidden = false;
        confirmBox.hidden = true;
    }

    function openForm(op, row) {
        form.reset();
        showErrors([]);
        showForm();
        var isAdd = op === 'add';
        document.getElementById('entry-title').textContent = isAdd ? '新增裝置' : '編輯裝置';
        setField('op', op);
        setField('key', isAdd ? '' : row.dataset.mac);
        setField('id', isAdd ? '' : row.dataset.id);
        setField('mac', isAdd ? '' : row.dataset.mac);
        setField('tunnel_group', isAdd ? '' : row.dataset.group);
        setField('tunnel_type', isAdd ? '' : row.dataset.type);
        setField('tunnel_medium', isAdd ? '' : row.dataset.medium);
        form.querySelector('.field-row').hidden = isAdd;
        document.getElementById('add-defaults').hidden = !isAdd;
        dialog.showModal();
        form.elements.id.focus();
    }

    function cell(row, tag, text, className) {
        var el = document.createElement(tag);
        el.textContent = text;
        if (className) { el.className = className; }
        row.appendChild(el);
    }

    function showConfirm(data) {
        preview = data;
        var titles = { add: '確認新增', edit: '確認修改', 'delete': '確認刪除' };
        var leads = { add: '即將新增以下裝置：', edit: '即將修改以下欄位：', 'delete': '即將刪除以下裝置，刪除後將無法再通過認證：' };
        document.getElementById('entry-title').textContent = titles[data.op];
        document.getElementById('confirm-lead').textContent = leads[data.op];
        var table = document.getElementById('confirm-table');
        table.textContent = '';
        if (data.op === 'edit') {
            var head = table.insertRow();
            cell(head, 'th', '欄位');
            cell(head, 'th', '修改前');
            cell(head, 'th', '修改後');
            data.changes.forEach(function (c) {
                var row = table.insertRow();
                cell(row, 'td', c.label);
                cell(row, 'td', c.before, 'mono old');
                cell(row, 'td', c.after, 'mono new');
            });
        } else {
            data.details.forEach(function (d) {
                var row = table.insertRow();
                cell(row, 'th', d.label);
                cell(row, 'td', d.value, 'mono');
            });
        }
        goButton.className = data.op === 'delete' ? 'btn danger' : 'btn primary';
        goButton.textContent = data.op === 'delete' ? '確認刪除' : '確認執行';
        goButton.disabled = false;
        document.getElementById('confirm-back').hidden = data.op === 'delete';
        form.hidden = true;
        confirmBox.hidden = false;
        if (!dialog.open) { dialog.showModal(); }
        goButton.focus();
    }

    function requestPreview() {
        showErrors([]);
        return post(BASE + '/entry/preview', new FormData(form)).then(function (data) {
            if (data.ok) {
                showConfirm(data);
            } else if (form.elements.op.value === 'delete') {
                window.alert(data.errors.join('\n'));
            } else {
                showForm();
                if (!dialog.open) { dialog.showModal(); }
                showErrors(data.errors);
            }
        });
    }

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        requestPreview();
    });

    document.getElementById('confirm-back').addEventListener('click', function () {
        document.getElementById('entry-title').textContent = form.elements.op.value === 'add' ? '新增裝置' : '編輯裝置';
        showForm();
    });

    goButton.addEventListener('click', function () {
        goButton.disabled = true;
        var data = new FormData(form);
        data.append('confirmed', '1');
        data.append('version', preview.version);
        post(BASE + '/entry/commit', data).then(function (result) {
            if (result.ok) {
                location.reload();
                return;
            }
            goButton.disabled = false;
            showErrors(result.errors);
        });
    });

    document.querySelectorAll('dialog .js-close').forEach(function (button) {
        button.addEventListener('click', function () { button.closest('dialog').close(); });
    });

    function showLogins(label, url, columns, retentionLabel) {
        var box = document.getElementById('logins-dialog');
        var body = document.getElementById('logins-rows');
        var errorBox = document.getElementById('logins-error');
        var note = document.getElementById('logins-note');
        var head = document.getElementById('logins-head');
        document.getElementById('logins-device').textContent = label;
        head.textContent = '';
        var headRow = head.insertRow();
        columns.forEach(function (column) { cell(headRow, 'th', column.title); });
        body.textContent = '';
        note.textContent = '讀取中…';
        errorBox.hidden = true;
        document.getElementById('logins-empty').hidden = true;
        document.getElementById('logins-wrap').hidden = true;
        box.showModal();
        fetch(url, { credentials: 'same-origin' }).then(function (res) {
            var type = res.headers.get('content-type') || '';
            if (res.redirected || type.indexOf('application/json') === -1) {
                location.href = BASE + '/login';
                throw new Error('login required');
            }
            return res.json();
        }).then(function (data) {
            if (!data.ok) {
                errorBox.textContent = data.errors.join('、');
                errorBox.hidden = false;
                note.textContent = '';
                return;
            }
            data.rows.forEach(function (item) {
                var tr = body.insertRow();
                columns.forEach(function (column) { cell(tr, 'td', item[column.key] || '未記錄', column.className); });
            });
            document.getElementById('logins-wrap').hidden = data.rows.length === 0;
            document.getElementById('logins-empty').hidden = data.rows.length !== 0;
            note.textContent = '共 ' + data.rows.length + ' 筆；' + retentionLabel + '保留最近 ' + data.retention + ' 筆，可到系統設定變更。';
        }).catch(function (err) {
            if (err.message !== 'login required') {
                errorBox.textContent = '讀取失敗，請稍後再試';
                errorBox.hidden = false;
                note.textContent = '';
            }
        });
    }

    document.addEventListener('click', function (event) {
        var adRow = event.target.closest('tr[data-account]');
        if (adRow) {
            if (event.target.classList.contains('js-ad-logins')) {
                showLogins(adRow.dataset.account + (adRow.dataset.name ? '（' + adRow.dataset.name + '）' : ''),
                    BASE + '/ad/logins?account=' + encodeURIComponent(adRow.dataset.account),
                    [{ title: '登入時間', key: 'time', className: 'nowrap' },
                     { title: '連線 AP', key: 'ap_name', className: 'nowrap' },
                     { title: '要求認證的 IP', key: 'ip', className: 'mono' },
                     { title: '裝置 MAC', key: 'mac', className: 'mono' },
                     { title: 'AP MAC', key: 'ap_mac', className: 'mono' },
                     { title: 'SSID', key: 'ssid' }], '每個帳號');
            }
            return;
        }
        var row = event.target.closest('tr[data-mac]');
        if (!row) { return; }
        if (event.target.classList.contains('js-logins')) {
            showLogins(row.dataset.id + '（' + row.dataset.mac + '）',
                BASE + '/entry/logins?mac=' + encodeURIComponent(row.dataset.mac),
                [{ title: '登入時間', key: 'time', className: 'nowrap' },
                 { title: '連線 AP', key: 'ap_name', className: 'nowrap' },
                 { title: '要求認證的 IP', key: 'ip', className: 'mono' },
                 { title: 'NAS-IP-Address', key: 'nas_ip', className: 'mono' },
                 { title: 'AP MAC', key: 'ap_mac', className: 'mono' },
                 { title: 'SSID', key: 'ssid' }], '每台裝置');
        } else if (event.target.classList.contains('js-edit')) {
            openForm('edit', row);
        } else if (event.target.classList.contains('js-delete')) {
            form.reset();
            showErrors([]);
            setField('op', 'delete');
            setField('key', row.dataset.mac);
            requestPreview();
        }
    });

    var addButton = document.getElementById('open-add');
    if (addButton) {
        addButton.addEventListener('click', function () { openForm('add'); });
        document.getElementById('open-import').addEventListener('click', function () {
            document.getElementById('import-dialog').showModal();
        });
    }

    document.querySelectorAll('form[data-confirm]').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!window.confirm(form.dataset.confirm)) { event.preventDefault(); return; }
            var search = document.getElementById('filter');
            var current = form.querySelector('.js-current-q');
            if (search && current) { current.value = search.value; }
        });
    });

    document.querySelectorAll('select[data-autosubmit]').forEach(function (select) {
        select.addEventListener('change', function () { select.form.submit(); });
    });

    document.querySelectorAll('[data-open-dialog]').forEach(function (button) {
        button.addEventListener('click', function () {
            document.getElementById(button.dataset.openDialog).showModal();
        });
    });

    var filter = document.getElementById('filter');
    if (filter) {
        var tbody = document.querySelector('#entries tbody');
        var rows = Array.prototype.slice.call(tbody.rows);
        var total = rows.filter(function (row) { return !row.dataset.other; }).length;
        // 分隔符號都忽略，AA:BB、aa-bb、aabb.ccdd 都找得到
        function squeeze(text) { return text.toLowerCase().replace(/[:.\-]/g, ''); }
        function applyFilter() {
            var words = squeeze(filter.value).split(/\s+/).filter(Boolean);
            var shown = 0;
            var others = 0;
            rows.forEach(function (row) {
                var text = squeeze(row.dataset.search || (row.dataset.id + ' ' + row.dataset.mac + ' ' + row.dataset.modified));
                var match = words.every(function (w) { return text.indexOf(w) !== -1; });
                row.hidden = !match || Boolean(row.dataset.other);
                if (match && row.dataset.other) { others += 1; }
                if (!row.hidden) { shown += 1; }
            });
            var hidden = document.getElementById('filter-q');
            if (hidden) { hidden.value = filter.value; }
            var hint = document.getElementById('other-status');
            if (hint) {
                hint.hidden = !(words.length && others);
                document.getElementById('other-count').textContent = others;
                document.getElementById('other-link').href = BASE + '/ad?status=all&q=' + encodeURIComponent(filter.value);
            }
            document.getElementById('row-count').textContent = words.length ? '符合 ' + shown + ' / ' + total + ' 筆' : '共 ' + total + ' 筆';
            document.getElementById('empty').hidden = shown !== 0;
        }
        filter.addEventListener('input', applyFilter);
        if (filter.value) { applyFilter(); }
        document.querySelectorAll('#entries th[data-sort]').forEach(function (th) {
            th.tabIndex = 0;
            function sort() {
                var ascending = th.getAttribute('aria-sort') !== 'ascending';
                document.querySelectorAll('#entries th[data-sort]').forEach(function (other) { other.setAttribute('aria-sort', 'none'); });
                th.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');
                var key = th.dataset.sort;
                rows.sort(function (a, b) {
                    var order = a.dataset[key].localeCompare(b.dataset[key], undefined, { numeric: true });
                    return ascending ? order : -order;
                });
                rows.forEach(function (row) { tbody.appendChild(row); });
            }
            th.addEventListener('click', sort);
            th.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); sort(); }
            });
        });
    }
}());
